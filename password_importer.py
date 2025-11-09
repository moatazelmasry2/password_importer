#!/usr/bin/env python3
"""
Import legacy plaintext password files into Postgres using SQLModel (SQLAlchemy + Pydantic v2).

- Input: --input-name supports a comma-separated list of paths to .txt or .tar.gz
  * Trailing comma is tolerated: "file1.txt,file2.tar.gz," -> the empty item is ignored
  * .txt files are read directly
  * .tar.gz files are streamed: every *.txt member is read via tarfile.extractfile() (no persistence)
- Each line must contain exactly --delimiter-count occurrences of ':' or it's logged to the error file.
- Two formats are supported (you select which via --delimiter-count):
  * delimiter-count=2 => format1: "site:username:password"
      - "site" may be a bare host or a full URL
      - We extract FQDN = netloc without credentials; keep port, lowercase stored
  * delimiter-count=1 => format2: "username:password"
      - Used for email accounts: fqdn = domain part of username's email
- --fqdn (if provided) ALWAYS wins for all rows (overrides email-derived domains)
- --country (optional) applies to all rows; auto-creates missing country
- Domains auto-created if they don't exist
- Unique login key: (domain_id, username, password); duplicates are skipped (ON CONFLICT DO NOTHING)
- End-of-run summary printed
"""

from __future__ import annotations

import re
import argparse
import ipaddress
import os
import sys
import io
import tarfile
import time
from typing import Iterable, Optional, Tuple, List, Dict, Any
import logging
from functools import lru_cache
from urllib.parse import urlsplit
from dataclasses import dataclass
import threading
import queue
from contextlib import contextmanager
import tarfile, codecs
import tldextract, idna
import hashlib
import struct
from hashlib import blake2b
from time import perf_counter
import unicodedata
from psycopg import Binary
import fnmatch


import psycopg
from psycopg import sql

logging.basicConfig(level=logging.INFO)

EXTRACTOR = tldextract.TLDExtract(
    suffix_list_urls=None,            # never hit network
    fallback_to_snapshot=True,        # use the built-in PSL snapshot
    cache_dir=None                    # no disk I/O
)

_prof = {
    "parse_time": 0.0,
    "domain_sql_time": 0.0,
    "domain_sql_calls": 0,
    "domain_cache_hits": 0,
    "domain_inserts": 0,
    "copy_logins_time": 0.0,
    "copy_logins_rows": 0,
    "merge_time": 0.0,
    "copy_ips_time": 0.0,
    "copy_ips_rows": 0,
    "final_commit_time": 0.0,
    "relog_time": 0.0,
}

Row = tuple[str, tuple]  # ("ip" | "login", row_tuple)

_ip4_re = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?$")
_ip6_bare_re = re.compile(r"^[0-9A-Fa-f:]+(?:%\w+)?(?:\:\d+)?$")
_ip6_bracket_re = re.compile(r"^\[[0-9A-Fa-f:]+\](?::\d+)?$")
_placeholder_pw = re.compile(r"^\[(?:NOT[_\- ]?SAVED|EMPTY|N/A)\]$", re.I)
_simple_host = re.compile(r"^[A-Za-z0-9.-]+(?::\d+)?$")
_strip_prefix = re.compile(
    r'^(?:www\.|login\.|app\.|accounts\.|api\.|auth\.|m\.|web\.|sso\.|account\.|signup\.|login3\.|apply\.|register\.)+',
    re.I
)
_special_url_login_re = re.compile(r'^(https?://.+?):([^:]+?):(.*)$')

# Pattern 1: site1:(site2):username:password
# - site2 is usually the same site as site1 with a minor path difference
_dual_url_tuple_re = re.compile(
    r'^(https?://[^:]+?):\((https?://[^)]+)\):([^:]+?):(.*)$'
)


WORKER_COUNT = 4  # tune for I/O; 2–8 is usually good
Q_MAXSIZE = 10000  # backpressure; adjust for memory

DEBUG_COPY_TRACE = True            # logs encodings + sample line
DEBUG_BISECT_ON_COPY_ERROR = True # set True only when you want to isolate a bad row

STAGE_IPS    = "ip_logins_stage"

# Runtime-configurable patterns (populated from CLI / file)
ALLOWLIST_PATTERNS: list[re.Pattern] = []
DENYLIST_PATTERNS:   list[re.Pattern] = []

# Skip usernames exactly in this set
SKIP_USERNAMES = {"TRUE", "FALSE", "UNKNOWN"}
SPECIAL_DOMAINS = {}  # per-domain routing removed (single table)
_BAD_ROW_LOGGED = {"public.logins": False}

# Buckets
BUCKETS = 256

STAGE_LOGINS = "logins_stage"

DEBUG_COPY_TEXT = True  # keep True until stable; set False to go back to binary later

domain_cache: dict[str, int] = {}

MERGE_REMOTE_SQL = f"""
SET LOCAL synchronous_commit = OFF;
SET LOCAL work_mem = '512MB';
SET LOCAL maintenance_work_mem = '4GB';
SET LOCAL wal_compression = ON;

-- Only IP pipeline remains: batch de-dup then insert
DROP TABLE IF EXISTS _ips_distinct;
CREATE TEMP TABLE _ips_distinct AS
SELECT DISTINCT ON (ip_address, username, password)
  ip_address, username, password
FROM {STAGE_IPS}
ORDER BY ip_address, username, password;

INSERT INTO public.ip_logins (ip_address, username, password)
SELECT ip_address, username, password
FROM _ips_distinct
ON CONFLICT DO NOTHING;

TRUNCATE {STAGE_IPS};

ANALYZE public.ip_logins;
""".strip()

MERGE_LOGINS_SQL = """
INSERT INTO public.logins (username, password, domain_id, cred_hash, bucket, country_id, valid)
SELECT DISTINCT
  s.username,
  s.password,
  s.domain_id,          -- stage is bigint; keep if target is bigint
  s.cred_hash,
  s.bucket::int,        -- cast down if target is int
  s.country_id,         -- bigint -> bigint (or cast if your target is int)
  s.valid
FROM logins_stage s
ON CONFLICT DO NOTHING;
TRUNCATE logins_stage;
""".strip()


# ---------------------------
# Pydantic v2 data models
# --------------------------

@dataclass(slots=True)
class ParsedLogin:
    username: str
    password: str
    domain_name: Optional[str]  # None when it's an IP (we'll use ip_full)
    verbatim_domain: bool = False
    ip_full: Optional[str] = None  # exact "host[:port]/path" (or full URL) when host is IP
 


# ---------------------------
# Utilities
# ---------------------------

def _introspect_cols(cur, relname: str) -> list[tuple[str, str]]:
    """
    Return [(column_name, type_text), ...] for a relation that's visible on the current search_path.
    Works with TEMP tables (pg_temp) created in this session.
    """
    cur.execute("""
        SELECT a.attname, (a.atttypid::regtype)::text
        FROM pg_attribute a
        JOIN pg_class c ON c.oid = a.attrelid
        WHERE c.relname = %s
          AND pg_table_is_visible(c.oid)
          AND a.attnum > 0
          AND NOT a.attisdropped
        ORDER BY a.attnum
    """, (relname,))
    return [(r[0], r[1]) for r in cur.fetchall()]

def _row_debug_signature(row: tuple) -> str:
    sig = []
    for x in row:
        if isinstance(x, (bytes, bytearray, memoryview)):
            blen = len(x if isinstance(x, (bytes, bytearray)) else x.tobytes())
            sig.append(f"bytea[{blen}]")
        elif x is None:
            sig.append("NULL")
        else:
            sig.append(f"{type(x).__name__}={x!r}")
    return " | ".join(sig)

def _print_stage_layout(cur, relname: str = None):
    relname = relname or STAGE_LOGINS
    cols = _introspect_cols(cur, relname)

def _emit_stage_line_bytes(r: tuple) -> bytes:
    """
    row -> ASCII bytes for TEXT COPY into logins_stage.
    r layout: (username_b, password_b, domain_id, cred_hash_b, bucket, country_id, valid)
    """
    u_b, p_b, did, ch_b, bkt, cid, val = r
    u_txt  = _bytea_text(u_b)     # "\x" + hex
    p_txt  = _bytea_text(p_b)
    ch_txt = _bytea_text(ch_b)
    did_txt = str(int(did))
    bkt_txt = str(int(bkt))
    cid_txt = (str(int(cid)) if cid is not None else r"\N")
    val_txt = ("t" if val is True else "f" if val is False else r"\N")
    line = "\t".join((u_txt, p_txt, did_txt, ch_txt, bkt_txt, cid_txt, val_txt)) + "\n"
    # Strict ASCII: if this ever raises, we know we constructed a non-ASCII line.
    return line.encode("ascii", "strict")

def _copy_text_block(cur, rows_bytes: list[bytes]) -> None:
    """
    COPY TEXT block into logins_stage with explicit ENCODING and SAVEPOINT.
    Raises psycopg.Error on server failure.
    """
    # Always use a savepoint so a failure doesn't poison the whole txn.
    cur.execute("SAVEPOINT sp_copy")
    try:
        with cur.copy(
            f"COPY {STAGE_LOGINS} "
            f"(username,password,domain_id,cred_hash,bucket,country_id,valid) "
            f"FROM STDIN WITH (FORMAT text, DELIMITER E'\\t', NULL '\\N', ENCODING 'UTF8')"
        ) as cp:
            for bline in rows_bytes:
                if DEBUG_COPY_TRACE and any(b > 0x7F for b in bline):
                    raise AssertionError("non-ASCII byte in stage COPY line")
                cp.write(bline)
        cur.execute("RELEASE SAVEPOINT sp_copy")
    except psycopg.Error:
        # Roll back just this COPY attempt
        cur.execute("ROLLBACK TO SAVEPOINT sp_copy")
        raise

def _bisect_find_bad_row(cur, rows: list[tuple]) -> int:
    """
    Find the first row that makes COPY fail using binary search.
    Uses savepoints so we don't abort the transaction.
    Returns 0-based index into 'rows'.
    """
    lines = [_emit_stage_line_bytes(r) for r in rows]

    lo, hi = 0, len(lines)
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        # Clean the stage each probe
        cur.execute(f"TRUNCATE {STAGE_LOGINS}")
        try:
            _copy_text_block(cur, lines[lo:mid])
            lo = mid  # first half OK -> bad row in second half
        except psycopg.Error:
            hi = mid  # failure in first half
    return lo

def _emit_stage_line_bytes(r: tuple) -> bytes:
    """
    r: (username_b, password_b, domain_id, cred_hash_b, bucket, country_id, valid)
    -> ASCII line for COPY TEXT
    """
    u_b, p_b, did, ch_b, bkt, cid, val = r
    u_txt  = _bytea_text(u_b)
    p_txt  = _bytea_text(p_b)
    ch_txt = _bytea_text(ch_b)
    did_txt = str(int(did))
    bkt_txt = str(int(bkt))
    cid_txt = (str(int(cid)) if cid is not None else r"\N")
    val_txt = ("t" if val is True else "f" if val is False else r"\N")
    line = "\t".join((u_txt, p_txt, did_txt, ch_txt, bkt_txt, cid_txt, val_txt)) + "\n"
    return line.encode("ascii", "strict")

def _as_str(x) -> str:
    return x.decode("ascii", "ignore") if isinstance(x, (bytes, bytearray)) else str(x)

def _normalize_row_for_binary_strict(row: tuple, table: str) -> tuple:
    """
    Return a tuple with the exact types needed by COPY BINARY into:
      (username bytea, password bytea, domain_id int4, cred_hash bytea,
       bucket int4, country_id int4 or None, valid bool or None)

    - bytea -> memoryview over raw bytes
    - ints  -> int()
    - bool  -> bool() or None
    """
    if not isinstance(row, tuple) or len(row) != 7:
        raise ValueError(f"[{table}] bad row length: {len(row) if isinstance(row, tuple) else 'n/a'} : {row!r}")

    u_b, p_b, did, ch_b, bkt, cid, val = row

    # username bytea
    if isinstance(u_b, memoryview):
        u_mv = u_b
    else:
        try:
            u_mv = memoryview(bytes(u_b))
        except Exception as e:
            raise TypeError(f"[{table}] username not bytes-like: {type(u_b).__name__}") from e

    # password bytea
    if isinstance(p_b, memoryview):
        p_mv = p_b
    else:
        try:
            p_mv = memoryview(bytes(p_b))
        except Exception as e:
            raise TypeError(f"[{table}] password not bytes-like: {type(p_b).__name__}") from e

    # cred_hash bytea
    if isinstance(ch_b, psycopg.Binary):
        ch_b = bytes(ch_b.adapted) if hasattr(ch_b, "adapted") else bytes(ch_b)
    try:
        ch_mv = memoryview(bytes(ch_b))
    except Exception as e:
        raise TypeError(f"[{table}] cred_hash not bytes-like: {type(ch_b).__name__}") from e

    # domain_id int4
    try:
        did = int(did)
    except Exception as e:
        raise TypeError(f"[{table}] domain_id not int: {did!r}") from e

    # bucket int4
    try:
        bkt = int(bkt)
    except Exception as e:
        raise TypeError(f"[{table}] bucket not int: {bkt!r}") from e

    # country_id int4 or None
    if cid is not None:
        try:
            cid = int(cid)
        except Exception as e:
            raise TypeError(f"[{table}] country_id not int/None: {cid!r}") from e

    # valid bool or None
    if val is not None and not isinstance(val, bool):
        val = bool(val)

    return (u_mv, p_mv, did, ch_mv, bkt, cid, val)

def _check_and_normalize_row_for_binary(row: tuple, table: str) -> tuple | None:
    # Expect (username_b, password_b, did, cred_hash_b, bucket, country_id|None, valid|None)
    if not isinstance(row, tuple) or len(row) != 7:
        return None
    u_b, p_b, did, ch_b, bkt, cid, val = row
    try:
        u_mv = memoryview(bytes(u_b))
        p_mv = memoryview(bytes(p_b))
        did  = int(did)
        bkt  = int(bkt)
        # cred_hash can be psycopg.Binary/bytes/memoryview
        if isinstance(ch_b, psycopg.Binary):
            ch_b = bytes(ch_b.adapted) if hasattr(ch_b, "adapted") else bytes(ch_b)
        ch_mv = memoryview(bytes(ch_b))
        if cid is not None:
            cid = int(cid)
        if val is not None and not isinstance(val, bool):
            val = bool(val)
        return (u_mv, p_mv, did, ch_mv, bkt, cid, val)
    except Exception:
        return None

def _log_bad_row_once(table: str, row: tuple):
    if not _BAD_ROW_LOGGED.get(table, False):
        _BAD_ROW_LOGGED[table] = True
        # Print a compact type signature so we can see what went wrong
        types = tuple(type(x).__name__ for x in row) if isinstance(row, tuple) else type(row).__name__

def _normalize_row_for_binary(row: tuple) -> tuple:
    # (username_b, password_b, did, cred_hash_b, bucket, country_id, valid)
    u_b, p_b, did, ch_b, bkt, cid, val = row

    # Force bytes-likes into memoryview for psycopg3 binary COPY
    if isinstance(u_b, memoryview): u_mv = u_b
    else:                           u_mv = memoryview(bytes(u_b))

    if isinstance(p_b, memoryview): p_mv = p_b
    else:                           p_mv = memoryview(bytes(p_b))

    # cred_hash might be bytes or psycopg.Binary – normalize to raw bytes
    if isinstance(ch_b, psycopg.Binary):
        ch_b = ch_b.adapted  # get underlying bytes-like
    ch_mv = memoryview(bytes(ch_b))

    # did/bkt must be int; cid can be int or None; val can be bool or None
    return (u_mv, p_mv, int(did), ch_mv, int(bkt), (None if cid is None else int(cid)), (None if val is None else bool(val)))

def _to_ascii_bytes(s: str) -> bytes | None:
    try:
        return s.encode("ascii", "strict")
    except UnicodeEncodeError:
        return None

def _should_skip_row_due_to_encoding(*fields: str) -> bool:
    # quick precheck: if any text field itself isn’t ASCII encodable, skip
    for f in fields:
        if _to_ascii_bytes(f) is None:
            return True
    return False

def _bytea_text(b: bytes | memoryview | bytearray) -> str:
    if isinstance(b, memoryview):
        b = b.tobytes()
    return "\\x" + bytes(b).hex()

# ---------------------------
# Domain resolver (single round-trip) & de-dup sets
# ---------------------------

def get_domain_id(cur, dn: str) -> int:
    dn = dn.lower()
    did = domain_cache.get(dn)
    if did is not None:
        _prof["domain_cache_hits"] += 1
        return did

    # return domain_id plus a flag telling whether it came from INSERT
    sql_txt = """
        WITH s AS (
          SELECT domain_id FROM public.domains WHERE domain_name = %s
        ), i AS (
          INSERT INTO public.domains(domain_name)
          SELECT %s WHERE NOT EXISTS (SELECT 1 FROM s)
          RETURNING domain_id
        )
        SELECT domain_id, TRUE  AS from_insert FROM i
        UNION ALL
        SELECT domain_id, FALSE AS from_insert FROM s
        LIMIT 1
    """
    t0 = perf_counter()
    cur.execute(sql_txt, (dn, dn))
    row = cur.fetchone()
    _prof["domain_sql_calls"] += 1
    _prof["domain_sql_time"] += (perf_counter() - t0)

    did, from_insert = row
    if from_insert:
        _prof["domain_inserts"] += 1
    domain_cache[dn] = did
    return did

def allowed_for_main(domain: str) -> bool:
    d = domain.lower()
    if ALLOWLIST_PATTERNS:  # if includes are specified, require a match
        if not any(p.match(d) for p in ALLOWLIST_PATTERNS):
            return False
    if DENYLIST_PATTERNS and any(p.match(d) for p in DENYLIST_PATTERNS):
        return False
    return True

def skip_username_val(u: str) -> bool:
    return u.upper() in SKIP_USERNAMES

def too_long(u: str | bytes, p: str | bytes, d: str) -> bool:
    # lengths in characters for text, bytes for bytea – use bytes everywhere to be safe
    if isinstance(u, str): u = u.encode("utf-8", "ignore")
    if isinstance(p, str): p = p.encode("utf-8", "ignore")
    return len(u) > 60 or len(p) > 60 or len(d) > 60

def uname8_bytes(username: str) -> bytes:
    ub = username.encode("utf-8", "ignore")
    return blake2b(ub, digest_size=8).digest()

def cred_hash_and_bucket(username: str, password_b: bytes) -> tuple[bytes, int]:
    u8 = uname8_bytes(username)
    h  = blake2b(u8 + b"\x00" + password_b, digest_size=32).digest()
    v  = int.from_bytes(h[:8], "big", signed=False)
    return h, int(v % BUCKETS)

def has_null(s: str | None) -> bool:
    return s is not None and "\x00" in s

def looks_binary_text(s: str, max_ctrl_ratio: float = 0.05) -> bool:
    """
    Treat as binary-ish if too many control chars (excl. \t\r\n).
    """
    if not s:
        return False
    ctrl = 0
    total = 0
    for ch in s:
        total += 1
        cat = unicodedata.category(ch)
        if ch not in ("\t", "\r", "\n") and (cat == "Cc" or cat == "Cf"):
            ctrl += 1
    return (total > 0) and (ctrl / total > max_ctrl_ratio)

def sanitize_text(s: Optional[str]) -> Optional[str]:
    if s is None:
        return None
    return s.replace("\x00", "")


@lru_cache(maxsize=500_000)
def normalize_domain_from_site(site: str) -> Optional[str]:
    """
    Return canonical hostname domain (eTLD+1), lowercased, no port.
    If the host is IPv4, return 'ip:<normalized_ipv4>'.
    IPv6 is ignored (treated as non-IP host).
    """
    if not site:
        return None
    s = site.strip()
    if not s:
        return None

    # Remove scheme if present
    if s.startswith(("http://", "https://")):
        s = s.split("://", 1)[1]
    elif s.startswith("//"):
        s = s[2:]

    # Strip userinfo
    if "@" in s:
        s = s.split("@", 1)[1]

    # Take host[:port]
    hostport = s.split("/", 1)[0]

    # If this clearly looks like IPv6, just treat as hostname (you said IPv6 doesn't matter)
    if "[" in hostport or hostport.count(":") > 1:
        host = hostport  # will fall through to PSL extraction
    else:
        host = hostport.split(":", 1)[0]

    host = host.strip().strip(".")
    if not host:
        return None

    # First: IPv4?
    try:
        ipaddress.IPv4Address(host)
        return f"ip:{host}"
    except ValueError:
        pass

    # Hostname → punycode → eTLD+1
    try:
        ascii_host = idna.encode(host).decode("ascii")
    except idna.IDNAError:
        ascii_host = host.lower()

    ext = EXTRACTOR(ascii_host)
    # registered_domain is deprecated; prefer top_domain_under_public_suffix
    top = ext.top_domain_under_public_suffix
    return (top or ascii_host).lower()


def parse_fullurl_with_embedded_credentials(line: str) -> Optional[ParsedLogin]:
    raw = line.strip()
    if not raw.lower().startswith(("http://", "https://")):
        return None
    m = _special_url_login_re.match(raw)
    if not m:
        return None
    url, username, password = (g.strip() for g in m.groups())
    if not url or not username or not password:
        return None

    # IPv4 first so we can preserve the suffix
    ip_full = extract_ip_address_token(url)
    if ip_full:
        return ParsedLogin(
            username=username, password=password,
            domain_name=None, verbatim_domain=False, ip_full=ip_full
        )

    # Hostname path → collapse to eTLD+1
    norm = normalize_domain_from_site(url)
    if not norm:
        return None
    # If normalize returned 'ip:...', it's IPv4 but we didn't catch it above – route as IP
    if norm.startswith("ip:"):
        return ParsedLogin(
            username=username, password=password,
            domain_name=None, verbatim_domain=False, ip_full=url  # keep full suffix
        )

    return ParsedLogin(
        username=username, password=password,
        domain_name=norm, verbatim_domain=False, ip_full=None
    )



def android_package_to_domain(pkg: str) -> Optional[str]:
    """
    Convert reverse-domain package (e.g., 'com.facebook.katana') to 'Facebook.com'
    using the first two labels reversed (vendor  '.' + tld).
    """
    if not pkg:
        return None
    labels = pkg.split(".")
    if len(labels) >= 2:
        tld = labels[0].lower()
        sld = labels[1].capitalize()
        return f"{sld}.{tld}"
    return pkg.lower()

def parse_android_uri(
    line: str,
    forced_fqdn: Optional[str],
) -> Optional[ParsedLogin]:
    """
    Parse Android-style credentials:
      'android://<cert-hash>@<package>/:username:password'
    - Bypasses --delimiter-count (android lines contain extra ':')
    - Derives domain from package via android_package_to_domain(), unless --fqdn is set.
    """
    raw = line.strip()
    if not raw.lower().startswith("android://"):
        return None
    
    rest = raw[len("android://"):]  # "<hash>@com.vendor.app/:username:password" OR "...@com.vendor.app:username:password"
    try:
        at_idx = rest.index("@")
    except ValueError:
        return None
    tail = rest[at_idx + 1 :].strip()  # "com.vendor.app/:username:password" OR "com.vendor.app:username:password"

    # Two observed variants:
    #   A) "...@com.pkg/:username:password"   (explicit "/:" separator)
    #   B) "...@com.pkg:username:password"    (single ":" after package)
    if "/:" in tail:
        sep_idx = tail.index("/:")
        package_name = tail[:sep_idx].strip()
        cred_part = tail[sep_idx + 2 :].strip()
    else:
        sep_idx = tail.find(":")
        if sep_idx == -1:
            return None
        package_name = tail[:sep_idx].strip()
        cred_part = tail[sep_idx + 1 :].strip()

    # allow colons inside username (e.g., "http://...:80"); split from the right
    if ":" not in cred_part:
        return None
    username, password = (p.strip() for p in cred_part.rsplit(":", 1))
    # tolerate accidental trailing slash in package segment
    package_name = package_name.split("/", 1)[0]
     
    if not username or not password:
        return None
    domain_name = forced_fqdn.strip().lower() if forced_fqdn else android_package_to_domain(package_name)
    if not domain_name:
        return None
    return ParsedLogin(username=username, password=password, domain_name=domain_name.lower())
 

def domain_from_email(username: str) -> Optional[str]:
    at = username.rfind("@")
    if at <= 0 or at == len(username) - 1:
        return None
    return username[at + 1 :].strip().lower()


def split_with_delimiter_count(line: str, delimiter_count: int) -> Optional[List[str]]:
    """
    Ensure the line has exactly delimiter_count occurrences of ':' and split accordingly.
    Returns list of parts (delimiter_count+1 items) or None if count mismatch.
    """
    if line.count(":") != delimiter_count:
        return None
    # For count N, we need N+1 fields. We always split from the left.
    if delimiter_count == 0:
        return [line]
    return line.split(":", delimiter_count)

def split_with_exact(line: str, delim: str, count: int) -> Optional[List[str]]:
    """
    Split by a custom delimiter only if it occurs exactly `count` times.
    Returns the parts (count+1) or None.
    """
    if line.count(delim) != count:
        return None
    if count == 0:
        return [line]
    return line.split(delim, count)

def extract_ip_address_token(full: str) -> Optional[str]:
    """
    If the host of `full` is IPv4, return the exact 'host[:port]/path[?q][#f]'
    with no scheme. Otherwise return None.
    This function intentionally ignores IPv6.
    """
    if not full:
        return None
    s = full.strip()

    # Strip scheme if present
    if s.startswith(("http://", "https://")):
        s = s.split("://", 1)[1]
    elif s.startswith("//"):
        s = s[2:]

    # Strip userinfo if present
    if "@" in s:
        s = s.split("@", 1)[1]

    # Split host[:port] and suffix
    if "/" in s:
        hostport, suffix = s.split("/", 1)
        suffix = "/" + suffix
    else:
        hostport, suffix = s, ""

    # If it looks like bracketed IPv6 or contains multiple colons, bail
    if "[" in hostport or hostport.count(":") > 1:
        return None

    host, sep, port = hostport.partition(":")

    # Quick strict IPv4 check with range validation
    parts = host.split(".")
    if len(parts) != 4:
        return None
    try:
        if not all(p.isdigit() and 0 <= int(p) <= 255 and len(p) <= 3 for p in parts):
            return None
    except ValueError:
        return None

    # Keep original port if present
    return (host + (":" + port if sep else "") + suffix)




def iter_lines_from_path(path: str) -> Iterable[Tuple[str, int]]:
    """
    Yield (line, line_number) from a .txt file path.
    UTF-8 with errors='replace'. Skips nothing here; caller decides what to ignore/log.
    """
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f, start=1):
            yield line.rstrip("\n"), i

def _iter_decoded_lines(f, encoding="utf-8", errors="replace", chunk_size=1<<20):
    """
    Read bytes from a non-seekable file-like object and yield decoded text lines.
    - Splits on '\n'
    - Strips trailing '\r' to normalize CRLF -> LF behavior like TextIOWrapper(newline=None)
    """
    decoder = codecs.getincrementaldecoder(encoding)(errors=errors)
    buf = ""
    while True:
        chunk = f.read(chunk_size)
        if not chunk:
            break
        buf += decoder.decode(chunk)
        # emit all complete lines; keep the last partial in buf
        if "\n" in buf:
            parts = buf.split("\n")
            for line in parts[:-1]:
                # mirror your old: line.rstrip("\n") after universal newlines => no '\r'
                yield line.rstrip("\r")
            buf = parts[-1]
    # flush decoder
    buf += decoder.decode(b"", final=True)
    if buf:
        yield buf.rstrip("\r")

def iter_lines_from_targz(path: str):
    """
    Yield (member_name, line, line_number) for each *.txt inside a .tar.gz, in streaming mode.
    """
    # streaming mode: r|gz (no full TOC in memory)
    with tarfile.open(path, mode="r|gz") as tf:
        while True:
            m = tf.next()
            if m is None:
                break
            if not m.isfile() or not m.name.endswith(".txt"):
                continue
            f = tf.extractfile(m)
            if f is None:
                continue
            try:
                for i, line in enumerate(_iter_decoded_lines(f), start=1):
                    yield m.name, line, i
            finally:
                try:
                    f.close()
                except Exception:
                    pass


def normalize_dsn(dsn: str) -> str:
    """
    Accept SQLAlchemy-style URLs like:
      postgresql+psycopg://..., postgresql+psycopg2://...
    and convert to libpq-style for psycopg:
      postgresql://...
    """
    for prefix in ("postgresql+psycopg://", "postgresql+psycopg2://"):
        if dsn.startswith(prefix):
            return "postgresql://" + dsn[len(prefix):]
    return dsn


def parse_line(line: str, delimiter_count: int, forced_fqdn: Optional[str]) -> Optional[ParsedLogin]:
    if not line or line.strip() == "" or line.lstrip().startswith("#") or len(line) > 400:
        return None

    special = parse_fullurl_with_embedded_credentials(line)
    if special:
        return special

    android_parsed = parse_android_uri(line, forced_fqdn)
    if android_parsed:
        return android_parsed

     # --------------------------------------------------
    # Pattern 1: site1:(site2):username:password
    # --------------------------------------------------
    m_dual = _dual_url_tuple_re.match(line.strip())
    if m_dual:
        site1, site2, username, password = (g.strip() for g in m_dual.groups())
        if not username or not password:
            return None
        # Prefer forced FQDN if present
        if forced_fqdn:
            return ParsedLogin(username=username, password=password,
                               domain_name=forced_fqdn.strip().lower(),
                               verbatim_domain=False, ip_full=None)
        # Normalize both; if either is IPv4, route as IP; otherwise use normalized hostname
        ip_full = extract_ip_address_token(site2) or extract_ip_address_token(site1)
        if ip_full:
            return ParsedLogin(username=username, password=password,
                               domain_name=None, verbatim_domain=False, ip_full=ip_full)
        d1 = normalize_domain_from_site(site1)
        d2 = normalize_domain_from_site(site2)
        # If both exist and differ (rare), keep d2 (the parenthesized one) but fall back to d1 if needed
        dn = (d2 or d1)
        if not dn:
            return None
        if dn.startswith("ip:"):
            # Safety: treat as IP route preserving full suffix from site2, else site1
            return ParsedLogin(username=username, password=password,
                               domain_name=None, verbatim_domain=False, ip_full=site2 or site1)
        return ParsedLogin(username=username, password=password,
                           domain_name=dn, verbatim_domain=False, ip_full=None)

    # --------------------------------------------------
    # Pattern 2: '|' delimiter (site|username|password) or (username|password)
    # --------------------------------------------------
    # 3 fields via '|'
    pipe3 = split_with_exact(line, "|", 2)
    if pipe3:
        site, username, password = (p.strip() for p in pipe3)
        if not username or not password:
            return None
        if forced_fqdn:
            return ParsedLogin(username=username, password=password,
                               domain_name=forced_fqdn.strip().lower(),
                               verbatim_domain=False, ip_full=None)
        # IP host?
        ip_full = extract_ip_address_token(site)
        if ip_full:
            return ParsedLogin(username=username, password=password,
                               domain_name=None, verbatim_domain=False, ip_full=ip_full)
        dn = normalize_domain_from_site(site)
        if not dn:
            return None
        if dn.startswith("ip:"):
            return ParsedLogin(username=username, password=password,
                               domain_name=None, verbatim_domain=False, ip_full=site)
        return ParsedLogin(username=username, password=password,
                           domain_name=dn, verbatim_domain=False, ip_full=None)

    # 2 fields via '|'
    pipe2 = split_with_exact(line, "|", 1)
    if pipe2:
        username, password = (p.strip() for p in pipe2)
        if not username or not password:
            return None
        dn = (forced_fqdn.strip().lower() if forced_fqdn else domain_from_email(username))
        if not dn:
            return None
        return ParsedLogin(username=username, password=password,
                           domain_name=dn, verbatim_domain=False, ip_full=None)

    # Don’t strip scheme here; we want exact suffix if it’s an IP
    effective_count = delimiter_count if delimiter_count is not None else line.count(":") if line.count(":") in (1,2) else None
    if effective_count is None:
        return None
    parts = split_with_delimiter_count(line, effective_count)
    if parts is None:
        return None

    if effective_count == 2:
        site, username, password = (p.strip() for p in parts)
        if _placeholder_pw.match(password) or not site or not username or not password:
            return None

        if forced_fqdn:
            return ParsedLogin(username=username, password=password,
                            domain_name=forced_fqdn.strip().lower(),
                            verbatim_domain=False, ip_full=None)

        ip_full = extract_ip_address_token(site)
        if ip_full:
            return ParsedLogin(username=username, password=password,
                            domain_name=None, verbatim_domain=False, ip_full=ip_full)

        domain = normalize_domain_from_site(site)
        if not domain:
            return None
        if domain.startswith("ip:"):
            # Safety net: treat as IP and keep suffix
            return ParsedLogin(username=username, password=password,
                            domain_name=None, verbatim_domain=False, ip_full=site)
        return ParsedLogin(username=username, password=password,
                        domain_name=domain, verbatim_domain=False, ip_full=None)

    elif effective_count == 1:
        username, password = (p.strip() for p in parts)
        if not username or not password:
            return None
        domain = (forced_fqdn.strip().lower() if forced_fqdn else domain_from_email(username))
        if not domain:
            return None
        return ParsedLogin(username=username, password=password, domain_name=domain,
                           verbatim_domain=False, ip_full=None)

    return None


# ---------------------------
# CLI / Main
# ---------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Parse plaintext files and stream directly into REMOTE Postgres.")
    p.add_argument(
        "--db-url",
        required=True,
        help="Postgres DSN for REMOTE (e.g. postgresql://user:pass@host:5432/dbname)",
    )
    p.add_argument(
        "--input-name",
        required=True,
        help="Comma-separated list of input files (.txt or .tar.gz). Trailing comma allowed.",
    )
    p.add_argument(
        "--delimiter-count",
        type=int,
        required=False,
        help="1 for username:password, 2 for site:username:password. If omitted, guessed per-line (1 or 2).",
    )
    p.add_argument("--fqdn", default=None, help="Force FQDN for all rows (overrides URL/email-derived).")
    p.add_argument("--country", default=None, help="Optional country name applied to all rows.")
    p.add_argument("--error-log", default="import_errors.log", help="File to append unparsable lines.")
    p.add_argument("--flush-rows", type=int, default=1_000_000, help="Rows per staging merge on REMOTE.")
    p.add_argument("--copy-rows", type=int, default=1_000_000,
               help="Rows to buffer per table before opening a COPY (must be <= flush-rows).")
    p.add_argument(
        "--include-pattern", action="append", default=[],
        help="Domain allowlist pattern (glob by default, e.g. '*.eg'). "
             "Repeatable. Use 're:<regex>' to provide a case-insensitive regex."
    )
    p.add_argument(
        "--exclude-pattern", action="append", default=[],
        help="Domain denylist pattern (glob by default). Repeatable. Use 're:<regex>' for regex."
    )
    p.add_argument(
        "--allowlist-file", default='./allowlist.txt',
        help="Path to newline-separated patterns. Lines may be glob or 're:<regex>'. "
             "Empty lines and lines starting with '#' are ignored."
    )

    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)

    # Parse input list; tolerate trailing comma
    raw_items = [x.strip() for x in args.input_name.split(",")]
    input_paths = [x for x in raw_items if x]
    if not input_paths:
        print("No input files were provided after parsing --input-name.", file=sys.stderr)
        return 2

    dsn = normalize_dsn(args.db_url)

    # Compile allow/deny patterns
    def _compile_pat(s: str) -> re.Pattern:
        s = s.strip()
        if not s:
            return None  # type: ignore
        if s.lower().startswith("re:"):
            return re.compile(s[3:], re.I)
        # glob -> regex
        return re.compile(fnmatch.translate(s), re.I)

    inc_raw: list[str] = list(args.include_pattern or [])
    exc_raw: list[str] = list(args.exclude_pattern or [])
    if args.allowlist_file and os.path.exists(args.allowlist_file):
        with open(args.allowlist_file, "r", encoding="utf-8", errors="replace") as _f:
            for line in _f:
                t = line.strip()
                if not t or t.startswith("#"):
                    continue
                if t.startswith("!"):  # allow '!pattern' to mean exclude
                    exc_raw.append(t[1:].strip())
                if t.startswith("*."):
                    inc_raw.append(t)
                else:
                    inc_raw.append("*." + t)
    # Fill global matchers
    ALLOWLIST_PATTERNS.clear()
    DENYLIST_PATTERNS.clear()
    for s in inc_raw:
        pat = _compile_pat(s)
        if pat: ALLOWLIST_PATTERNS.append(pat)
    for s in exc_raw:
        pat = _compile_pat(s)
        if pat: DENYLIST_PATTERNS.append(pat)

    with open(args.error_log, "a", encoding="utf-8") as err, \
        psycopg.connect(dsn, autocommit=False) as conn:

        # create per-input stripped file
        input_basename = os.path.basename(args.input_name)
        output_dir = os.path.join(os.path.dirname(args.input_name), "output")
        os.makedirs(output_dir, exist_ok=True)
        stripped_path = os.path.join(output_dir, f"{input_basename}_stripped.txt")
        stripped = open(stripped_path, "w", encoding="utf-8", errors="replace")

        with conn.cursor() as _ce:
            _ce.execute("SET client_encoding = 'UTF8'")
            _ce.execute("SET standard_conforming_strings = on")
            _ce.execute("SET bytea_output = 'hex'")
            _ce.execute("SHOW client_encoding")
            client_enc = _ce.fetchone()[0]
            _ce.execute("SHOW server_encoding")
            server_enc = _ce.fetchone()[0]
        with conn.cursor() as s:
            s.execute("SET synchronous_commit = off")
            s.execute("SET wal_compression = on")
            s.execute("SET work_mem = '512MB'")
            s.execute("SET maintenance_work_mem = '4GB'")
        with conn.cursor() as cur:
            # Ensure targets/staging exist, then TRUNCATE staging to avoid leftovers
            cur.execute(f"TRUNCATE {STAGE_IPS};")
            # Recreate staging table every run to guarantee column types (TEXT for username/password).
            cur.execute(f"DROP TABLE IF EXISTS {STAGE_LOGINS};")
            cur.execute(f"""
                CREATE UNLOGGED TABLE {STAGE_LOGINS} (
                  username   text   NOT NULL,
                  password   text   NOT NULL,
                  domain_id  bigint NOT NULL,
                  cred_hash  bytea  NOT NULL,
                  bucket     bigint NOT NULL,
                  country_id bigint,
                  valid      boolean
                );
            """)
            cur.execute(f"ALTER TABLE {STAGE_LOGINS} SET (autovacuum_enabled = false, toast.autovacuum_enabled = false);")
            _print_stage_layout(cur, STAGE_LOGINS)
            cur.execute("SELECT domain_id, domain_name FROM public.domains WHERE domain_name = ANY(%s)",
                        (list(SPECIAL_DOMAINS.keys()),))
            for did, dn in cur.fetchall(): domain_cache[dn] = did
            conn.commit()  # make DDL visible on this session boundary


            total_lines = 0
            skipped_blank_or_comment = 0
            error_lines = 0
            dropped_by_allowlist = 0
            enqueued_login_rows  = 0
            copied_login_rows    = 0
            # --- client-side dedup sets ---
            # Full rows (domain_id known): key = (domain_id, bucket, cred_hash)
            seen_stage: set[tuple[int, int, bytes]] = set()

            # Waiting rows (domain_id not yet known): key = (domain_name str, bucket, cred_hash bytes)
            seen_wait: set[tuple[str, int, bytes]] = set()

            # (Optional) IP pipeline: key = (ip_address, username_str, password_bytes)
            seen_ips: set[tuple[str, str, bytes]] = set()

            buf_logins: List[tuple] = []
            buf_ips: List[tuple] = []
            buf_main: list[tuple] = []

            staged_since_merge = 0
            COPY_THRESHOLD = min(getattr(args, "copy_rows", 1_000_000), args.flush_rows)
            # client-side de-dup
            seen_login_keys: set[tuple[int, str, str]] = set()   # (domain_id, username_txt, password_txt)
            seen_ip_keys: set[tuple[str, str, str]]   = set()    # (ip_address, username_txt, password_txt)


            def _append_to_buffer(row: tuple) -> None:
                nonlocal enqueued_login_rows, seen_stage
                did   = row[2]
                ch_b  = row[3]
                bkt   = row[4]
                skey = (int(did), int(bkt), bytes(ch_b))
                if skey in seen_stage:
                    return
                seen_stage.add(skey)
                enqueued_login_rows += 1
                buf_main.append(row)
            def _check_row_shape(row: tuple, table: str):
                if not isinstance(row, tuple) or len(row) != 7:
                    raise ValueError(f"[{table}] Bad row shape: {type(row)} len={len(row) if isinstance(row, tuple) else 'n/a'} | {row!r}")
                u, p, did, ch, bkt, cid, val = row
                # username MUST be bytea-compatible
                if not isinstance(u, (bytes, memoryview, bytearray)):
                    raise TypeError(f"[{table}] username must be bytes-like (bytea), got {type(u)}")
                if not isinstance(p, (bytes, memoryview, bytearray)):
                    raise TypeError(f"[{table}] password must be bytes-like, got {type(p)}")
                if not isinstance(did, int):
                    raise TypeError(f"[{table}] domain_id must be int, got {type(did)}")
                if not (isinstance(ch, psycopg.Binary) or isinstance(ch, (bytes, memoryview, bytearray))):
                    raise TypeError(f"[{table}] cred_hash must be bytea-like, got {type(ch)}")
                if not isinstance(bkt, int):
                    raise TypeError(f"[{table}] bucket must be int, got {type(bkt)}")
                if cid is not None and not isinstance(cid, int):
                    raise TypeError(f"[{table}] country_id must be int or None, got {type(cid)}")
                if val is not None and not isinstance(val, bool):
                    raise TypeError(f"[{table}] valid must be bool or None, got {type(val)}")

            def _copy_rows_text_stage(cur, rows: list[tuple]) -> int:
                if not rows:
                    return 0
                # Let psycopg adapt each field (TEXT/INT/BOOL/BYTEA) correctly.
                cur.execute("SAVEPOINT sp_copy")
                try:
                    t0 = perf_counter()
                    with cur.copy(
                        f"COPY {STAGE_LOGINS} "
                        f"(username,password,domain_id,cred_hash,bucket,country_id,valid) "
                        f"FROM STDIN WITH (FORMAT text)"
                    ) as cp:
                        for (u_txt, p_txt, did, ch_b, bkt, cid, val) in rows:
                            # TEXT fields: str; BYTEA: psycopg.Binary; ints/bools: native
                            cp.write_row((u_txt, p_txt, int(did), Binary(ch_b), int(bkt), cid, val))
                    cur.execute("RELEASE SAVEPOINT sp_copy")
                    _prof["copy_logins_time"] += (perf_counter() - t0)
                    wrote = len(rows)
                    rows.clear()
                    _prof["copy_logins_rows"] += wrote
                    return wrote
                except psycopg.Error:
                    cur.execute("ROLLBACK TO SAVEPOINT sp_copy")
                    raise
                


            def _copy_rows(cur, _final_table_name: str, rows: list[tuple]) -> int:
                # We always COPY into the TEMP stage (binary), then MERGE to the real tables.
                return _copy_rows_binary_stage(cur, rows)

            def copy_flush() -> None:
                nonlocal staged_since_merge, copied_login_rows  # <-- add this
                # resolve domains first

                w = _copy_rows_text_stage(cur, buf_main);          copied_login_rows += w
                if w: print(f"[copy public.logins] wrote={w}")
                staged_since_merge += w

                t0 = perf_counter()
                cur.execute(MERGE_LOGINS_SQL)
                _prof["merge_time"] += (perf_counter() - t0)
                seen_stage.clear()
                # IPs path unchanged (your existing code), but no need to touch copied_login_rows there.

                # IPs unchanged:
                # binary COPY for IPs (username stays text; password is bytea)
                # IPs: binary COPY (ip_address text, username text, password bytea)
                if buf_ips:
                    t0 = perf_counter()
                    with cur.copy(
                        f"COPY {STAGE_IPS} (ip_address,username,password) FROM STDIN WITH (FORMAT text)"
                    ) as cp:
                        for ip_addr, uname_txt, pw_txt in buf_ips:
                            cp.write_row((ip_addr, uname_txt, pw_txt))
                    _prof["copy_ips_time"] += (perf_counter() - t0)
                    _prof["copy_ips_rows"] += len(buf_ips)
                    staged_since_merge += len(buf_ips)
                    buf_ips.clear()
            

            def _total_login_buf():
                return len(buf_main)

            def maybe_copy_and_merge() -> None:
                nonlocal staged_since_merge
                if _total_login_buf() >= COPY_THRESHOLD or len(buf_ips) >= COPY_THRESHOLD:
                    copy_flush()
                    conn.commit()  # keep transactions bounded

                if staged_since_merge >= args.flush_rows:
                    cur.execute(MERGE_REMOTE_SQL)  # IPs only
                    conn.commit()
                    staged_since_merge = 0

            def final_merge() -> None:
                copy_flush()
                if staged_since_merge:
                    cur.execute(MERGE_REMOTE_SQL)
                conn.commit()

            # here's def process_line
            def process_line(line: str, _lineno: int) -> None:
                nonlocal total_lines, skipped_blank_or_comment, error_lines, dropped_by_allowlist

                total_lines += 1
                parsed = parse_line(line, args.delimiter_count, args.fqdn)

                # validate username/password presence
                if parsed is None or has_null(parsed.username) or has_null(parsed.password):
                    if (not line) or (line.strip() == "") or line.lstrip().startswith("#") \
                       or line.count(":") == 0 or "[NOT_SAVED]" in line:
                        skipped_blank_or_comment += 1
                    else:
                        err.write(f"{line}\n")
                        stripped.write(f"{line}\n")
                        error_lines += 1
                    return

                # IP route
                if parsed.ip_full:
                    uname_txt = parsed.username.replace("\t", " ")
                    pw_txt    = parsed.password
                    if has_null(uname_txt) or has_null(pw_txt) or looks_binary_text(uname_txt) or looks_binary_text(pw_txt):
                        err.write(f"{line}\n"); error_lines += 1; return
                    ip_key = (parsed.ip_full, uname_txt, pw_txt)
                    if ip_key in seen_ip_keys:
                        return
                    seen_ip_keys.add(ip_key)
                    buf_ips.append((parsed.ip_full, uname_txt, pw_txt))
                    maybe_copy_and_merge()
                    return

                # hostname route: require domain
                if parsed.domain_name is None or has_null(parsed.domain_name):
                    err.write(f"{line}\n")
                    error_lines += 1
                    return
                # Domain allow/deny matching:
                # - If include patterns exist, only domains matching them pass.
                # - Exclude patterns always remove a match.
                # - Domain string is lowercased canonical eTLD+1 from normalize_domain_from_site()
                if not allowed_for_main(parsed.domain_name):
                    dropped_by_allowlist += 1
                    stripped.write(f"{line}\n")
                    return

                if skip_username_val(parsed.username) or \
                    too_long(parsed.username, parsed.password, parsed.domain_name) or \
                    has_null(parsed.username) or has_null(parsed.password) or \
                    looks_binary_text(parsed.username) or looks_binary_text(parsed.password):
                    err.write(f"{line}\n")
                    error_lines += 1
                    return

                uname_txt = parsed.username
                pw_txt    = parsed.password
                pw_b = pw_txt.encode("utf-8", "strict")
                ch_b, bucket = cred_hash_and_bucket(uname_txt, pw_b)

                # client-side unique key: (domain_id, username, password)
                did = get_domain_id(cur, parsed.domain_name)
                # client-side unique key: (domain_id, username_txt, password_txt)
                lkey = (did, uname_txt, pw_txt)
                if lkey in seen_login_keys:
                    return
                seen_login_keys.add(lkey)

                row = (uname_txt, pw_txt, did, ch_b, int(bucket), None, None)
                _append_to_buffer(row)
                maybe_copy_and_merge()

            # Process inputs
            t_parse0 = perf_counter()
            for path in input_paths:
                if path.endswith(".tar.gz"):
                    it = iter_lines_from_targz(path)  # (member_name, line, lineno)
                    for _member_name, line, _lineno in it:
                        process_line(line, _lineno)

                elif path.endswith(".txt"):
                    it = iter_lines_from_path(path)  # (line, lineno)
                    for line, _lineno in it:
                        process_line(line, _lineno)
                else:
                    print(f"Skipping unsupported file type: {path}", file=sys.stderr)
                copy_flush()
                conn.commit()
            _prof["parse_time"] += (perf_counter() - t_parse0)
            copy_flush()              # push buffered rows into COPY
            final_merge()
        t0_fc = perf_counter()
        conn.commit()
        _prof["final_commit_time"] = (perf_counter() - t0_fc)

        print(
            "Import summary:\n"
            f"  Total lines seen:         {total_lines}\n"
            f"  Blank/comment skipped:    {skipped_blank_or_comment}\n"
            f"  Error lines written:      {error_lines}\n"
            f"  Dropped by allowlist:     {dropped_by_allowlist}\n"
            f"  Enqueued login rows:      {enqueued_login_rows}\n"
            f"  Copied login rows:        {copied_login_rows}\n"
            f"  Error log file:           {os.path.abspath(args.error_log)}"
        )
        stripped.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
