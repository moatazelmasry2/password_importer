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

import psycopg
from psycopg import sql

logging.basicConfig(level=logging.INFO)

TABLES_TOGGLE = ["public.logins", "public.ip_logins"]
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


WORKER_COUNT = 4  # tune for I/O; 2–8 is usually good
Q_MAXSIZE = 10000  # backpressure; adjust for memory

STAGE_LOGINS = "logins_stage_by_name"
STAGE_IPS    = "ip_logins_stage"

DDL_REMOTE_PREP = f"""
CREATE EXTENSION IF NOT EXISTS citext;

-- UNLOGGED staging on REMOTE
CREATE UNLOGGED TABLE IF NOT EXISTS {STAGE_LOGINS} (
  username     text   NOT NULL,
  password     bytea   NOT NULL,
  domain_name  citext,
  country_name citext,
  valid        boolean
);

CREATE UNLOGGED TABLE IF NOT EXISTS {STAGE_IPS} (
  ip_address text NOT NULL,
  username   text NOT NULL,
  password   bytea NOT NULL
);

-- Targets (idempotent)
CREATE TABLE IF NOT EXISTS public.countries (
  country_id   bigserial PRIMARY KEY,
  country_name text UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS public.domains (
  domain_id    bigserial PRIMARY KEY,
  domain_name  text UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS public.logins (
  login_id   bigint,  -- optional surrogate; not a PK
  username   text NOT NULL,
  password   bytea NOT NULL,
  domain_id  int  NOT NULL REFERENCES public.domains(domain_id),
  country_id int  REFERENCES public.countries(country_id),
  valid      boolean,
  CONSTRAINT pk_logins_domain_user_pass PRIMARY KEY (domain_id, username, password)
) PARTITION BY HASH (domain_id);

DO $$
DECLARE i int;
BEGIN
  FOR i IN 0..31 LOOP
    EXECUTE format($f$
      CREATE TABLE IF NOT EXISTS public.logins_%s
      PARTITION OF public.logins
      FOR VALUES WITH (MODULUS 32, REMAINDER %s);
    $f$, i, i);
  END LOOP;
END$$;

CREATE INDEX IF NOT EXISTS idx_logins_domain_user ON public.logins (domain_id, username);

CREATE TABLE IF NOT EXISTS public.ip_logins (
  ip_id      bigserial PRIMARY KEY,
  ip_address text NOT NULL,
  username   text NOT NULL,
  password   bytea NOT NULL,
  CONSTRAINT uq_iplogin_ip_user_pass UNIQUE (ip_address, username, password)
);

DROP TABLE IF EXISTS logins_stage_by_name;
CREATE TEMP TABLE logins_stage_by_name (
  username text NOT NULL,
  password bytea NOT NULL,
  domain_name citext,
  country_name citext,
  valid boolean
) ON COMMIT PRESERVE ROWS;

DROP TABLE IF EXISTS ip_logins_stage;
CREATE TEMP TABLE ip_logins_stage (
  ip_address text NOT NULL,
  username text NOT NULL,
  password bytea NOT NULL
) ON COMMIT PRESERVE ROWS;

CREATE UNIQUE INDEX IF NOT EXISTS idx_domains_domain_name_unique
  ON public.domains (domain_name);

CREATE UNIQUE INDEX IF NOT EXISTS idx_countries_country_name_unique
  ON public.countries (country_name);

-- Also ensure uniques for dedupe on inserts (used by ON CONFLICT DO NOTHING later)
CREATE UNIQUE INDEX IF NOT EXISTS uq_login_domain_user_pass
  ON public.logins (domain_id, username, password);

CREATE UNIQUE INDEX IF NOT EXISTS uq_iplogin_ip_user_pass
  ON public.ip_logins (ip_address, username, password);

""".strip()

MERGE_REMOTE_SQL = f"""
SET LOCAL synchronous_commit = OFF;
SET LOCAL work_mem = '512MB';
SET LOCAL maintenance_work_mem = '4GB';

-- 0) Optional: avoid background overhead on staging
-- ALTER TABLE logins_stage_by_name SET (autovacuum_enabled = false);
-- ALTER TABLE ip_logins_stage       SET (autovacuum_enabled = false);

-- 1) Ensure names (hash agg is cheap)
INSERT INTO public.domains(domain_name)
SELECT DISTINCT domain_name
FROM logins_stage_by_name
WHERE domain_name IS NOT NULL
ON CONFLICT (domain_name) DO NOTHING;

INSERT INTO public.countries(country_name)
SELECT DISTINCT country_name
FROM logins_stage_by_name
WHERE country_name IS NOT NULL
ON CONFLICT (country_name) DO NOTHING;

-- 2) Resolve ids once into a TEMP table
DROP TABLE IF EXISTS _logins_resolved;
CREATE TEMP TABLE _logins_resolved AS
SELECT
  s.username,
  s.password,
  d.domain_id,
  c.country_id,
  s.valid
FROM logins_stage_by_name s
LEFT JOIN public.domains   d ON d.domain_name  = s.domain_name
LEFT JOIN public.countries c ON c.country_name = s.country_name;

-- 3) De-dup inside the batch to reduce ON CONFLICT work
-- DISTINCT ON is fast and memory-friendly with adequate work_mem
DROP TABLE IF EXISTS _logins_distinct;
CREATE TEMP TABLE _logins_distinct AS
SELECT DISTINCT ON (domain_id, username, password)
  username, password, domain_id, country_id, valid
FROM _logins_resolved
WHERE domain_id IS NOT NULL
ORDER BY domain_id, username, password;

-- 3b) Optional: a small temp index can help if target is huge
-- CREATE INDEX ON _logins_distinct (domain_id, username, password);

-- 4) Bulk insert into target, fewer conflicts now
INSERT INTO public.logins (username, password, domain_id, country_id, valid)
SELECT username, password, domain_id, country_id, valid
FROM _logins_distinct
ON CONFLICT (domain_id, username, password) DO NOTHING;

-- 5) IPs: batch de-dup too
DROP TABLE IF EXISTS _ips_distinct;
CREATE TEMP TABLE _ips_distinct AS
SELECT DISTINCT ON (ip_address, username, password)
  ip_address, username, password
FROM ip_logins_stage
ORDER BY ip_address, username, password;

INSERT INTO public.ip_logins (ip_address, username, password)
SELECT ip_address, username, password
FROM _ips_distinct
ON CONFLICT DO NOTHING;

-- 6) Clean staging
TRUNCATE logins_stage_by_name;
TRUNCATE ip_logins_stage;

-- 7) Optional: ANALYZE after big load to improve subsequent queries quickly
ANALYZE public.logins;
ANALYZE public.ip_logins;
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

def has_null(s: str | None) -> bool:
    return s is not None and "\x00" in s

def sanitize_text(s: Optional[str]) -> Optional[str]:
    if s is None:
        return None
    return s.replace("\x00", "")

def toggle_tables(conn: psycopg.Connection, mode: str) -> None:
    """
    Toggle tables between UNLOGGED and LOGGED on the same connection.
    If a table is partitioned, apply to each partition (children).
    Requires AccessExclusiveLock; you're the only user so fine.
    """
    if mode not in {"unlogged", "logged"}:
        raise ValueError("mode must be 'unlogged' or 'logged'")

    def _split_qualified(name: str) -> tuple[str, str]:
        if "." in name:
            s, t = name.split(".", 1)
            return s, t
        return "public", name

    with conn.cursor() as cur:
        altered: list[str] = []

        for t in TABLES_TOGGLE:
            schema, table = _split_qualified(t)

            # Does table exist? Is it partitioned?
            cur.execute(
                """
                SELECT c.oid, c.relkind = 'p' AS is_partitioned
                FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = %s AND c.relname = %s
                """,
                (schema, table),
            )
            row = cur.fetchone()
            if row is None:
                # Table not found: skip quietly
                continue

            is_partitioned = bool(row[1])

            if is_partitioned:
                # Toggle each child partition
                cur.execute(
                    """
                    SELECT format('%%I.%%I', nc.nspname, cc.relname) AS child
                    FROM pg_inherits i
                    JOIN pg_class cc ON cc.oid = i.inhrelid
                    JOIN pg_namespace nc ON nc.oid = cc.relnamespace
                    JOIN pg_class pc ON pc.oid = i.inhparent
                    JOIN pg_namespace np ON np.oid = pc.relnamespace
                    WHERE np.nspname = %s AND pc.relname = %s
                    """,
                    (schema, table),
                )
                children = [r[0] for r in cur.fetchall()]
                for child in children:
                    cur.execute(f"ALTER TABLE {child} SET {mode.upper()};")
                altered.extend(children)
            else:
                # Plain table
                cur.execute(f"ALTER TABLE {schema}.{table} SET {mode.upper()};")
                altered.append(f"{schema}.{table}")

        if mode == "logged":
            # make durable & refresh stats
            cur.execute("CHECKPOINT;")
            for name in altered:
                cur.execute(f"ANALYZE {name};")

    conn.commit()


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

    ext = tldextract.extract(ascii_host)
    # registered_domain is deprecated; prefer top_domain_under_public_suffix
    top = getattr(ext, "top_domain_under_public_suffix", None) or ext.registered_domain
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
    p.add_argument("--toggle-unlogged", action="store_true",
               help="Temporarily set target tables UNLOGGED before import and restore LOGGED after.")

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

    toggled = False
    with open(args.error_log, "a", encoding="utf-8") as err, \
         psycopg.connect(dsn, autocommit=False) as conn:

        with conn.cursor() as cur:
            # Ensure targets/staging exist, then TRUNCATE staging to avoid leftovers
            cur.execute(DDL_REMOTE_PREP)
            cur.execute(f"TRUNCATE {STAGE_LOGINS};")
            cur.execute(f"TRUNCATE {STAGE_IPS};")
            conn.commit()  # make DDL visible on this session boundary

            # Optional: set target tables UNLOGGED for faster ingest
            if args.toggle_unlogged:
                toggle_tables(conn, "unlogged")
                toggled = True

            total_lines = 0
            skipped_blank_or_comment = 0
            error_lines = 0

            buf_logins: List[tuple] = []
            buf_ips: List[tuple] = []

            staged_since_merge = 0
            COPY_THRESHOLD = min(getattr(args, "copy_rows", 1_000_000), args.flush_rows)

            def copy_flush() -> None:
                nonlocal staged_since_merge, buf_logins, buf_ips
                if buf_logins:
                    with cur.copy(
                        f"COPY {STAGE_LOGINS} (username,password,domain_name,country_name,valid) "
                        f"FROM STDIN WITH (FORMAT binary)"
                    ) as cp:
                        for r in buf_logins:
                            cp.write_row(r)
                    staged_since_merge += len(buf_logins)
                    buf_logins.clear()

                if buf_ips:
                    with cur.copy(
                        f"COPY {STAGE_IPS} (ip_address,username,password) "
                        f"FROM STDIN WITH (FORMAT binary)"
                    ) as cp:
                        for r in buf_ips:
                            cp.write_row(r)
                    staged_since_merge += len(buf_ips)
                    buf_ips.clear()

            def maybe_copy_and_merge() -> None:
                nonlocal staged_since_merge
                if len(buf_logins) >= COPY_THRESHOLD or len(buf_ips) >= COPY_THRESHOLD:
                    copy_flush()
                if staged_since_merge >= args.flush_rows:
                    cur.execute(MERGE_REMOTE_SQL)
                    staged_since_merge = 0

            def final_merge() -> None:
                copy_flush()
                if staged_since_merge:
                    cur.execute(MERGE_REMOTE_SQL)

            def process_line(line: str, _lineno: int) -> None:
                nonlocal total_lines, skipped_blank_or_comment, error_lines

                total_lines += 1
                if total_lines % 100000 == 0:
                    logging.debug("Processed %d lines", total_lines)
                parsed = parse_line(line, args.delimiter_count, args.fqdn)
                if parsed is None or has_null(parsed.username) or \
                    has_null(parsed.password):
                    if (not line) or (line.strip() == "") or \
                    line.lstrip().startswith("#") or line.count(":") == 0\
                    or "[NOT_SAVED]" in line:
                        skipped_blank_or_comment += 1
                    else:
                        err.write(f"{line}\n")
                        error_lines += 1
                    return
                
                uname = sanitize_text(parsed.username)
                password = sanitize_text(parsed.password)
                dname = sanitize_text(parsed.domain_name)

                if has_null(parsed.username)  or has_null(parsed.password) \
                    or has_null(parsed.domain_name):
                    err.write(f"{line}\n")
                    error_lines += 1
                    return
                    
                password_bytes = parsed.password.encode("utf-8", "strict")
                # For verbatim-domain (special URL cases), always store in logins (skip IP bucketing)
                ip_token = parsed.ip_full  # exact "host[:port]/path"
                if ip_token:
                    buf_ips.append((
                        ip_token,
                        parsed.username.replace("\t"," "),
                        password_bytes
                    ))
                else:
                    buf_logins.append((
                        parsed.username.replace("\t"," "),
                        password_bytes,
                        parsed.domain_name.lower(),
                        (args.country.strip().lower() if args.country else None),
                        None,
                    ))

                maybe_copy_and_merge()

            # Process inputs
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
            final_merge()
        conn.commit()

        # Restore LOGGED if we toggled
        if toggled:
            toggle_tables(conn, "logged")

    print(
        "Import summary:\n"
        f"  Total lines seen:         {total_lines}\n"
        f"  Blank/comment skipped:    {skipped_blank_or_comment}\n"
        f"  Error lines written:      {error_lines}\n"
        f"  Error log file:           {os.path.abspath(args.error_log)}"
    )
    return 0





if __name__ == "__main__":
    raise SystemExit(main())
