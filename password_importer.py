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


import psycopg
from psycopg import sql

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

WORKER_COUNT = 4  # tune for I/O; 2–8 is usually good
Q_MAXSIZE = 10000  # backpressure; adjust for memory

STAGE_LOGINS = "logins_stage_by_name"
STAGE_IPS    = "ip_logins_stage"

DDL_REMOTE_PREP = f"""
CREATE EXTENSION IF NOT EXISTS citext;

-- UNLOGGED staging on REMOTE
CREATE UNLOGGED TABLE IF NOT EXISTS {STAGE_LOGINS} (
  username     text   NOT NULL,
  password     text   NOT NULL,
  domain_name  citext,
  country_name citext,
  valid        boolean
);

CREATE UNLOGGED TABLE IF NOT EXISTS {STAGE_IPS} (
  ip_address text NOT NULL,
  username   text NOT NULL,
  password   text NOT NULL
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
  password   text NOT NULL,
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
  password   text NOT NULL,
  CONSTRAINT uq_iplogin_ip_user_pass UNIQUE (ip_address, username, password)
);

DROP TABLE IF EXISTS logins_stage_by_name;
CREATE TEMP TABLE logins_stage_by_name (
  username text NOT NULL,
  password text NOT NULL,
  domain_name citext,
  country_name citext,
  valid boolean
) ON COMMIT PRESERVE ROWS;

DROP TABLE IF EXISTS ip_logins_stage;
CREATE TEMP TABLE ip_logins_stage (
  ip_address text NOT NULL,
  username text NOT NULL,
  password text NOT NULL
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
    domain_name: str




# ---------------------------
# Utilities
# ---------------------------

def make_producer_for_path(path: str, args, out_q: "queue.Queue[Optional[Row]]"):
    def _producer():
        try:
            if path.endswith(".tar.gz"):
                it = iter_lines_from_targz(path)  # yields (member_name, line, lineno)
                for _member, line, _lineno in it:
                    parsed = parse_line(line, args.delimiter_count, args.fqdn)
                    if parsed is None:
                        continue  # keep your error logging if desired
                    ip_token = extract_ip_address_token(parsed.domain_name)
                    if ip_token:
                        row = ("ip", (ip_token, parsed.username.replace("\t"," "), parsed.password.replace("\t"," ")))
                    else:
                        row = ("login", (parsed.username.replace("\t"," "),
                                         parsed.password.replace("\t"," "),
                                         parsed.domain_name.lower(),
                                         (args.country.strip().lower() if args.country else None),
                                         None))
                    out_q.put(row)
            elif path.endswith(".txt"):
                for line, _lineno in iter_lines_from_path(path):
                    parsed = parse_line(line, args.delimiter_count, args.fqdn)
                    if parsed is None:
                        continue
                    ip_token = extract_ip_address_token(parsed.domain_name)
                    if ip_token:
                        row = ("ip", (ip_token, parsed.username.replace("\t"," "), parsed.password.replace("\t"," ")))
                    else:
                        row = ("login", (parsed.username.replace("\t"," "),
                                         parsed.password.replace("\t"," "),
                                         parsed.domain_name.lower(),
                                         (args.country.strip().lower() if args.country else None),
                                         None))
                    out_q.put(row)
            else:
                # unsupported extension; ignore or log
                pass
        finally:
            out_q.put(None)  # sentinel from this producer
    return _producer

def writer_thread(dsn: str, args, in_q: "queue.Queue[Optional[Row]]", producer_count: int):
    buf_logins, buf_ips = [], []
    staged_since_merge = 0
    COPY_THRESHOLD = min(getattr(args, "copy_rows", 1_000_000), args.flush_rows)
    finished = 0

    with psycopg.connect(dsn, autocommit=False) as conn:
        with conn.cursor() as cur:
            # Targets + (TEMP) staging per run
            cur.execute("CREATE EXTENSION IF NOT EXISTS citext;")
            cur.execute("""
            CREATE TABLE IF NOT EXISTS public.countries (
              country_id   bigserial PRIMARY KEY,
              country_name citext UNIQUE NOT NULL
            );
            CREATE TABLE IF NOT EXISTS public.domains (
              domain_id    bigserial PRIMARY KEY,
              domain_name  citext UNIQUE NOT NULL
            );
            CREATE TABLE IF NOT EXISTS public.logins (
              login_id   bigserial PRIMARY KEY,
              username   text NOT NULL,
              password   text NOT NULL,
              domain_id  bigint REFERENCES public.domains(domain_id),
              country_id bigint REFERENCES public.countries(country_id),
              valid      boolean,
              CONSTRAINT uq_login_domain_user_pass UNIQUE (domain_id, username, password)
            );
            CREATE TABLE IF NOT EXISTS public.ip_logins (
              ip_id      bigserial PRIMARY KEY,
              ip_address text NOT NULL,
              username   text NOT NULL,
              password   text NOT NULL,
              CONSTRAINT uq_iplogin_ip_user_pass UNIQUE (ip_address, username, password)
            );
            """)
            # TEMP staging
            cur.execute(f"DROP TABLE IF EXISTS {STAGE_LOGINS};")
            cur.execute(f"CREATE TEMP TABLE {STAGE_LOGINS} (username text NOT NULL, password text NOT NULL, domain_name citext, country_name citext, valid boolean) ON COMMIT PRESERVE ROWS;")
            cur.execute(f"DROP TABLE IF EXISTS {STAGE_IPS};")
            cur.execute(f"CREATE TEMP TABLE {STAGE_IPS} (ip_address text NOT NULL, username text NOT NULL, password text NOT NULL) ON COMMIT PRESERVE ROWS;")
            conn.commit()

            def copy_flush():
                nonlocal staged_since_merge, buf_logins, buf_ips
                if buf_logins:
                    with cur.copy(f"COPY {STAGE_LOGINS} (username,password,domain_name,country_name,valid) FROM STDIN WITH (FORMAT binary)") as cp:
                        for r in buf_logins: cp.write_row(r)
                    staged_since_merge += len(buf_logins)
                    buf_logins.clear()
                if buf_ips:
                    with cur.copy(f"COPY {STAGE_IPS} (ip_address,username,password) FROM STDIN WITH (FORMAT binary)") as cp:
                        for r in buf_ips: cp.write_row(r)
                    staged_since_merge += len(buf_ips)
                    buf_ips.clear()

            def maybe_merge():
                nonlocal staged_since_merge
                if staged_since_merge >= args.flush_rows:
                    cur.execute(MERGE_REMOTE_SQL)
                    staged_since_merge = 0
                    conn.commit()

            while True:
                item = in_q.get()
                if item is None:
                    finished += 1
                    if finished == producer_count:
                        # drain remaining, flush, final merge
                        copy_flush()
                        if staged_since_merge:
                            cur.execute(MERGE_REMOTE_SQL)
                            conn.commit()
                        break
                    continue

                kind, row = item
                if kind == "ip":
                    buf_ips.append(row)
                else:
                    buf_logins.append(row)

                # thresholds
                if len(buf_logins) >= COPY_THRESHOLD or len(buf_ips) >= COPY_THRESHOLD:
                    copy_flush()
                maybe_merge()


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
    if not site:
        return None
    s = site.strip()
    if not s:
        return None

    # quick scheme-strip
    if s.startswith("http://") or s.startswith("https://"):
        s = s.split("://", 1)[1]

    # take host fast
    host = s.split("/", 1)[0]
    # handle potential userinfo
    if "@" in host:
        host = host.split("@", 1)[1]

    if _simple_host.match(host):
        return _strip_prefix.sub("", host).lower()

    # rare fallback
    parts = urlsplit(f"//{s}" if "://" not in s and not s.startswith("//") else s, allow_fragments=False)
    netloc = parts.netloc or parts.path
    if not netloc:
        return None
    if "@" in netloc:
        netloc = netloc.split("@", 1)[1]
    return _strip_prefix.sub("", netloc).lower()


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
    rest = raw[len("android://"):]  # "<hash>@com.vendor.app/:username:password"
    try:
        at_idx = rest.index("@")
        slash_idx = rest.index("/", at_idx + 1)
    except ValueError:
        return None
    package_name = rest[at_idx + 1 : slash_idx].strip()
    cred_part = rest[slash_idx + 1 :].strip()
    if cred_part.startswith(":"):
        cred_part = cred_part[1:]
    if cred_part.count(":") != 1:
        return None
    username, password = (p.strip() for p in cred_part.split(":", 1))
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
    If the host of `full` is IPv4 (optionally with :port), return the ORIGINAL `full`
    (including any :port and path) so we store it exactly as-is.
    If the host is not IPv4, return None.
    No IPv6 supported per requirements.
    """
    if not full:
        return None
    s = full.strip()
    # Quick scheme strip to get host[:port]/path
    if "://" in s:
        s = s.split("://", 1)[1]
    host_port_path = s.split("/", 1)[0]  # "<host[:port]>"

    # Separate host from port if present
    host, sep, _ = host_port_path.partition(":")
    # IPv4 quick check: 4 dot-separated decimal octets 0..255 (loose check + range guard)
    parts = host.split(".")
    if len(parts) != 4:
        return None
    try:
        if all(0 <= int(p) <= 255 for p in parts) and all(p.isdigit() and len(p) <= 3 for p in parts):
            return full  # keep original string, including :port and /path
    except ValueError:
        return None
    return None


def iter_lines_from_path(path: str) -> Iterable[Tuple[str, int]]:
    """
    Yield (line, line_number) from a .txt file path.
    UTF-8 with errors='replace'. Skips nothing here; caller decides what to ignore/log.
    """
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f, start=1):
            yield line.rstrip("\n"), i


def iter_lines_from_targz(path: str) -> Iterable[Tuple[str, str, int]]:
    with tarfile.open(path, mode="r|gz") as tf:  # streaming, no full TOC
        while True:
            m = tf.next()
            if m is None:
                break
            if not m.isfile() or not m.name.endswith(".txt"):
                continue
            f = tf.extractfile(m)
            if f is None:
                continue
            with io.TextIOWrapper(f, encoding="utf-8", errors="replace") as reader:
                for i, line in enumerate(reader, start=1):
                    yield m.name, line.rstrip("\n"), i


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


def parse_line(
    line: str,
    delimiter_count: int,
    forced_fqdn: Optional[str],
) -> Optional[ParsedLogin]:
    """
    Parse a single line according to the provided delimiter_count.
    - If it begins with 'android://', handle via parse_android_uri() first.
    - If delimiter_count == 2: format1 "site:username:password"
    - If delimiter_count == 1: format2 "username:password"
    - Otherwise: treat as error (None)
    Enforces non-empty fields; returns ParsedLogin or None.
    """
    # Skip blanks and comments early
    if not line or line.strip() == "" or \
        line.lstrip().startswith("#") or len(line) > 400:
        return None  # caller should treat this as a skip (not an error)

    android_parsed = parse_android_uri(line, forced_fqdn)
    if android_parsed:
        return android_parsed

    line = re.sub(r'^https?://', '', line)
    # If delimiter_count is not provided, guess from this line
    effective_count = delimiter_count
    if effective_count is None:
        c = line.count(":")
        if c in (1, 2):
            effective_count = c
        else:
            return None

    parts = split_with_delimiter_count(line, effective_count)
    if parts is None:
        return None

    try:
        if effective_count == 2:
            site, username, password = (p.strip() for p in parts)
            if _placeholder_pw.match(password):
                return None
            if not site or not username or not password:
                return None
            domain = forced_fqdn.strip().lower() if forced_fqdn else normalize_domain_from_site(site)
            if not domain:
                return  None
            return ParsedLogin(username=username, password=password, domain_name=domain)

        elif effective_count == 1:
            username, password = (p.strip() for p in parts)
            if not username or not password:
                return None
            domain = forced_fqdn.strip().lower() if forced_fqdn else domain_from_email(username)
            if not domain:
                return None
            return ParsedLogin(username=username, password=password, domain_name=domain)

        else:
            # You said you will provide delimiter-count to match file(s), but if not 1 or 2, mark as error.
            return None

    except Exception:
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

            # Process inputs
            for path in input_paths:
                if path.endswith(".tar.gz"):
                    it = iter_lines_from_targz(path)  # (member_name, line, lineno)
                    for _member_name, line, _lineno in it:
                        total_lines += 1
                        parsed = parse_line(line, args.delimiter_count, args.fqdn)
                        if parsed is None:
                            if (not line) or (line.strip() == "") or line.lstrip().startswith("#") or line.count(":") == 0:
                                skipped_blank_or_comment += 1
                            else:
                                err.write(f"{line}\n")
                                error_lines += 1
                            continue

                        ip_token = extract_ip_address_token(parsed.domain_name)
                        if ip_token:
                            buf_ips.append((
                                ip_token,
                                parsed.username.replace("\t"," "),
                                parsed.password.replace("\t"," "),
                            ))
                        else:
                            buf_logins.append((
                                parsed.username.replace("\t"," "),
                                parsed.password.replace("\t"," "),
                                parsed.domain_name.lower(),
                                (args.country.strip().lower() if args.country else None),
                                None,
                            ))
                        maybe_copy_and_merge()

                elif path.endswith(".txt"):
                    it = iter_lines_from_path(path)  # (line, lineno)
                    for line, _lineno in it:
                        total_lines += 1
                        if total_lines % 100000 == 0:
                            logging.debug("Processed %d lines", total_lines)

                        parsed = parse_line(line, args.delimiter_count, args.fqdn)
                        if parsed is None:
                            if (not line) or (line.strip() == "") or line.lstrip().startswith("#") or line.count(":") == 0:
                                skipped_blank_or_comment += 1
                            else:
                                err.write(f"{line}\n")
                                error_lines += 1
                            continue

                        ip_token = extract_ip_address_token(parsed.domain_name)
                        if ip_token:
                            buf_ips.append((
                                ip_token,
                                parsed.username.replace("\t"," "),
                                parsed.password.replace("\t"," "),
                            ))
                        else:
                            buf_logins.append((
                                parsed.username.replace("\t"," "),
                                parsed.password.replace("\t"," "),
                                parsed.domain_name.lower(),
                                (args.country.strip().lower() if args.country else None),
                                None,
                            ))
                        maybe_copy_and_merge()
                else:
                    print(f"Skipping unsupported file type: {path}", file=sys.stderr)

                # Per-file flush helps memory bounds
                copy_flush()

            # Final merge & commit data
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
