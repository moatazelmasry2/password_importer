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
      - We extract FQDN = netloc without credentials; keep `www` and port, lowercase stored
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


FINAL_CHUNK_SIZE = 500_000  # rows per insert batch

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

from urllib.parse import urlsplit

from sqlmodel import SQLModel, Field, Session, create_engine, select
from sqlalchemy import UniqueConstraint, Column, text
from sqlalchemy.dialects.postgresql import CITEXT, insert as pg_insert
from pydantic import BaseModel, field_validator
from dataclasses import dataclass

_ip4_re = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?$")
_ip6_bare_re = re.compile(r"^[0-9A-Fa-f:]+(?:%\w+)?(?:\:\d+)?$")
_ip6_bracket_re = re.compile(r"^\[[0-9A-Fa-f:]+\](?::\d+)?$")
_placeholder_pw = re.compile(r"^\[(?:NOT[_\- ]?SAVED|EMPTY|N/A)\]$", re.I)
_simple_host = re.compile(r"^[A-Za-z0-9.-]+(?::\d+)?$")
_strip_prefix = re.compile(
    r'^(?:www\.|login\.|app\.|accounts\.|api\.|auth\.|m\.|web\.|sso\.|account\.|signup\.|login3\.|apply\.|register\.)+',
    re.I
)

INIT_SQL = """
SET constraint_exclusion = on;

DROP TABLE IF EXISTS logins_stage;
CREATE UNLOGGED TABLE logins_stage (
    username    text NOT NULL,
    password    text NOT NULL,
    domain_name citext,
    country_id  integer,
    valid       boolean
);

DROP TABLE IF EXISTS ip_logins_stage;
CREATE UNLOGGED TABLE ip_logins_stage (
    ip_address text NOT NULL,
    username   text NOT NULL,
    password   text NOT NULL
);
""".strip()

# ---------------------------
# Pydantic v2 data models
# ---------------------------

class RawLine(BaseModel):
    raw: str

@dataclass(slots=True)
class ParsedLogin:
    username: str
    password: str
    domain_name: str

# class ParsedLogin(BaseModel):
#     username: str
#     password: str
#     domain_name: str  # lowercased before create/get

#     @field_validator("username", "password", "domain_name")
#     @classmethod
#     def not_empty(cls, v: str) -> str:
#         if v is None or len(v.strip()) == 0:
#             raise ValueError("empty field")
#         return v


# ---------------------------
# SQLModel ORM schema
# ---------------------------

class Country(SQLModel, table=True):
    __tablename__ = "countries"
    country_id: Optional[int] = Field(default=None, primary_key=True)
    # case-insensitive unique name (CITEXT)
    country_name: str = Field(
        sa_column=Column(CITEXT(), unique=True, nullable=False)
    )


class Domain(SQLModel, table=True):
    __tablename__ = "domains"
    domain_id: Optional[int] = Field(default=None, primary_key=True)
    # case-insensitive unique name (CITEXT)
    domain_name: str = Field(
        sa_column=Column(CITEXT(), unique=True, nullable=False)
    )


class Login(SQLModel, table=True):
    __tablename__ = "logins"
    __table_args__ = (
        # Unique tuple (domain_id, username, password)
        UniqueConstraint("domain_id", "username", "password", name="uq_login_domain_user_pass"),
    )

    login_id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(nullable=False)
    password: str = Field(nullable=False)

    # FK columns are nullable per your spec
    domain_id: Optional[int] = Field(default=None, foreign_key="domains.domain_id", nullable=True)
    country_id: Optional[int] = Field(default=None, foreign_key="countries.country_id", nullable=True)

    # valid is optional/nullable; we leave it NULL unless future logic sets it
    valid: Optional[bool] = Field(default=None, nullable=True)


class IpLogin(SQLModel, table=True):
    __tablename__ = "ip_logins"
    __table_args__ = (
        UniqueConstraint("ip_address", "username", "password", name="uq_iplogin_ip_user_pass"),
    )
    ip_id: Optional[int] = Field(default=None, primary_key=True)
    ip_address: str = Field(nullable=False)   # e.g., "192.168.1.10", "192.168.1.10:22", "[2001:db8::1]:443", "2001:db8::1"
    username: str = Field(nullable=False)
    password: str = Field(nullable=False)


# ---------------------------
# Utilities
# ---------------------------

def run_init_sql(engine) -> None:
    """
    Execute the baked init SQL in a safe, idempotent way.
    We split on ';' so multiple statements work reliably across drivers.
    """
    stmts = [s.strip() for s in INIT_SQL.split(";") if s.strip()]
    with engine.begin() as conn:  # transaction; auto-commit/rollback
        for stmt in stmts:
            conn.exec_driver_sql(stmt)
    logging.info("Initialized staging tables (logins_stage, ip_logins_stage).")

def ensure_citext(engine) -> None:
    """Enable the CITEXT extension if not already present."""
    with engine.connect() as conn:
        conn.execute(text("CREATE EXTENSION IF NOT EXISTS citext;"))
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
    if not full:
        return None
    s = full.strip()
    if "://" in s:
        s = s.split("://", 1)[1]
    host = s.split("/", 1)[0]

    # Quick regex gate to avoid ipaddress() except path
    h = host
    if h.startswith("[") and "]" in h:
        hbare = h[1:h.index("]")]
        is_candidate = bool(_ip6_bracket_re.match(host))
        ipstr = hbare
    elif ":" in h and not h.replace(":", "").isdigit():
        is_candidate = bool(_ip6_bare_re.match(h))
        ipstr = h
    else:
        is_candidate = bool(_ip4_re.match(h))
        ipstr = h

    if not is_candidate:
        return None
    try:
        ipaddress.ip_address(ipstr)
        return full  # include :port and path as you intended
    except ValueError:
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
    """
    Yield (member_name, line, line_number) for each *.txt file inside a .tar.gz archive.
    Streams content; does not persist to disk.
    """
    with tarfile.open(path, mode="r:gz") as tf:
        for m in tf.getmembers():
            if not m.isfile():
                continue
            if not m.name.endswith(".txt"):
                continue
            f = tf.extractfile(m)
            if f is None:
                continue
            # Wrap in TextIO for proper decoding
            with io.TextIOWrapper(f, encoding="utf-8", errors="replace") as reader:
                for i, line in enumerate(reader, start=1):
                    yield m.name, line.rstrip("\n"), i


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
# Persistence helpers
# ---------------------------

def get_or_create_country_id(sess: Session, cache: Dict[str, int], country_name: str) -> int:
    key = country_name.lower()
    if key in cache:
        return cache[key]

    obj = sess.exec(select(Country).where(Country.country_name == key)).first()
    if obj is None:
        obj = Country(country_name=key)
        sess.add(obj)
        sess.commit()
        sess.refresh(obj)
    cache[key] = obj.country_id  # type: ignore
    return obj.country_id  # type: ignore


def get_or_create_domain_id(sess: Session, cache: Dict[str, int], domain_name: str) -> int:
    key = domain_name
    if key in cache:
        return cache[key]

    obj = sess.exec(select(Domain).where(Domain.domain_name == key)).first()
    if obj is None:
        obj = Domain(domain_name=key)
        sess.add(obj)
        sess.flush()           # <-- gets primary key without commit
        # DO NOT sess.commit() here
    cache[key] = obj.domain_id  # type: ignore
    return obj.domain_id        # type: ignore




# ---------------------------
# CLI / Main
# ---------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Import plaintext password files into Postgres via SQLModel.")

    p.add_argument(
        "--db-url",
        required=True,
        help="SQLAlchemy URL for Postgres, e.g. postgresql+psycopg://user:pass@host:5432/dbname",
    )
    p.add_argument(
        "--input-name",
        required=True,
        help="Comma-separated list of input files (.txt or .tar.gz). Trailing comma is allowed.",
    )
    p.add_argument(
        "--delimiter-count",
        type=int,
        required=False,
        help="Exact number of ':' delimiters each parsed line must contain (1 for username:password, 2 for site:username:password).",
    )
    p.add_argument(
        "--fqdn",
        default=None,
        help="Explicit fqdn to force for all rows (overrides URL/email-derived domains).",
    )
    p.add_argument(
        "--country",
        default=None,
        help="Optional country name to apply to all rows; created if missing.",
    )
    p.add_argument(
        "--error-log",
        default="import_errors.log",
        help="Path to append unparsable lines. Only the original line is written.",
    )
    p.add_argument(
        "--batch-size",
        type=int,
        default=1000,
        help="Number of rows to buffer before writing to DB.",
    )
    p.add_argument("--copy-chunk-size",
        type=int,
        default=3_000_000,
        help="Number of rows to buffer before flushing a COPY in copy mode.")
    return p

def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)

    # Parse input list; tolerate trailing comma
    raw_items = [x.strip() for x in args.input_name.split(",")]
    input_paths = [x for x in raw_items if x]

    if not input_paths:
        print("No input files were provided after parsing --input-name.", file=sys.stderr)
        return 2
    logging.debug("Creatin engine")
    # Setup engine and schema (with CITEXT)
    engine = create_engine(args.db_url, pool_pre_ping=True, future=True)
    ensure_citext(engine)
    logging.debug("creating model")
    SQLModel.metadata.create_all(engine)

    run_init_sql(engine)

    with engine.begin() as conn:
        conn.execute(text("""
            ALTER TABLE public.logins
            ALTER COLUMN username SET COMPRESSION lz4,
            ALTER COLUMN password SET COMPRESSION lz4;
        """))
    
    
    with engine.begin() as conn:
        conn.exec_driver_sql("""
            CREATE UNLOGGED TABLE IF NOT EXISTS logins_stage (
                username  text NOT NULL,
                password  text NOT NULL,
                domain_id integer,
                country_id integer,
                valid boolean
            );
        """)
        conn.exec_driver_sql("""
            CREATE UNLOGGED TABLE IF NOT EXISTS ip_logins_stage (
                ip_address text NOT NULL,
                username   text NOT NULL,
                password   text NOT NULL
            );
        """)

    logging.debug("finished creating model")

    # Caches for FK lookups
    domain_cache: Dict[str, int] = {}
    country_cache: Dict[str, int] = {}

    # Optional fixed country_id
    fixed_country_id: Optional[int] = None

    
    with Session(engine) as sess, open(args.error_log, "a", encoding="utf-8") as err:
        if args.country:
            logging.debug("Creating country")
            fixed_country_id = get_or_create_country_id(sess, country_cache, args.country.strip())

        buffer: List[Dict[str, Any]] = []
        buffer_ip: List[Dict[str, Any]] = []
        staged_rows_logins = 0
        staged_rows_ip = 0
        copy_rows: List[tuple] = []
        copy_rows_ip: List[tuple] = []

        total_lines = 0
        skipped_blank_or_comment = 0
        error_lines = 0
        inserted_total = 0
        skipped_conflicts_total = 0

        def _merge_logins_chunk(conn, chunk_size: int) -> tuple[int, float]:
            """
            Merge a window of rows from logins_stage -> logins.
            - Resolves domain_id via join to domains.
            - Inserts any missing domains for the selected batch.
            - Uses CTID alias (_ctid) to delete exactly the staged rows merged.
            """
            import time
            t0 = time.perf_counter()

            conn.exec_driver_sql("DROP TABLE IF EXISTS _logins_batch;")
            conn.exec_driver_sql("DROP TABLE IF EXISTS _pick;")

            # 1) Pick a stable window from the base table, INCLUDING CTID (aliased).
            conn.exec_driver_sql(f"""
                CREATE TEMP TABLE _pick ON COMMIT DROP AS
                SELECT
                    ctid              AS _ctid,
                    username,
                    password,
                    domain_name,
                    country_id,
                    valid
                FROM logins_stage
                ORDER BY domain_name, username, password
                LIMIT {chunk_size};
            """)

            # 2) Make sure all domains for this window exist (cheap, idempotent upsert).
            conn.exec_driver_sql("""
                INSERT INTO domains (domain_name)
                SELECT DISTINCT domain_name
                FROM _pick
                WHERE domain_name IS NOT NULL
                ON CONFLICT (domain_name) DO NOTHING;
            """)

            # 3) Materialize the batch with resolved domain_id.
            conn.exec_driver_sql("""
                CREATE TEMP TABLE _logins_batch ON COMMIT DROP AS
                SELECT
                    p._ctid,
                    p.username,
                    p.password,
                    d.domain_id,
                    p.country_id,
                    p.valid
                FROM _pick p
                JOIN domains d ON d.domain_name = p.domain_name;
            """)

            batch_rows = conn.exec_driver_sql("SELECT COUNT(*) FROM _logins_batch;").scalar_one()
            if batch_rows == 0:
                return 0, time.perf_counter() - t0

            # 4) Insert into target, de-duping inside the batch to ease ON CONFLICT.
            res = conn.exec_driver_sql("""
                INSERT INTO logins (username, password, domain_id, country_id, valid)
                SELECT username, password, domain_id, country_id, valid
                FROM (
                    SELECT DISTINCT ON (domain_id, username, password)
                        username, password, domain_id, country_id, valid
                    FROM _logins_batch
                    ORDER BY domain_id, username, password
                ) q
                ON CONFLICT DO NOTHING;
            """)
            inserted = res.rowcount or 0

            # 5) Delete exactly the rows we merged from staging via CTID alias.
            conn.exec_driver_sql("""
                DELETE FROM logins_stage s
                USING _logins_batch b
                WHERE s.ctid = b._ctid;
            """)

            return inserted, time.perf_counter() - t0


        def _merge_ip_logins_chunk(conn, chunk_size: int) -> tuple[int, float]:
            """
            Merge a window of rows from ip_logins_stage -> ip_logins.
            Uses CTID alias (_ctid) to delete exactly the staged rows consumed.
            """
            import time
            t0 = time.perf_counter()

            conn.exec_driver_sql("DROP TABLE IF EXISTS _ip_pick;")
            conn.exec_driver_sql("DROP TABLE IF EXISTS _ip_batch;")

            # 1) Pick a stable window directly from the base table, include CTID as alias.
            conn.exec_driver_sql(f"""
                CREATE TEMP TABLE _ip_pick ON COMMIT DROP AS
                SELECT
                    ctid        AS _ctid,
                    ip_address,
                    username,
                    password
                FROM ip_logins_stage
                ORDER BY ip_address, username, password
                LIMIT {chunk_size};
            """)

            # 2) Optionally pre-dedupe inside the batch to ease ON CONFLICT work.
            conn.exec_driver_sql("""
                CREATE TEMP TABLE _ip_batch ON COMMIT DROP AS
                SELECT DISTINCT ON (ip_address, username, password)
                    _ctid, ip_address, username, password
                FROM _ip_pick
                ORDER BY ip_address, username, password;
            """)

            batch_rows = conn.exec_driver_sql("SELECT COUNT(*) FROM _ip_batch;").scalar_one()
            if batch_rows == 0:
                return 0, time.perf_counter() - t0

            # 3) Insert into target.
            res = conn.exec_driver_sql("""
                INSERT INTO ip_logins (ip_address, username, password)
                SELECT ip_address, username, password
                FROM _ip_batch
                ON CONFLICT DO NOTHING;
            """)
            inserted = res.rowcount or 0

            # 4) Delete exactly the staged rows we just handled via CTID alias.
            conn.exec_driver_sql("""
                DELETE FROM ip_logins_stage s
                USING _ip_batch b
                WHERE s.ctid = b._ctid;
            """)

            return inserted, time.perf_counter() - t0


        def final_copy():
            """
            Chunked, ordered merge directly from staging tables (which are already deduped
            by their UNIQUE indexes) → target tables, then TRUNCATE staging.
            Prints timings for logins merge, ip_logins merge, and cleanup.
            """
            start_all = time.perf_counter()
            with sess.bind.begin() as conn:
                # Local tuning for this single transaction
                conn.exec_driver_sql("SET LOCAL synchronous_commit = OFF;")
                conn.exec_driver_sql("SET LOCAL work_mem = '256MB';")
                conn.exec_driver_sql("SET LOCAL maintenance_work_mem = '2GB';")

                # 1) Chunked merge for logins
                t1 = time.perf_counter()
                total_inserted_logins = 0
                chunk_no = 0
                while True:
                    chunk_no += 1
                    inserted, chunk_secs = _merge_logins_chunk(conn, FINAL_CHUNK_SIZE)
                    if inserted == 0:
                        break
                    total_inserted_logins += inserted
                    print(f"[final_copy] logins chunk {chunk_no}: +{inserted} rows in {chunk_secs:.2f}s")

                logins_secs = time.perf_counter() - t1

                # 2) Chunked merge for ip_logins
                t2 = time.perf_counter()
                total_inserted_ip = 0
                ip_chunk_no = 0
                while True:
                    ip_chunk_no += 1
                    inserted, chunk_secs = _merge_ip_logins_chunk(conn, FINAL_CHUNK_SIZE)
                    if inserted == 0:
                        break
                    total_inserted_ip += inserted
                    print(f"[final_copy] ip_logins chunk {ip_chunk_no}: +{inserted} rows in {chunk_secs:.2f}s")

                ip_secs = time.perf_counter() - t2

                # 3) Cleanup staging (should already be empty; TRUNCATE is cheap/idempotent)
                t3 = time.perf_counter()
                conn.exec_driver_sql("TRUNCATE TABLE logins_stage;")
                conn.exec_driver_sql("TRUNCATE TABLE ip_logins_stage;")
                cleanup_secs = time.perf_counter() - t3

            total_secs = time.perf_counter() - start_all
            print(
                "[final_copy] timings:\n"
                f"  logins merge: {logins_secs:.2f}s (inserted {total_inserted_logins})\n"
                f"  ip merge:     {ip_secs:.2f}s (inserted {total_inserted_ip})\n"
                f"  cleanup:      {cleanup_secs:.2f}s\n"
                f"  total:        {total_secs:.2f}s"
            )

        def handle_parsed(parsed: ParsedLogin, raw_line: str) -> None:
            """
            Route a successfully ParsedLogin either to:
            - ip_logins (when domain_name is an IP or IP:port), or
            - logins (normal domains with FK to domains/countries).

            Uses the same batching/flush logic as the rest of the importer.
            """
            nonlocal buffer, buffer_ip, error_lines, domain_cache, fixed_country_id

            try:
                # Detect IPv4 / IPv6 (with optional port) and route to ip_logins
                ip_token = extract_ip_address_token(parsed.domain_name)
                if ip_token:
                    copy_rows_ip.append((ip_token, parsed.username, parsed.password))
                else:
                    u = parsed.username.replace("\t", " ")
                    p = parsed.password.replace("\t", " ")
                    # sanitize domain/IP if needed
                    copy_rows.append((u, p, parsed.domain_name.lower(), 
                                      fixed_country_id, None))

                if len(copy_rows) >= args.copy_chunk_size or \
                    len(copy_rows_ip) >= args.copy_chunk_size:
                    flush()
                    logging.debug(f"Flushing after Chunks: {copy_rows}")

            except Exception:
                # On any failure, write the exact original line to the error log
                err.write(f"{raw_line}\n")
                error_lines += 1


        def _copy_flush(conn, table_name: str, cols: List[str], rows: List[tuple]) -> int:
            if not rows:
                return 0
            sql = f"COPY {table_name} ({', '.join(cols)}) FROM STDIN"
            n = len(rows)
            with conn.connection.dbapi_connection.cursor() as cur:
                with cur.copy(sql) as cp:
                    for r in rows:
                        cp.write_row(r)
            rows.clear()
            return n



        def flush():
            nonlocal staged_rows_logins, staged_rows_ip
            if copy_rows or copy_rows_ip:
                with sess.bind.begin() as conn:
                    staged_rows_logins += _copy_flush(conn, "logins_stage",
                                                    ["username","password","domain_name",
                                                     "country_id","valid"],
                                                    copy_rows)
                    staged_rows_ip += _copy_flush(conn, "ip_logins_stage",
                                                ["ip_address","username","password"],
                                                copy_rows_ip)

            # Trigger a merge if staging is getting big (tune threshold)
            MERGE_THRESHOLD = 6_000_000  # rows across both staging tables
            if (staged_rows_logins + staged_rows_ip) >= MERGE_THRESHOLD:
                final_copy()
                staged_rows_logins = 0
                staged_rows_ip = 0

        for path in input_paths:
            if path.endswith(".tar.gz"):
                for member_name, line, lineno in iter_lines_from_targz(path):
                    total_lines += 1

                    parsed = parse_line(line, args.delimiter_count, args.fqdn)
                    if parsed is None:
                        # Either blank/comment (skip) or format mismatch -> check delimiter count
                        if not line or line.strip() == "" or line.lstrip().startswith("#") or line.count(":") == 0:
                            skipped_blank_or_comment += 1
                        else:
                            err.write(f"{line}\n")
                            error_lines += 1
                        continue

                    handle_parsed(parsed, line)

            elif path.endswith(".txt"):
                for line, lineno in iter_lines_from_path(path):
                    total_lines += 1
                    if total_lines % 100000 == 0:
                        logging.debug("Processed %d lines", total_lines)
                    parsed = parse_line(line, args.delimiter_count, args.fqdn)
                    if parsed is None:
                        if not line or line.strip() == "" or line.lstrip().startswith("#") or line.count(":") == 0:
                            skipped_blank_or_comment += 1
                        else:
                            err.write(f"{line}\n")
                            error_lines += 1
                        continue

                    handle_parsed(parsed, line)
            else:
                print(f"Skipping unsupported file type: {path}", file=sys.stderr)
            
            print(
            "Import summary:\n"
            f"  File processed            {path}\n"
            f"  Total lines seen:         {total_lines}\n"
            f"  Blank/comment skipped:    {skipped_blank_or_comment}\n"
            f"    - Inserted new:         {inserted_total}\n"
            f"    - Duplicates skipped:   {skipped_conflicts_total}\n"
            f"  Error lines written:      {error_lines}\n"
            f"  Error log file:           {os.path.abspath(args.error_log)}"
            )
            flush()
            final_copy()
        # Final flush
        flush()
        final_copy()

        # Summary
        processed_rows = inserted_total + skipped_conflicts_total
        print(
            "Import summary:\n"
            f"  Total lines seen:         {total_lines}\n"
            f"  Blank/comment skipped:    {skipped_blank_or_comment}\n"
            f"  Parsed rows (attempted):  {processed_rows}\n"
            f"    - Inserted new:         {inserted_total}\n"
            f"    - Duplicates skipped:   {skipped_conflicts_total}\n"
            f"  Error lines written:      {error_lines}\n"
            f"  Error log file:           {os.path.abspath(args.error_log)}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
