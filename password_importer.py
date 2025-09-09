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

import argparse
import os
import sys
import io
import tarfile
from typing import Iterable, Optional, Tuple, List, Dict, Any

from urllib.parse import urlsplit

from sqlmodel import SQLModel, Field, Session, create_engine, select
from sqlalchemy import UniqueConstraint, Column, text
from sqlalchemy.dialects.postgresql import CITEXT, insert as pg_insert
from pydantic import BaseModel, field_validator

# ---------------------------
# Pydantic v2 data models
# ---------------------------

class RawLine(BaseModel):
    raw: str


class ParsedLogin(BaseModel):
    username: str
    password: str
    domain_name: str  # lowercased before create/get

    @field_validator("username", "password", "domain_name")
    @classmethod
    def not_empty(cls, v: str) -> str:
        if v is None or len(v.strip()) == 0:
            raise ValueError("empty field")
        return v


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


# ---------------------------
# Utilities
# ---------------------------

def ensure_citext(engine) -> None:
    """Enable the CITEXT extension if not already present."""
    with engine.connect() as conn:
        conn.execute(text("CREATE EXTENSION IF NOT EXISTS citext;"))
        conn.commit()


def normalize_domain_from_site(site: str) -> Optional[str]:
    """
    Extract FQDN (authority/netloc) from a site string.
    Rules:
      - Keep `www.` if present
      - Keep port if present
      - Strip userinfo (user:pass@)
      - Lowercase the final domain string
      - Accept bare hosts like "example.com" or "sub.example.co.uk:8443"
    """
    s = site.strip()
    if not s:
        return None

    # If scheme is missing, urlsplit will treat it as path; prefix '//' to parse netloc
    needs_slashes = "://" not in s and not s.startswith("//")
    candidate = f"//{s}" if needs_slashes else s

    parts = urlsplit(candidate, allow_fragments=False)
    netloc = parts.netloc or parts.path  # path if still no netloc (e.g., bare host without //)
    if not netloc:
        return None

    # Remove credentials if any
    if "@" in netloc:
        netloc = netloc.split("@", 1)[1]

    return netloc.lower()


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
    - If delimiter_count == 2: format1 "site:username:password"
    - If delimiter_count == 1: format2 "username:password"
    - Otherwise: treat as error (None)
    Enforces non-empty fields; returns ParsedLogin or None.
    """
    # Skip blanks and comments early
    if not line or line.strip() == "" or line.lstrip().startswith("#"):
        return None  # caller should treat this as a skip (not an error)

    parts = split_with_delimiter_count(line, delimiter_count)
    if parts is None:
        return RawLine(raw=line) and None  # mismatch -> error at caller

    try:
        if delimiter_count == 2:
            site, username, password = (p.strip() for p in parts)
            if not site or not username or not password:
                return RawLine(raw=line) and None
            domain = forced_fqdn.strip().lower() if forced_fqdn else normalize_domain_from_site(site)
            if not domain:
                return RawLine(raw=line) and None
            return ParsedLogin(username=username, password=password, domain_name=domain)

        elif delimiter_count == 1:
            username, password = (p.strip() for p in parts)
            if not username or not password:
                return RawLine(raw=line) and None
            domain = forced_fqdn.strip().lower() if forced_fqdn else domain_from_email(username)
            if not domain:
                return RawLine(raw=line) and None
            return ParsedLogin(username=username, password=password, domain_name=domain)

        else:
            # You said you will provide delimiter-count to match file(s), but if not 1 or 2, mark as error.
            return RawLine(raw=line) and None

    except Exception:
        # Anything unexpected: treat as unparsable
        return RawLine(raw=line) and None


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
    key = domain_name.lower()
    if key in cache:
        return cache[key]

    obj = sess.exec(select(Domain).where(Domain.domain_name == key)).first()
    if obj is None:
        obj = Domain(domain_name=key)
        sess.add(obj)
        sess.commit()
        sess.refresh(obj)
    cache[key] = obj.domain_id  # type: ignore
    return obj.domain_id  # type: ignore


def bulk_insert_logins(
    sess: Session,
    rows: List[Dict[str, Any]],
) -> Tuple[int, int]:
    """
    Insert many rows with ON CONFLICT DO NOTHING on (domain_id, username, password).
    Returns (inserted_count, skipped_conflicts_estimate).
    """
    if not rows:
        return (0, 0)
    stmt = pg_insert(Login.__table__).values(rows)  # type: ignore[attr-defined]
    stmt = stmt.on_conflict_do_nothing(
        index_elements=["domain_id", "username", "password"]
    )
    result = sess.exec(stmt)
    # For PostgreSQL, rowcount reflects actually inserted rows (conflicts not counted)
    inserted = result.rowcount or 0
    sess.commit()
    skipped = len(rows) - inserted
    return inserted, skipped


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
        required=True,
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
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)

    # Parse input list; tolerate trailing comma
    raw_items = [x.strip() for x in args.input_name.split(",")]
    input_paths = [x for x in raw_items if x]

    if not input_paths:
        print("No input files were provided after parsing --input-name.", file=sys.stderr)
        return 2

    # Setup engine and schema (with CITEXT)
    engine = create_engine(args.db_url, pool_pre_ping=True, future=True)
    ensure_citext(engine)
    SQLModel.metadata.create_all(engine)

    # Caches for FK lookups
    domain_cache: Dict[str, int] = {}
    country_cache: Dict[str, int] = {}

    # Optional fixed country_id
    fixed_country_id: Optional[int] = None

    with Session(engine) as sess, open(args.error_log, "a", encoding="utf-8") as err:
        if args.country:
            fixed_country_id = get_or_create_country_id(sess, country_cache, args.country.strip())

        buffer: List[Dict[str, Any]] = []

        total_lines = 0
        skipped_blank_or_comment = 0
        error_lines = 0
        inserted_total = 0
        skipped_conflicts_total = 0

        def flush():
            nonlocal inserted_total, skipped_conflicts_total, buffer
            if not buffer:
                return
            inserted, skipped = bulk_insert_logins(sess, buffer)
            inserted_total += inserted
            skipped_conflicts_total += skipped
            buffer = []

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

                    try:
                        # Resolve domain_id
                        domain_id = get_or_create_domain_id(sess, domain_cache, parsed.domain_name.lower())

                        row = {
                            "username": parsed.username,
                            "password": parsed.password,
                            "domain_id": domain_id,
                            "country_id": fixed_country_id,
                            "valid": None,
                        }
                        buffer.append(row)
                        if len(buffer) >= args.batch_size:
                            flush()
                    except Exception:
                        # On any failure, record the exact original line
                        err.write(f"{line}\n")
                        error_lines += 1

            elif path.endswith(".txt"):
                for line, lineno in iter_lines_from_path(path):
                    total_lines += 1
                    parsed = parse_line(line, args.delimiter_count, args.fqdn)
                    if parsed is None:
                        if not line or line.strip() == "" or line.lstrip().startswith("#") or line.count(":") == 0:
                            skipped_blank_or_comment += 1
                        else:
                            err.write(f"{line}\n")
                            error_lines += 1
                        continue

                    try:
                        domain_id = get_or_create_domain_id(sess, domain_cache, parsed.domain_name.lower())
                        row = {
                            "username": parsed.username,
                            "password": parsed.password,
                            "domain_id": domain_id,
                            "country_id": fixed_country_id,
                            "valid": None,
                        }
                        buffer.append(row)
                        if len(buffer) >= args.batch_size:
                            flush()
                    except Exception:
                        err.write(f"{line}\n")
                        error_lines += 1
            else:
                print(f"Skipping unsupported file type: {path}", file=sys.stderr)

        # Final flush
        flush()

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
