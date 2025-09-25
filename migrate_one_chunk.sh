#!/usr/bin/env bash
set -euo pipefail

# ------- Config (edit if needed) -------
LOCAL_DSN="${LOCAL_DSN:-postgresql://postgres:postgres@127.0.0.1:5433/intranet}"   # local SSD DB
NAS_HOST="${NAS_HOST:-127.0.0.1}"    # NAS Postgres host
NAS_PORT="${NAS_PORT:-5432}"         # NAS Postgres port
NAS_USER="${NAS_USER:-postgres}"
NAS_PASS="${NAS_PASS:-postgres}"
NAS_DB_TARGET="${NAS_DB_TARGET:-intranet}"       # real DB on NAS
NAS_DB_STAGE="${NAS_DB_STAGE:-intranet}"   # temp DB name per chunk

# Parallelism (tune these)
DUMP_JOBS="${DUMP_JOBS:-4}"          # pg_dump threads
RESTORE_JOBS="${RESTORE_JOBS:-8}"    # pg_restore threads

# Temp paths
TMPDIR="${TMPDIR:-/tmp}"
DUMP_DIR="$TMPDIR/chunk_dir_$$"      # directory-format dump

# Build DSNs
NAS_DSN_TARGET="postgresql://$NAS_USER:$NAS_PASS@$NAS_HOST:$NAS_PORT/$NAS_DB_TARGET"
NAS_DSN_ADMIN="postgresql://$NAS_USER:$NAS_PASS@$NAS_HOST:$NAS_PORT/postgres"   # to create/drop DBs
NAS_DSN_STAGE="postgresql://$NAS_USER:$NAS_PASS@$NAS_HOST:$NAS_PORT/$NAS_DB_STAGE"

echo "== [1/7] Directory dump from LOCAL (domains,countries,logins,ip_logins) → $DUMP_DIR =="
rm -rf "$DUMP_DIR"; mkdir -p "$DUMP_DIR"
pg_dump "$LOCAL_DSN" \
  -Fd -j "$DUMP_JOBS" \
  --data-only --no-owner --no-privileges \
  -t public.domains -t public.countries -t public.logins -t public.ip_logins \
  -f "$DUMP_DIR"

echo "== [2/7] Create fresh stage DB on NAS: $NAS_DB_STAGE =="
psql "$NAS_DSN_ADMIN" -v ON_ERROR_STOP=1 <<SQL
DROP DATABASE IF EXISTS "$NAS_DB_STAGE";
CREATE DATABASE "$NAS_DB_STAGE";
ALTER DATABASE "$NAS_DB_STAGE" SET synchronous_commit = off;
ALTER DATABASE "$NAS_DB_STAGE" SET maintenance_work_mem = '2GB';
ALTER DATABASE "$NAS_DB_STAGE" SET work_mem = '256MB';
SQL

echo "== [3/7] Create stage tables as UNLOGGED with NO constraints/indexes =="
psql "$NAS_DSN_STAGE" -v ON_ERROR_STOP=1 <<'SQL'
CREATE EXTENSION IF NOT EXISTS citext;

-- NOTE: Keep IDs so we can map by name later, but do NOT declare PK/UNIQUE here.
CREATE UNLOGGED TABLE countries (
  country_id   int,
  country_name citext
);
CREATE UNLOGGED TABLE domains (
  domain_id    int,
  domain_name  citext
);
CREATE UNLOGGED TABLE logins (
  login_id   int,
  username   text,
  password   text,
  domain_id  int,
  country_id int,
  valid      boolean
);
CREATE UNLOGGED TABLE ip_logins (
  ip_id      int,
  ip_address text,
  username   text,
  password   text
);
SQL

echo "== [4/7] Parallel restore into stage DB (heap-only, skipping SEQUENCE SET; sync_commit=off) =="
# Build a TOC list and remove SEQUENCE SET entries (these are the setval() statements)
TOC_LIST="$TMPDIR/toc_$$.list"
TOC_LIST_NOSEQ="$TMPDIR/toc_$$.no_seqset.list"

pg_restore -Fd -l "$DUMP_DIR" > "$TOC_LIST"
# Drop every line that contains ' SEQUENCE SET '
grep -v ' SEQUENCE SET ' "$TOC_LIST" > "$TOC_LIST_NOSEQ"

# Restore only the filtered items; with UNLOGGED stage tables this is very fast
psql "$NAS_DSN_STAGE" -v ON_ERROR_STOP=1 -c "SET synchronous_commit=OFF;"
pg_restore -Fd -j "$RESTORE_JOBS" -L "$TOC_LIST_NOSEQ" -d "$NAS_DSN_STAGE" "$DUMP_DIR"


echo "== [5/7] Merge stage → target via dblink (skip duplicates with ON CONFLICT DO NOTHING) =="
psql "$NAS_DSN_TARGET" -v ON_ERROR_STOP=1 <<SQL
SET LOCAL synchronous_commit = OFF;
CREATE EXTENSION IF NOT EXISTS dblink;

-- connect to stage DB
SELECT dblink_connect('stage',
  'host=$NAS_HOST port=$NAS_PORT dbname=$NAS_DB_STAGE user=$NAS_USER password=$NAS_PASS');

-- 1) ensure names exist in target
INSERT INTO domains(domain_name)
SELECT DISTINCT domain_name
FROM dblink('stage','SELECT domain_name FROM domains') AS t(domain_name citext)
WHERE domain_name IS NOT NULL
ON CONFLICT (domain_name) DO NOTHING;

INSERT INTO countries(country_name)
SELECT DISTINCT country_name
FROM dblink('stage','SELECT country_name FROM countries') AS t(country_name citext)
WHERE country_name IS NOT NULL
ON CONFLICT (country_name) DO NOTHING;

-- 2) insert logins by mapping stage ids -> names -> target ids
WITH s_dom AS (
  SELECT * FROM dblink('stage',
    'SELECT domain_id, domain_name FROM domains'
  ) AS x(domain_id int, domain_name citext)
), s_cty AS (
  SELECT * FROM dblink('stage',
    'SELECT country_id, country_name FROM countries'
  ) AS x(country_id int, country_name citext)
), s_log AS (
  SELECT * FROM dblink('stage',
    'SELECT login_id, username, password, domain_id, country_id, valid FROM logins ORDER BY login_id'
  ) AS x(login_id int, username text, password text, domain_id int, country_id int, valid boolean)
)
INSERT INTO logins (username, password, domain_id, country_id, valid)
SELECT l.username,
       l.password,
       d_pub.domain_id,
       c_pub.country_id,
       l.valid
FROM s_log l
LEFT JOIN s_dom d_stg ON d_stg.domain_id = l.domain_id
LEFT JOIN domains d_pub ON d_pub.domain_name = d_stg.domain_name
LEFT JOIN s_cty c_stg ON c_stg.country_id = l.country_id
LEFT JOIN countries c_pub ON c_pub.country_name = c_stg.country_name
ON CONFLICT DO NOTHING;

-- 3) ip_logins are self-contained
INSERT INTO ip_logins (ip_address, username, password)
SELECT ip_address, username, password
FROM dblink('stage','SELECT ip_address, username, password FROM ip_logins ORDER BY ip_id')
  AS x(ip_address text, username text, password text)
ON CONFLICT DO NOTHING;

SELECT dblink_disconnect('stage');
SQL

echo "== [6/7] Drop stage DB and delete dump dir (free NAS + local space) =="
psql "$NAS_DSN_ADMIN" -v ON_ERROR_STOP=1 -c "DROP DATABASE \"$NAS_DB_STAGE\";"
rm -rf "$DUMP_DIR"

echo "== [7/7] Wipe LOCAL tables to keep disk flat =="
psql "$LOCAL_DSN" -v ON_ERROR_STOP=1 -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
psql "$LOCAL_DSN" -v ON_ERROR_STOP=1 <<'SQL'
CREATE EXTENSION IF NOT EXISTS citext;
CREATE TABLE IF NOT EXISTS countries (
  country_id   serial PRIMARY KEY,
  country_name citext UNIQUE NOT NULL
);
CREATE TABLE IF NOT EXISTS domains (
  domain_id    serial PRIMARY KEY,
  domain_name  citext UNIQUE NOT NULL
);
CREATE TABLE IF NOT EXISTS logins (
  login_id   serial PRIMARY KEY,
  username   text NOT NULL,
  password   text NOT NULL,
  domain_id  int,
  country_id int,
  valid      boolean,
  CONSTRAINT uq_login_domain_user_pass UNIQUE (domain_id, username, password)
);
CREATE TABLE IF NOT EXISTS ip_logins (
  ip_id      serial PRIMARY KEY,
  ip_address text NOT NULL,
  username   text NOT NULL,
  password   text NOT NULL,
  CONSTRAINT uq_iplogin_ip_user_pass UNIQUE (ip_address, username, password)
);
SQL

echo "✔ Migration done (parallel restore, unlogged stage). Local reset complete."
