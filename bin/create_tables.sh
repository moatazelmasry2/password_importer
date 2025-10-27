#!/bin/bash

# 1) Drop old data & recreate schema
# Drop the old tables (ignore errors if they don't exist)
podman exec -i combos psql -h /tmp -U postgres -d intranet <<'SQL'
\set ON_ERROR_STOP on
BEGIN;
DROP TABLE IF EXISTS public.logins CASCADE;
DROP TABLE IF EXISTS public.ip_logins CASCADE;
DROP TABLE IF EXISTS public.countries CASCADE;
DROP TABLE IF EXISTS public.domains CASCADE;
COMMIT;
SQL

# Create core tables
podman exec -i combos psql -h /tmp -U postgres -d intranet <<'SQL'
\set ON_ERROR_STOP on
BEGIN;

CREATE EXTENSION IF NOT EXISTS citext;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE public.countries (
  country_id   bigserial PRIMARY KEY,
  country_name text UNIQUE NOT NULL
);

CREATE TABLE public.domains (
  domain_id    bigserial PRIMARY KEY,
  domain_name  text UNIQUE NOT NULL
);

-- Main logins parent (same schema), bytea username/password, PK with bucket
CREATE TABLE public.logins (
  login_id   bigint,   -- optional
  username   bytea NOT NULL,
  password   bytea NOT NULL,
  domain_id  int  NOT NULL REFERENCES public.domains(domain_id),
  cred_hash  bytea NOT NULL,
  bucket     int  NOT NULL,
  country_id int  REFERENCES public.countries(country_id),
  valid      boolean,
  CONSTRAINT pk_logins_domain_bucket_hash PRIMARY KEY (domain_id, bucket, cred_hash)
) PARTITION BY HASH (domain_id, bucket);

-- IP logins unchanged
CREATE TABLE public.ip_logins (
  ip_id      bigserial PRIMARY KEY,
  ip_address text NOT NULL,
  username   text NOT NULL,
  password   bytea NOT NULL,
  CONSTRAINT uq_iplogin_ip_user_pass UNIQUE (ip_address, username, password)
);

COMMIT;
SQL

# Create 1024 hash partitions for main logins (domain_id,bucket)
DBCONN="-h /tmp -U postgres -d intranet"
TOTAL=1024
BATCH=128
i=0
while [ $i -lt $TOTAL ]; do
  j=$(( i + BATCH )); [ $j -gt $TOTAL ] && j=$TOTAL
  sql="\\set ON_ERROR_STOP on
BEGIN;"
  while [ $i -lt $j ]; do
    sql+="
CREATE TABLE IF NOT EXISTS public.logins_${i}
  PARTITION OF public.logins
  FOR VALUES WITH (MODULUS 1024, REMAINDER ${i});"
    i=$(( i + 1 ))
  done
  sql+="
COMMIT;"
  podman exec -i combos psql $DBCONN <<SQL
${sql}
SQL
done

# Create 5 per-domain tables (same schema) + 32 bucket partitions each
podman exec -i combos psql -h /tmp -U postgres -d intranet <<'SQL'
\set ON_ERROR_STOP on
BEGIN;

-- Helper to create a per-domain parent table
CREATE OR REPLACE FUNCTION _mk_domain_logins(parent_name text) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  EXECUTE format($f$
    CREATE TABLE IF NOT EXISTS public.%I (
      login_id   bigint,
      username   bytea NOT NULL,
      password   bytea NOT NULL,
      domain_id  int  NOT NULL REFERENCES public.domains(domain_id),
      cred_hash  bytea NOT NULL,
      bucket     int  NOT NULL,
      country_id int  REFERENCES public.countries(country_id),
      valid      boolean,
      CONSTRAINT pk_%1$s PRIMARY KEY (domain_id, bucket, cred_hash)
    ) PARTITION BY HASH (bucket);
  $f$, parent_name);
END$$;

SELECT _mk_domain_logins('logins_facebook');
SELECT _mk_domain_logins('logins_outlook');
SELECT _mk_domain_logins('logins_linkedin');
SELECT _mk_domain_logins('logins_twitter');
SELECT _mk_domain_logins('logins_gmail');

COMMIT;
SQL

# Create the 32 children for each:
DBCONN="-h /tmp -U postgres -d intranet"
parents=(logins_facebook logins_outlook logins_linkedin logins_twitter logins_gmail)

for p in "${parents[@]}"; do
  echo "Creating children for ${p}..."
  sql="\\set ON_ERROR_STOP on
BEGIN;"
  for r in $(seq 0 31); do
    sql+="
CREATE TABLE IF NOT EXISTS public.${p}_${r}
  PARTITION OF public.${p}
  FOR VALUES WITH (MODULUS 32, REMAINDER ${r});"
  done
  sql+="
COMMIT;"
  podman exec -i combos psql $DBCONN <<SQL
${sql}
SQL
done

