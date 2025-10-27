-- -- Drop main partitioned table (children go with CASCADE)
-- DROP TABLE IF EXISTS public.logins CASCADE;

-- -- Drop IP tables
-- DROP TABLE IF EXISTS public.ip_logins_stage;
-- DROP TABLE IF EXISTS public.ip_logins;

-- -- (Keep lookup tables if you want to preserve data; otherwise drop them too)
-- DROP TABLE IF EXISTS public.domains CASCADE;
-- DROP TABLE IF EXISTS public.countries CASCADE;

-- -- Drop helper function if present
-- DROP FUNCTION IF EXISTS public._mk_domain_logins(text);


CREATE EXTENSION IF NOT EXISTS citext;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ======================================================
-- 3) Lookup tables (create if missing)
-- ======================================================
CREATE TABLE IF NOT EXISTS public.countries (
  country_id   bigserial PRIMARY KEY,
  country_name text UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS public.domains (
  domain_id    bigserial PRIMARY KEY,
  domain_name  text UNIQUE NOT NULL
);

-- helpful uniques (idempotent)
CREATE UNIQUE INDEX IF NOT EXISTS idx_domains_domain_name_unique
  ON public.domains (domain_name);
CREATE UNIQUE INDEX IF NOT EXISTS idx_countries_country_name_unique
  ON public.countries (country_name);

-- ======================================================
-- 4) Main LOGINS (partitioned by bucket)
--    - username/password: TEXT
--    - PK: (domain_id, bucket, cred_hash)
-- ======================================================
CREATE TABLE public.logins (
  login_id   bigserial,
  username   text   NOT NULL,
  password   text   NOT NULL,
  domain_id  bigint NOT NULL REFERENCES public.domains(domain_id),
  cred_hash  bytea  NOT NULL,
  bucket     int    NOT NULL,
  country_id bigint REFERENCES public.countries(country_id),
  valid      boolean,
  CONSTRAINT pk_logins_domain_bucket_hash PRIMARY KEY (domain_id, bucket, cred_hash)
) PARTITION BY HASH (bucket);

DO $$
DECLARE i int;
BEGIN
  FOR i IN 0..255 LOOP
    EXECUTE format($f$
      CREATE TABLE public.logins_p%s
      PARTITION OF public.logins
      FOR VALUES WITH (MODULUS 256, REMAINDER %s)
    $f$, i, i);
  END LOOP;
END$$ LANGUAGE plpgsql;

-- ======================================================
-- 7) IP logins and UNLOGGED staging
-- ======================================================
CREATE TABLE public.ip_logins (
  ip_id      bigserial PRIMARY KEY,
  ip_address text   NOT NULL,
  username   text   NOT NULL,
  password   text   NOT NULL,
  CONSTRAINT uq_iplogin_ip_user_pass UNIQUE (ip_address, username, password)
);

DROP TABLE IF EXISTS public.ip_logins_stage;
CREATE UNLOGGED TABLE public.ip_logins_stage (
  ip_address text  NOT NULL,
  username   text  NOT NULL,
  password   text  NOT NULL
);

COMMIT;


-- ======================================================
-- OPTIONAL: Post-load indexes (run AFTER bulk import)
-- ======================================================
-- OPTIONAL: Post-load indexes (run AFTER bulk import)
-- Suggested (create only what you query):
-- CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_logins_domain_username ON public.logins (domain_id, username);
-- CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_logins_domain_cred     ON public.logins (domain_id, cred_hash);
-- -- Example generator for main 1024 children:
-- DO $$
-- DECLARE i int;
-- BEGIN
--   FOR i IN 0..1023 LOOP
--     EXECUTE format('CREATE INDEX IF NOT EXISTS idx_logins_domain_user_%s ON public.logins_%s (domain_id, username);', i, i);
--     EXECUTE format('CREATE INDEX IF NOT EXISTS idx_logins_domain_cred_%s ON public.logins_%s (domain_id, cred_hash);', i, i);
--   END LOOP;
-- END$$;

-- -- Example generator for per-domain 32 children each:
-- DO $$
-- DECLARE r int;
-- DECLARE p text;
-- BEGIN
--   FOR p IN SELECT unnest(ARRAY['logins_facebook','logins_outlook','logins_linkedin','logins_twitter','logins_gmail']) LOOP
--     FOR r IN 0..31 LOOP
--       EXECUTE format('CREATE INDEX IF NOT EXISTS idx_%s_domain_user_%s ON public.%s_%s (domain_id, username);', p, r, p, r);
--       EXECUTE format('CREATE INDEX IF NOT EXISTS idx_%s_domain_cred_%s ON public.%s_%s (domain_id, cred_hash);', p, r, p, r);
--     END LOOP;
--   END LOOP;
-- END$$;

-- ANALYZE public.logins;
-- ANALYZE public.logins_facebook;
-- ANALYZE public.logins_outlook;
-- ANALYZE public.logins_linkedin;
-- ANALYZE public.logins_twitter;
-- ANALYZE public.logins_gmail;
-- ANALYZE public.ip_logins;