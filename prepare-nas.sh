psql "postgresql://postgres:postgres@127.0.0.1:5432/intranet" -v ON_ERROR_STOP=1 <<'SQL'
CREATE EXTENSION IF NOT EXISTS citext;
CREATE EXTENSION IF NOT EXISTS dblink;

-- Base tables (create if missing)
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
  domain_id  int  REFERENCES domains(domain_id),
  country_id int  REFERENCES countries(country_id),
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
