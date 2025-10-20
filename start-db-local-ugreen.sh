#!/usr/bin/env bash
set -euo pipefail


### Only the first time when creating the database:
# podman unshare chown -R 999:999 /volume1/NFS/combos_pgdata/pgroot
# podman unshare chmod    700     /volume1/NFS/combos_pgdata/pgroot

# ------------ Config you can tweak -----------------------------------------
ROOT_PATH="/volume1/NFS"
PG_PARENT="${ROOT_PATH}/combos_pgdata/pgroot"   # must exist; owned by 999:999 (see prep step)
PG_SUBDIR="pgdata"                              # cluster dir under PG_PARENT
CONTAINER_NAME="combos"
HOST_PORT=5438
PG_MAJOR=17
IMG="docker.io/library/postgres:${PG_MAJOR}"

# Security/auth
POSTGRES_USER="postgres"
POSTGRES_PASSWORD="postgres"                    # change later; supports SCRAM
POSTGRES_DB="intranet"

# App role for later read access (created on first init)
APP_USER="intranet_ro"
APP_PASSWORD="intranet_ro_pwd"                  # change in real use
APP_PRIVS_DB="intranet"                         # DB where we grant privileges

# Network access (restrict these for production)
ALLOW_V4="0.0.0.0/0"
ALLOW_V6="::/0"

# Runtime profile: SAFE (durable) or DEV (fast/unsafe)
DB_PROFILE="${DB_PROFILE:-SAFE}"
# ---------------------------------------------------------------------------

# Stop & replace old container
podman stop "${CONTAINER_NAME}" 2>/dev/null || true
podman rm   "${CONTAINER_NAME}" 2>/dev/null || true

# Choose tuning by profile
if [[ "${DB_PROFILE}" == "SAFE" ]]; then
  PG_TUNING=(
    -c listen_addresses='*'
    -c unix_socket_directories=/tmp
    -c wal_level=replica
    -c autovacuum=on
    -c synchronous_commit=on
    -c fsync=on
    -c full_page_writes=on
    -c shared_buffers=512MB
    -c work_mem=64MB
    -c effective_cache_size=512GB
    -c max_wal_size=1GB
    -c checkpoint_completion_target=0.9
    -c wal_buffers=-1
    -c effective_io_concurrency=200
    -c max_worker_processes=8
    -c max_parallel_workers=8
    -c max_parallel_workers_per_gather=2
    -c checkpoint_timeout=15min
    -c temp_buffers=64MB
    -c max_wal_senders=0
    -c max_replication_slots=0
    -c maintenance_work_mem=1GB
  )
else
  # Your original fast settings (NOT durable – fine for import/dev)
  PG_TUNING=(
    -c listen_addresses='*'
    -c unix_socket_directories=/tmp
    -c max_connections=100 \
    -c shared_buffers=16GB \
    -c effective_cache_size=48GB \
    -c work_mem=96MB \
    -c maintenance_work_mem=3GB \
    -c temp_buffers=128MB \
    -c max_wal_size=24GB \
    -c checkpoint_timeout=20min \
    -c checkpoint_completion_target=0.9 \
    -c wal_buffers=-1 \
    -c wal_compression=on \
    -c effective_io_concurrency=256 \
    -c max_worker_processes=8 \
    -c max_parallel_workers=8 \
    -c max_parallel_workers_per_gather=2 \
    -c max_parallel_maintenance_workers=2 \
    -c wal_level=replica \
    -c autovacuum=on \
    -c synchronous_commit=on \
    -c fsync=on \
    -c full_page_writes=on \
    -c max_wal_senders=0
  )
fi

# Run container (rootless), bind /pg, avoid anon VOLUME via tmpfs
podman run -d \
  --name "${CONTAINER_NAME}" \
  --restart unless-stopped \
  -p ${HOST_PORT}:5432 \
  -v "${PG_PARENT}:/pg:rw" \
  --tmpfs /var/lib/postgresql/data:rw,size=64m \
  -e PGDATA="/pg/${PG_SUBDIR}" \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=intranet \
  --user 999:999 \
  --entrypoint bash \
  "${IMG}" -lc '
set -euo pipefail
PG_BIN=/usr/lib/postgresql/'"${PG_MAJOR}"'/bin
PGDATA=${PGDATA:?}

echo Effective user:
id
echo PGDATA: ${PGDATA}
[ -d "$(dirname "${PGDATA}")" ] || { echo ERROR: parent mount missing; exit 2; }

if [ ! -s "${PGDATA}/PG_VERSION" ]; then
  echo INIT: First run - initializing cluster
  pwfile=$(mktemp); umask 177; echo "${POSTGRES_PASSWORD}" > "${pwfile}"
  "${PG_BIN}/initdb" -D "${PGDATA}" --username="${POSTGRES_USER:-postgres}" --pwfile="${pwfile}"
  rm -f "${pwfile}"

  # Allow localhost + all (tighten later to your CIDRs)
  cat >> ${PGDATA}/pg_hba.conf <<EOF
host all all 127.0.0.1/32 scram-sha-256
host all all ::1/128 scram-sha-256
host all all 0.0.0.0/0 scram-sha-256
host all all ::/0 scram-sha-256
EOF

  # Start a temporary local server on socket only and bootstrap DB/role
  "${PG_BIN}/pg_ctl" -D "${PGDATA}" -w start -o "-c listen_addresses='' -c unix_socket_directories=/tmp"

  # Ensure database exists
  createdb -h /tmp -U "${POSTGRES_USER:-postgres}" "${POSTGRES_DB}" 2>/dev/null || true

  # Create RO role if missing; grant minimal privileges
  psql -h /tmp -U "${POSTGRES_USER:-postgres}" -d "${POSTGRES_DB}" <<'SQL'
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'intranet_ro') THEN
    CREATE ROLE intranet_ro LOGIN PASSWORD 'intranet_ro_pwd';
  END IF;
END
$$;
GRANT CONNECT ON DATABASE intranet TO intranet_ro;
GRANT USAGE ON SCHEMA public TO intranet_ro;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO intranet_ro;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO intranet_ro;
SQL

  # Stop temp server; main exec starts with final tuning
  "${PG_BIN}/pg_ctl" -D "${PGDATA}" -m fast -w stop
else
  echo INIT: Existing cluster detected
fi

exec "${PG_BIN}/postgres" -D "${PGDATA}" \
  -c listen_addresses="*" \
  -c unix_socket_directories=/tmp \
  -c shared_buffers=1GB \
  -c work_mem=512MB \
  -c effective_cache_size=1GB \
  -c max_wal_size=1GB \
  -c checkpoint_completion_target=0.9 \
  -c wal_buffers=-1 \
  -c effective_io_concurrency=200 \
  -c max_worker_processes=8 \
  -c max_parallel_workers=8 \
  -c max_parallel_workers_per_gather=2 \
  -c wal_level=minimal \
  -c autovacuum=off \
  -c synchronous_commit=off \
  -c fsync=off \
  -c full_page_writes=off \
  -c checkpoint_timeout=30min \
  -c temp_buffers=256MB \
  -c max_wal_senders=0 \
  -c max_replication_slots=0 \
  -c maintenance_work_mem=4GB
'

echo "Postgres '${CONTAINER_NAME}' is up on port ${HOST_PORT} (profile: ${DB_PROFILE})."


### Create the DB
# podman exec -e PGPASSWORD=postgres -it combos /usr/lib/postgresql/17/bin/createdb -h /tmp -U postgres intranet


# When starting: 
# DB_PROFILE=DEV ./start-db.sh
# import your data...
# DB_PROFILE=SAFE ./start-db.sh

## Jump into the database
# podman exec -e PGPASSWORD=postgres -it combos psql -h 127.0.0.1 -p 5432 -U postgres -d intranet
