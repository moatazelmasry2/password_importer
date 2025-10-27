#!/usr/bin/env bash
set -euo pipefail

### One-time prep (first cluster only):
# podman unshare chown -R 999:999 /volume1/NFS/combos_pgdata/pgroot
# podman unshare chmod    700     /volume1/NFS/combos_pgdata/pgroot

# ------------ Config you can tweak -----------------------------------------
ROOT_PATH="/home/moataz"
PG_PARENT="${ROOT_PATH}/combos_pgdata/pgroot"   # must exist; owned by 999:999
PG_SUBDIR="pgdata"                              # cluster dir under PG_PARENT
CONTAINER_NAME="combos"
HOST_PORT=5438
PG_MAJOR=17
IMG="docker.io/library/postgres:${PG_MAJOR}"

# Security/auth
POSTGRES_USER="postgres"
POSTGRES_PASSWORD="postgres"                    # change later
POSTGRES_DB="intranet"

# Network access (tighten for prod)
ALLOW_V4="${ALLOW_V4:-0.0.0.0/0}"
ALLOW_V6="${ALLOW_V6:-::/0}"

# Runtime profile: SAFE (durable) or DEV (fast/unsafe)
DB_PROFILE="${DB_PROFILE:-SAFE}"
# ---------------------------------------------------------------------------

# Stop & replace old container
podman stop "${CONTAINER_NAME}" 2>/dev/null || true
podman rm   "${CONTAINER_NAME}" 2>/dev/null || true

# Choose tuning by profile (8 CPU / 64 GB RAM) — SAFE≈DEV except durability
if [[ "${DB_PROFILE}" == "SAFE" ]]; then
  PG_TUNING=(
    -c
    listen_addresses='*'
    -c
    unix_socket_directories=/tmp
    -c
    max_connections=200
    -c
    shared_buffers=16GB
    -c
    effective_cache_size=48GB
    -c
    work_mem=96MB
    -c
    maintenance_work_mem=3GB
    -c
    temp_buffers=128MB
    -c
    max_wal_size=24GB
    -c
    checkpoint_timeout=20min
    -c
    checkpoint_completion_target=0.9
    -c
    wal_buffers=-1
    -c
    wal_compression=on
    -c
    effective_io_concurrency=256
    -c
    max_worker_processes=8
    -c
    max_parallel_workers=8
    -c
    max_parallel_workers_per_gather=2
    -c
    max_parallel_maintenance_workers=2
    -c
    wal_level=replica
    -c
    autovacuum=on
    -c
    synchronous_commit=on
    -c
    fsync=on
    -c
    full_page_writes=on
    -c
    max_wal_senders=0
    -c
    max_replication_slots=0
    -c
    max_locks_per_transaction=4096
  )
else
  PG_TUNING=(
    -c
    listen_addresses='*'
    -c
    unix_socket_directories=/tmp
    -c
    max_connections=200
    -c
    shared_buffers=16GB
    -c
    effective_cache_size=48GB
    -c
    work_mem=96MB
    -c
    maintenance_work_mem=3GB
    -c
    temp_buffers=128MB
    -c
    max_wal_size=32GB
    -c
    checkpoint_timeout=20min
    -c
    checkpoint_completion_target=0.9
    -c
    wal_buffers=-1
    -c
    wal_compression=on
    -c
    effective_io_concurrency=256
    -c
    max_worker_processes=8
    -c
    max_parallel_workers=8
    -c
    max_parallel_workers_per_gather=4
    -c
    max_parallel_maintenance_workers=2
    -c
    wal_level=replica
    -c
    autovacuum=on
    -c
    synchronous_commit=off
    -c
    fsync=off
    -c
    full_page_writes=off
    -c
    max_wal_senders=0
    -c
    max_replication_slots=0
    -c
    max_locks_per_transaction=4096
  )
fi

# Serialize PG_TUNING array as newline-separated (simple/safe)
PG_TUNING_STR="$(printf '%s\n' "${PG_TUNING[@]}")"

# Run container (rootless), bind /pg, avoid anon VOLUME via tmpfs
sudo podman run -d \
  --name "${CONTAINER_NAME}" \
  --restart unless-stopped \
  -p ${HOST_PORT}:5432 \
  -v "${PG_PARENT}:/pg:rw,U" \
  --tmpfs /var/lib/postgresql/data:rw,size=64m \
  -e PG_MAJOR="${PG_MAJOR}" \
  -e PGDATA="/pg/${PG_SUBDIR}" \
  -e POSTGRES_USER="${POSTGRES_USER}" \
  -e POSTGRES_PASSWORD="${POSTGRES_PASSWORD}" \
  -e POSTGRES_DB="${POSTGRES_DB}" \
  -e ALLOW_V4="${ALLOW_V4}" \
  -e ALLOW_V6="${ALLOW_V6}" \
  -e PG_TUNING="${PG_TUNING_STR}" \
  --user 999:999 \
  --entrypoint bash \
  "${IMG}" -lc '
set -euo pipefail

PGDATA=${PGDATA:?}
PG_MAJOR=${PG_MAJOR:?}

echo "Effective user:"; id
echo "PGDATA: ${PGDATA}"
[ -d "$(dirname "${PGDATA}")" ] || { echo "ERROR: parent mount missing"; exit 2; }

# Pin Postgres bin dir
if [ -x "/usr/lib/postgresql/${PG_MAJOR}/bin/postgres" ]; then
  PG_BIN="/usr/lib/postgresql/${PG_MAJOR}/bin"
elif command -v postgres >/dev/null 2>&1; then
  PG_BIN="$(dirname "$(command -v postgres)")"
else
  echo "ERROR: postgres binary not found"; exit 3
fi
export PATH="${PG_BIN}:${PATH}"

# First run: init cluster and minimal config
if [ ! -s "${PGDATA}/PG_VERSION" ]; then
  echo "INIT: First run - initializing cluster"

  pwfile=$(mktemp); umask 177; printf "%s\n" "${POSTGRES_PASSWORD}" > "${pwfile}"
  "${PG_BIN}/initdb" -D "${PGDATA}" --username="${POSTGRES_USER}" --pwfile="${pwfile}"
  rm -f "${pwfile}"

  # Allow local + configured CIDRs (tighten later)
  {
    echo "host all all 127.0.0.1/32 scram-sha-256"
    echo "host all all ::1/128 scram-sha-256"
    echo "host all all ${ALLOW_V4} scram-sha-256"
    echo "host all all ${ALLOW_V6} scram-sha-256"
  } >> "${PGDATA}/pg_hba.conf"

  # Start a temporary local server on socket only
  "${PG_BIN}/pg_ctl" -D "${PGDATA}" -w start -o "-c listen_addresses='' -c unix_socket_directories=/tmp"

  # Ensure database exists (ignore if already exists)
  createdb -h /tmp -U "${POSTGRES_USER}" "${POSTGRES_DB}" 2>/dev/null || true

  # Stop temp server; main exec starts with final tuning
  "${PG_BIN}/pg_ctl" -D "${PGDATA}" -m fast -w stop
else
  echo "INIT: Existing cluster detected"
fi

# Rebuild PG_TUNING array safely from newline-separated env
EXTRA=()
if [ -n "${PG_TUNING:-}" ]; then
  while IFS= read -r line; do
    [ -n "$line" ] && EXTRA+=("$line")
  done <<EOT
${PG_TUNING}
EOT
fi

echo "Starting postgres with ${#EXTRA[@]} custom -c settings."
exec "${PG_BIN}/postgres" -D "${PGDATA}" "${EXTRA[@]}"
'

echo "Postgres '${CONTAINER_NAME}' is up on port ${HOST_PORT} (profile: ${DB_PROFILE})."

### (Optional) Later, create a read-only role & grants in a separate step, not during boot:
# podman exec -e PGPASSWORD="${POSTGRES_PASSWORD}" -it "${CONTAINER_NAME}" \
#   psql -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" \
#   -c "CREATE ROLE intranet_ro LOGIN PASSWORD 'intranet_ro_pwd';" \
#   -c "GRANT CONNECT ON DATABASE ${POSTGRES_DB} TO intranet_ro;" \
#   -c "GRANT USAGE ON SCHEMA public TO intranet_ro;" \
#   -c "GRANT SELECT ON ALL TABLES IN SCHEMA public TO intranet_ro;" \
#   -c "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO intranet_ro;"


### Create the DB manually (if needed later):
# podman exec -e PGPASSWORD="${POSTGRES_PASSWORD}" -it "${CONTAINER_NAME}" createdb -h /tmp -U "${POSTGRES_USER}" "${POSTGRES_DB}"

### Jump into the database:
# podman exec -e PGPASSWORD="postgres" -it "combos" psql -h 127.0.0.1 -p 5432 -U "postgres" -d "intranet"


# To start the database
# DEBUG=1 DB_PROFILE=DEV ./start-db-local-ugreen.sh
# DB_PROFILE=SAFE ./start-db-local-ugreen.sh