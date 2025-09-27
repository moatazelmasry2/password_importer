docker stop combos 2>/dev/null || true
docker rm combos 2>/dev/null || true

# Prepare a *subdirectory* on the NAS that will be PGDATA
sudo mkdir -p /Volumes/nfs/combos_pgdata/pgroot
sudo chmod 700 /Volumes/nfs/combos_pgdata/pgroot

docker run -d \
  --name combos \
  -p 5432:5432 \
  -v /Volumes/nfs/combos_pgdata/pgroot:/var/lib/postgresql/data \
  -e PGDATA=/var/lib/postgresql/data \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=intranet \
  --entrypoint bash \
  postgres:17 -lc '
set -euo pipefail

PGDATA="${PGDATA:-/var/lib/postgresql/data}"
PG_BIN="/usr/lib/postgresql/17/bin"

mkdir -p "$PGDATA"
chmod 700 "$PGDATA" || true

owner_uid=$(stat -c "%u" "$PGDATA")
owner_gid=$(stat -c "%g" "$PGDATA")
echo "PGDATA owner detected: ${owner_uid}:${owner_gid}"

if ! getent group "${owner_gid}" >/dev/null 2>&1; then groupadd -g "${owner_gid}" pggrp || true; fi
if ! id -u "${owner_uid}" >/dev/null 2>&1; then useradd -u "${owner_uid}" -g "${owner_gid}" -M -d /var/lib/postgresql -s /bin/bash pgusr || true; fi

if [ ! -f "$PGDATA/PG_VERSION" ]; then
  pwfile="/tmp/pgpass.$$"
  gosu "${owner_uid}:${owner_gid}" sh -c "umask 177; echo \"$POSTGRES_PASSWORD\" > $pwfile"
  gosu "${owner_uid}:${owner_gid}" "$PG_BIN/initdb" -D "$PGDATA" --username="${POSTGRES_USER:-postgres}" --pwfile="$pwfile"
  gosu "${owner_uid}:${owner_gid}" rm -f "$pwfile"
  grep -q "192.168.65.1/32" "$PGDATA/pg_hba.conf" || cat >> "$PGDATA/pg_hba.conf" <<EOF
host    all     all     127.0.0.1/32         scram-sha-256
host    all     all     ::1/128              scram-sha-256
host    all     all     192.168.65.1/32      scram-sha-256
EOF
fi

exec gosu "${owner_uid}:${owner_gid}" "$PG_BIN/postgres" -D "$PGDATA" \
  -c listen_addresses='\''*'\'' \
  -c unix_socket_directories=/tmp \
  -c shared_buffers=4GB \
  -c work_mem=512MB \
  -c effective_cache_size=6GB \
  -c max_wal_size=12GB \
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
  -c max_replication_slots=0  \
  -c maintenance_work_mem=4GB
'

### Create the DB
# docker exec -it combos bash -lc '/usr/lib/postgresql/17/bin/createdb -h /var/lib/postgresql -U postgres intranet'

# docker exec -e PGPASSWORD=postgres -it combos /usr/lib/postgresql/17/bin/psql -h 127.0.0.1 -U postgres -d intranet