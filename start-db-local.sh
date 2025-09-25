docker stop combos_local 2>/dev/null || true
docker rm combos_local 2>/dev/null || true


docker run -d \
  --name combos_local \
  -p 5433:5432 \
  -v combos17:/var/lib/postgresql/data \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=intranet \
  postgres:17 \
  -c shared_buffers=4GB \
  -c work_mem=256MB \
  -c effective_cache_size=6GB \
  -c max_wal_size=12GB \
  -c checkpoint_completion_target=0.9 \
  -c wal_buffers=-1 \
  -c effective_io_concurrency=200 \
  -c max_worker_processes=8 \
  -c max_parallel_workers=8 \
  -c max_parallel_workers_per_gather=2  \
  -c wal_level=minimal \
  -c autovacuum=off \
  -c synchronous_commit=off \
  -c fsync=off \
  -c full_page_writes=off \
  -c checkpoint_timeout=30min \
  -c temp_buffers=256MB \
  -c max_wal_senders=0


### Create the DB
# docker exec -it combos_local bash -lc '/usr/lib/postgresql/17/bin/createdb -h /var/lib/postgresql -U postgres intranet'

 
# docker exec -it combos_local psql -U postgres -d intranet


