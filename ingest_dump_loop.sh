#!/usr/bin/env bash
set -euo pipefail

# DSNs for importer (SQLAlchemy form) and migrator (psql form)
LOCAL_SQLA="postgresql+psycopg://postgres:postgres@127.0.0.1:5433/intranet"

# tune importer a bit
BATCH_SIZE=100000
COPY_CHUNK=2000000

for f in "$@"; do
  echo "==== Ingesting locally: $f ====" >> ./migrate_one_chunk.log
  python3 password_importer.py \
    --db-url "$LOCAL_SQLA" \
    --input-name "$f" \
    --delimiter-count 2 \
    --batch-size "$BATCH_SIZE" \
    --copy-chunk-size "$COPY_CHUNK"

  echo "==== Dump → restore → merge → wipe ====" >> ./migrate_one_chunk.log
  ./migrate_one_chunk.sh >> ./migrate_one_chunk.log
  echo "==== Done: $f ====" >> ./migrate_one_chunk.log
  mv $f /Volumes/nfs/processed/
done
