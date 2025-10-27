#!/usr/bin/env bash
# Usage: ./run-imports.sh /path/to/input_dir
set -uoe pipefail

# ---- Config ---------------------------------------------------------------
DB_URL="postgresql://postgres:postgres@127.0.0.1:5438/intranet"  # fixed port 5438
DELIMITER_COUNT=2
FLUSH_ROWS=100000000
COPY_ROWS=5000000

PROCESSED_DIR="/volume1/NFS/processed"
LOG_DIR="/volume1/NFS/processed/logs"
# ---------------------------------------------------------------------------

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 /path/to/input_dir" >&2
  exit 2
fi

INPUT_DIR="$1"
if [[ ! -d "$INPUT_DIR" ]]; then
  echo "ERROR: input dir not found: $INPUT_DIR" >&2
  exit 2
fi

# Resolve script dir (so we can call your python reliably)
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# Non-recursive file list, null-delimited (handles spaces safely)
while IFS= read -r -d '' f; do
  echo "Processing $f"
  time python password_importer.py   --db-url \
  'postgresql://postgres:postgres@localhost:5438/intranet'   \
  --input-name $f --error-log error_logs/$(basename ${f})_errors.log \
  --delimiter-count 2 --flush-rows $FLUSH_ROWS  --copy-rows $COPY_ROWS

  if [ $? -eq 0 ]; then
    mv $f $PROCESSED_DIR;
    echo "Moved $f to $PROCESSED_DIR"
  else
      echo "Failure with $f"
  fi

  echo "Processed $f"

done < <(find "$INPUT_DIR" -maxdepth 1 -type f -print0)
