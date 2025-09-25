#!/bin/env bash

python3 password_importer.py \
  --db-url 'postgresql+psycopg://postgres:postgres@localhost:5432/intranet' \
  --input-name 'old1.txt,old2.tar.gz,' \
  --delimiter-count 2 \
  --country 'Germany' \
  --error-log ./bad_lines.log \
  --batch-size 2000

# Format2: username:password (emails), one colon, force fqdn override for all rows
python3 password_importer.py \
  --db-url 'postgresql+psycopg://postgres:postgres@localhost:5432/intranet' \
  --input-name 'mail_accounts.txt,archive.tar.gz' \
  --delimiter-count 1 \
  --fqdn 'gmail.com'


python3 password_importer.py \
  --db-url 'postgresql+psycopg://postgres:postgres@localhost:5432/intranet' \
  --input-name '/Volumes/personal_folder/workspace/TT/data/LOGZ/arabic-0001.tar.gz' \
  --delimiter-count 1


python3 password_importer.py \
  --db-url 'postgresql+psycopg://postgres:postgres@localhost:5432/intranet' \
  --input-name '/Volumes/nfs/LOGZ/TXT_ALIEN-777.tar.gz' \
  --delimiter-count 2  2>/dev/null