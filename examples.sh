#!/bin/bash

time python password_importer.py \
  --db-url 'postgresql://postgres:postgres@localhost:5438/intranet' \
  --input-name /volume1/NFS/LOGZ/TXT_ALIEN-777.tar.gz \
  --delimiter-count 2 --flush-rows 2000000  --copy-rows 2000000 --toggle-unlogged