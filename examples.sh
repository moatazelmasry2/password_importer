#!/bin/bash

time python password_importer.py \
  --db-url 'postgresql://postgres:postgres@localhost:5438/intranet' \
  --input-name /home/moataz/workspace/TT/data/LOGZ/TXTLOG_ALIEN-FREE-0183.tar.gz \
  --delimiter-count 2 --flush-rows 200000000  --copy-rows 200000000 --toggle-unlogged