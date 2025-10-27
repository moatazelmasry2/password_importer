#!/bin/bash

time python password_importer.py   --db-url 'postgresql://postgres:postgres@localhost:5438/intranet'  \
 --input-name ~/private-2570-2.txt  --delimiter-count 2 --flush-rows 2000000  --copy-rows 2000000 \
 --toggle-unlogged --skip-relog

