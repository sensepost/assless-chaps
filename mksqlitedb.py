#!/usr/bin/env python3
import sqlite3
from sys import argv
import subprocess

# NB create the index after import, or you'll have a slow time

print(f'[-] Creating database {argv[1]} from CSV file {argv[2]}')

with sqlite3.connect(argv[1]) as db:
  cur = db.cursor()
  cur.execute('CREATE TABLE IF NOT EXISTS hashes \
    (twobytes TEXT NOT NULL COLLATE NOCASE,\
    chunk1 TEXT NOT NULL COLLATE NOCASE,\
    chunk2 TEXT NOT NULL COLLATE NOCASE);\
  ')
  #cur.execute('CREATE INDEX IF NOT EXISTS tb ON hashes (twobytes);')

print('[-] Starting import, this can take a long time if the CSV is large')

subprocess.call(["sqlite3", argv[1], 
  ".mode csv", 
  f'.import {argv[2]} hashes'])

print('[-] Creating index ...')

with sqlite3.connect(argv[1]) as db:
  cur = db.cursor()
  cur.execute('CREATE INDEX IF NOT EXISTS tb ON hashes (twobytes);')

print('[+] All done')
