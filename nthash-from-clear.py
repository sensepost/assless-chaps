#!/usr/bin/env python3


import hashlib
import binascii
from sys import argv

with open(argv[1],'r') as clears:
  for pwd in clears.read().split('\n'):
    byts = binascii.hexlify(hashlib.new("md4",pwd.encode("utf-16le")).digest())
    two = byts[-4:].decode("utf-8")
    frst = byts[0:14].decode("utf-8")
    scnd = byts[14:28].decode("utf-8")
    print(f'{two},{frst},{scnd}') 
