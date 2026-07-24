#!/usr/bin/env python3

from pathlib import Path
from sys import argv

from Crypto.Hash import MD4


def nt_hash(password: str) -> str:
    return MD4.new(password.encode("utf-16le")).hexdigest()


input_file = Path(argv[1])

with input_file.open("r", encoding="utf-8", errors="surrogateescape") as clears:
    for line in clears:
        pwd = line.rstrip("\r\n")
        digest = nt_hash(pwd)

        two = digest[-4:]
        first = digest[0:14]
        second = digest[14:28]

        print(f"{two},{first},{second}")
