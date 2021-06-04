# assless-chaps
Crack MSCHAPv2 challenge/responses quickly using a database of NT hashes

# Introduction

Assless CHAPs is an efficient way to recover the NT hash used in a MSCHAPv2 exchange if you have the challenge and response (e.g. from a WiFi EAP WPE attack).

It requires a hash database, instructions on how to make these are available below.

# Technique

MSCHAPv2 splits the NThash into three parts, and uses each part as different keys to DES encrypt the same challenge (derived from the peer and authenticator challenges). The NTHash is split into two 7-byte keys, and one 2-byte key. This means the last key is padded with NULLs to make a key of the required length. This can be rapidly brute forced due to the efficiency of DES operation and a keyspace of 65 335. Once we have those two bytes, we can look up all NThashes in our database, that end in those two bytes. This provides a much smaller set of possible hashes to check.

This is a form of rainbow table attack.

# Speed

Here is the comparison for three sample challenge/response's and three different wordlists, a small private one, rockyou, and the Have I Been Pwned list. These were done on my Macbook Pro 2016. Hashcat is using [this](https://github.com/hashcat/hashcat/pull/2607) hash schucking kernel and the two builtin GPUs and a pure rather than optimised kernel (as the latter doesn't exist yet). Hash3 isn't in the lists to simulate worst case performance. I'm not including the time hashcat takes to build the dictionary cache on first run.

*Hash1*

Small hashlist:
```
hashcat 0.50s user 0.27s system 55% cpu 1.405 total (8597.8 kH/s)
assless 0.05s user 0.00s system 294% cpu 0.018 total
```
Rockyou hashlist:
```
hashcat 2.67s user 0.51s system 93% cpu 3.413 total
assless 0.05s user 0.01s system 281% cpu 0.021 total
```
HIBP hashlist:
```
hashcat 59.97s user 11.72s system 136% cpu 52.603 total (5620.6 kH/s)
assless 0.05s user 0.00s system 292% cpu 0.018 total
```

*Hash 2*

Small hashlist:
```
hashcat 0.51s user 0.27s system 55% cpu 1.409 total (8704.7 kH/s)
assless 0.03s user 0.00s system 248% cpu 0.012 total
```
Rockyou hashlist:
```
hashcat 2.20s user 0.46s system 110% cpu 2.409 total (5798.4 kH/s)
assless 0.03s user 0.00s system 231% cpu 0.015 total
```
HIBP hashlist:
```
hashcat 65.37s user 12.74s system 135% cpu 57.712 total (5768.7 kH/s)
assless 0.03s user 0.00s system 249% cpu 0.013 total
```

*Hash 3*

Hash 3 doesn't exist in any of the hashlists to simulate a worst case lookup performance.

Small hashlist:
```
hashcat 0.67s user 0.34s system 66% cpu 1.526 total (7550.1 kH/s)
assless 0.02s user 0.00s system 211% cpu 0.012 total
```
Rockyou hashlist:
```
hashcat 2.71s user 0.52s system 94% cpu 3.415 total (5685.4 kH/s)
assless 0.02s user 0.01s system 181% cpu 0.014 total
```
HIBP hashlist:
```
hashcat 125.19s user 27.62s system 139% cpu 1:49.75 total (5634.9 kH/s)
assless 0.06s user 0.03s system 115% cpu 0.075 total
```

# Installing

The rust version will require SQLite 3.6.8 or newer.

The python version requires `python3`, `sqlite3` and `pycryptodome`.

The database creation utility requires python3 and the sqlite3 CLI.

# Compiling

This only applies to the rust version. You'll need [cargo](https://doc.rust-lang.org/cargo/).

With cargo installed, merely change to the assless-chaps-rs directory, and build it with:
`cargo build --release`

The resulting binary will be in the `target/release/` directory.

# Usage

Assless requires the challenge, response and database of NThashes. Optionally, the python version can use the bundled optimised two byte lookup file. The simplest usage looks like this:

`./assless-chaps <Challenge> <Response> <hashes.db>`

or

`python3 assless-chaps.py <Challenge> <Response> <hashes.db>`

For example:

`./assless-chaps 5d79b2a85966d347 556fdda5f67d2b746ca3315fd8b93adcab5c792790a92e87 rockyou.db`
or
`python3 assless-chaps.py 5d79b2a85966d347 556fdda5f67d2b746ca3315fd8b93adcab5c792790a92e87 rockyou.db`

The output should look like:

```
[-] Two byte lookup file not provided, will brute force instead.
[+] Found in 22636 tries: 586c
[-] Found 222 hashes ending in 586c
[+] Found hash: 8846f7eaee8fb1
[-] Found after 186 hashes.
[+] Found hash: 17ad06bdd830b7
[+] Full hash: 8846f7eaee8fb117ad06bdd830b7586c
```

The final full hash `8846f7eaee8fb117ad06bdd830b7586c` is the NT hash for `password`.

## Two bytes lookup - Python only for now

I spent some time building a list of all 65 535 possible two byte values sorted by most prevalent across a large corpus of passwords. This file is includes as `twobytes`. You can just pass it as the fourth argument to assless.

This typically saves a few rounds of DES, but doesn't make a large speed difference. It might if you're doing many hashes.

`python3 assless-chaps.py 5d79b2a85966d347 556fdda5f67d2b746ca3315fd8b93adcab5c792790a92e87 rockyou.db twobytes`

```
[+] Found in 65533 tries: 586c
[-] Found 222 hashes ending in 586c
[+] Found hash: 8846f7eaee8fb1
[-] Found after 186 hashes.
[+] Found hash: 17ad06bdd830b7
[+] Full hash: 8846f7eaee8fb117ad06bdd830b7586c
```

# Creating your own hash dictionary

The `mksqlitedb.py` file will assist in turning a CSV hash file into the database.

`python3 mksqlitedb.py <database name> <csv file>`

The CSV file requires three columns:

* The last two bytes of the hash (the last four ASCII characters)
* The first 7 bytes (the first 14 ASCII characters)
* The second 7 bytes (the 15-29th ASCII characters

For example, the hash `8846f7eaee8fb117ad06bdd830b7586c` will become:

`586c,8846f7eaee8fb1,17ad06bdd830b7`

An example regexp transformation for this would be:
`echo 8846f7eaee8fb117ad06bdd830b7586c | sed "s/^\(.\{14\}\)\(.\{14\}\)\(.\{4\}\)$/\3,\1,\2/"`

You can either take an existing list of hashes (such as the [Have I Been Pwned lists](https://haveibeenpwned.com/Passwords) or generate your own from hashcat and your favourite wordlist/rules combinations.

## Using Have I Been Pwned

The HIBP password lists are already downloadable as NT Hashes, one just needs to remove the count file and convert them to CSV format so they can be imported into the database.

This can be done using the standard Unix utility `sed`:

`sed "s/^\(.\{14\}\)\(.\{14\}\)\(.\{4\}\):.*/\3,\1,\2/ pwned-passwords-ntlm-ordered-by-hash.txt" > hibp.csv`

After which it can be imported using `mksqlitedb.py`.

## Using hashcat

You'll need to make a small code change to the mode 1000 OpenCL module to make it spit out every hash, rather than only those matching your crack candidate. By default, it will generate the hash in the right CSV format required.

* Change to your hashcat `OpenCL` directory: `cd hashcat/OpenCL`
* Apply the patch: `patch < m01000_a0-pure.cl.patch`
* Prepare a file with an impossible to crack NT hash like `11111111111111111111111111111111`
* Crack as normal, but disable your potfile and redirect the output to a file: `hashcat -m1000 impossible_hash rockyou.txt -r best64.rule --potfile-disable --quiet > rockyou.csv`
* Create your hashes database: `python3 mksqlitedb.py rockyou.db rockyou.csv`

## A note on disk space and file sizes

The SQLite database is typically 61% larger that the CSV file used to create it. It can also take some time to create the database depending on the size of files. Prepare your filesystem requirements accordingly.

Here is an example using the rockyou dictionary:

* Base rockyou dictionary 129M
* hashcat generated rockyou.csv 462M
* Resulting SQLite database rockyou.db 746M
* BZip2 maximum compression rockyou.db.bz2 339M

You could save space by converting and inserting each hash dynamically and skipping the need for the intermediary CSV file.
