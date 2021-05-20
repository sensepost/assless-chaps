# assless-chaps
Crack MSCHAPv2 challenge/responses quickly using a database of NT hashes

# Introduction

Assless CHAPs is an efficient way to recover the NT hash used in a MSCHAPv2 exchange if you have the challenge and response (e.g. from a WiFi EAP WPE attack).

It requires a hash database, instructions on how to make these are available below.

# Installing

Assless requires `python3`, `sqlite3` and `pycryptodome`. While Python has sqlite3 as part of the standard library, the command line utility is required for database creation.

# Using

Assless requires the challnge, response and database of NThashes. Optionally, it can use the bundled optimised two byte lookup file. The simplest usage looks like this:

`python3 assless-chaps.py <Challenge> <Response> <hashes.db>`

For example:

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

## Two bytes lookup

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

The SQLite database is typically 68% larger that the CSV file used to create it. It can also take some time to create the database depending on the size of files. Prepare your filesystem requirements accordingly.

Here is an example using the rockyou dictionary:

* Base rockyou dictionary 129M
* hashcat generated rockyou.csv 462M time taken 1m 18s
* Resulting SQLite database rockyou.db 764M time taken for import 3m
* BZip2 maximum compression rockyou.db.bz2 339M

You could save space by converting and inserting each hash dynamically and skipping the need for the intermediary CSV file.
