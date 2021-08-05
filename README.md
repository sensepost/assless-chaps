# assless-chaps
Crack MSCHAPv2/NTLMv1 challenge/responses quickly using a database of NT hashes

# Introduction

Assless CHAPs is an efficient way to recover the NT hash used in a MSCHAPv2/NTLMv1 exchange if you have the challenge and response (e.g. from a WiFi EAP WPE attack).

It requires a database of NT hashes, instructions on how to make these  from existing lists or using hashcat with wordlists and rules are available below. I've included a sample database from [SecLists](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt). You'll need to bunzip it.

# Technique

An MSCHAPv2 exchange does not require the clear-text password to be "cracked", rather we merely need the NThash used.

MSCHAPv2 splits the NThash into three parts, and uses each part as different keys to DES encrypt the same challenge (derived from the peer and authenticator challenges). The NTHash is split into two 7-byte keys, and one 2-byte key. This means the last key is padded with NULLs to make a key of the required length. This can be rapidly brute forced due to the efficiency of DES operation and a keyspace of 65 535. Once we have those two bytes, we can look up all NThashes in our database, that end in those two bytes. This provides a much smaller set of possible hashes to check.

This is a form of space vs time tradeoff, similar to a rainbow table. It's also a form of [hash shucking](https://www.scottbrady91.com/Authentication/Beware-of-Password-Shucking).

# Presentation

This was first presented at [Defcon 29's RF Hacking Village](https://www.youtube.com/watch?v=lm7Cuktpnb4). The slides are included in this repository.

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

The HIBP password lists are already downloadable as NT Hashes, one just needs to remove the count form the file and convert them to CSV format to be imported into the database.

This can be done using the standard Unix utility `sed` like so:

`sed "s/^\(.\{14\}\)\(.\{14\}\)\(.\{4\}\):.*/\3,\1,\2/ pwned-passwords-ntlm-ordered-by-hash.txt" > hibp.csv`

After which it can be imported using `mksqlitedb.py hibp.db hibp.xsc`.

## Using hashcat to create a hash csv file from wordlists and rules

You'll need to make a small code change to the mode 1000 OpenCL module to make it spit out every hash, rather than only those matching your crack candidate. By default, it will generate the hash in the right CSV format required.

* Change to your hashcat `OpenCL` directory: `cd hashcat/OpenCL`
* Apply the patch: `patch < m01000_a0-pure.cl.patch`
* Prepare a file with an impossible to crack NT hash like `echo 11111111111111111111111111111111 > impossible_hash`
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

# NTLMv1 SSP

NTLMv1 will work in exactly the same way, unless it's using SSP. You'll know if SSP is in use if you get an LM response that ends in a bunch of zeros. You can use the included `ntlm-ssp.py` to produce the server challenge that assless will need.

Run it like this:
`python3 ntlm-ssp.py <lm response> <challenge>`

For example if we use the example NTLMv1-SSP challenge response from the [hashcat example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes):
`u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c`

You would pass in the LM and challenge like so:

`python3 ntlm-ssp.py 338d08f8e26de93300000000000000000000000000000000 cb8086049ec4736c`

And get the following response:

`The server challenge is: 724edf24aea0d68b`

Which can then be cracked with assless-chaps like normal:

`./assless-chaps 724edf24aea0d68b 9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41 hashes.db`
