from hashlib import md5
from binascii import unhexlify
from sys import argv

if len(argv) == 1 or argv[1] == "-h" or argv[1] == "--help":
  print(f"usage: {argv[0]} <lm response> <challenge>")
  quit()

lm = argv[1]
chal = argv[2]

if lm[20:48] != "0000000000000000000000000000":
  print("This isn't an NTLMv1 SSP exchange")

combined = chal + lm[0:16]
m = md5()
m.update(unhexlify(combined))
md5hash = m.hexdigest()
srvchallenge = md5hash[0:16]

print(f"The server challenge is: {srvchallenge}")
