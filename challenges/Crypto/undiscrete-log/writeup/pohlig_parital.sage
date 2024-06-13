import socket
from time import sleep
from Crypto.Util.number import long_to_bytes

def subgroup(g,a,pi,p):
    gi = pow(g,(p-1)//pi,p)
    hi = pow(a,(p-1)//pi,p)
    c = 1
    while c < p:
        if pow(gi,c,p) == hi:
            return c
        c += 1
    return -1

pn = 0
q = int(2582249878086908589655919172003011874329705792829223512830659356540647622016841194629645353280137831435903171972747493557)
mods = []
while int(prod([i[0] for i in mods])).bit_length() < 512:
  pm = pn + 1
  while True:
    n = 1
    for i in primes(pn,pm):
      n *= i
    if int(n*q).bit_length() > 500:
       n = 1
       for i in primes(pn,pm-1):
         n *= i
       pn = pm-1
       re = n*q
       break
    pm += 1
  pw = 512-int(re).bit_length()
  for i in range(2**pw,2**(pw+1)):
    if is_prime(re*i+1):
      if int(re*i+1).bit_length() > 512:
        print("toobig")
        exit()
      elif int(re*i+1).bit_length() < 512:
        print(int(re*i+1).bit_length())
        for i in range(2**(pw+1),2**(pw+2)):
          if is_prime(re*i+1): break
        if int(re*i+1).bit_length() != 512:
          print("!!!!")
          exit()
        break
      else: break
  p = (re*i+1)
  if not is_prime(p) or int(p).bit_length() != 512:
    print("eorr")
    exit()
  facts = []
  for l in [[i[0]]*i[1] for i in (p-1).factor()]:
    facts += l
  stfacts = str(facts)[1:-1].replace(',','')
  r = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  r.connect(('0.cloud.chals.io',int(18975)))
  while b':' not in r.recv(1024): pass
  r.sendall(str(p).encode() + b'\n')
  while b':' not in r.recv(1024): pass
  r.sendall(str(stfacts).encode() + b'\n')
  sleep(1)
  data = r.recv(1024).split(b'\n')
  g = int(data[0].decode().split(' ')[2])
  ciph = int(data[1].decode().split(' ')[2])
  for fac in facts[:-1]:
    res = (fac, subgroup(g,ciph,fac,p))
    if res not in mods: mods.append(res)
  print(int(prod([i[0] for i in mods])).bit_length())
mds = []
res = []
for i in mods:
  mds.append(i[0])
  res.append(i[1])
res = crt(res,mds)
print(long_to_bytes(res).decode())

  