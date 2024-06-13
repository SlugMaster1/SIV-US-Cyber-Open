from tqdm import tqdm
# y^2 = x^3 + a*x + b
x,y = [47955680961873936976498017250517754087050557384283400732143179213184250507270, 29032426704946836093200696288262246197660493082656478242711220086643009788423]
p = 61858486249019152861579012404896413787226732625798419511000717349447821289579
res = (y**2-x**3)%p
a = x*2024%p
for c in tqdm(range(2024,2**32)):
    if (res-a)%p < c:
        b = res-a
        a = (res - b)*pow(x,-1,p)%p
        print(f"a: {a}")
        print(f"b: {b}")
        break
    a = (a+x)%p

ct = b"\x18\xf4$\xf1\xe5WA[\xf2P\xfa\xfcEE\t\xed\xe2m\xaf\xf6$K\xf6\xae\xd9K\x81\x95D\xe3`W\x8f\x04\xfbI\xe5\x06\xd3\xe9\x1a\x1e\x16\xfbZ\xe6\xd2\x06\xd6o|#ns'm\x12\x96\x1d\x8d\xd1\xbd<\xd9\x1dy\x0b\xa95i\xfds\x86|\xad\x92\x88\xa7\x07="
from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES
import hashlib
secret = (str(a) + str(b)).encode()
key = hashlib.sha256(secret).digest()[:16]
iv = ct[:16]
ct = ct[16:]
cipher = AES.new(key, AES.MODE_CBC, iv=iv)
print(unpad(cipher.decrypt(ct),16).decode())