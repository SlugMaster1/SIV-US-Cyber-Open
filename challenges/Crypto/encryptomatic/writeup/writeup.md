# Writeup
## Analysis

The **main.py** file that we are given is pretty simple. It just takes user input and appends it to the flag before encoding it with AES. 

## Solution 

This is a pretty common attack to see in AES CTFs called an **oracle attack**. It involves that fact that you can control the some data to encode as well as the position of the data you want to decode in the cipher. This allows you to discern the plaintext without the key. The process works like this: <br />
Using this challenge as an example, if we have the flag positioned after user data as such:

**USER DATA** + **SIVUSCG{t3st_fl4g}**

Then we can take advantage of the properties of AES to position the flag like this:<br />

&nbsp;<span style="color:green">Block 1</span> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span style="color:red">Block 2</span><br />
<span style="color:green">AAAAAAAAAAAAAAAS</span> | <span style="color:red">IVUSCG{t3st_fl4g}</span><br />
From there we can get the value of our padding encoded plus one character of the flag. And with that we can brute force it one character at a time to determine the value. Say that the first block encoded to **6ee9c3464ff1f31239c3b34d83a77790** we can go about it like this: <br />
AAAAAAAAAAAAAAA + **A** --> Encode = 26160040bcea6a90293528123897b2b6 != 6ee9c3464ff1f31239c3b34d83a77790<br />
AAAAAAAAAAAAAAA + **B** --> Encode = b47ff07918a16e5bf7fbed8dbd0b123b != 6ee9c3464ff1f31239c3b34d83a77790<br />
AAAAAAAAAAAAAAA + **C** --> Encode = de9b703b46b7634a2e97e2f93dad6601 != 6ee9c3464ff1f31239c3b34d83a77790<br />
...<br />
AAAAAAAAAAAAAAA + **S** --> Encode = 6ee9c3464ff1f31239c3b34d83a77790 == 6ee9c3464ff1f31239c3b34d83a77790<br />

Now we know that the first character is S. Now we move on to the next character<br />
&nbsp;<span style="color:green">Block 1</span> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span style="color:red">Block 2</span><br />
<span style="color:green">AAAAAAAAAAAAAASI</span> | <span style="color:red">VUSCG{t3st_fl4g}</span><br />
And so on until we get the flag. I wrote a script to do this:
```python
from pwn import remote

r = remote('0.cloud.chals.io', 28962)
flag = b''
while True:
    r.recvuntil(b'> ')
    r.sendline(b'A' * (15 - len(flag)))
    r.recvuntil(b': ')
    d = r.recvline().decode()[:-1]
    en = bytes.fromhex(d[:32])
    for i in range(32, 256):
        (r.recvuntil(b'> '))
        r.sendline(b'A' * (15 - len(flag)) + flag + chr(i).encode())
        r.recvuntil(b': ')
        d = r.recvline().decode()[:-1]
        de = bytes.fromhex(d[:32])
        if en == de:
            break
    else:
        print('err')
    flag += chr(i).encode()
    print(flag.decode())
```
This gets me `SIVUSCG{3CB_sl1d` but then it stalls. You may notice that the length of what it gets is exactly 16 bytes, which is the size of one block in this AES implementation. This is a simple fix, I just need to modify the script to look at the second block after 16 bytes:
```python
from pwn import remote

r = remote('0.cloud.chals.io', 28962)
flag = b''
while len(flag) < 16:
    r.recvuntil(b'> ')
    r.sendline(b'A' * (15 - len(flag)))
    r.recvuntil(b': ')
    d = r.recvline().decode()[:-1]
    en = bytes.fromhex(d[:32])
    for i in range(32, 256):
        (r.recvuntil(b'> '))
        r.sendline(b'A' * (15 - len(flag)) + flag + chr(i).encode())
        r.recvuntil(b': ')
        d = r.recvline().decode()[:-1]
        de = bytes.fromhex(d[:32])
        if en == de:
            break
    else:
        print('err')
    flag += chr(i).encode()
    print(flag.decode())

while chr(flag[-1]) != '}':
    r.recvuntil(b'> ')
    r.sendline(b'A' * (31 - len(flag)))
    r.recvuntil(b': ')
    d = r.recvline().decode()[:-1]
    en = bytes.fromhex(d[32:64])
    for i in range(33, 256):
        (r.recvuntil(b'> '))
        r.sendline(b'A' * (31 - len(flag)) + flag + chr(i).encode())
        r.recvuntil(b': ')
        d = r.recvline().decode()[:-1]
        de = bytes.fromhex(d[32:64])
        if en == de:
            break
    else:
        print('err')
    flag += chr(i).encode()
    print(flag.decode())
```
And that is all I need. <br />

Flag: `SIVUSCG{3CB_sl1d3_t0_th3_l3ft}`