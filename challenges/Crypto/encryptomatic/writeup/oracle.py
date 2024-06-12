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
