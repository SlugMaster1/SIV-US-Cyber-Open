from sys import argv
from hashlib import sha256
from functools import reduce
from randcrack import RandCrack
from Crypto.Util.number import long_to_bytes

def xor(var, key):
    return bytes(a ^^ b for a, b in zip(var, key))

def _xs64(state):
    mask=0xffffffffffffffff
    state = state & mask
    state ^^= (state << 7) & mask
    state ^^= (state >> 9) & mask
    return state & mask


def xs64_gen(state):
    while True:
        state = _xs64(state)
        yield state

def lcg_mod(x0,x1,x2,x3,x4):
    d1 = x2-x1
    d2 = x3-x2
    c1 = x1-x0
    c2 = x2-x1
    d3 = x3-x2
    d4 = x4-x3
    c3 = x2-x1
    c4 = x3-x2
    return gcd(d1*c2-d2*c1,d3*c4-d4*c3)

def lcg_ab(x0,x1,x2,m):
    a = (x2-x1)*pow(x1-x0,-1,m)%m
    b = (x1-x0*a)%m
    return (a,b)

def lcg_gen(a,b,m,state):
    while True:
        state = (a*state + b) % m
        yield state

def intxor(a,b):
    return a ^^ b

def lfsr_gen(regs, taps):
    taps.sort()
    taps=taps[::-1]
    while True:
        output = 0
        for _ in range(64):
            output *= 2
            new_bit = reduce(intxor, [regs[(len(regs)-1)-t] for t in taps])
            del regs[0]
            regs.append(new_bit)
            output += new_bit
        yield output

def lfsr_break(lfsr):
    regs = []
    k = int('{:064b}'.format(lfsr[0])[::-1],2)
    for i in range(64):
        regs.append(k&1)
        k >>= 1
    k = int('{:064b}'.format(lfsr[1])[::-1],2)
    for i in range(64):
        regs.append(k&1)
        k >>= 1
    lsdict = set()
    ogrgs = lfsr
    for i in range(128):
        for j in range(i,128):
            for k in range(j,128):
                lsdict.add((i,j,k))
    count = 2
    done = False
    end = False
    while True:
        k = int('{:064b}'.format(lfsr[count])[::-1],2)
        for i in range(64):
            rems = set()
            b = k&1
            k >>= 1
            r = regs[127]
            for ls in lsdict:
                if r^^regs[ls[0]]^^regs[ls[1]]^^regs[ls[2]] != b: rems.add(ls)
            del regs[0]
            regs.append(b)
            for rem in rems: lsdict.remove(rem)
            if len(lsdict) == 1: done = True
            elif not lsdict: return None
            #print(len(lsdict))
        if end: return (lsdict.pop(),ogrgs)
        if done: end = True
        count += 1

def lsrcs(lfsr,level,rems):
    try: res = lfsr_break(lfsr)
    except IndexError:
        res = lsrcs(lfsr + [rems[level][0]],level+1,rems)
        if res:
            return res
        res = lsrcs(lfsr + [rems[level][1]],level+1,rems)
        return res
    return res


if __name__ == '__main__':
    if len(argv) != 2:
        print("Usage: solve.sage <output file>")
        exit(1)
    fil = open(argv[1])
    ct, rands = fil.read().split('\n')
    fil.close()
    rands = [list(map(int,row)) for row in eval(rands)]
    # XS64
    for r in rands[0]:
        if _xs64(r) in rands[1]:
            first_xs = r
            break
    del rands[0][rands[0].index(first_xs)]
    i = 1
    for r in xs64_gen(first_xs):
        if i == 500:
            fxs = r
            break
        del rands[i][rands[i].index(r)]
        i += 1
    print("Cracked XS64")
    # LCG
    for a in rands[0]:
        for b in rands[1]:
            for c in rands[2]:
                for d in rands[3]:
                    for e in rands[4]:
                        xs = [a,b,c,d,e]
                        m = lcg_mod(*xs)
                        if m.bit_length() == 64: break
                    else: continue
                    break
                else: continue
                break
            else: continue
            break
        else: continue
        break
    a,b = lcg_ab(*xs[:3],m)
    del rands[0][rands[0].index(xs[0])]
    i = 1
    for r in lcg_gen(a,b,m,xs[0]):
        if i == 500:
            flcg = r
            break
        del rands[i][rands[i].index(r)]
        i += 1
    print("Cracked LCG")
    # LFSR
    taps, lfsr = lsrcs([],0,rands)
    taps = [128] + [127-t for t in taps]
    regs = []
    k = int('{:064b}'.format(lfsr[0])[::-1],2)
    for i in range(64):
        regs.append(k&1)
        k >>= 1
    k = int('{:064b}'.format(lfsr[1])[::-1],2)
    for i in range(64):
        regs.append(k&1)
        k >>= 1
    del rands[0][rands[0].index(lfsr[0])]
    del rands[1][rands[1].index(lfsr[1])]
    i = 2
    for r in lfsr_gen(regs,taps):
        if i == 500:
            flsfr = r
            break
        del rands[i][rands[i].index(r)]
        i += 1
    print("Cracked LSFR")
    # MT
    rc = RandCrack()
    for i in range(312):
        top = rands[i][0]>>32
        bot = rands[i][0]&0xffffffff
        rc.submit(top)
        rc.submit(bot)
    for i in range(312,500):
        rc.predict_randrange(0, 4294967295)
        rc.predict_randrange(0, 4294967295)
    top = rc.predict_randrange(0, 4294967295)
    bot = rc.predict_randrange(0, 4294967295)
    fmt = top << 32 | bot
    print("Cracked MT")
    tmp = [fxs,fmt,flcg,flsfr]
    key = b''.join([long_to_bytes(x) for x in tmp])
    print(xor(bytes.fromhex(ct), sha256(key).digest()).decode())