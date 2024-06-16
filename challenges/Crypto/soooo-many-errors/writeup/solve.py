import requests
from Crypto.Util.number import long_to_bytes

def solve(polys):
    r = requests.get('https://uscybercombine-s4-crypto-soooo-many-errors.chals.io/get_flag')
    data = eval(r.text)
    flag_bin = ''
    for b in data:
        for e in b:
            p = e[0]
            if p not in polys: 
                flag_bin += '0'
                break
        else: flag_bin += '1'
    return long_to_bytes(int(flag_bin,2)).decode()

def get_polys():
    polys = []
    while len(polys) < 1225:
        r = requests.post('https://uscybercombine-s4-crypto-soooo-many-errors.chals.io/encrypt?m=%3f')
        data = eval(r.text)
        for b in data:
            for e in b:
                p = e[0]
                if p not in polys: polys.append(p)
        print(f"Enumerating Polynomials : {len(polys)}/1225",end='\r')
    return polys

if __name__ == '__main__':
    polys = get_polys()
    print("Solving Flag:")
    flag = solve(polys)
    print(flag)