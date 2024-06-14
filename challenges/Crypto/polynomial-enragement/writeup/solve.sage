P.<x> = PolynomialRing(ZZ)
p1 = 125*x^40 + 358*x^39 + 577*x^38 + 1299*x^37 + 1316*x^36 + 1164*x^35 + 1029*x^34 + 1095*x^33 + 1309*x^32 + 5569*x^31 + 5170*x^30 + 5290*x^29 + 5240*x^28 + 4826*x^27 + 4570*x^26 + 4644*x^25 + 4658*x^24 + 4663*x^23 + 4593*x^22 + 4821*x^21 + 4592*x^20 + 5335*x^19 + 5044*x^18 + 2946*x^17 + 3597*x^16 + 3400*x^15 + 3750*x^14 + 4394*x^13 + 5228*x^12 + 4881*x^11 + 5021*x^10 + 3911*x^9 + 4993*x^8 + 3154*x^7 + 2524*x^6 + 2995*x^5 + 3136*x^4 + 3237*x^3 + 2735*x^2 + 2896*x + 92
p2 = 1750*x^40 + 1512*x^39 + 1429*x^38 + 1821*x^37 + 1724*x^36 + 1785*x^35 + 1186*x^34 + 1284*x^33 + 1633*x^32 + 1641*x^31 + 1215*x^30 + 1178*x^29 + 1408*x^28 + 1256*x^27 + 355*x^26 + 786*x^25 + 815*x^24 + 726*x^23 + 921*x^22 + 1289*x^21 + 1437*x^20 + 1461*x^19 + 941*x^18 + 1557*x^17 + 1023*x^16 + 606*x^15 + 1104*x^14 + 1037*x^13 + 1073*x^12 + 555*x^11 + 965*x^10 - 100*x^9 - 163*x^8 - 304*x^7 - 325*x^6 - 298*x^5 - 488*x^4 - 107*x^3 - 106*x^2 - 209*x - 351

flag = list(b'SIVUSCG{')
e1 = []
e2 = []
b1 = []
b2 = []
for i in range(6):
    c1 = p1.coefficients()[i]
    c2 = p2.coefficients()[i]
    for j in range(i):
        c1 -= flag[j+1]*b1[i-j-1]
        c2 -= flag[j+1]*b2[i-j-1]
    b1.append(round(c1/flag[0]))
    b2.append(round(c2/flag[0]))
    e1.append(c1-b1[-1]*flag[0])
    e2.append(c2-b2[-1]*flag[0])
flagpoly = gcd(p1-P(e1),p2-P(e2))
print(bytes(flagpoly.coefficients()).decode())