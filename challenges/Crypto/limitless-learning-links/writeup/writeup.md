# Writeup
## Analysis

This problem is a simple ECC implementation except for the fact that the *a* and *b* values are hidden (these are usually public) and that finding them is the goal.

## Solution 

This one is a bit unusual in that the way that you have to solve it. The only thing that we are given is *G*, and *p*. This, to the best of my knowledge is not enough to solve for a and b. The generator (G) is a point on the curve, so setting setting up our values into the typical elliptic curve equation gives:

$G_y^2 = G_x^3 + aG_x + b \mod p$

At this point we are trying to solve a singe equation for two unknowns. This is impossible. But there is an important key to the solution:
```python
a = random.randint(2024, 2^32)
b = random.randint(2024, a)
```
Both a and b are less than $2^{32}$ which is $4294967296$. This is possible to brute force in a rather short time, but only if the calculations per loop iteration are kept to a minimum. There are two options to brute force: a or b. It may be tempting to choose b because it is less than an and therefore will require fewer loop iterations to find, but I think that a is actually better. The reason I came to this conclusion is thus:

If we solve the elliptic curve equation for a and b we get

$a = (G_y^2 - G_x^3 - b)G_x^{-1} \mod p$ <br />
$b = G_y^2 - G_x^3 - aG_x \mod p$

Since brute forcing b, that is, solving for a, requires a modular inverse calculation every time, the extra iterations of a would be outweighed by the time saved per iteration. But at the end of the day, it is possible to do both ways. So I wrote the following script to brute force it:
```python
from tqdm import tqdm
# y^2 = x^3 + a*x + b
x,y = [47955680961873936976498017250517754087050557384283400732143179213184250507270, 29032426704946836093200696288262246197660493082656478242711220086643009788423]
p = 61858486249019152861579012404896413787226732625798419511000717349447821289579
res = (y**2-x**3)%p
a = x*2024%p
for c in tqdm(range(2024,2**32)):
    if (res-a)%p < c:
        print(f"b: {res-a}")
        print(f"a: {(res - b)*pow(x,-1,p)%p}")
        exit()
    a = (a+x)%p
```
This script only took 30 minutes to run on my computer, but it could have been faster if I implemented multiprocessing. So, not that bad. The result is:
```python
b = 1099709974
a = 2771904210
```
From these I can decrypt the ciphertext and get the flag:

Flag: `SIVUSCG{ICANMAKETHISFLAGASLONGASIWANT...YEAHHHHHH}`
