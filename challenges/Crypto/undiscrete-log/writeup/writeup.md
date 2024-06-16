
# Writeup
## Analysis

This is an implementation of a discrete logarithm problem. The discrete logarithm problem is as follows:

$x = g^a \mod p$

Where all of $x$, $g$, and $p$ are known and you need to determine $a$. This is considered a *hard* problem, that is, it can't be solved consistently in an efficient manner.
This is a challenge where the user can chose the modulus with a few caveats: the modulus must be a prime of exactly 512 bits and the prime minus one must have a factor that is larger than $2^{400}$.

## Solution 

This one is quite the thing indeed. It is rather tricky in the way that it presents itself. Obviously having the user control the modulus in the discrete logarithm problem is a bad idea, otherwise this problem would be impossible. That much is easy to figure out. The real question is *why* is this a bad thing? For an explanation we can look at a good implementation of this. A very common implementation of this type of crypto-system is in Diffie–Hellman key exchange. The specifics of that are outside the scope of this writeup, but basically the modulus in that algorithm is chosen so that it is, what is referred to as a *safe* prime. Safe primes have the following form:

$p = 2q + 1$

where $p$ is the safe prime and $q$ is also a prime. They are chosen like this to avoid vulnerabilities posed by the **Pohlig–Hellman algorithm**. More details can be found [here](https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm), but basically it allows us to find congruences in the exponent for each of the factors of the order of the prime (which is $p-1$). This can be solved in $O(\sqrt{n})$ for each $n$ that is a factor of $p-1$. So safe primes are chosen so that the only information that an attacker can get using this algorithm is the congruence of the exponent mod 2 (whether it is even or odd, which is pretty much nothing). The reason why an attacker cannot get the congruence mod $q$ (the other factor of $p-1$ in a safe prime) is because it is too large. If $p$ is 512 bits then $q$ will be 511 bits and solving it will take $\sqrt{2^{511}}$ or $2^{255.5}$ iterations. This is obviously infeasible. 

So where does this put us with our prime? Our prime must also have a factor greater than $2^{400}$ so solving it would take $2^{200}$ iterations. This is also infeasible and why any discrete log calculator would fail on this task. So how can it be done? Well since it only specifies that a factor must be larger than $2^{400}$
and the prime is 512 bits, we have about 112 bits to work with. If we fill this with smaller primes we can solve the for congruences for about 112 bits of data. This, by itself, is not enough. But there is an important part of this script to make note of:
```python
ciph = pow(g,flag,p)
```
The exponent is *always* the same no matter how many times you connect to the server.  So if we can get 112 bits each time, this will only take a maximum of 5 connections to get all 512 bits of the exponent. Though that is easier said than done really. First I found a good prime that is greater than $2^{400}$:
```python
q = 2^400
while not is_prime(q):
    q += 1
```
This gives the number $2582249878086908589655919172003011874329705792829223512830659356540647622016841194629645353280137831435903171972747493557$ which is $2^{400} + 181$ and is the smallest 400 bit prime. This number $q$ will serve as the basis for the rest of the algorithm. Now I can build my prime. The first thing is to get a bunch of small prime factors.
```python
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
```
This generates unique small primes within a specified range until their product multiplied by $q$ is greater than 500 bits. This ensures that I have at least 12 bits of leeway so that I can ensure that all of these numbers multiplied together plus one is a prime. The next stage:
```python
pw = 512-int(re).bit_length()
for i in range(2**pw,2**(pw+1)):
  if is_prime(re*i+1):
    break
```
This part brute forces the last few bits up to 512 so that the product plus one is a prime. This is a little messy, but it gets the job done. 

I also defined a function that can find congruences for all of the small factors that I just made using the Pohlig–Hellman algorithm:
```python
def subgroup(g,a,pi,p):
    gi = pow(g,(p-1)//pi,p)
    hi = pow(a,(p-1)//pi,p)
    c = 1
    while c < p:
        if pow(gi,c,p) == hi:
            return c
        c += 1
    return -1
```

From there I just sent these primes to the server until I more than 512 bits of data to work with. What I am left with is a bunch of small congruences, e.g., 

$a \mod 2 = 1$

$a \mod 7 = 5$

$a \mod 181 = 102$

etc.

where $a$ is the flag. How can we turn these into an actual number? Why, **Chinese remainder theorem** of course! CRT is actually quite simple, but I don't want to explain it here. Basically this will get me the flag. This explanation was a bit superficial, the real process it a bit more complex than I made it out to be so I recommend seeing my [script](pohlig_parital.sage) for more detail.

Flag: `SIVUSCG{welcome_to_the_intro_to_CRT!}`