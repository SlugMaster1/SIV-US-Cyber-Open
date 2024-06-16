# Writeup
## Analysis

This is quite a problem. It involves four different PRNGs:
 - Linear-feedback shift register (LFSR)
 - Linear congruential generator (LCG)
 - Xor Shift 64 (XS64)
 - Mersenne twister (MT)

Each are used to generate 501 values. The first 500 values are shuffled amongst the others and printed out. The goal is to find the 501st by reversing all four of the PRNGs.

## Solution 

The first problem is that each of the rows of the output are shuffled so it is impossible to determine which value came from which PRNG. So we will need to determine that first. We need to start with the most simple PRNGs to reduce the complexity of solving the more difficult ones. I first ordered them by complexity and figured how many values I would need to break them:

 1. XS64 (2 values)
 2. LCG (5 values)
 3. LFSR (5*ish* values)
 4. MT (312 values)

So I will solve them in this order.

### XS64

The XS64 is a very simple PRNG. It doesn't have any seed values or anything, the only thing needed to crack it is the initial state, which is one of the for values in the first row of the outputted data. I wrote a simple python script to do this:
```python
for r in rands[0]:
    if _xs64(r) in rands[1]:
        first_xs = r
        break
```
This initial state will be used to determine the rest of the states and eliminate them. 

### LCG

The LCG is slightly more complicated. Breaking an LCG with a known modulus can be done with three sequential values, but when you are not given the modulus, as in this case, it takes five. We can use the following algorithm to do so:

I am going to call the five sequential values $x_0$, $x_1$, $x_2$, $x_3$, and $x_4$ such that they are arranged in the LCG as such:

$x_1 = ax_0 + b \mod m$ <br />
$x_2 = ax_1 + b \mod m$ <br />
$x_3 = ax_2 + b \mod m$ <br />
$x_4 = ax_3 + b \mod m$ <br />

And we need to solve for $a$, $b$, and $m$. We can eliminate $b$:

$x_2 - x_1 = (ax_1 + b) - (ax_0 + b) = a(x_1 - x_0) \mod m$<br />
Repeat for all:<br />
$x_2 - x_1 = a(x_1 - x_0) \mod m$<br />
$x_3 - x_2 = a(x_2 - x_1) \mod m$<br />
$x_4 - x_3 = a(x_3 - x_2) \mod m$<br />

Now we can establish the following congruence:

$(x_3 - x_2)(x_1 - x_0) = a(x_2 - x_1)(x_1 - x_0) \mod m$<br />
$(x_2 - x_1)(x_2 - x_1) = a(x_2 - x_1)(x_1 - x_0) \mod m$<br />
Therefore:<br />
$(x_3 - x_2)(x_1 - x_0) = (x_2 - x_1)(x_2 - x_1) \mod m$<br />
$(x_3 - x_2)(x_1 - x_0) - (x_2 - x_1)(x_2 - x_1) = 0 \mod m$

Which, by virtue of how the modulus works, means that $m$ must be a factor of $(x_3 - x_2)(x_1 - x_0) - (x_2 - x_1)(x_2 - x_1)$, which we can calculate. Now to find which factor it is I can repeat the last section with the 2nd and 3rd equations:

$(x_4 - x_3)(x_2 - x_1) = a(x_3 - x_2)(x_2 - x_1) \mod m$<br />
$(x_3 - x_2)(x_3 - x_2) = a(x_3 - x_2)(x_2 - x_1) \mod m$<br />
Therefore:<br />
$(x_4 - x_3)(x_2 - x_1) = (x_3 - x_2)(x_3 - x_2) \mod m$<br />
$(x_4 - x_3)(x_2 - x_1) - (x_3 - x_2)(x_3 - x_2) = 0 \mod m$

Meaning that $m$ is also a factor of $(x_4 - x_3)(x_2 - x_1) - (x_3 - x_2)(x_3 - x_2)$. So to recover $m$ we can compute the shared factors by

$m = \gcd((x_3 - x_2)(x_1 - x_0) - (x_2 - x_1)(x_2 - x_1), (x_4 - x_3)(x_2 - x_1) - (x_3 - x_2)(x_3 - x_2))$

**NOTE** it is possible that this will produce $m$ times some small factor, such as $2m$ if, by chance those two also share some other factor as well as $m$, so you may need to factor some small things out. In this problem that was not an issue, but it can happen.

Now that we know $m$ we can determine $a$ and $b$:

$x_1 = ax_0 + b \mod m$<br />
$x_2 = ax_1 + b \mod m$<br />
$x_2 - x_1 = (ax_1 + b) - (ax_0 + b) \mod m$<br />
$x_2 - x_1 = ax_1 - ax_0 \mod m$<br />
$x_2 - x_1 = a(x_1 - x_0) \mod m$ <br />
$a = (x_2 - x_1)(x_1 - x_0)^{-1} \mod m$<br />

Now that we know $a$ we can solve for $b$:

$b = x_1 - x_0a \mod m$

That is all well and good, but how do we determine the values for our five $x$ variables? Brute force of course! Because we need five values and there are only 3 choices per row, we only really have to compute $3^5$ or $243$ iterations, which is nothing, especially for a rather simple operation like this one. We can determine which choice is correct by the value returned from the modulus calculation. Numbers that are not a valid LCG will return a very small number (usually less than 100), but as we know 
```python
m = getPrime(64)
```
$m$ is a 64 bit number. Once we know that we can calculate the rest.

### LFSR

LSFR is a bit tricky to crack. It has two state values called **taps** and **regs**. The taps are a static group of three integers between 0 and 128 along with 128. The regs are a list of 128 bits that get rotated every time. The taps decide which regs to use and the regs control which bit is outputted. One thing about the regs that I noticed is that they rotate every time to reflect the bit that was just produced. So since the regs are 128 bits and each number it produces is 64 bits, once it has produced 2 numbers we can ascertain the state of the regs.
```python
regs = []
k = int('{:064b}'.format(lfsr[0])[::-1],2)
for i in range(64):
    regs.append(k&1)
    k >>= 1
k = int('{:064b}'.format(lfsr[1])[::-1],2)
for i in range(64):
    regs.append(k&1)
    k >>= 1
```
 Now the main problem comes from finding the taps. Since there are only three that we do not know and they are unordered there are only 341376 possible taps combinations. So the way I did it is that the script generates every possible tap combination, checks to see if it works, and discards it if it doesn't. It repeats this process until there is only one possibility left:
 ```python
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
```
I also added a bit of assureance so that once there is only one correct option left it must generate at least another 64 correct bits to ensure that there are no false posatives. This was sucessfully able to reverse the LFSR, but I needed to try every possible sequence for this, because, again, I didn't actually know which values were generated by the LFSR. I wrote a little recursive function to do this for me:
```python
def lsrcs(lfsr,level,rems):
    try: res = lfsr_break(lfsr)
    except IndexError:
        res = lsrcs(lfsr + [rems[level][0]],level+1,rems)
        if res:
            return res
        res = lsrcs(lfsr + [rems[level][1]],level+1,rems)
        return res
    return res
```
This takes some time to run but is successfully able to reverse it.

### MT

The MT is *WAY* more complicated than anything else so far. I am not even going to pretend to understand how it works. Luckily, I don't have to. There is a great tool called [Randcrack](https://github.com/tna0y/Python-random-module-cracker) that can do it all for me. Randcrack requires 624 sequential 32-bit numbers to reverse it. Since the numbers generated in this case are 64-bit we only need 312. As you can see in the challenge code:
```python
top = random.getrandbits(32)
bot = random.getrandbits(32)
yield top << 32 | bot
```
The numbers are generated top then bottom bits, so they must be fed in in that order. So I fed them in like so:
```python
rc = RandCrack()
for i in range(312):
    top = rands[i][0]>>32
    bot = rands[i][0]&0xffffffff
    rc.submit(top)
    rc.submit(bot)
```
This will allow randcrack to predict the next values.

### Bringing it all together

Now that we have cracked all four of the PRNGs we can generate the 501st term in the sequence and decrypt the ciphertext:
```python
tmp = [fxs,fmt,flcg,flsfr]
key = b''.join([long_to_bytes(x) for x in tmp])
print(xor(bytes.fromhex(ct), sha256(key).digest()).decode())
```
Flag: `SIVUSCG{ah_pr3d1ct4ble_3ntr0py!}`