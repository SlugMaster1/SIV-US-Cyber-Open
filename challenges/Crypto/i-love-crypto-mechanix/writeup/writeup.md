# Writeup
## Analysis

This program uses an LCG to generate some random padding before encoding the same message three times with RSA using an exponent of **SPOILER ALERT:** Bad idea.

## Solution 
### LCG

First thing is to deal with that pesky LCG. Since we are given the prime modulus this will be an easy decrypt and we only need 3 sequential outputs to do that. And, what do you know, the hints array that we are given just so happen to be 3 sequential outputs! Lets call these outputs *$x_0$*, *$x_1$*, and *$x_2$*. And given the equation for an LCG:

$y = ax + b \mod m$<br />

We can arrange our values as such:<br /><br />
$x_1 = ax_0 + b \mod m$<br />
$x_2 = ax_1 + b \mod m$<br />

And we need to solve for a and b. The first step is to eliminate b from the equation:

$x_2 - x_1 = (ax_1 + b) - (ax_0 + b) \mod m$<br />
$x_2 - x_1 = ax_1 - ax_0 \mod m$<br />

Now solve for a

$x_2 - x_1 = a(x_1 - x_0) \mod m$ <br />
$a = (x_2 - x_1)(x_1 - x_0)^{-1} \mod m$<br />

Now that we know a we can solve for b<br />

$b = x_1 - ax_0 \mod m$

Now that we know the value of a and b we can determine the values in the output array. There is a small problem, as you can see in the code below
```python
outputs = []
for i in range(6):
	outputs.append(lcg.next())

hints = []
for i in range(3):
	hints.append(lcg.next())
```
The hints are generated *after* the outputs so I can't just run it through the LCG to get the values. So to solve backwards I will have to use a reverse LCG. The way you do this is, take the normal LCG equation:

$y = ax + b \mod m$

and solve for x:

$x =  (y - b)a^{-1} \mod m$

Now we can do the LCG backwards to solve for the outputs.

### RSA

Now that we have the value of the outputs we can *finally* solve for the flag from the RSA encryption seen here:
```python
c1 = pow(outputs[0] * flag + outputs[1], e, N)
c2 = pow(outputs[2] * flag + outputs[3], e, N)
c3 = pow(outputs[4] * flag + outputs[5], e, N)
```
The first thing that we can do is write these as equations:

$c_1 = (o_0f + o_1)^e \mod N$<br />
$c_2 = (o_2f + o_3)^e \mod N$<br />
$c_2 = (o_4f + o_5)^e \mod N$<br />

Where $f$ is the flag and the $o$ are the outputs.
These equations can be evaluated using $e=3$:

$c_1 = o_0^3f^3 + 3o_0^2o_1f^2 + 3o_0o_1^2f + o_1^3 \mod N$<br />
$c_2 = o_2^3f^3 + 3o_2^2o_3f^2 + 3o_0o_3^2f + o_3^3 \mod N$<br />
$c_3 = o_4^3f^3 + 3o_4^2o_5f^2 + 3o_0o_5^2f + o_5^3 \mod N$<br />

There are a few ways to solve this system of equations, the way I used is to put the coefficients into a matrix and use Gaussian elimination. Setting up the matrix like so:

$`\begin{bmatrix} o_0^3 & 3o_0^2o_1 & 3o_0o_1^2 & o_1^3 & c_1 \\ o_2^3 & 3o_2^2o_3 & 3o_2o_3^2 & o_3^3 & c_2 \\ o_4^3 & 3o_4^2o_5 & 3o_4o_5^2 & o_5^3 & c_3\end{bmatrix}`$ <br />

Don't forget that this matrix is mod N. Doing this will solve the equation so that there is only three terms left in the last row of the matrix. We will call those terms A, B, and C:

$`\begin{bmatrix} 0 & 0 & A & B & C\end{bmatrix}`$ <br />

Those terms are the $f$ coefficient, the constant, and the solution to the equation respectively. Plugging them back into equation form produces:

$Af + B = C \mod n$ <br />

This can easily be solved for $f$ as so:

$f = (C-B)*A^{-1} \mod n$ <br />

Converting this from a long gives <br />
Flag: `SIVUSCG{Y0u_mus1_b3_M4ster_0f_th3_LCGs!}`