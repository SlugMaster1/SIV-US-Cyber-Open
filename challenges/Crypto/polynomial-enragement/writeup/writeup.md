# Writeup
## Analysis

This is a bit of an unusual one. It relies on recovering an original polynomial from two instances of the polynomial with two errors thrown in. The equations are set up as follows:

$p_1 = fg + n_1$<br />
$p_2 = fh + n_2$

Where $f$ is the flag polynomial, $h$ and $g$ are noise polynomials of degree 10, $n_1$ and $n_2$ are noise polynomials of degree 5, and $p_1$ and $p_2$ are the results of the operation as well as the only thing we are given.

## Solution 

The if not for the $n$ polynomials this problem could be solved rather easily by performing a polynomial GCD. This is like a normal GCD except with polynomials. If I were given $fg$ and $fh$ I could find their shared factor using the **gcd** function in Sagemath. The problem is that the two small noise polynomials disallow this, so the goal is to find a way to get rid of them.

I am not quite sure what the intended solution to this problem was, I know that it isn't the way I solved it, but I think that alternative ways of solving problems can give a lot of insight. My method relies on the fact that I already know the first 8 characters of the flag. This because the flag must start with `SIVUSCG{` which means that I also know the first 8 terms in the flag polynomial. Using this knowledge I can start calculating from the smallest terms first. *Note I will be using the notation* $p_1(1)$ *as a way of describing getting the* $x^1$ *term from the polynomial, this is not* $p_1$ *evaluated at* $x=1$.

So we know that $p_1(0) = f(0)g(0) + n_1(0)$ because that is the only way to make an $x^0$ term in a polynomial. We know $p_1(0)$ because it is in the polynomial we are given, and we know $f(0)$ because it is just the ascii value of the first character of the flag (S) which is 83. If we plug the values we know into the equation we get:

$92 = 83g(0) + n_1(0)$

Which leaves me with two unknowns and only one equation. This is not possible to solve normally, but I am going to employ a forbidden technique where I completely ignore the error term $n_1$. Why can I do this? Well if we look at the way that the noise polynomials are generated:
```python
noise1 = P.random_element(degree=5)
noise2 = P.random_element(degree=5)
```
We can see that they are generated randomly. The specifics of this randomness are not very well documented, but I think that it is somewhat Gaussian with a mean at zero. So I generated a bunch of these just to test it out, and what I found was that the terms of these polynomials are almost always less than 10. The reason this is important is because if I solve the above equation like so:

$92 - n_1(0) = 83g(0)$<br />
$\frac{92 - n_1(0)}{83} = g(0)$

And so if $n_1(0)$ is less than $\frac{83}{2}$ (as it almost certainly is) then we can consider it a safe assumption that $g(0) = \lfloor \frac{p_1(0)}{f(0)} \rceil$, or more specifically $g(0) = \lfloor \frac{92}{83} \rceil = 1$. Using this knowledge we can determine that

$n_1(0) = p_1(0) - f(0)g(0)$ <br />
$n_1(0) = 92 - 83*1$  <br />
$n_1(0) = 9$

Now on to the next step. We know that:

$p_1(1) = f(1)g(0) + f(0)g(1) + n_1(1)$ <br />
$2896 = 73*1 + 83g(1) + n_1(1)$ <br />
$2823 = 83g(1) + n_1(1)$

Which is analogous to the previous equation:

$92 = 83g(0) + n_1(0)$

So we can make the same assumptions that we did last time: 

$g(1) = \lfloor \frac{2823}{83} \rceil$ <br />
$g(1) = 34$<br />
$n_1(1) = p_1(1) - f(1)g(0) - f(0)g(1)$<br />
$`n_1(1) = 2896 - 73*1 - 83*34`$<br />
$n_1(1) = 1$

Repeat these step until you recover the entire $n_1$ polynomial, and repeat for $n_2$. This will produce the following:

$n_1 = 6x^5 + x^4 - x^3 + x^2 + x + 9$ <br />
$n_2 = -x^5 + 2x^4 + x^3 - x^2 - 19$

Now, using the original equations we can solve for $f$ like so:

$p_1 = fg + n_1$<br />
$p_2 = fh + n_2$<br />
$p_1 - n_1 = fg$<br />
$p_2 - n_2 = fh$<br />
$f = \gcd(fg,fh) = \gcd(p_1 - n_1,p_2 - n_2)$

The coefficients of the $f$ polynomial represent each byte of the flag.

Flag: `SIVUSCG{Poly_GCD-is_kinda_cool}`
