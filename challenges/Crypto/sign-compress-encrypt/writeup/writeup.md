# Writeup
## Analysis

This encryption script is unusual in that it compresses the data before encryption. I remember doing a very similar challenge on [CryptoHack](https://aes.cryptohack.org/ctrime) a while ago so I already knew how to solve this one. 

## Solution 

The data being compressed beforehand may seem innocuous, but it is the most important detail. Notice how the data is appended and prepended by the flag before compression:
```python
signed = secret + data + secret
compressed = zlib.compress(signed.encode())
```
An important aspect of compression algorithms is that they make data smaller, but more importantly they work best with repeated data. So the key here is that compressing `HelloHelloHello` will produce a smaller result than compressing `HelloHellpHello`. So, in theory, if we know the length of the data after compression we can ascertain a little bit about the flag. The good thing about this challenge is that it is using a stream cipher called ChaCha20. The nice thing about stream ciphers is that the length of the ciphertext is the same as the length of the plaintext. So the method that we can use to solve this is as follows:

Input the known bytes of the flag with some dummy character appended (I used `!` because it seemed unlikely that the flag would contain it) and measure the length of the output:
```
SIVUSCG{t3st_fl4g}SIVUSCG{!SIVUSCG{t3st_fl4g} --> compression --> length = 47
```
And then brute force the character until one results in a shorter result:
```
SIVUSCG{t3st_fl4g}SIVUSCG{ASIVUSCG{t3st_fl4g} --> compression --> length = 47
SIVUSCG{t3st_fl4g}SIVUSCG{BSIVUSCG{t3st_fl4g} --> compression --> length = 47
...
SIVUSCG{t3st_fl4g}SIVUSCG{tSIVUSCG{t3st_fl4g} --> compression --> length = 46!
```
Now we add that to our known flag and repeat. There was a small stumble with this. I was able to retrieve `SIVUSCG{C0mpr3S` before the algorithm reported that every letter as producing the same size data. This can happen at times because of the particulars of the algorithm, but in this case it seems pretty obvious that it is trying to spell out compression, so I just manually appended an `S` and continued.

Flag: `SIVUSCG{C0mpr3SS10n_IsnT_s3cUr3}`