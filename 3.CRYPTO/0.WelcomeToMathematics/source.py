from Crypto.Util.number import getPrime, inverse, bytes_to_long
import random
import math
from sympy import isprime
FLAG = b'MSEC{?????????????????????????????????????????????????????????????????????????????????????????}'

def gen_key():
    q = getPrime(2048)
    upper_bound = isqrt(q // 2)
    lower_bound = isqrt(q // 4)
    f = random.randint(2, upper_bound)
    while True:
        g = random.randint(lower_bound, upper_bound)
        if math.gcd(f, g) == 1:
            break
    h = (inverse(f, q)*g) % q
    return (q, h), (f, g)

def encrypt(q, h, m):
    assert m < isqrt(q // 2)
    r = random.randint(2, isqrt(q // 2))
    e = (r*h + m) % q
    return e

def decrypt(q, h, f, g, e):
    a = (f*e) % q
    m = (a*inverse(f, g)) % g
    return m

def isqrt(n):
    x = n
    y = (x + 1) // 2
    while y < x:
        x = y
        y = (x + n // x) // 2
    return x

public, private = gen_key()
q, h = public
f, g = private

m = bytes_to_long(FLAG)
e = encrypt(q, h, m)

print(f'Pk: {(q,h)}')
print(f'Enc: {e}')

