import math
import random
import primes

def invmod(a, p, maxiter=1000000):
    """The multiplicitive inverse of a in the integers modulo p:
         a * b == 1 mod p
       Returns b.
       (http://code.activestate.com/recipes/576737-inverse-modulo-p/)"""
    if a == 0:
        raise ValueError('0 has no inverse mod %d' % p)
    r = a
    d = 1
    for i in xrange(min(p, maxiter)):
        d = ((p // r + 1) * d) % p
        r = (d * a) % p
        if r == 1:
            break
    else:
        raise ValueError('%d has no inverse mod %d' % (a, p))
    return d

class PrivateKey(object):

    def __init__(self, p, q, n):
        self.l = (p-1) * (q-1)
        self.m = invmod(self.l, n)

    def __repr__(self):
        return '<PrivateKey: %s %s>' % (self.l, self.m)

class PublicKey(object):

    @classmethod
    def from_n(cls, n):
        return cls(n)

    def __init__(self, n):
        self.n = n
        self.n_sq = n * n
        self.g = n + 1

    def __repr__(self):
        return '<PublicKey: %s>' % self.n

def generate_keypair(bits):
    p = primes.generate_prime(bits / 2)
    q = primes.generate_prime(bits / 2)
    n = p * q
    return PrivateKey(p, q, n), PublicKey(n)

def encrypt(pk, plain):
    while True:
        # r = primes.generate_prime(long(round(math.log(pub.n, 2))))
        r = random.randint(1, pk.n - 1)
        if r > 0 and r < pk.n and pk.n % r != 0:
            break
    x = pow(r, pk.n, pk.n_sq)
    cipher = (pow(pk.g, plain, pk.n_sq) * x) % pk.n_sq
    return cipher

def random_cipher(pk):
    return random.randint(1, pk.n_sq)

def e_add(pk, a, b):
    """Add one encrypted integer to another"""
    return a * b % pk.n_sq

def e_add_const(pk, a, n):
    """Add constant n to an encrypted integer"""
    return a * pow(pk.g, n, pk.n_sq) % pk.n_sq

def e_mul_const(pk, a, n):
    """Multiplies an ancrypted integer by a constant"""
    return pow(a, n, pk.n_sq)

def decrypt(sk, pk, cipher):
    x = pow(cipher, sk.l, pk.n_sq) - 1
    plain = ((x // pk.n) * sk.m) % pk.n
    return plain

def scalarize(pk, cipher):
    return pow(cipher, random.randint(0, pk.n - 1), pk.n_sq)