#!/usr/bin/env python
import math
import random
import paillier
import primes
from GTProtocol import GTProtocol



'''
    Blake-Kolesnikov's Protocol 2004
    based on Paillier scheme
'''


class BT04(GTProtocol):
    def generate_keypair(self):
        cs = self.cipher_suite
        return paillier.generate_keypair(cs.modulus_length)

    def encode_x(self, pk, x):
        N = len(x)
        C = [0] * N 
        for i in range(N):
            C[i] = paillier.encrypt(pk, x[i])
        return C

    def encode_y(self, pk, C, y):
        N = len(y)
        T = [0] * N
        R_prev = 0
        for i in range(N):
            D = paillier.e_add(pk, paillier.encrypt(pk, -y[i]), C[i])
            F = paillier.e_add(pk, paillier.e_add(pk, C[i], paillier.encrypt(pk, y[i])), paillier.e_mul_const(pk, C[i], -2*y[i]))
            if i == 0:
                R = F
                R_prev = R
            else:
                R = paillier.e_add(pk, paillier.e_mul_const(pk, R_prev, 2), F)
                R_prev = R

            T[i] = paillier.e_add(pk, paillier.e_mul_const(pk, paillier.e_add_const(pk, R, -1), random.randint(0, pk.n-1)), D)

        random.shuffle(T)
        return T

    def compute_GT(self, sk, pk, T):
        for t in T:
            d = paillier.decrypt(sk, pk, t)
            if d == 1:
                return 1
            elif d == -1:
                return 0
        return 0