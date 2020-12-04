#!/usr/bin/env python
import math
import paillier
import primes
import random
import elgamal
from GTProtocol import GTProtocol

'''
    Lin-Tzeng's Protocol 2005
    based on Paillier or El Gamal scheme
'''

class LT05(GTProtocol):

    def generate_keypair(self):
        cs = self.cipher_suite
        scheme = cs.scheme
        if scheme == "Paillier":
            sk, pk = paillier.generate_keypair(cs.modulus_length)
            # print(pk.n)
        elif scheme == "ElGamal":
            sk, pk = elgamal.generate_keys(cs.modulus_length)
            # print(pk.p)
        return sk, pk

    def encode_x(self, pk, x):
        N = len(x)
        scheme = self.cipher_suite.scheme

        T = [[0] * N for i in range(2)]

        if scheme == "Paillier":
            for j in range(N):
                T[x[j]][j] = paillier.encrypt(pk,0)
                # r = random.randint(0, pk.n-1)
                T[1-x[j]][j] = paillier.random_cipher(pk)
        elif scheme == "ElGamal":
            for j in range(N):
                T[x[j]][j] = elgamal.encrypt(pk,1)
                T[1-x[j]][j] = elgamal.random_cipher(pk)
    
        return T

    def encode_y(self, pk, T, y):
        scheme = self.cipher_suite.scheme
        N = len(y)

        C = [0 for i in range(N)]
        c = 0
        if scheme == "Paillier":
            for i in range(N):
                if y[i] == 0:
                    y[i] = 1
                    c_t = T[y[0]][0]
                    for k in range(1, i + 1):
                        c_t = paillier.e_add(pk, c_t, T[y[k]][k])
                    c_t = paillier.scalarize(pk, c_t)
                    C[c] = c_t
                    c += 1
                    y[i] = 0

            for i in range(c,N):
                # r = random.randint(0, pk.n-1)
                C[i] = paillier.random_cipher(pk)

        elif scheme == "ElGamal":
            for i in range(N):
                if y[i] == 0:
                    y[i] = 1
                    c_t = T[y[0]][0]
                    for k in range(1, i + 1):
                        c_t = elgamal.c_mul(pk, c_t, T[y[k]][k])
                    c_t = elgamal.scalarize(pk, c_t)
                    C[c] = c_t
                    c += 1
                    y[i] = 0

            for i in range(c,N):
                # r = random.randint(0, pk.n-1)
                C[i] = elgamal.random_cipher(pk)

        random.shuffle(C)
        return C

    def compute_GT(self, sk, pk, C):
        
        scheme = self.cipher_suite.scheme

        if scheme == "Paillier":
            for c in C:
                if paillier.decrypt(sk, pk, c) == 0:
                    return 1 # x > y
            else:
                return 0 # x <= y
        elif scheme == "ElGamal":
            for c in C:
                if elgamal.decrypt(sk, c) == 1:
                    return 1 # x > y
            else:
                return 0 # x <= y
