

# GT Problem

Yao’s Millionaires’ (”greater than” or ”GT”) problem is to determine who is richer between two parties such that no information about a party’s amount of assets is leaked to the other party.Yao gave the ﬁrst protocol for solving the secure comparison problem. However, the solution was exponential in time and space requirements.Thereafter, many other protocols with great improvement are proposed. In 2004, **Blake and Kolesnikov** [1] presented a two-round protocol for the problem using the additive homomorphic Paillier cryptosystem. Its computation cost is O(n log N) and the communication cost is O(n log N). In 2005 **Lin and Tzeng** 2005 [2] proposed a two-round protocol for solving the millionaire problem in the setting of semi-honest parties using multiplicative or additive homomorphic encryption schemes. We implemented both protocols and compared their computation and communication cost. 

# Implementation

## **Blake-Kolesnikov Protocol(BT04)**

In 2004, Blake and Kolesnikov constructed a two-round GT protocol based on **additive** homomorphic (e.g. Paillier) cryptosystem.They defined a primitive called SCOT, a stronger version of COT[3] and exploit the structure of the GT predicate in a novel way to arrive at a solution that is more eﬃcient and ﬂexible than the best previously known (of Fischlin [4]) in the semi-honest setting with unbounded receiver.

## Lin-Tzeng Protocol(LT05)

In 2005, Hsiao-Ying Lin and Wen-Guey Tzeng constrcuted a two-round GT protocol based on either an **additive**(e.g. **Paillier**) or a **multiplicative**(e.g. El **Gamal**) homomorphic encryption scheme, while most previous protocols [BK04] are based on additive or XOR encryption schemes only. The computation and communication costs of their protocol are in the same asymptotic order(**n log N**) as those of the other eﬃcient protocols. Nevertheless, since multiplicative homomorphic encryption scheme is more eﬃcient than an additive one practically, our construction saves computation time in practicality.



## Complexity Analysis

#### BT04

For computation, the receiver (Alice) needs n encryptions and n decryptions. The sender (Bob) needs n modular multiplications in the 2a step, n modular multiplications and n inversions in the 2b step, 2n modular multiplications in the 2c step, and (2 + log N)n modular multiplications in the 2d step. Each inversion takes 1 modular multiplications. Overall, the protocol needs 4n modular exponentiations (modN^2 ) and 7n modular multiplication (modN^2 ) The communication cost is n ciphertexts for the receiver and n ciphertexts for the sender. The overall communication cost is 4nlogN bits

#### LT05

In Step 1, Alice encrypts n 1′s. In Step 2, Bob computes ct , t ∈ Sy0, by reusing intermediate values. This takes (2n − 3) multiplications of ciphertexts at most. Step 2 uses n scalaring operations at most. In Step 3, Alice decrypts n ciphertexts.

To compare fairly, we convert all operations to the number of modular multiplications. For the ElGamal scheme, each encryption takes 2log p modular multiplications, each decryption takes log p modular multiplications, and each scalaring operation takes 2 log p modular multiplications. Overall, our GT protocol needs 5n log p + 4n − 6 (= n × 2logp + 2 × (2n−3) + n × 2logp + n × logp) modular multiplications.

Communication complexity. The size of exchanged messages between Alice and Bob is the size of T and c1, c2 , . . . , cn , which is 6n log p (= 3n × 2logp) bits.

|        | computation of Alice | computation of Bob | total computation | communication |
| ------ | -------------------- | ------------------ | ----------------- | ------------- |
| [LT05] | 3n log p             | 2n log p + 4n − 6  | 5n log p + 4n − 6 | 6n log p      |
| [BK04] | 12n log N            | 4n log N + 28n     | 16n log N + 28n   | 4n log N      |

## Field Test

Python 2.7

```
$ python test.py
--- Testing LinTzeng Protocol ---
[1]Testing Paillier based... 
Encryption Scheme: Paillier
Modulus Length: 256
Input Length: 100
---100/100 passed 8.53471922874 seconds ---

[2]Testing ElGamal based... 
Encryption Scheme: ElGamal
Modulus Length: 256
Input Length: 100
---100/100 passed 7.4218378067 seconds ---

--- Testing Blake-Kolesnikov's Protocol ---
Encryption Scheme: Paillier
Modulus Length: 256
Input Length: 100
---100/100 passed 8.9105682373 seconds ---
```

The test result matches the analysis that LT05 is faster than BT04. Additionally, we test LT05 twice based on Paillier and El Gamal respectively where the one with El Gamal is faster.

# Circuit Compiler

In all secure 2-party or multi-party MPC solutions, the first step consists of transforming the function specification from its original representation (e.g., English, code in some high-level programming language, etc.) into an intermediate representation (e.g. a Boolean circuit, an arithmetic circuit, a mixed-mode circuit, etc.)

This transformation is usually accomplished either directly by a human or, much more preferably, **automatically** through so called circuit compilers.

https://github.com/samee/obliv-c

# Remarks

Both constructions are secure in the semi-honest setting. In the malicious setting, each round requires additional messages to assure legality of the sent messages. The techniques are mostly based on non-interactive zero-knowledge proof of knowledge.

# Reference

[1] Ian F Blake and Vladimir Kolesnikov. Strong conditional oblivious transfer and computing on intervals. In Advances in Cryptology-ASIACRYPT 2004, pages 515–529. Springer, 2004.

[2] Hsiao-Ying Lin and Wen-Guey Tzeng. An eﬃcient solution to the millionaires ′problem based on homomorphic encryption. In Applied Cryptography and Network Security, pages 456–466. Springer, 2005.

[3] G. Di Crescenzo, R. Ostrovsky, and S. Rajagopalan. Conditional oblivious transfer and time-released encryption. In Proc. CRYPTO 99, pages 74–89. Springer-Verlag, 1999. 

[4] Marc Fischlin. A cost-eﬀective pay-per-multiplication comparison method for millionaires. In RSA Security 2001 Cryptographer’s Track, pages 457–471. SpringerVerlag, 2001.