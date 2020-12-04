
import random
import time
import timer
from CipherSuite import CipherSuite
from LT05 import LT05

def test_func(N, func, *args):
    t = timer.timer()
    succ = 0
    for i in range(N):
        try:
            func(t, *args)
            succ += 1
        except:
            pass
    print "---%d/%d passed %s seconds ---\n" % (succ, N , t.record())

def sim_LTPProtocol(timer, cipher_suite, input_length):
    ltp = LT05(cipher_suite)

    sk, pk = ltp.generate_keypair()

    N = input_length

    x = [random.randint(0,1) for i in range(N)]
    y = [random.randint(0,1) for i in range(N)]

    GT = -1 
    for i in range(N):
        if x[i] > y[i]:
            GT = 1 # x[i] > y[i]
            break
        elif x[i] < y[i]:
            GT = 0 # x[i] < y[i]
            break
    else:
        GT = 0 # x[i] == y[i]

    timer.start()
    T = ltp.encode_x(pk, x)
    C = ltp.encode_y(pk, T, y)
    gt = ltp.compute_GT(sk, pk, C)
    timer.pause()

    # print (str(gt)+","+str(GT))
    assert( gt == GT)



def test_LinTzengProtocol(N = 100):

    paillier = CipherSuite()
    paillier.scheme = "Paillier"
    paillier.modulus_length = 256
    
    elgamal = CipherSuite()
    elgamal.scheme = "ElGamal"
    elgamal.modulus_length = 256

    input_length = 100


    print "--- Testing LinTzeng Protocol ---"
    print "[1]Testing Paillier based... "
    print(paillier)
    print "Input Length: %d" % input_length

    test_func( N, sim_LTPProtocol, paillier, input_length)


    print "[2]Testing ElGamal based... "
    print(elgamal)
    print "Input Length: %d" % input_length

    test_func( N, sim_LTPProtocol, elgamal, input_length)




def sim_BlakeKolesnikovProtocol(timer, cipher_suite, input_length):
    
    btp = BT04(cipher_suite)

    sk, pk = btp.generate_keypair()

    N = input_length
    
    x = [random.randint(0,1) for i in range(N)]
    y = [random.randint(0,1) for i in range(N)]

    GT = -1 
    for i in range(N):
        if x[i] > y[i]:
            GT = 1 # x[i] > y[i]
            break
        elif x[i] < y[i]:
            GT = 0 # x[i] < y[i]
            break
    else:
        GT = 0 # x[i] == y[i]

    timer.start()
    C = btp.encode_x(pk, x)
    T = btp.encode_y(pk, C, y)
    gt = btp.compute_GT(sk, pk, T)
    timer.pause()
    assert( gt == GT)

def test_BlakeKolesnikovProtocol(N = 100):

    paillier = CipherSuite()
    paillier.scheme = "Paillier"
    paillier.modulus_length = 256
    input_length = 100

    print "--- Testing Blake-Kolesnikov's Protocol ---"
    print(paillier)

    print "Input Length: %d" % input_length
    test_func( N, sim_LTPProtocol, paillier, input_length)


test_LinTzengProtocol(100)
test_BlakeKolesnikovProtocol(100)