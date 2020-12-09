
import random
import time
import timer
import math
from CipherSuite import CipherSuite
from LT05 import LT05
import matplotlib.pyplot as plt 


def test_func(N, func, *args):
    t = timer.timer()
    succ = 0
    for i in range(N):
        try:
            func(t, *args)
            succ += 1
        except:
            pass
    tr = t.record()
    print "---%d/%d passed %s seconds ---\n" % (succ, N, tr)
    return tr

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

    result = []
    paillier = CipherSuite()
    paillier.scheme = "Paillier"
    
    elgamal = CipherSuite()
    elgamal.scheme = "ElGamal"

    for i in range(1,5):
        input_length = 20*i
        for j in range(1,5):
            if i == 4:
                paillier.modulus_length = 32*2*j
                elgamal.modulus_length = 32*2*j
            else:
                paillier.modulus_length = 256
                elgamal.modulus_length = 256
            if i == 4 or i != 4 and j == 1:
                print "--- Testing LinTzeng Protocol ---"
                print "[1]Testing Paillier based... "
                print(paillier)
                print "Input Length: %d" % input_length

                tr = test_func( N, sim_LTPProtocol, paillier, input_length)
                result.append((paillier.scheme, input_length, paillier.modulus_length, tr))

                
                print "[2]Testing ElGamal based... "
                print(elgamal)
                print "Input Length: %d" % input_length

                tr = test_func( N, sim_LTPProtocol, elgamal, input_length)
                result.append((elgamal.scheme, input_length, elgamal.modulus_length, tr))
    return result



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
    result = []

    for i in range(1,5):
        input_length = 20*i
        for j in range(1,5):
            if i == 4:
                paillier.modulus_length = 32*2*j
            else:
                paillier.modulus_length = 256
            
            if i == 4 or i != 4 and j == 1:
                print "--- Testing Blake-Kolesnikov's Protocol ---"
                print(paillier)

                print "Input Length: %d" % input_length
                tr = test_func( N, sim_LTPProtocol, paillier, input_length)
                result.append((input_length, paillier.modulus_length, tr))
    return result



Rl = test_LinTzengProtocol(100)
Rb = test_BlakeKolesnikovProtocol(100)


x_p_10_n_LT, y_p_10_n_LT = [],[]
x_e_10_n_LT, y_e_10_n_LT = [],[]

x_10_n_BT, y_10_n_BT = [],[]

x_p_i_128_LT, y_p_i_128_LT = [],[]
x_e_i_128_LT, y_e_i_128_LT = [],[]

x_i_128_BT, y_i_128_BT = [], []


for r in Rl:
    if r[0] == "Paillier":
        if r[1] == 80:
            x_p_10_n_LT.append(r[2])
            y_p_10_n_LT.append(r[3])
        if r[2] == 256:
            x_p_i_128_LT.append(r[1])
            y_p_i_128_LT.append(r[3])
    elif r[0] == "ElGamal":
        if r[1] == 80:
            x_e_10_n_LT.append(r[2])
            y_e_10_n_LT.append(r[3])
        if r[2] == 256:
            x_e_i_128_LT.append(r[1])
            y_e_i_128_LT.append(r[3])
for r in Rb:
    if r[0] == 80:
        x_10_n_BT.append(r[1])
        y_10_n_BT.append(r[2])
    if r[1] == 256:
        x_i_128_BT.append(r[0])
        y_i_128_BT.append(r[2])


plt.figure(1)
plt.plot(x_p_10_n_LT, y_p_10_n_LT, label = "LT-Pailler") 
plt.plot(x_e_10_n_LT, y_e_10_n_LT, label = "LT-ElGamal") 
plt.plot(x_10_n_BT, y_10_n_BT, label = "BT") 
plt.title('Input = 80') 
plt.legend() 
plt.xlabel('Log(Modulus)') 
plt.ylabel('Time') 

plt.figure(2)
plt.plot(x_p_i_128_LT, y_p_i_128_LT, label = "LT-Paillier") 
plt.plot(x_e_i_128_LT, y_e_i_128_LT, label = "LT-ElGamal") 
plt.plot(x_i_128_BT, y_i_128_BT, label = "BT") 
plt.title('Modulus = 256') 
plt.legend() 
plt.xlabel('Input') 
plt.ylabel('Time') 
plt.show()





