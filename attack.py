# This code is for TC final project
# The following script is an implementation of
# a fault injection attack on LED cipher.
# Based on a paper by P. Jovanovic
# Author: Aneesh Dogra, aneesh13014@iiitd.ac.in

from functools import reduce
from math import log
import sys
sbox = [12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2];
inverse_memo = {}

# constants used in the multGF2 function
mask1 = mask2 = polyred = None
def setGF2(degree, irPoly):
    """Define parameters of binary finite field GF(2^m)/g(x)
       - degree: extension degree of binary field
       - irPoly: coefficients of irreducible polynomial g(x)
    """
    def i2P(sInt):
        """Convert an integer into a polynomial"""
        return [(sInt >> i) & 1
                for i in reversed(range(sInt.bit_length()))]    
    
    global mask1, mask2, polyred
    mask1 = mask2 = 1 << degree
    mask2 -= 1
    polyred = reduce(lambda x, y: (x << 1) + y, i2P(irPoly)[1:])

def find_inverse(x):
    if x in inverse_memo:
        return inverse_memo[x]
    for i in range(0, 0xF + 1):
        if multGF2(x, i) == 1:
            inverse_memo[x] = i
            return i
       
def multGF2(p1, p2):
    """Multiply two polynomials in GF(2^m)/g(x)"""
    p = 0
    while p2:
        if p2 & 1:
            p ^= p1
        p1 <<= 1
        if p1 & mask1:
            p1 ^= polyred
        p2 >>= 1
    return p & mask2

def sbox_inv(x):
    return sbox.index(x)

def calculate_fault_equation(cipher, key, cipherf, mid):
    minv = [[0xC, 0xC, 0xD, 4],
            [3,   8,   4, 5],
            [7, 6, 2, 0xE],
            [0xD, 9, 9, 0xD]]

    # set the field to the appropriate GF used in LED
    setGF2(4, 0b10011)

    s = 0
    s ^= multGF2(minv[mid][0], cipher[0] ^ key[0])
    s ^= multGF2(minv[mid][1], cipher[1] ^ key[1])
    s ^= multGF2(minv[mid][2], cipher[2] ^ key[2])
    s ^= multGF2(minv[mid][3], cipher[3] ^ key[3])

    #print mid, s,
    s = sbox_inv(s)
    #print s

    s1 = 0
    s1 ^= multGF2(minv[mid][0], cipherf[0] ^ key[0])
    s1 ^= multGF2(minv[mid][1], cipherf[1] ^ key[1])
    s1 ^= multGF2(minv[mid][2], cipherf[2] ^ key[2])
    s1 ^= multGF2(minv[mid][3], cipherf[3] ^ key[3])

    #print s1,
    s1 = sbox_inv(s1)
    #print s1

    return s ^ s1

if __name__ == "__main__":
  
    if len(sys.argv) != 4:
        print 'usage: python attack.py <no_fault_cipher> <faulty_cipher> <your_key>'
        sys.exit(1)

    cipher_text = sys.argv[1]
    cipher_text = format(int(cipher_text, base=16), '064b')
    cipher_text = [cipher_text[x:x+4] for x in range(0, len(cipher_text), 4)]
    cipher_text = [int(x, 2) for x in cipher_text]
    cipher = cipher_text

    print 'cipher_block:', cipher

    cipherf = sys.argv[2]
    cipherf = format(int(cipherf, base=16), '064b')
    cipherf = [cipherf[x:x+4] for x in range(0, len(cipherf), 4)]
    cipherf = [int(x, 2) for x in cipherf]

    print 'fault_cipher_block:', cipherf

    setGF2(4, 0b10011)

    # define fault equations
    faults_a = [[0, 4, 8, 12], [3, 7, 11, 15], [2, 6, 10, 14], [1, 5,  9, 13]]
    faults_d = [[1, 5, 9, 13], [0, 4,  8, 12], [3, 7, 11, 15], [2, 6, 10, 14]]
    faults_c = [[2, 6, 10, 14], [1, 5, 9, 13], [0, 4,  8, 12], [3, 7, 11, 15]]
    faults_b = [[3, 7, 11, 15], [2, 6, 10, 14], [1, 5, 9, 13], [0, 4, 8,  12]]

    coefs = {'a': [4, 8, 0xB, 2],
             'b': [1, 6, 0xE, 2],
             'c': [2, 5, 0xA, 0xF],
             'd': [2, 6, 9, 0xB]}


    sxis = {}
    for z in range(0, 4):
        for y in [faults_a, faults_b, faults_c, faults_d]:
            eq = y[z]
            print 'trying equation', eq
            sxi = []
            if y == faults_a:
                cur = 'a'
            if y == faults_b:
                cur = 'b'
            if y == faults_c:
                cur = 'c'
            if y == faults_d:
                cur = 'd'

            for i in range(0, 0xF + 1):
                sxi.append(set({}))
            for i in range(0x0, 0xF + 1):
                for j in range(0x0, 0xF + 1):
                    for k in range(0x0, 0xF + 1):
                        for l in range(0x0, 0xF + 1):
                            s = calculate_fault_equation([cipher[eq[0]], cipher[eq[1]], cipher[eq[2]], cipher[eq[3]]],
                                                         [i, j, k, l],
                                                         [cipherf[eq[0]], cipherf[eq[1]], cipherf[eq[2]], cipherf[eq[3]]],
                                                         z)
                            
                            sxi[multGF2(find_inverse(coefs[cur][z]), s)].add((i, j, k, l))
            sxis[(cur, z)] = sxi
    #print sxis[('a', 2)]
    # now we have the list of Sx, we need to check the values for which
    # Sx,0 Sx,1 Sx,2 and Sx,3 are all non-empty


    fault_values = {}
    for x in ['a', 'b', 'c', 'd']:
        for j in range(0, 0xF + 1):
            if len(sxis[x, 0][j]) != 0:
                is_empty = 0
                for z in range(0, 4):
                    if len(sxis[(x, z)][j]) == 0:
                        is_empty = 1
                        break
                if not is_empty:
                    if x not in fault_values:
                        fault_values[x] = set()
                    fault_values[x].add(j)
    print 'possible fault values: ', fault_values

    k1 = set()
    k2 = set()
    k3 = set()
    k4 = set()
    keyspace = 0
    for a in fault_values['a']:
        for b in fault_values['b']:
            for c in fault_values['c']:
                for d in fault_values['d']:
                    k0_4_8_12 = sxis[('a', 0)][a].intersection(sxis[('d', 1)][d]).intersection(sxis[('c', 2)][c]).intersection(sxis[('b', 3)][b])
                    k1_5_9_13 = sxis[('a', 3)][a].intersection(sxis[('d', 0)][d]).intersection(sxis[('c', 1)][c]).intersection(sxis[('b', 2)][b])
                    k2_6_10_14 = sxis[('a', 2)][a].intersection(sxis[('d', 3)][d]).intersection(sxis[('c', 0)][c]).intersection(sxis[('b', 1)][b])
                    k3_7_11_15 = sxis[('a', 1)][a].intersection(sxis[('d', 2)][d]).intersection(sxis[('c', 3)][c]).intersection(sxis[('b', 0)][b])

                    keyspace += len(k0_4_8_12) * len(k1_5_9_13) * len(k2_6_10_14) * len(k3_7_11_15)

                    k1 = k1.union(k0_4_8_12)
                    k2 = k2.union(k1_5_9_13)
                    k3 = k3.union(k2_6_10_14)
                    k4 = k4.union(k3_7_11_15) 


    print 'keyspace reduced to: %d keys, which is 2^%d' % (keyspace, log(keyspace, 2))

    ourkey = int(sys.argv[3], 16)
    rk = format(ourkey, '064b')
    rk = [rk[x:x+4] for x in range(0, len(rk), 4)]
    rk = [int(x, 2) for x in rk]
    print 'Checking if the key exists in our possibilities:', (rk[0], rk[4], rk[8], rk[12]) in k1, (rk[1], rk[5], rk[9], rk[13]) in k2, (rk[2], rk[6], rk[10], rk[14]) in k3, (rk[3], rk[7], rk[11], rk[15]) in k4
