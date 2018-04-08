import sys, subprocess, random
from fault import Fault
from matrices import s, sInv, rcon

# Define global variable for interactions with oracle
interactions = 0
multiplyTable = []
keys = [[] for i in range(16)]  # Initialise the key list to fit 16*8bit key bytes

def addKey(block, key):
    global keys
    keys[block].append(key)

# This function communicates with the attack target
def communicate(target, message, fault):
    global interactions
    # Send fault + plaintext to attack target.
    if fault is None:
        faultString = ""
    else:
        faultString = fault.description()
    messageString  = "{0:X}".format(message)
    target.stdin.write(faultString + "\n")
    target.stdin.write(messageString  + "\n")
    target.stdin.flush()

    # Receive ciphertext from attack target.
    ctxt = int(target.stdout.readline().strip(), 16)
    interactions += 1
    return ctxt


def generateMessages(amount):
    print "Generating " + str(amount) + " messages... ",
    random.seed() # Seed internal PRNG with current time (don't really care too much about true randomness here...)
    messages = []
    while(len(messages) != amount):
        m = random.getrandbits(128)
        while (m.bit_length() != 128):
            m = random.getrandbits(128)
        messages.append(m)
    print "COMPLETE!"
    return messages


# This function creates a lookup table for multiplication in the Galois Field of 2^8.
def createMultiplyTable():
    global multiplyTable
    for i in range(256):
        subTable = []
        for j in range(256):
            subTable.append(_gf28Multiply(i, j))
        multiplyTable.append(subTable)


# Modified peasants algorithm to perform multiplication in GF8 under the Rijndael irreducible polynomial.
def _gf28Multiply(a, b):
    # Setup initial values + ensure 8 bit max
    p = 0
    a = a & 255
    b = b & 255
    for i in range(8):
        # If the rightmost bit of b is set, exclusive OR the product p by the value of a.
        if (b & 1) == 1:
            p = p ^ a
        # Shift b one bit to the right
        b = b >> 1
        # Is leftmost bit of a set to 1?
        carry = (a & 128) >> 7
        # Shift a one bit to the left, discarding the leftmost bit, and making the new rightmost bit zero
        a = (a << 1) & 255
        # If carry had a value of one, exclusive or a with the hexadecimal number 0x1b. 0x1b corresponds to the irreducible polynomial with the high term eliminated.
        if carry:
            a = a ^ 0x1b
    return p


# From the paper this calculates the possible set of delta 1 values (Section 3.1)
def findDelta1Keys(x, xF):
    for k0 in range(256):
        line1 = sInv[x[0] ^ k0] ^ sInv[xF[0] ^ k0]
        delta1 = multiplyTable[line1][141] # 2^-1 = 141 in Rijndael GF2^8 field

        for k13 in range(256):
            line2 = sInv[x[13] ^ k13] ^ sInv[xF[13] ^ k13]
            if line2 == delta1:

                for k10 in range(256):
                    line3 = sInv[x[10] ^ k10] ^ sInv[xF[10] ^ k10]
                    if line3 == delta1:

                        for k7 in range(256):
                            line4 = sInv[x[7] ^ k7] ^ sInv[xF[7] ^ k7]
                            if multiplyTable[line4][246] == delta1: # 3^-1 = 246 in Rijndael GF2^8 field
                                # Add this combination to the key store
                                addKey(0, k0)
                                addKey(13, k13)
                                addKey(10, k10)
                                addKey(7, k7)

# From the paper this calculates the possible set of delta 2 values (Section 3.1)
def findDelta2Keys(x, xF):
    for k4 in range(256):
        line1 = sInv[x[4] ^ k4] ^ sInv[xF[4] ^ k4]
        delta2 = multiplyTable[line1][246] # 3^-1 = 246 in Rijndael GF2^8 field

        for k1 in range(256):
            line2 = sInv[x[1] ^ k1] ^ sInv[xF[1] ^ k1]
            if multiplyTable[line2][141] == delta2: # 2^-1 = 141 in Rijndael GF2^8 field

                for k14 in range(256):
                    line3 = sInv[x[14] ^ k14] ^ sInv[xF[14] ^ k14]
                    if line3 == delta2:

                        for k11 in range(256):
                            line4 = sInv[x[11] ^ k11] ^ sInv[xF[11] ^ k11]
                            if line4 == delta2:
                                # Add this combination to the key store
                                addKey(4, k4)
                                addKey(1, k1)
                                addKey(14, k14)
                                addKey(11, k11)

# From the paper this calculates the possible set of delta 3 values (Section 3.1)
def findDelta3Keys(x, xF):
    for k8 in range(256):
        delta3 = sInv[x[8] ^ k8] ^ sInv[xF[8] ^ k8]

        for k5 in range(256):
            line2 = sInv[x[5] ^ k5] ^ sInv[xF[5] ^ k5]
            if multiplyTable[line2][246] == delta3: # 3^-1 = 246 in Rijndael GF2^8 field

                for k2 in range(256):
                    line3 = sInv[x[2] ^ k2] ^ sInv[xF[2] ^ k2]
                    if multiplyTable[line3][141] == delta3: # 2^-1 = 141 in Rijndael GF2^8 field

                        for k15 in range(256):
                            line4 = sInv[x[15] ^ k15] ^ sInv[xF[15] ^ k15]
                            if line4 == delta3:
                                # Add this combination to the key store
                                addKey(8, k8)
                                addKey(5, k5)
                                addKey(2, k2)
                                addKey(15, k15)

# From the paper this calculates the possible set of delta 4 values (Section 3.1)
def findDelta4Keys(x, xF):
    for k12 in range(256):
        delta4 = sInv[x[12] ^ k12] ^ sInv[xF[12] ^ k12]

        for k9 in range(256):
            line2 = sInv[x[9] ^ k9] ^ sInv[xF[9] ^ k9]
            if line2 == delta4:

                for k6 in range(256):
                    line3 = sInv[x[6] ^ k6] ^ sInv[xF[6] ^ k6]
                    if multiplyTable[line3][246] == delta4: # 3^-1 = 246 in Rijndael GF2^8 field

                        for k3 in range(256):
                            line4 = sInv[x[3] ^ k3] ^ sInv[xF[3] ^ k3]
                            if multiplyTable[line4][141] == delta4: # 2^-1 = 141 in Rijndael GF2^8 field
                                # Add this combination to the key store
                                addKey(12, k12)
                                addKey(9, k9)
                                addKey(6, k6)
                                addKey(3, k3)

# From the paper this refines the keyset using the equations in Section 3.3
def fEquation1(x, xF, k):
    f2 = sInv[ multiplyTable[14][ sInv[ x[0]   ^ k[0]  ] ^ (k[0] ^ s[ k[13] ^ k[9]  ] ^ rcon[10]) ]
             ^ multiplyTable[11][ sInv[ x[13]  ^ k[13] ] ^ (k[1] ^ s[ k[14] ^ k[10] ])            ]
             ^ multiplyTable[13][ sInv[ x[10]  ^ k[10] ] ^ (k[2] ^ s[ k[15] ^ k[11] ])            ]
             ^ multiplyTable[ 9][ sInv[ x[7]   ^ k[7]  ] ^ (k[3] ^ s[ k[12] ^ k[8]  ])            ] ]\
       ^ sInv[ multiplyTable[14][ sInv[ xF[0]  ^ k[0]  ] ^ (k[0] ^ s[ k[13] ^ k[9]  ] ^ rcon[10]) ]
             ^ multiplyTable[11][ sInv[ xF[13] ^ k[13] ] ^ (k[1] ^ s[ k[14] ^ k[10] ])            ]
             ^ multiplyTable[13][ sInv[ xF[10] ^ k[10] ] ^ (k[2] ^ s[ k[15] ^ k[11] ])            ]
             ^ multiplyTable[ 9][ sInv[ xF[7]  ^ k[7]  ] ^ (k[3] ^ s[ k[12] ^ k[8]  ])            ] ]

    return multiplyTable[f2][141] # 2^-1 = 141 in Rijndael GF2^8 field

# From the paper this refines the keyset using the equations in Section 3.3
def fEquation2(x, xF, k):
    f = sInv[ multiplyTable[ 9][ sInv[ x[12]  ^ k[12] ] ^ (k[12]  ^ k[8]) ]
            ^ multiplyTable[14][ sInv[ x[9]   ^ k[9]  ] ^ (k[9]  ^ k[13]) ]
            ^ multiplyTable[11][ sInv[ x[6]   ^ k[6]  ] ^ (k[14] ^ k[10]) ]
            ^ multiplyTable[13][ sInv[ x[3]   ^ k[3]  ] ^ (k[15] ^ k[11]) ] ]\
      ^ sInv[ multiplyTable[ 9][ sInv[ xF[12] ^ k[12] ] ^ (k[12] ^ k[8])  ]
            ^ multiplyTable[14][ sInv[ xF[9]  ^ k[9]  ] ^ (k[9]  ^ k[13]) ]
            ^ multiplyTable[11][ sInv[ xF[6]  ^ k[6]  ] ^ (k[14] ^ k[10]) ]
            ^ multiplyTable[13][ sInv[ xF[3]  ^ k[3]  ] ^ (k[15] ^ k[11]) ] ]

    return f

# From the paper this refines the keyset using the equations in Section 3.3
def fEquation3(x, xF, k):
    f = sInv[ multiplyTable[13][ sInv[ x[8]   ^ k[8]  ] ^ (k[8]  ^ k[4])  ]
            ^ multiplyTable[ 9][ sInv[ x[5]   ^ k[5]  ] ^ (k[9]  ^ k[5])  ]
            ^ multiplyTable[14][ sInv[ x[2]   ^ k[2]  ] ^ (k[10] ^ k[6])  ]
            ^ multiplyTable[11][ sInv[ x[15]  ^ k[15] ] ^ (k[11] ^ k[7])  ] ]\
      ^ sInv[ multiplyTable[13][ sInv[ xF[8]  ^ k[8]  ] ^ (k[8]  ^ k[4])  ]
            ^ multiplyTable[ 9][ sInv[ xF[5]  ^ k[5]  ] ^ (k[9]  ^ k[5])  ]
            ^ multiplyTable[14][ sInv[ xF[2]  ^ k[2]  ] ^ (k[10] ^ k[6])  ]
            ^ multiplyTable[11][ sInv[ xF[15] ^ k[15] ] ^ (k[11] ^ k[7])  ] ]

    return f

# From the paper this refines the keyset using the equations in Section 3.3
def fEquation4(x, xF, k):
    f3 = sInv[ multiplyTable[11][ sInv[ x[4]   ^ k[4]  ] ^ (k[4]  ^ k[0])  ]
            ^ multiplyTable[13][ sInv[ x[1]   ^ k[1]  ] ^ (k[5]  ^ k[1])  ]
            ^ multiplyTable[ 9][ sInv[ x[14]  ^ k[14] ] ^ (k[6]  ^ k[2])  ]
            ^ multiplyTable[14][ sInv[ x[11]  ^ k[11] ] ^ (k[7]  ^ k[3])  ] ]\
      ^ sInv[ multiplyTable[11][ sInv[ xF[4]  ^ k[4]  ] ^ (k[4]  ^ k[0])  ]
            ^ multiplyTable[13][ sInv[ xF[1]  ^ k[1]  ] ^ (k[5]  ^ k[1])  ]
            ^ multiplyTable[ 9][ sInv[ xF[14] ^ k[14] ] ^ (k[6]  ^ k[2])  ]
            ^ multiplyTable[14][ sInv[ xF[11] ^ k[11] ] ^ (k[7]  ^ k[3])  ] ]

    return multiplyTable[f3][246] # 3^-1 = 246 in Rijndael GF2^8 field

def blockify(ctxt, ctxtFaulty):
    x =  [ _getBlock(ctxt, i)       for i in range(16) ]
    xF = [ _getBlock(ctxtFaulty, i) for i in range(16) ]
    return x, xF

# Given a ciphertext it returns the corresponding byte block
def _getBlock(ctxt, number):
    return (ctxt >> (120-(number*8))) & 0xFF

def step1(x, xF):
    findDelta1Keys(x, xF)
    findDelta2Keys(x, xF)
    findDelta3Keys(x, xF)
    findDelta4Keys(x, xF)

def main():
    # Spin up a subprocess.
    target = subprocess.Popen(args=["noah", sys.argv[1]], stdout=subprocess.PIPE, stdin=subprocess.PIPE)
    # Perform the attack
    createMultiplyTable() # Create table for Galois Field multiplication lookup
    ctxt = 309576198173487898485272507802272752224
    ctxtFaulty = 213524607176099836202173306380891822739
    # Turn ciphertexts into block arrays
    x, xF = blockify(ctxt, ctxtFaulty)
    # Perform step 1 of attack
    step1(x, xF)

    key = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]
    # Perform step 2 of attack
    print fEquation1(x, xF, key)
    print fEquation2(x, xF, key)
    print fEquation3(x, xF, key)
    print fEquation4(x, xF, key)


    # print keys

    # Print the key
    # Print the number of oracle interactions required
    print "Total oracle interactions: " + str(interactions)

# # Useful for verifying the delta 1 stage for a fixed ciphertext...
# def getComparitors(keys):
#     candidates = []
#     for i in range(len(keys[3])):
#         candidates.append([keys[3][i], keys[6][i], keys[9][i], keys[12][i]])
#     return candidates

if (__name__ == "__main__"):
    main()
