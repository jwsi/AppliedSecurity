import sys, subprocess, random, copy, time
from matrices import s, sInv, rcon
from fault import Fault

# Define global variable for interactions with oracle
sampleSize = 100
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
    k_0_7_10_13 = []
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
                                k_0_7_10_13.append([k0, k7, k10, k13])
    k_0_7_10_13.sort()
    return k_0_7_10_13


# From the paper this calculates the possible set of delta 2 values (Section 3.1)
def findDelta2Keys(x, xF):
    k_1_4_11_14 = []
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
                                k_1_4_11_14.append([k1, k4, k11, k14])
    k_1_4_11_14.sort()
    return k_1_4_11_14


# From the paper this calculates the possible set of delta 3 values (Section 3.1)
def findDelta3Keys(x, xF):
    k_2_5_8_15 = []
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
                                k_2_5_8_15.append([k2, k5, k8, k15])
    k_2_5_8_15.sort()
    return k_2_5_8_15


# From the paper this calculates the possible set of delta 4 values (Section 3.1)
def findDelta4Keys(x, xF):
    k_3_6_9_12 = []
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
                                k_3_6_9_12.append([k3, k6, k9 , k12])
    k_3_6_9_12.sort()
    return k_3_6_9_12


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


# Given a ctxt and faulty ctxt it will produce lists of blocks of the ciphertext
def blockify(ctxt, ctxtFaulty):
    x =  [ _getBlock(ctxt, i)       for i in range(16) ]
    xF = [ _getBlock(ctxtFaulty, i) for i in range(16) ]
    return x, xF


# Given a ciphertext it returns the corresponding byte block
def _getBlock(ctxt, number):
    return (ctxt >> (120-(number*8))) & 0xFF


# This step executes section 3.1 of the attack in full
def step1(target):
    keys = [[] for i in range(16)]
    ALL_k_0_7_10_13 = []
    ALL_k_1_4_11_14 = []
    ALL_k_2_5_8_15  = []
    ALL_k_3_6_9_12  = []
    messages = generateMessages(sampleSize)
    fault = Fault(8, "SubBytes", "before", 0, 0)
    firstTime = True
    for m in messages:
        ctxt       = communicate(target, m, None)
        ctxtFaulty = communicate(target, m, fault)
        x, xF = blockify(ctxt, ctxtFaulty)
        k_0_7_10_13 = findDelta1Keys(x, xF)
        k_1_4_11_14 = findDelta2Keys(x, xF)
        k_2_5_8_15  = findDelta3Keys(x, xF)
        k_3_6_9_12  = findDelta4Keys(x, xF)

        ALL_k_0_7_10_13 = intersect(k_0_7_10_13, ALL_k_0_7_10_13, firstTime)
        ALL_k_1_4_11_14 = intersect(k_1_4_11_14, ALL_k_1_4_11_14, firstTime)
        ALL_k_2_5_8_15  = intersect(k_2_5_8_15,  ALL_k_2_5_8_15,  firstTime)
        ALL_k_3_6_9_12  = intersect(k_3_6_9_12,  ALL_k_3_6_9_12,  firstTime)
        firstTime = False

    print str(len(ALL_k_0_7_10_13))
    print str(len(ALL_k_1_4_11_14))
    print str(len(ALL_k_2_5_8_15 ))
    print str(len(ALL_k_3_6_9_12 ))
    listLen = len(ALL_k_0_7_10_13) + len(ALL_k_1_4_11_14) + len(ALL_k_2_5_8_15) + len(ALL_k_3_6_9_12)
    print "Stage 1 recovery: " + str(listLen) + " hypotheses found"
    # for keySet in ALL_k_0_7_10_13:
    #     keys[0].append(keySet[0])
    #     keys[7].append(keySet[1])
    #     keys[10].append(keySet[2])
    #     keys[13].append(keySet[3])
    # for keySet in ALL_k_1_4_11_14:
    #     keys[1].append(keySet[0])
    #     keys[4].append(keySet[1])
    #     keys[11].append(keySet[2])
    #     keys[14].append(keySet[3])
    # for keySet in ALL_k_2_5_8_15:
    #     keys[2].append(keySet[0])
    #     keys[5].append(keySet[1])
    #     keys[8].append(keySet[2])
    #     keys[15].append(keySet[3])
    # for keySet in ALL_k_0_7_10_13:
    #     keys[0].append(keySet[0])
    #     keys[7].append(keySet[1])
    #     keys[10].append(keySet[2])
    #     keys[13].append(keySet[3])



# Returns the intersection of two lists
def intersect(a, b, cloneIfEmpty):
    if cloneIfEmpty and (len(a) == 0 or len(b) == 0):
        return copy.copy(b) if len(a) == 0 else copy.copy(a)
    return [list(x) for x in set(tuple(x) for x in a).intersection(set(tuple(x) for x in b))]



# This step executes section 3.3 of the attack in full
def step2(x, xF):
    possibleKeys = []
    for i in range(len(keys[0])):
        print "i is at " + str(i) + " out of 240..."
        for j in range(len(keys[1])):
            for k in range(len(keys[2])):
                for l in range(len(keys[3])):
                    key = [keys[ 0][i], keys[ 1][j], keys[ 2][k], keys[ 3][l],
                           keys[ 4][j], keys[ 5][k], keys[ 6][l], keys[ 7][i],
                           keys[ 8][k], keys[ 9][l], keys[10][i], keys[11][j],
                           keys[12][l], keys[13][i], keys[14][j], keys[15][k]]
                    f = fEquation1(x, xF, key)
                    if fEquation2(x, xF, key) == f:
                        if fEquation3(x, xF, key) == f:
                            if fEquation4(x, xF, key) == f:
                                possibleKeys.append(key)
    return possibleKeys





# This is the main function of the attack
def main():
    start = time.time()
    # Spin up a subprocess.
    target = subprocess.Popen(args=["noah", sys.argv[1]], stdout=subprocess.PIPE, stdin=subprocess.PIPE)
    # Perform the attack
    createMultiplyTable() # Create table for Galois Field multiplication lookup
    # ctxt1 = 309576198173487898485272507802272752224
    # ctxtFaulty1 = 213524607176099836202173306380891822739
    # ctxt2 = 266831768776891864963488848972572001878
    # ctxtFaulty2 = 58855063624842956889966105343294270242
    # ctxt3 = 46131487838347580498881944052497770950
    # ctxtFaulty3 = 255539361176520542558409181556479638508
    # fault = Fault(8, "SubBytes", "before", 0, 0)
    # print fault.description()
    # print communicate(target, 327423114947905701800067518410874098196, fault)
    # print generateMessages(1)
    # Turn ciphertexts into block arrays
    # x1, xF1 = blockify(ctxt1, ctxtFaulty1)
    # x2, xF2 = blockify(ctxt2, ctxtFaulty2)
    # x3, xF3 = blockify(ctxt3, ctxtFaulty3)
    # Perform step 1 of attack
    step1(target)
    # global keys
    # print keys
    # keys = [[] for i in range(16)]
    # step1(x2, xF2)
    # print keys
    # keys = [[] for i in range(16)]
    # step1(x3, xF3)
    # print keys
    # Perform step 2 of attack
    # possibleKeys = step2(x, xF)
    # print possibleKeys

    # Print the key
    # Print the number of oracle interactions required
    print "Total oracle interactions: " + str(interactions)
    end = time.time()
    print str(end-start)

# # Useful for verifying the delta 1 stage for a fixed ciphertext...
def getComparitors(keys):
    candidates = []
    for i in range(len(keys[0])):
        candidates.append([keys[0][i], keys[7][i], keys[10][i], keys[13][i]])
    return candidates

if (__name__ == "__main__"):
    main()
