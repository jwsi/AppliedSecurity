import sys, subprocess, random
from fault import Fault
from sbox import s, sInv

# Define global variable for interactions with oracle
interactions = 0
multiplyTable = []
keys = [[] for i in range(16)]  # Initialise the key list to fit 16*8bit key bytes

def addKey(block, key):
    global keys
    keys[block-1].append(key)

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


# Given a ciphertext it returns the corresponding byte block
def getBlock(ctxt, number):
    return (ctxt >> (128-(number*8))) & 0xFF


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
    for k1 in range(256):
        line1 = sInv[ getBlock(x, 1) ^ k1 ] ^ sInv[ getBlock(xF, 1) ^ k1 ]
        delta1 = multiplyTable[line1][141] # 2^-1 = 141 in Rijndael GF2^8 field

        for k14 in range(256):
            line2 = sInv[ getBlock(x, 14) ^ k14 ] ^ sInv[ getBlock(xF, 14) ^ k14 ]
            if line2 == delta1:

                for k11 in range(256):
                    line3 = sInv[ getBlock(x, 11) ^ k11 ] ^ sInv[ getBlock(xF, 11) ^ k11 ]
                    if line3 == delta1:

                        for k8 in range(256):
                            line4 = sInv[ getBlock(x, 8) ^ k8 ] ^ sInv[ getBlock(xF, 8) ^ k8 ]
                            if multiplyTable[line4][246] == delta1: # 3^-1 = 246 in Rijndael GF2^8 field
                                # Add this combination to the key store
                                addKey(1, k1)
                                addKey(14, k14)
                                addKey(11, k11)
                                addKey(8, k8)

# From the paper this calculates the possible set of delta 2 values (Section 3.1)
def findDelta2Keys(x, xF):
    for k5 in range(256):
        line1 = sInv[ getBlock(x, 5) ^ k5 ] ^ sInv[ getBlock(xF, 5) ^ k5 ]
        delta2 = multiplyTable[line1][246] # 3^-1 = 246 in Rijndael GF2^8 field

        for k2 in range(256):
            line2 = sInv[ getBlock(x, 2) ^ k2 ] ^ sInv[ getBlock(xF, 2) ^ k2 ]
            if multiplyTable[line2][141] == delta2: # 2^-1 = 141 in Rijndael GF2^8 field

                for k15 in range(256):
                    line3 = sInv[ getBlock(x, 15) ^ k15 ] ^ sInv[ getBlock(xF, 15) ^ k15 ]
                    if line3 == delta2:

                        for k12 in range(256):
                            line4 = sInv[ getBlock(x, 12) ^ k12 ] ^ sInv[ getBlock(xF, 12) ^ k12 ]
                            if line4 == delta2:
                                # Add this combination to the key store
                                addKey(5, k5)
                                addKey(2, k2)
                                addKey(15, k15)
                                addKey(12, k12)

# From the paper this calculates the possible set of delta 3 values (Section 3.1)
def findDelta3Keys(x, xF):
    for k9 in range(256):
        delta3 = sInv[ getBlock(x, 9) ^ k9 ] ^ sInv[ getBlock(xF, 9) ^ k9 ]

        for k6 in range(256):
            line2 = sInv[ getBlock(x, 6) ^ k6 ] ^ sInv[ getBlock(xF, 6) ^ k6 ]
            if multiplyTable[line2][246] == delta3: # 3^-1 = 246 in Rijndael GF2^8 field

                for k3 in range(256):
                    line3 = sInv[ getBlock(x, 3) ^ k3 ] ^ sInv[ getBlock(xF, 3) ^ k3 ]
                    if multiplyTable[line3][141] == delta3: # 2^-1 = 141 in Rijndael GF2^8 field

                        for k16 in range(256):
                            line4 = sInv[ getBlock(x, 16) ^ k16 ] ^ sInv[ getBlock(xF, 12) ^ k16 ]
                            if line4 == delta3:
                                # Add this combination to the key store
                                addKey(9, k9)
                                addKey(6, k6)
                                addKey(3, k3)
                                addKey(16, k16)

# From the paper this calculates the possible set of delta 4 values (Section 3.1)
def findDelta4Keys(x, xF):
    for k13 in range(256):
        delta4 = sInv[ getBlock(x, 13) ^ k13 ] ^ sInv[ getBlock(xF, 13) ^ k13 ]

        for k10 in range(256):
            line2 = sInv[ getBlock(x, 10) ^ k10 ] ^ sInv[ getBlock(xF, 10) ^ k10 ]
            if line2 == delta4:

                for k7 in range(256):
                    line3 = sInv[ getBlock(x, 7) ^ k7 ] ^ sInv[ getBlock(xF, 7) ^ k7 ]
                    if multiplyTable[line3][246] == delta4: # 3^-1 = 246 in Rijndael GF2^8 field

                        for k4 in range(256):
                            line4 = sInv[ getBlock(x, 4) ^ k4 ] ^ sInv[ getBlock(xF, 4) ^ k4 ]
                            if multiplyTable[line4][141] == delta4: # 2^-1 = 141 in Rijndael GF2^8 field
                                # Add this combination to the key store
                                addKey(13, k13)
                                addKey(10, k10)
                                addKey(7, k7)
                                addKey(4, k4)


# This is the main function
def main():
    # Spin up a subprocess.
    target = subprocess.Popen(args=["noah", sys.argv[1]], stdout=subprocess.PIPE, stdin=subprocess.PIPE)
    # Perform the attack
    createMultiplyTable() # Create table for Galois Field multiplication lookup
    ctxt = 309576198173487898485272507802272752224
    ctxtFaulty = 213524607176099836202173306380891822739
    findDelta1Keys(ctxt, ctxtFaulty)
    findDelta2Keys(ctxt, ctxtFaulty)
    findDelta3Keys(ctxt, ctxtFaulty)
    findDelta4Keys(ctxt, ctxtFaulty)
    print keys



    # Print the key
    # Print the number of oracle interactions required
    print "Total oracle interactions: " + str(interactions)


if (__name__ == "__main__"):
    main()
