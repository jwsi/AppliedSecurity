import sys, subprocess, random
from fault import Fault
from sbox import s, sInv

# Define global variable for interactions with oracle
interactions = 0
multiplyTable = []


# This function communicates with the attack target
def communicate(target, message, fault):
    global interactions
    # Send label & ciphertext to attack target.
    messageString  = "{0:X}".format(message)
    faultString = fault.description()
    target.stdin.write(faultString + "\n")
    target.stdin.write(messageString  + "\n")
    target.stdin.flush()

    # Receive result code from attack target.
    ctxt = int(target.stdout.readline().strip())
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


# This is the main function
def main():
    # Spin up a subprocess.
    target = subprocess.Popen(args=["noah", sys.argv[1]], stdout=subprocess.PIPE, stdin=subprocess.PIPE)
    # Perform the attack

    # Print the key
    createMultiplyTable()
    print multiplyTable
    # Print the number of oracle interactions required
    print "Total oracle interactions: " + str(interactions)


if (__name__ == "__main__"):
    main()
