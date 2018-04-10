import sys, subprocess, random, copy, time
from fault import Fault
from delta import findDelta1Keys, findDelta2Keys, findDelta3Keys, findDelta4Keys
from fequations import fEquation1, fEquation2, fEquation3, fEquation4
from Crypto.Cipher import AES
from matrices import rcon, s

# Define global variables for message sample size and interactions with oracle
sampleSize = 4
interactions = 0

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


def generateCiphertexts(target, messages):
    print "Creating ciphertexts from message set...",
    ctxts, ctxtBlockPairs = [], []
    fault = Fault(8, "SubBytes", "before", 0, 0)
    for m in messages:
        ctxt       = communicate(target, m, None)
        ctxtFaulty = communicate(target, m, fault)
        x, xF = blockify(ctxt, ctxtFaulty)
        ctxtBlockPairs.append([x, xF])
        ctxts.append(ctxt)
    print "   COMPLETE!"
    return ctxts, ctxtBlockPairs


# Generate a given amount of random 128bit messages
def generateMessages(amount):
    print "Generating " + str(amount) + " random messages...",
    random.seed() # Seed internal PRNG with current time (don't really care too much about true randomness here...)
    messages = []
    while(len(messages) != amount):
        m = random.getrandbits(128)
        while (m.bit_length() != 128):
            m = random.getrandbits(128)
        messages.append(m)
    print "            COMPLETE!"
    return messages


# Given a ctxt and faulty ctxt it will produce lists of blocks of the ciphertext
def blockify(ctxt, ctxtFaulty):
    x =  [ _getBlock(ctxt, i)       for i in range(16) ]
    xF = [ _getBlock(ctxtFaulty, i) for i in range(16) ]
    return x, xF


# Given a 16 element byte list the function will return a 128 bit integer
def deBlockify(byteList):
    result = 0
    for index, byte in enumerate(byteList):
        result += byte << (120-(index*8))
        index += 1
    return result


# Given a ciphertext it returns the corresponding byte block
def _getBlock(ctxt, number):
    return (ctxt >> (120-(number*8))) & 0xFF


# This step executes section 3.1 of the attack in full
def step1(ctxtBlockPairs):
    print "\nPerforming stage 1 of the attack...",
    keys = [[] for _ in range(16)]
    ALL_k_0_7_10_13 = []
    ALL_k_1_4_11_14 = []
    ALL_k_2_5_8_15  = []
    ALL_k_3_6_9_12  = []
    firstTime = True
    for (x, xF) in ctxtBlockPairs:
        k_0_7_10_13 = findDelta1Keys(x, xF)
        k_1_4_11_14 = findDelta2Keys(x, xF)
        k_2_5_8_15  = findDelta3Keys(x, xF)
        k_3_6_9_12  = findDelta4Keys(x, xF)

        ALL_k_0_7_10_13 = intersect(k_0_7_10_13, ALL_k_0_7_10_13, firstTime)
        ALL_k_1_4_11_14 = intersect(k_1_4_11_14, ALL_k_1_4_11_14, firstTime)
        ALL_k_2_5_8_15  = intersect(k_2_5_8_15,  ALL_k_2_5_8_15,  firstTime)
        ALL_k_3_6_9_12  = intersect(k_3_6_9_12,  ALL_k_3_6_9_12,  firstTime)
        firstTime = False

    for keySet in ALL_k_0_7_10_13:
        keys[0].append(keySet[0])
        keys[7].append(keySet[1])
        keys[10].append(keySet[2])
        keys[13].append(keySet[3])
    for keySet in ALL_k_1_4_11_14:
        keys[1].append(keySet[0])
        keys[4].append(keySet[1])
        keys[11].append(keySet[2])
        keys[14].append(keySet[3])
    for keySet in ALL_k_2_5_8_15:
        keys[2].append(keySet[0])
        keys[5].append(keySet[1])
        keys[8].append(keySet[2])
        keys[15].append(keySet[3])
    for keySet in ALL_k_3_6_9_12:
        keys[3].append(keySet[0])
        keys[6].append(keySet[1])
        keys[9].append(keySet[2])
        keys[12].append(keySet[3])
    print "        COMPLETE! -> ",
    print "Possible keys found: " + str(len(keys[0]) * len(keys[1]) * len(keys[2]) * len(keys[3]))
    return keys


# Returns the intersection of two lists and removes duplicates
def intersect(a, b, cloneIfEmpty):
    if cloneIfEmpty and (len(a) == 0 or len(b) == 0):
        return copy.copy(b) if len(a) == 0 else copy.copy(a)
    return [list(x) for x in set(tuple(x) for x in a).intersection(set(tuple(x) for x in b))]


# This step executes section 3.3 of the attack in full
def step2(ctxtBlockPairs, keys):
    print "Performing stage 2 of the attack...",
    possibleKeys = []
    x, xF = ctxtBlockPairs[0]
    for i in range(len(keys[0])):
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
    print "        COMPLETE! -> ",
    print "Possible keys found: " + str(len(possibleKeys))
    return possibleKeys


# Given the 10th round key this function will backtrack to the original AES key (see Rijndael key schedule Wiki)
def getAESKey(k):
    for i in range(10, 0, -1):
        # Last 32 bit word (as xor is self-inverse perform forward operation again...)
        k[12] = k[12] ^ k[8]
        k[13] = k[13] ^ k[9]
        k[14] = k[14] ^ k[10]
        k[15] = k[15] ^ k[11]

        k[8]  = k[8]  ^ k[4]
        k[9]  = k[9]  ^ k[5]
        k[10] = k[10] ^ k[6]
        k[11] = k[11] ^ k[7]

        k[4]  = k[4]  ^ k[0]
        k[5]  = k[5]  ^ k[1]
        k[6]  = k[6]  ^ k[2]
        k[7]  = k[7]  ^ k[3]

        # Final step is harder as we have to reverse the key-schedule core on the last 32 bit word...
        k[0]  = k[0]  ^ s[ k[13] ] ^ rcon[i]
        k[1]  = k[1]  ^ s[ k[14] ]
        k[2]  = k[2]  ^ s[ k[15] ]
        k[3]  = k[3]  ^ s[ k[12] ]
    return k


# Given a list of byte arrays for keys, a list of messages and a list of ciphertexts this will return a valid key
def verifyKeys(keys, messages, ctxtBlockPairs):
    print "Performing key verification...",
    for key in keys:
        AESKey = getAESKey(key)
        failure = False
        for i in range(len(messages)):
            obj = AES.new(str(bytearray(AESKey)))
            decryption = obj.decrypt(str(bytearray(ctxtBlockPairs[i][0])))
            if deBlockify([ord(x) for x in decryption]) != messages[i]:
                failure = True
        if not failure:
            print "             COMPLETE!\n"
            return deBlockify(key)
    print "The key could not be recovered - please try again..."
    raise Exception("Key recovery failure")


# This is the main function of the attack
def main():
    start = time.time()
    # Spin up a subprocess.
    target = subprocess.Popen(args=["noah", sys.argv[1]], stdout=subprocess.PIPE, stdin=subprocess.PIPE)
    # Perform the attack
    messages = generateMessages(sampleSize)
    print messages
    _, ctxtBlockPairs = generateCiphertexts(target, messages)
    keys = step1(ctxtBlockPairs)
    keys  = step2(ctxtBlockPairs, keys)
    key = verifyKeys(keys, messages, ctxtBlockPairs)
    print "Key successfully recovered: ""{0:X}".format(key) + " (hex string)"
    # Print the number of oracle interactions required
    print "Total oracle interactions: " + str(interactions)
    end = time.time()
    print str(end-start)

if (__name__ == "__main__"):
    main()
