import sys, subprocess, random
from montgomery import *

# Define global variable for interactions with oracle
interactions = 0


# This function extracts parameters from a config file
def getParams(file):
    print "Parsing the config file... ",
    conf = open(file, "r")
    N = int(conf.readline().strip(), 16)
    e = int(conf.readline().strip(), 16)
    conf.close()
    print " COMPLETE!"
    print "N (RSA Modulus): " + " "*5 + str(N)
    print "e (public exponent): " + " " + str(e) + "\n"
    return (N, e)


# This function communicates with the attack target
def communicate(target, c):
    global interactions
    # Send label & ciphertext to attack target.
    ctxt  = "{0:0256X}".format(c)
    target.stdin.write(ctxt  + "\n")
    target.stdin.flush()

    # Receive result code from attack target.
    time = int(target.stdout.readline().strip())
    result = int(target.stdout.readline().strip(), 16)
    interactions += 1
    return result, time


def oracle1(messages, mTemps, N, e, R, Ninv):
    M1 = {}
    M2 = {}
    mTemps1 = {}
    for m, time in messages.iteritems():
        mMont = montgomeryForm(m, N, R)
        res = montgomeryMultiplication(mTemps[m], mMont, N, R, Ninv)[0]
        res, reduced = montgomeryMultiplication(res, res, N, R, Ninv)
        mTemps1[m] = res
        if reduced:
            M1[m] = time
        else:
            M2[m] = time
    return M1, M2, mTemps1


def oracle2(messages, mTemps, N, e, R, Ninv):
    M3 = {}
    M4 = {}
    mTemps2 = {}
    for m, time in messages.iteritems():
        res, reduced = montgomeryMultiplication(mTemps[m], mTemps[m], N, R, Ninv)
        mTemps2[m] = res
        if reduced:
            M3[m] = time
        else:
            M4[m] = time
    return M3, M4, mTemps2


def analyse(M1, M2, M3, M4):
    avgF1 = float(sum(M1.values()))/len(M1)
    avgF2 = float(sum(M2.values()))/len(M2)
    avgF3 = float(sum(M3.values()))/len(M3)
    avgF4 = float(sum(M4.values()))/len(M4)
    diff1 = abs(avgF1 - avgF2)
    diff2 = abs(avgF3 - avgF4)
    if (diff1 > diff2) and avgF1 > avgF2:
        return "1"
    elif (diff2 > diff1) and avgF3 > avgF4:
        return "0"
    else:
        return "warn"


def correctKey(target, b, N):
    key0 = int(b + "0", 2)
    key1 = int(b + "1", 2)
    testMessage, res = groundTruth
    if pow(testMessage, key0, N) == res:
        return True, key0
    elif pow(testMessage, key1, N) == res:
        return True, key1
    return False, b


def attack(target, N, e):
    b = "1" # we know the initial key bit = 1
    messages = generateMessages(4000, target, N)
    R = montgomeryR(N)
    Ninv = modularInverse(N, R)
    mTemps = {m : montgomeryForm(m*m, N, R) for m in messages.keys()}
    correct = False
    while not correct:
        print "calculating next bit... ",
        M1, M2, mTemps1 = oracle1(messages, mTemps, N, e, R, Ninv)
        M3, M4, mTemps2 = oracle2(messages, mTemps, N, e, R, Ninv)
        nextBit = analyse(M1, M2, M3, M4)
        if nextBit == "1":
            mTemps = mTemps1
            b = b + "1"
        elif nextBit == "0":
            mTemps = mTemps2
            b = b + "0"
        else: # Error detected restart the operation...
            print "ERROR DETECTED! Rebuilding key..."
            b = "1"
            if len(messages) < 10000:
                messages.update(generateMessages(1000, target, N))
            else:
                print "CLEARING MESSAGE SET..."
                messages = generateMessages(4000, target, N)
            mTemps = {m: montgomeryForm( pow(pow(m, int(b, 2), N), 2, N) , N, R) for m in messages.keys()}
            continue
        correct, key = correctKey(target, b, N)
        print "Found bit! Key so far: " + "".join(b)
        if correct:
            print "FOUND KEY: " + "{0:b}".format(key)
            break
    print "\nKey: {0:X}".format(key)


def generateMessages(amount, target, N):
    print "Generating " + str(amount) + " messages... ",
    random.seed() # Seed internal PRNG with current time (don't really care too much about true randomness here...)
    messages = {}
    m = random.getrandbits(N.bit_length())
    res, time = communicate(target, m)
    messages[m] = time
    global groundTruth
    groundTruth = (m, res)
    while(len(messages) != amount):
        m = random.getrandbits(N.bit_length())
        while (m >= N):
            m = random.getrandbits(N.bit_length())
        res, time = communicate(target, m)
        messages[m] = time
    print "COMPLETE!"
    return messages


# This is the main function
def main():
    # Parse the config file.
    (N, e) = getParams(sys.argv[2])
    # Spin up a subprocess.
    target = subprocess.Popen(args=sys.argv[1], stdout=subprocess.PIPE, stdin=subprocess.PIPE)
    # Perform the attack
    attack(target, N, e)
    # Print the number of oracle interactions required
    print "Total oracle interactions: " + str(interactions)


if (__name__ == "__main__"):
    main()
