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
    print "COMPLETE!"
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


def oracle1(messages, mTemps1, b, N, e, R, Ninv):
    M1 = {}
    M2 = {}
    for m, time in messages.iteritems():
        mMont = montgomeryForm(m, N, R)
        res = montgomeryMultiplication(mTemps1[m], mMont, N, R, Ninv)[0]
        res, reduced = montgomeryMultiplication(res, res, N, R, Ninv)
        mTemps1[m] = res
        if reduced:
            M1[m] = time
        else:
            M2[m] = time
    return M1, M2, mTemps1


def oracle2(messages, mTemps2, b, N, e, R, Ninv):
    M3 = {}
    M4 = {}
    for m, time in messages.iteritems():
        res, reduced = montgomeryMultiplication(mTemps2[m], mTemps2[m], N, R, Ninv)
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
    if (avgF1 > avgF2) and (abs(1-(avgF3/avgF4)) < 0.05):
        return "1"
    elif (avgF3 > avgF4) and (abs(1-(avgF1/avgF2)) < 0.05):
        return "0"
    else:
        raise Exception("Statistical analysis could not accurately predict the next key bit")


def attack(target, N, e):
    b = "1" # we know the initial key bit = 1
    messages = generateMessages(1500, target, N)
    R = montgomeryR(N)
    Ninv = modularInverse(N, R)
    mTemps1 = {m : montgomeryForm(m*m, N, R) for m in messages.keys()}
    mTemps2 = mTemps1.copy()
    for i in range(0, 63):
        print "calculating bit " + str(63 - i),
        M1, M2, mTemps1 = oracle1(messages, mTemps1, b, N, e, R, Ninv)
        M3, M4, mTemps2 = oracle2(messages, mTemps2, b, N, e, R, Ninv)
        nextBit = analyse(M1, M2, M3, M4)
        b = b + nextBit
        print " key so far... " + b
    print "{0:X}".format(int(b, 2))


def generateMessages(amount, target, N):
    random.seed() # Seed internal PRNG with current time (don't really care too much about true randomness here...)
    messages = {}
    for i in range(0, amount):
        m = random.getrandbits(N.bit_length()) % N
        _, time = communicate(target, m)
        messages[m] = time
    return messages


# This is the main function
def main():
    # Parse the config file.
    (N, e) = getParams(sys.argv[2])
    # Spin up a subprocess.
    target = subprocess.Popen(args=["noah", sys.argv[1]], stdout=subprocess.PIPE, stdin=subprocess.PIPE)
    # Perform the attack
    attack(target, N, e)
    # Retrieve the key

    # Print the number of oracle interactions required
    print "Total oracle interactions: " + str(interactions)


if (__name__ == "__main__"):
    main()
