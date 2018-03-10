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


def oracle1(messages, b, N, e, R, Ninv):
    M1 = []
    M2 = []
    for m in messages:
        mTemp = (m ** int(b, 2)) ** 2
        mTempMont = montgomeryForm(mTemp, N, R)
        mMont = montgomeryForm(m, N, R)
        res = montgomeryMultiplication(mTempMont, mMont, N, R, Ninv)[0]
        res = montgomeryMultiplication(res, res, N, R, Ninv)[1]
        if res:
            M1.append(m)
        else:
            M2.append(m)
    return M1, M2


def oracle2(messages, b, N, e, R, Ninv):
    M3 = []
    M4 = []
    for m in messages:
        mTemp = (m ** int(b, 2)) ** 2
        mTempMont = montgomeryForm(mTemp, N, R)
        res = montgomeryMultiplication(mTempMont, mTempMont, N, R, Ninv)[1]
        if res:
            M3.append(m)
        else:
            M4.append(m)
    return M3, M4


def calculateTiming(target, M1, M2, M3, M4):
    # Perform the timing on each of the message arrays
    F1 = []
    F2 = []
    F3 = []
    F4 = []
    for m in M1:
        res, time = communicate(target, m)
        F1.append(time)
    for m in M2:
        res, time = communicate(target, m)
        F2.append(time)
    for m in M3:
        res, time = communicate(target, m)
        F3.append(time)
    for m in M4:
        res, time = communicate(target, m)
        F4.append(time)
    return F1, F2, F3, F4


def analyse(F1, F2, F3, F4):
    avgF1 = sum(F1)/len(F1)
    # print avgF1
    avgF2 = sum(F2)/len(F2)
    # print avgF2
    avgF3 = sum(F3)/len(F3)
    # print avgF3
    avgF4 = sum(F4)/len(F4)
    # print avgF4
    if (avgF1 > avgF2) and (abs(avgF3 - avgF4) < 20):
        return "1"
    elif (avgF3 > avgF4) and (abs(avgF1 - avgF2) < 20):
        return "0"
    else:
        raise Exception("Statistical analysis could not accurately predict the next key bit")


def attack(target, N, e):
    b = "1" # we know the initial key bit = 1
    lenN = N.bit_length()
    # messages = generateMessages(2000, lenN)
    messages = [7437547582898201166504790977009610016749607629859363723369068181167009518876199364654610230480145538179909148502618573185612444121691839267565803294923702420005740938330614081786981007239523341371497003489375266303038180338735276899083164028033783243467202599597567762300353895115906651794955198976961277782, 28322960429222631649519165870154768807551969381586638880015921551868899479825915114670445913524003181840626189062434078298169148285240351148854593202066887026127177236564723164830250463764344731177585826562788177010357956222963602960797909232584786281688554448416696221018039806357035293662240436721652725740]
    R = montgomeryR(N)
    Ninv = modularInverse(N, R)
    # for i in range(0, 63):
        # Step 1: calculate M1 -> M4
    M1, M2 = oracle1(messages, b, N, e, R, Ninv)
    M3, M4 = oracle2(messages, b, N, e, R, Ninv)
    # Step 2: calculate F1 -> F4 from attack target
    # F1, F2, F3, F4 = calculateTiming(target, M1, M2, M3, M4)
        # Step 3: predict the next key bit
        # nextBit = analyse(F1, F2, F3, F4)
        # b = nextBit + b
        # print i
    print b


def generateMessages(amount, bitLength):
    random.seed() # Seed internal PRNG with current time (don't really care too much about true randomness here...)
    messages = []
    for i in range(0, amount):
        messages.append(random.getrandbits(bitLength))
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
