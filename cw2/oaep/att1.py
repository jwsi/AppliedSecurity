import sys, subprocess, math, hashlib
from decimal import Decimal


# This function extracts parameters from a config file
def getParams(file):
    print "Attempting to parse the config file..."
    conf = open(file, "r")
    N = int(conf.readline(), 16)
    print "N (RSA Modulus): "      + str(N)
    e = int(conf.readline(), 16)
    print "e (public exponent): "  + str(e)
    l = int(conf.readline(), 16)
    print "l (octal OAEP label): " + str(l)
    c = int(conf.readline(), 16)
    print "c (octal ciphertext): " + str(c) + "\n"
    conf.close()
    return (N, e, l, c)


# This function communicates with the attack target
def communicate(target, l, c):
    # Send label & ciphertext to attack target.
    ctxt  = hex(c)[2:-1].upper().zfill(256)
    label = hex(l)[2:-1].upper().zfill(256)
    target.stdin.write(label + "\n")
    target.stdin.write(ctxt  + "\n")
    target.stdin.flush()

    # Receive result code from attack target.
    result = int(target.stdout.readline().strip())
    return result


def step1(target, e, c, l, N):
    # We know m is in [0, B] and f1 * m is in [0, 2B]
    print "Starting step 1 of the attack..."
    f1 = 1
    resultCode = 0
    while resultCode != 1:
        f1 = f1 * 2
        challenge = pow(f1, e, N)
        challenge = (challenge * c) % N
        resultCode = communicate(target, l, challenge)
    print "f1 = " + str(f1) + "\n"
    return f1


def step2(target, l, f1, e, c, N, B):
    print "Starting step 2 of the attack..."
    # Now f1*m is in [B, 2B] therefore f1/2 * m is in [B/2, B]
    f2 = int(math.floor(Decimal (N+B)/B) * f1/2)
    challenge = pow(f2, e, N)
    challenge = (challenge * c) % N
    print hex(challenge)[2:-1].upper()
    resultCode = communicate(target, l, challenge)
    while resultCode == 1:
        f2 = f2 + (f1 / 2)
        challenge = pow(f2, e, N)
        challenge = (challenge * c) % N
        print hex(challenge)[2:-1].upper()
        resultCode = communicate(target, l, challenge)
    print "f2 = " + str(f2) + "\n"
    return f2


def step3(target, l, f2, e, c, N, B, k):
    print "Starting step 3 of the attack..."
    m_min = int(math.ceil( Decimal   (N) /f2 ))
    m_max = int(math.floor(Decimal  (N+B)/f2 ))
    while m_min != m_max:
        f_tmp = int(math.floor(Decimal  (2 * B) / (m_max - m_min) ))
        i     = int(math.floor(Decimal  (f_tmp * m_min) / N       ))
        f3    = int(math.ceil( Decimal  (i * N) / m_min           ))
        challenge = pow(f3, e, N)
        challenge = (challenge * c) % N
        resultCode = communicate(target, l, challenge)
        if resultCode == 1:
            m_min = int(math.ceil(  (i * N + B)/f3 ))
        else:
            m_max = int(math.floor( (i * N + B)/f3 ))
        print m_max - m_min

    challenge = pow(m_max, e, N)
    print c
    print challenge
    print hex(m_max)[2:-1].upper()

    print resultCode
    print "f3 = " + str(f3) + "\n"



# This is the main function
def main():
    # Parse the config file.
    (N, e, l, c) = getParams(sys.argv[2])
    k = int(math.ceil(math.log(N, 256)))
    B = pow(2, (8 * (k - 1)))
    # Spin up a subprocess.
    target = subprocess.Popen(args=["noah", sys.argv[1]], stdout=subprocess.PIPE, stdin=subprocess.PIPE)

    f1 = step1(target, e, c, l, N)
    f2 = step2(target, l, f1, e, c, N, B)
    step3(target, l, f2, e, c, N, B, k)


if (__name__ == "__main__"):
    main()
