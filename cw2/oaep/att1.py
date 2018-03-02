import sys, subprocess, math


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
    c = hex(c)[2:].upper()
    l = hex(l)[2:].upper()
    target.stdin.write(l + "\n")
    target.stdin.write(c + "\n")
    target.stdin.flush()

    # Receive result code from attack target.
    result = int(target.stdout.readline().strip())
    return result


def step1(target, e, c, l, N):
    # We know m is in [0, B] and f1 * m is in [0, 2B]
    print "Starting step 1 of the attack..."
    f1 = 2
    resultCode = 0
    while resultCode != 1:
        challenge = pow(f1, e, N)
        challenge = (challenge * c) % N
        resultCode = communicate(target, l, challenge)
        f1 = f1 * 2
    print "f1 = " + str(f1) + "\n"
    return f1


def step2(target, l, f1, N):
    print "Starting step 2 of the attack..."
    # Now f1*m is in [B, 2B] therefore f1/2 * m is in [B/2, B]
    k = int(math.ceil(math.log(N, 256)))
    B = pow(2, (8 * (k - 1)))
    f2 = int(math.floor(float(N+B)/B) * f1/2)
    resultCode = 1
    while resultCode == 1:
        resultCode = communicate(target, l, f2)
        f2 = f2 + f1/2
    print "f2 = " + str(f2) + "\n"
    return f2





# This is the main function
def main():
    # Parse the config file.
    (N, e, l, c) = getParams(sys.argv[2])

    # Spin up a subprocess.
    target = subprocess.Popen(args=["noah", sys.argv[1]], stdout=subprocess.PIPE, stdin=subprocess.PIPE)
    f1 = step1(target, e, c, l, N)
    step2(target, l, f1, N)


if (__name__ == "__main__"):
    main()
