import sys, subprocess, math

# Define global variable for interactions with oracle
interactions = 0

# This function extracts parameters from a config file
def getParams(file):
    print "Attempting to parse the config file..."
    conf = open(file, "r")
    N = int(conf.readline(), 16)
    print "N (RSA Modulus): "      + str(N)
    e = int(conf.readline(), 16)
    print "e (public exponent): "  + str(e)
    l = int(conf.readline(), 16)
    print "l (octet OAEP label): " + str(l)
    c = int(conf.readline(), 16)
    print "c (octet ciphertext): " + str(c) + "\n"
    conf.close()
    return (N, e, l, c)


# This function communicates with the attack target
def communicate(target, l, c):
    global interactions
    # Send label & ciphertext to attack target.
    ctxt  = hex(c)[2:-1].upper().zfill(256)
    label = hex(l)[2:-1].upper().zfill(256)
    target.stdin.write(label + "\n")
    target.stdin.write(ctxt  + "\n")
    target.stdin.flush()

    # Receive result code from attack target.
    result = int(target.stdout.readline().strip())
    interactions += 1
    return result


# This function performs step 1 from Manger's paper
def step1(target, e, c, l, N):
    print "Starting step 1 of the attack..."
    f1 = 1
    resultCode = 0
    while resultCode != 1:
        f1 = f1 * 2
        challenge  = pow(f1, e, N)
        challenge  = (challenge * c) % N
        resultCode = communicate(target, l, challenge)
    print "f1 = " + str(f1) + "\n"
    return f1


# This function performs step 2 from Manger's paper
def step2(target, l, f1, e, c, N, B):
    print "Starting step 2 of the attack..."
    f2 = divFloor((N+B), B) * (f1 / 2)
    challenge  = pow(f2, e, N)
    challenge  = (challenge * c) % N
    resultCode = communicate(target, l, challenge)
    while resultCode == 1:
        f2 = f2 + (f1 / 2)
        challenge  = pow(f2, e, N)
        challenge  = (challenge * c) % N
        resultCode = communicate(target, l, challenge)
    print "f2 = " + str(f2) + "\n"
    return f2


# This function performs step 3 from Manger's paper
def step3(target, l, f2, e, c, N, B, k):
    print "Starting step 3 of the attack..."
    m_min = divCeil ( N    , f2 )
    m_max = divFloor( (N+B), f2 )
    while m_min != m_max:
        f_tmp = divFloor( (2 * B)        , (m_max - m_min) )
        i     = divFloor( (f_tmp * m_min), N               )
        f3    = divCeil ( (i * N)        , m_min           )

        challenge  = pow(f3, e, N)
        challenge  = (challenge * c) % N
        resultCode = communicate(target, l, challenge)

        if resultCode == 1:
            m_min = divCeil ( (i * N + B), f3 )
        else:
            m_max = divFloor( (i * N + B), f3 )
    print "f3 = " + str(f3)
    print "encoded plaintext (octet string): " + hex(c)[2:-1].upper().zfill(256) + "\n"
    return m_max


# This function returns the floor of a/b
def divFloor(a, b):
    mod = a % b
    multiple = a - mod
    return multiple / b


# This function returns the ceiling of a/b
def divCeil(a, b):
    mod = a % b
    if mod == 0:
        return a/b
    multiple = a - mod
    return multiple/b + 1



# This is the main function
def main():
    # Parse the config file.
    (N, e, l, c) = getParams(sys.argv[2])
    k = int(math.ceil(math.log(N, 256)))
    B = pow(2, (8 * (k - 1)))
    # Spin up a subprocess.
    target = subprocess.Popen(args=["noah", sys.argv[1]], stdout=subprocess.PIPE, stdin=subprocess.PIPE)
    # Perform the attack
    f1 = step1(target, e, c, l, N)
    f2 = step2(target, l, f1, e, c, N, B)
    encoded_m = step3(target, l, f2, e, c, N, B, k)
    # Decode the message
    # Print the number of oracle interactions required
    print interactions


if (__name__ == "__main__"):
    main()
