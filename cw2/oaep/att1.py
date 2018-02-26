import sys, subprocess, math



# This function extracts parameters from a config file
def getParams(file):
    print "Attempting to parse the config file..."
    conf = open(file, "r")
    N = int(conf.readline(), 16)
    print "N (RSA Modulus): " + str(N)
    e = int(conf.readline(), 16)
    print "e (public exponent): " + str(e)
    l = conf.readline()[:-1] # remove newline
    print "l (octal OAEP label): " + str(l)
    c = conf.readline()[:-1] # remove newline
    print "c (octal ciphertext): " + str(c)
    conf.close()
    return (N, e, l, c)


# This function communicates with the attack target
def communicate(target, l, c):
    # Send label & ciphertext to attack target.
    target.stdin.write(l + "\n")
    target.stdin.write(c + "\n")
    target.stdin.flush()

    # Receive result code from attack target.
    result = int(target.stdout.readline().strip())
    return result


# This is the main function
def main():
    # Parse the config file.
    (N, e, l, c) = getParams(sys.argv[2])
    # Construct the variables required for an attack.
    k = int(math.ceil(math.log(N, 256)))
    B = 2 ** (8 * (k - 1))

    # Spin up a subprocess.
    target = subprocess.Popen(args=["noah", sys.argv[1]], stdout=subprocess.PIPE, stdin=subprocess.PIPE)

    # Begin the attack
    result = communicate(target, l, c)
    print result


if (__name__ == "__main__"):
    main()
