import sys, subprocess, math, hashlib

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
def communicate(target, l, c):
    global interactions
    # Send label & ciphertext to attack target.
    ctxt  = "{0:0256X}".format(c)
    label = "{0:X}".format(l)
    target.stdin.write(label + "\n")
    target.stdin.write(ctxt  + "\n")
    target.stdin.flush()

    # Receive result code from attack target.
    result = int(target.stdout.readline().strip())
    interactions += 1
    return result





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


# This function implements XOR of hex strings and pads to fit input length
def hexXOR(a, b):
    a_int = int(a, 16)
    b_int = int(b, 16)
    pad = str(max(len(a), len(b)))
    return ("{0:0" + pad + "X}").format(a_int ^ b_int)


# This is the main function
def main():
    # Parse the config file.
    (N, e) = getParams(sys.argv[2])
    # Spin up a subprocess.
    target = subprocess.Popen(args=["noah", sys.argv[1]], stdout=subprocess.PIPE, stdin=subprocess.PIPE)
    # Perform the attack

    # Retrieve the key

    # Print the number of oracle interactions required
    print "Total oracle interactions: " + str(interactions)


if (__name__ == "__main__"):
    main()
