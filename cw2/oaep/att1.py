# Copyright (C) 2017 Daniel Page <csdsp@bristol.ac.uk>
#
# Use of this source code is restricted per the CC BY-NC-ND license, a copy of
# which can be found via http://creativecommons.org (and should be included as
# LICENSE.txt within the associated archive or repository).

import sys, subprocess

def getParams(file):
    print "Attempting to parse the config file..."
    conf = open(file, "r")
    N = int(conf.readline(), 16)
    print "N (RSA Modulus): " + str(N)
    e = int(conf.readline(), 16)
    print "e (public exponent): " + str(e)
    l = conf.readline()[:-1]
    print "l (octal OAEP label): " + str(l)
    c = conf.readline()[:-1]
    print "c (octal ciphertext): " + str(c)
    conf.close()
    return (N, e, l, c)

def communicate(l, c):
    # Send G to attack target.
    target.stdin.write(l + "\n")
    target.stdin.write(c + "\n")
    target.stdin.flush()

    # Receive ( t, r ) from attack target.
    result = int(target.stdout.readline().strip())
    return result

if (__name__ == "__main__"):
    # Read in and parse the config file
    (N, e, l, c) = getParams(sys.argv[2])

    print sys.argv[1]
    target = subprocess.Popen(args=["noah", sys.argv[1]], stdout=subprocess.PIPE, stdin=subprocess.PIPE)

    result = communicate(l, c)
    print result
    #
    # # Construct handles to attack target standard input and output.
    # target_out = target.stdout
    # target_in = target.stdin
    #
    # # Execute a function representing the attacker.
    # attack()
