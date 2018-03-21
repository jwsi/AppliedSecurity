import sys, subprocess
from fault import Fault

# Define global variable for interactions with oracle
interactions = 0


# This function communicates with the attack target
def communicate(target, m, f):
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


# This is the main function
def main():
    # Spin up a subprocess.
    target = subprocess.Popen(args=["noah", sys.argv[1]], stdout=subprocess.PIPE, stdin=subprocess.PIPE)
    # Perform the attack

    # Print the key

    # Print the number of oracle interactions required
    print "Total oracle interactions: " + str(interactions)


if (__name__ == "__main__"):
    main()
