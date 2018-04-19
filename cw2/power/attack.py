import sys, subprocess, time

# Define global variable for interactions with oracle
sample_size = 1
interactions = 0

# This function communicates with the attack target and returns a power trace and a plaintext message
def communicate(target, sector, block):
    global interactions
    # Send fault + plaintext to attack target
    sector_string = "{0:032X}".format(sector) # Pad sector to 32 HEX chars
    block_string  = str(block)
    target.stdin.write(block_string  + "\n")
    target.stdin.write(sector_string + "\n")
    target.stdin.flush()

    # Receive ciphertext from attack target.
    power_trace = target.stdout.readline().strip().split(",")[1:]
    msg         = int(target.stdout.readline().strip(), 16)
    interactions += 1
    return power_trace, msg

# This function generates a number of power traces equal to the sample_size
def generate_traces(target):
    power_traces = []
    for i in range(sample_size):
        power_traces.append(communicate(target, 1, 1)[0])
    return power_traces


# This is the main function of the attack
def main():
    start = time.time()
    # Spin up a subprocess.
    target = subprocess.Popen(args=["noah", sys.argv[1]], stdout=subprocess.PIPE, stdin=subprocess.PIPE)
    # Perform the attack

    power_traces = generate_traces(target)

    end = time.time()
    print "Time taken: " + str(round(end - start, 3)) + " seconds\n"
    # Print the target material recovered
    # print "Key successfully recovered (hex string): " + "{0:X}".format(key)
    # Print the number of oracle interactions required
    print "Total oracle interactions: " + str(interactions)


if (__name__ == "__main__"):
    main()
