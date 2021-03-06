from matrices import s_inv, multiply_table

# From the paper this calculates the possible set of delta 1 values (Section 3.1)
def find_delta1_keys(x, xF):
    k_0_7_10_13 = []
    for k0 in range(256):
        line1 = s_inv[x[0] ^ k0] ^ s_inv[xF[0] ^ k0]
        delta1 = multiply_table[line1][141] # 2^-1 = 141 in Rijndael GF2^8 field

        for k13 in range(256):
            line2 = s_inv[x[13] ^ k13] ^ s_inv[xF[13] ^ k13]
            if line2 == delta1:

                for k10 in range(256):
                    line3 = s_inv[x[10] ^ k10] ^ s_inv[xF[10] ^ k10]
                    if line3 == delta1:

                        for k7 in range(256):
                            line4 = s_inv[x[7] ^ k7] ^ s_inv[xF[7] ^ k7]
                            if multiply_table[line4][246] == delta1: # 3^-1 = 246 in Rijndael GF2^8 field
                                k_0_7_10_13.append([k0, k7, k10, k13])
    k_0_7_10_13.sort()
    return k_0_7_10_13


# From the paper this calculates the possible set of delta 2 values (Section 3.1)
def find_delta2_keys(x, xF):
    k_1_4_11_14 = []
    for k4 in range(256):
        delta2 = s_inv[x[4] ^ k4] ^ s_inv[xF[4] ^ k4]

        for k1 in range(256):
            line2 = s_inv[x[1] ^ k1] ^ s_inv[xF[1] ^ k1]
            if line2 == delta2:

                for k14 in range(256):
                    line3 = s_inv[x[14] ^ k14] ^ s_inv[xF[14] ^ k14]
                    if multiply_table[line3][246] == delta2: # 3^-1 = 246 in Rijndael GF2^8 field

                        for k11 in range(256):
                            line4 = s_inv[x[11] ^ k11] ^ s_inv[xF[11] ^ k11]
                            if multiply_table[line4][141] == delta2: # 2^-1 = 141 in Rijndael GF2^8 field
                                k_1_4_11_14.append([k1, k4, k11, k14])
    k_1_4_11_14.sort()
    return k_1_4_11_14


# From the paper this calculates the possible set of delta 3 values (Section 3.1)
def find_delta3_keys(x, xF):
    k_2_5_8_15 = []
    for k8 in range(256):
        delta3 = s_inv[x[8] ^ k8] ^ s_inv[xF[8] ^ k8]

        for k5 in range(256):
            line2 = s_inv[x[5] ^ k5] ^ s_inv[xF[5] ^ k5]
            if multiply_table[line2][246] == delta3: # 3^-1 = 246 in Rijndael GF2^8 field

                for k2 in range(256):
                    line3 = s_inv[x[2] ^ k2] ^ s_inv[xF[2] ^ k2]
                    if multiply_table[line3][141] == delta3: # 2^-1 = 141 in Rijndael GF2^8 field

                        for k15 in range(256):
                            line4 = s_inv[x[15] ^ k15] ^ s_inv[xF[15] ^ k15]
                            if line4 == delta3:
                                k_2_5_8_15.append([k2, k5, k8, k15])
    k_2_5_8_15.sort()
    return k_2_5_8_15


# From the paper this calculates the possible set of delta 4 values (Section 3.1)
def find_delta4_keys(x, xF):
    k_3_6_9_12 = []
    for k12 in range(256):
        line1 = s_inv[x[12] ^ k12] ^ s_inv[xF[12] ^ k12]
        delta4 = multiply_table[line1][246] # 3^-1 = 246 in Rijndael GF2^8 field

        for k9 in range(256):
            line2 = s_inv[x[9] ^ k9] ^ s_inv[xF[9] ^ k9]
            if multiply_table[line2][141] == delta4: # 2^-1 = 141 in Rijndael GF2^8 field

                for k6 in range(256):
                    line3 = s_inv[x[6] ^ k6] ^ s_inv[xF[6] ^ k6]
                    if line3 == delta4:

                        for k3 in range(256):
                            line4 = s_inv[x[3] ^ k3] ^ s_inv[xF[3] ^ k3]
                            if line4 == delta4:
                                k_3_6_9_12.append([k3, k6, k9 , k12])
    k_3_6_9_12.sort()
    return k_3_6_9_12
