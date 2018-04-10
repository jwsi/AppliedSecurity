from matrices import s, s_inv, multiply_table, rcon

# From the paper this refines the keyset using the equations in Section 3.3
def f_equation1(x, xF, k):
    f2 = s_inv[  multiply_table[14][s_inv[x[ 0] ^ k[ 0]] ^ (k[0] ^ s[k[13] ^ k[ 9]] ^ rcon[10])]
               ^ multiply_table[11][s_inv[x[13] ^ k[13]] ^ (k[1] ^ s[k[14] ^ k[10]])]
               ^ multiply_table[13][s_inv[x[10] ^ k[10]] ^ (k[2] ^ s[k[15] ^ k[11]])]
               ^ multiply_table[ 9][s_inv[x[ 7] ^ k[ 7]] ^ (k[3] ^ s[k[12] ^ k[ 8]])]] \
       ^ s_inv[  multiply_table[14][s_inv[xF[ 0] ^ k[ 0]] ^ (k[0] ^ s[k[13] ^ k[ 9]] ^ rcon[10])]
               ^ multiply_table[11][s_inv[xF[13] ^ k[13]] ^ (k[1] ^ s[k[14] ^ k[10]])]
               ^ multiply_table[13][s_inv[xF[10] ^ k[10]] ^ (k[2] ^ s[k[15] ^ k[11]])]
               ^ multiply_table[ 9][s_inv[xF[ 7] ^ k[ 7]] ^ (k[3] ^ s[k[12] ^ k[ 8]])]]

    return multiply_table[f2][141] # 2^-1 = 141 in Rijndael GF2^8 field


# From the paper this refines the keyset using the equations in Section 3.3
def f_equation2(x, xF, k):
    f = s_inv[  multiply_table[ 9][s_inv[x[12] ^ k[12]] ^ (k[12] ^ k[ 8])]
              ^ multiply_table[14][s_inv[x[ 9] ^ k[ 9]] ^ (k[ 9] ^ k[13])]
              ^ multiply_table[11][s_inv[x[ 6] ^ k[ 6]] ^ (k[14] ^ k[10])]
              ^ multiply_table[13][s_inv[x[ 3] ^ k[ 3]] ^ (k[15] ^ k[11])]] \
      ^ s_inv[  multiply_table[ 9][s_inv[xF[12] ^ k[12]] ^ (k[12] ^ k[ 8])]
              ^ multiply_table[14][s_inv[xF[ 9] ^ k[ 9]] ^ (k[ 9] ^ k[13])]
              ^ multiply_table[11][s_inv[xF[ 6] ^ k[ 6]] ^ (k[14] ^ k[10])]
              ^ multiply_table[13][s_inv[xF[ 3] ^ k[ 3]] ^ (k[15] ^ k[11])]]

    return f


# From the paper this refines the keyset using the equations in Section 3.3
def f_equation3(x, xF, k):
    f = s_inv[  multiply_table[13][s_inv[x[ 8] ^ k[ 8]] ^ (k[ 8] ^ k[4])]
              ^ multiply_table[ 9][s_inv[x[ 5] ^ k[ 5]] ^ (k[ 9] ^ k[5])]
              ^ multiply_table[14][s_inv[x[ 2] ^ k[ 2]] ^ (k[10] ^ k[6])]
              ^ multiply_table[11][s_inv[x[15] ^ k[15]] ^ (k[11] ^ k[7])]] \
      ^ s_inv[  multiply_table[13][s_inv[xF[ 8] ^ k[ 8]] ^ (k[ 8] ^ k[4])]
              ^ multiply_table[ 9][s_inv[xF[ 5] ^ k[ 5]] ^ (k[ 9] ^ k[5])]
              ^ multiply_table[14][s_inv[xF[ 2] ^ k[ 2]] ^ (k[10] ^ k[6])]
              ^ multiply_table[11][s_inv[xF[15] ^ k[15]] ^ (k[11] ^ k[7])]]

    return f


# From the paper this refines the keyset using the equations in Section 3.3
def f_equation4(x, xF, k):
    f3 = s_inv[  multiply_table[11][s_inv[x[ 4] ^ k[ 4]] ^ (k[4] ^ k[0])]
               ^ multiply_table[13][s_inv[x[ 1] ^ k[ 1]] ^ (k[5] ^ k[1])]
               ^ multiply_table[ 9][s_inv[x[14] ^ k[14]] ^ (k[6] ^ k[2])]
               ^ multiply_table[14][s_inv[x[11] ^ k[11]] ^ (k[7] ^ k[3])]] \
       ^ s_inv[  multiply_table[11][s_inv[xF[ 4] ^ k[ 4]] ^ (k[4] ^ k[0])]
               ^ multiply_table[13][s_inv[xF[ 1] ^ k[ 1]] ^ (k[5] ^ k[1])]
               ^ multiply_table[ 9][s_inv[xF[14] ^ k[14]] ^ (k[6] ^ k[2])]
               ^ multiply_table[14][s_inv[xF[11] ^ k[11]] ^ (k[7] ^ k[3])]]

    return multiply_table[f3][246] # 3^-1 = 246 in Rijndael GF2^8 field
