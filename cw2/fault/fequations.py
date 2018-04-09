from matrices import s, sInv, multiplyTable, rcon

# From the paper this refines the keyset using the equations in Section 3.3
def fEquation1(x, xF, k):
    f2 = sInv[ multiplyTable[14][ sInv[ x[0]   ^ k[0]  ] ^ (k[0] ^ s[ k[13] ^ k[9]  ] ^ rcon[10]) ]
             ^ multiplyTable[11][ sInv[ x[13]  ^ k[13] ] ^ (k[1] ^ s[ k[14] ^ k[10] ])            ]
             ^ multiplyTable[13][ sInv[ x[10]  ^ k[10] ] ^ (k[2] ^ s[ k[15] ^ k[11] ])            ]
             ^ multiplyTable[ 9][ sInv[ x[7]   ^ k[7]  ] ^ (k[3] ^ s[ k[12] ^ k[8]  ])            ] ]\
       ^ sInv[ multiplyTable[14][ sInv[ xF[0]  ^ k[0]  ] ^ (k[0] ^ s[ k[13] ^ k[9]  ] ^ rcon[10]) ]
             ^ multiplyTable[11][ sInv[ xF[13] ^ k[13] ] ^ (k[1] ^ s[ k[14] ^ k[10] ])            ]
             ^ multiplyTable[13][ sInv[ xF[10] ^ k[10] ] ^ (k[2] ^ s[ k[15] ^ k[11] ])            ]
             ^ multiplyTable[ 9][ sInv[ xF[7]  ^ k[7]  ] ^ (k[3] ^ s[ k[12] ^ k[8]  ])            ] ]

    return multiplyTable[f2][141] # 2^-1 = 141 in Rijndael GF2^8 field


# From the paper this refines the keyset using the equations in Section 3.3
def fEquation2(x, xF, k):
    f = sInv[ multiplyTable[ 9][ sInv[ x[12]  ^ k[12] ] ^ (k[12]  ^ k[8]) ]
            ^ multiplyTable[14][ sInv[ x[9]   ^ k[9]  ] ^ (k[9]  ^ k[13]) ]
            ^ multiplyTable[11][ sInv[ x[6]   ^ k[6]  ] ^ (k[14] ^ k[10]) ]
            ^ multiplyTable[13][ sInv[ x[3]   ^ k[3]  ] ^ (k[15] ^ k[11]) ] ]\
      ^ sInv[ multiplyTable[ 9][ sInv[ xF[12] ^ k[12] ] ^ (k[12] ^ k[8])  ]
            ^ multiplyTable[14][ sInv[ xF[9]  ^ k[9]  ] ^ (k[9]  ^ k[13]) ]
            ^ multiplyTable[11][ sInv[ xF[6]  ^ k[6]  ] ^ (k[14] ^ k[10]) ]
            ^ multiplyTable[13][ sInv[ xF[3]  ^ k[3]  ] ^ (k[15] ^ k[11]) ] ]

    return f


# From the paper this refines the keyset using the equations in Section 3.3
def fEquation3(x, xF, k):
    f = sInv[ multiplyTable[13][ sInv[ x[8]   ^ k[8]  ] ^ (k[8]  ^ k[4])  ]
            ^ multiplyTable[ 9][ sInv[ x[5]   ^ k[5]  ] ^ (k[9]  ^ k[5])  ]
            ^ multiplyTable[14][ sInv[ x[2]   ^ k[2]  ] ^ (k[10] ^ k[6])  ]
            ^ multiplyTable[11][ sInv[ x[15]  ^ k[15] ] ^ (k[11] ^ k[7])  ] ]\
      ^ sInv[ multiplyTable[13][ sInv[ xF[8]  ^ k[8]  ] ^ (k[8]  ^ k[4])  ]
            ^ multiplyTable[ 9][ sInv[ xF[5]  ^ k[5]  ] ^ (k[9]  ^ k[5])  ]
            ^ multiplyTable[14][ sInv[ xF[2]  ^ k[2]  ] ^ (k[10] ^ k[6])  ]
            ^ multiplyTable[11][ sInv[ xF[15] ^ k[15] ] ^ (k[11] ^ k[7])  ] ]

    return f


# From the paper this refines the keyset using the equations in Section 3.3
def fEquation4(x, xF, k):
    f3 = sInv[ multiplyTable[11][ sInv[ x[4]   ^ k[4]  ] ^ (k[4]  ^ k[0])  ]
            ^ multiplyTable[13][ sInv[ x[1]   ^ k[1]  ] ^ (k[5]  ^ k[1])  ]
            ^ multiplyTable[ 9][ sInv[ x[14]  ^ k[14] ] ^ (k[6]  ^ k[2])  ]
            ^ multiplyTable[14][ sInv[ x[11]  ^ k[11] ] ^ (k[7]  ^ k[3])  ] ]\
      ^ sInv[ multiplyTable[11][ sInv[ xF[4]  ^ k[4]  ] ^ (k[4]  ^ k[0])  ]
            ^ multiplyTable[13][ sInv[ xF[1]  ^ k[1]  ] ^ (k[5]  ^ k[1])  ]
            ^ multiplyTable[ 9][ sInv[ xF[14] ^ k[14] ] ^ (k[6]  ^ k[2])  ]
            ^ multiplyTable[14][ sInv[ xF[11] ^ k[11] ] ^ (k[7]  ^ k[3])  ] ]

    return multiplyTable[f3][246] # 3^-1 = 246 in Rijndael GF2^8 field
