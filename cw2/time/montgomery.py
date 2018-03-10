# This stores the inverse of a mod N in inv. Algorithm only completes if gcd(a, N) == 1.
def modularInverse(a, N):
    (g, inv, _) = gcdExt(a, N)
    if g != 1:
        raise Exception("a and N are not co-prime!")
    return inv

# Returns the results of the extended Euclidean algorithm.
def gcdExt(a, b):
    s, sTemp, t, tTemp = 1, 0, 0, 1
    while b != 0:
        q, a, b = a / b, b, a % b
        s, sTemp = sTemp, s - q * sTemp
        t, tTemp = tTemp, t - q * tTemp
    return a, s, t


# Finds appropriate value of R for montgomery calculations.
def montgomeryR(N):
    # Set original R to base size of processor (2^64) in most cases
    Rorig = 2 ** 64
    R = Rorig

    # Cannot use an even N - protects against infinite loop!
    if (N & 1) == 0:
        raise Exception("Cannot use an even modulus!")

    # No need to check for co-prime condition as we know N is a semiprime...
    while (R < N):
        R = R * Rorig
    return R


# This algorithm is the montgomery reduction algorithm.
def montgomeryReduction(T, N, R, Ninv):
    m = (T * (-Ninv)) % R
    t = T + m*N
    t = (t / R) % N
    return t


# Given a and b in montgomery form it will compute and store (a*b) mod N in montgomery form.
def montgomeryMultiplication(aMont, bMont, N, R, Ninv):
    abRR = aMont * bMont
    return montgomeryReduction(abRR, N, R, Ninv)


# This function stores the montgomery form of integer a. I.e. aR (mod N)
def montgomeryForm(a, N, R):
    res = a * R
    return res % N