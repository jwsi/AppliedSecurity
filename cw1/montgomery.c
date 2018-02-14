#include "montgomery.h"

// This stores the inverse of a mod N in inv. Algorithm only completes if gcd(a, N) == 1.
void modularInverse(mpz_t inv, const mpz_t a, const mpz_t N){
    mpz_t g, t;
    mpz_init(g);
    mpz_init(t);
    mpz_gcdext(g, inv, t, a, N); // set inv to modular inverse of a mod N.
    if (mpz_cmp_si (g, 1) != 0){ // Check to ensure gcd(a, N) is 1 (i.e. co-prime)
        abort();
    }
}

// Finds appropriate value of R for montgomery calculations
void montgomeryR(mpz_t R, const mpz_t N){
    mpz_t Rorig;
    mpz_init(Rorig);
    // Set original R to base size of processor (2^64)
    mpz_set_si(Rorig, 2);
    mpz_pow_ui(Rorig, Rorig, 64);
    mpz_set(R, Rorig);

    if (mpz_fdiv_ui(N, 2) == 0){ // Cannot use an even N - protects against infinite loop!
        abort();
    }

    // No need to check for co-prime condition as we know N is semiprime
    while(mpz_cmp(R, N) <= 0){
        mpz_mul(R, R, Rorig);
    }
}

// This algorithm is the montgomery reduction algorithm
void montgomeryReduction(mpz_t t, const mpz_t Tconst, const mpz_t N, const mpz_t R, const mpz_t NinvConst){
    mpz_t T;
    mpz_init(T);
    mpz_set(T, Tconst);
    // perform the montgomery reduction
    mpz_t m, Ninv, temp;
    mpz_init(Ninv);
    mpz_init(m);
    mpz_init(temp);
    // Calculate bit length of R
    long size = mpz_sizeinbase(R, 2);
    // setup m
    mpz_neg(Ninv, NinvConst);
    mpz_mul(temp, T, Ninv);
    mpz_fdiv_r_2exp(m, temp, size-1); // Replace mod operation with remainder from bit shift
    // setup t
    mpz_mul(t, m, N);
    mpz_add(temp, t, T);
    mpz_fdiv_q_2exp(t, temp, size-1); // We know R is an exact power of 2 so do a rightwards bit shift...

    if (mpz_cmp(t, N) >= 0){
        mpz_sub(t, t, N);
    }
}

// Given a and b in montgomery form it will compute and store (a*b) mod N in montgomery form.
void montgomeryMultiplication(mpz_t abMont, const mpz_t aMont, const mpz_t bMont, const mpz_t N, const mpz_t R, const mpz_t Ninv){
    mpz_t abRR;
    mpz_init(abRR);

    // compute aR * bR
    mpz_mul(abRR, aMont, bMont);

    montgomeryReduction(abMont, abRR, N, R, Ninv);
}

// Given b in montgomery form and k in integer form. Will store b^k in montgomery form.
void montgomeryExponentiation(mpz_t res, const mpz_t bConst, int k, const mpz_t N, const mpz_t R, const mpz_t Ninv){
    mpz_t b;
    mpz_init(b);
    mpz_set(b, bConst);
    mpz_set(res, b);
    for (int i = 1; i < k; i++){
        montgomeryMultiplication(res, res, b, N, R, Ninv);
    }
}

// This function stores the montgomery form of integer a. I.e. aR (mod N)
void montgomeryForm(mpz_t res, const mpz_t a, const mpz_t N, const mpz_t R){
    // compute aR (mod N)
    mpz_mul(res, a, R);
    mpz_mod(res, res, N);
}
