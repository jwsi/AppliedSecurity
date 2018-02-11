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
    mpz_t temp;
    mpz_init(temp);
    mpz_set_si(R, 1);
    mpz_gcd(temp, R, N);

    if (mpz_fdiv_ui(N, 2) == 0){ // Cannot use an even N - protects against infinite loop!
        abort();
    }

    while(mpz_cmp(R, N) <= 0 || mpz_cmp_si(temp, 1) != 0){
        mpz_mul_si(R, R, 2);
        mpz_gcd(temp, R, N);
    }
}

// This algorithm is the montgomery reduction algorithm
void montgomeryReduction(mpz_t t, const mpz_t Tconst, const mpz_t N, const mpz_t R){
    mpz_t T;
    mpz_init(T);
    mpz_set(T, Tconst);
    // perform the montgomery reduction
    mpz_t Ninv, m;
    mpz_init(Ninv);
    mpz_init(m);
    // find N^-1 mod R
    modularInverse(Ninv, N, R);
    // setup m
    mpz_neg(Ninv, Ninv);
    mpz_mul(m, T, Ninv);
    mpz_mod(m, m, R);
    // setup t
    mpz_mul(t, m, N);
    mpz_add(t, t, T);
    mpz_div(t, t, R);
    // deal with mod operation efficiently
    if (mpz_cmp(t, N) >= 0){
        mpz_sub(t, t, N);
    }
}

// Given a and b in montgomery form it will compute and return (a*b) mod N in montgomery form.
void montgomeryMultiplication(mpz_t abMont, const mpz_t aMont, const mpz_t bMont, const mpz_t N, const mpz_t R){
    mpz_t abRR;
    mpz_init(abRR);

    // compute aR * bR
    mpz_mul(abRR, aMont, bMont);

    montgomeryReduction(abMont, abRR, N, R);
}

// Given b in montgomery form and k in integer form. Will output b^k in montgomery form.
void montgomeryExponentiation(mpz_t res, const mpz_t b, int k, const mpz_t N, const mpz_t R){
    mpz_set(res, b);
    for (int i = 1; i < k; i++){
        montgomeryMultiplication(res, res, b, N, R);
    }
}

// This function returns the montgomery form of integer a. I.e. aR (mod N)
void montgomeryForm(mpz_t r, const mpz_t a, const mpz_t N, const mpz_t R){
    // compute aR (mod N)
    mpz_mul(r, a, R);
    mpz_mod(r, r, N);
}
