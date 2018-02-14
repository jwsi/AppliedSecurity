#ifndef __MONTGOMERY_H
#define __MONTGOMERY_H

#include  <stdio.h>
#include <stdlib.h>

#include <string.h>
#include    <gmp.h>

// This stores the inverse of a mod N in inv. Algorithm only completes if gcd(a, N) == 1.
void modularInverse(mpz_t inv, const mpz_t a, const mpz_t N);

// Finds appropriate value of R for montgomery calculations
void montgomeryR(mpz_t R, const mpz_t N);

// This algorithm is the montgomery reduction algorithm
void montgomeryReduction(mpz_t t, const mpz_t Tconst, const mpz_t N, const mpz_t R);

// Given a and b in montgomery form it will compute and store (a*b) mod N in montgomery form.
void montgomeryMultiplication(mpz_t abMont, const mpz_t aMont, const mpz_t bMont, const mpz_t N, const mpz_t R);

// Given b in montgomery form and k in integer form. Will store b^k in montgomery form.
void montgomeryExponentiation(mpz_t res, const mpz_t bConst, int k, const mpz_t N, const mpz_t R);

// This function stores the montgomery form of integer a. I.e. aR (mod N)
void montgomeryForm(mpz_t res, const mpz_t a, const mpz_t N, const mpz_t R);

#endif
