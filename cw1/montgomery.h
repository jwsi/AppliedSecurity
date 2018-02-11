#ifndef __MONTGOMERY_H
#define __MONTGOMERY_H

#include  <stdio.h>
#include <stdlib.h>

#include <string.h>
#include    <gmp.h>

void modularInverse(mpz_t inv, const mpz_t a, const mpz_t N);

void montgomeryR(mpz_t R, const mpz_t N);

void montgomeryReduction(mpz_t t, const mpz_t T, const mpz_t N, const mpz_t R);

void montgomeryMultiplication(mpz_t abMont, const mpz_t aMont, const mpz_t bMont, const mpz_t N, const mpz_t R);

void montgomeryForm(mpz_t r, const mpz_t a, const mpz_t N, const mpz_t R);

#endif
