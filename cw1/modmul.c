/* Copyright (C) 2017 Daniel Page <csdsp@bristol.ac.uk>
 *
 * Use of this source code is restricted per the CC BY-NC-ND license, a copy of
 * which can be found via http://creativecommons.org (and should be included as
 * LICENSE.txt within the associated archive or repository).
 */

#include "modmul.h"

/* Perform stage 1:
 *
 * - read each 3-tuple of N, e and m from stdin,
 * - compute the RSA encryption c, then
 * - write the ciphertext c to stdout.
 */

void stage1() {
    // Initialise the required multi precision integer variables
    mpz_t N, e, m, c;
    mpz_init( N );
    mpz_init( e );
    mpz_init( m );
    mpz_init( c );

    /* For each challenge in the input:
       Read in N, e and m. (%ZX to read in upper-case hex).
       Try reading in an N to detect a challenge.
       Abort if e or m are NOT successfully parsed (malformed challenge).
       Otherwise compute RSA encryption & print result to stdout
    */
    while (gmp_scanf( "%ZX", N ) == 1){

        if(gmp_scanf( "%ZX", e ) != 1){
            abort();
        }
        if(gmp_scanf( "%ZX", m ) != 1){
            abort();
        }

        // Compute ciphertext : c = m^e (mod N)
        mpz_powm (c, m, e, N);
        gmp_printf( "%ZX\n", c );
    }

    // Free the multi precision variables
    mpz_clear( N );
    mpz_clear( e );
    mpz_clear( m );
    mpz_clear( c );
}

/* Perform stage 2:
 *
 * - read each 9-tuple of N, d, p, q, d_p, d_q, i_p, i_q and c from stdin,
 * - compute the RSA decryption m, then
 * - write the plaintext m to stdout.
 */

void stage2() {
    // Initialise the required multi precision integer variables
    mpz_t N, d, p, q, dp, dq, ip, iq, c, m;
    mpz_init ( N );
    mpz_init ( d );
    mpz_init ( p );
    mpz_init ( q );
    mpz_init ( dp );
    mpz_init ( dq );
    mpz_init ( ip );
    mpz_init ( iq );
    mpz_init ( c );
    mpz_init ( m );

    while (gmp_scanf( "%ZX", N ) == 1){

        if(gmp_scanf( "%ZX", d ) != 1){
            abort();
        }
        if(gmp_scanf( "%ZX", p ) != 1){
            abort();
        }
        if(gmp_scanf( "%ZX", q ) != 1){
            abort();
        }
        if(gmp_scanf( "%ZX", dp ) != 1){
            abort();
        }
        if(gmp_scanf( "%ZX", dq ) != 1){
            abort();
        }
        if(gmp_scanf( "%ZX", ip ) != 1){
            abort();
        }
        if(gmp_scanf( "%ZX", iq ) != 1){
            abort();
        }
        if(gmp_scanf( "%ZX", c ) != 1){
            abort();
        }

        // Compute ciphertext : c = m^e (mod N)
        mpz_powm (m, c, d, N);
        gmp_printf( "%ZX\n", m );
    }

    // Free the multi precision variables
    mpz_clear( N );
    mpz_clear( d );
    mpz_clear( p );
    mpz_clear( q );
    mpz_clear( dp );
    mpz_clear( dq );
    mpz_clear( ip );
    mpz_clear( iq );
    mpz_clear( c );
}

/* Perform stage 3:
 *
 * - read each 5-tuple of p, q, g, h and m from stdin,
 * - compute the ElGamal encryption c = (c_1,c_2), then
 * - write the ciphertext c to stdout.
 */

void stage3() {

  // fill in this function with solution

}

/* Perform stage 4:
 *
 * - read each 5-tuple of p, q, g, x and c = (c_1,c_2) from stdin,
 * - compute the ElGamal decryption m, then
 * - write the plaintext m to stdout.
 */

void stage4() {

  // fill in this function with solution

}

/* The main function acts as a driver for the assignment by simply invoking the
 * correct function for the requested stage.
 */

int main( int argc, char* argv[] ) {
  if( 2 != argc ) {
    abort();
  }

  if     ( !strcmp( argv[ 1 ], "stage1" ) ) {
    stage1();
  }
  else if( !strcmp( argv[ 1 ], "stage2" ) ) {
    stage2();
  }
  else if( !strcmp( argv[ 1 ], "stage3" ) ) {
    stage3();
  }
  else if( !strcmp( argv[ 1 ], "stage4" ) ) {
    stage4();
  }
  else {
    abort();
  }

  return 0;
}
