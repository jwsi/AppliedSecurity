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
       Otherwise compute RSA encryption & print result to stdout.
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

    /* For each challenge in the input:
       Read in N, d, p, q, dp, dq, ip, iq and c. (%ZX to read in upper-case hex).
       Try reading in an N to detect a challenge.
       Abort if further lines are NOT successfully parsed (malformed challenge).
       Otherwise compute RSA decryption & print result to stdout.
    */
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

        // Compute plaintext : m = c^d (mod N)
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
    // Initialise the required multi precision integer variables
    mpz_t p, q, g, h, m, r, c1, c2;
    mpz_init ( p );
    mpz_init ( q );
    mpz_init ( g );
    mpz_init ( h );
    mpz_init ( m );
    mpz_init ( r );
    mpz_init ( c1 );
    mpz_init ( c2 );

    gmp_randstate_t randState;
    gmp_randinit_default (randState);
    // gmp_randseed (randState, seed)

    /* For each challenge in the input:
       Read in p, q, g, h and m. (%ZX to read in upper-case hex).
       Try reading in an p to detect a challenge.
       Abort if further lines are NOT successfully parsed (malformed challenge).
       Otherwise compute RSA encryption & print result to stdout.
    */
    while (gmp_scanf( "%ZX", p ) == 1){

        if(gmp_scanf( "%ZX", q ) != 1){
            abort();
        }
        if(gmp_scanf( "%ZX", g ) != 1){
            abort();
        }
        if(gmp_scanf( "%ZX", h ) != 1){
            abort();
        }
        if(gmp_scanf( "%ZX", m ) != 1){
            abort();
        }

        // Compute random integer for encryption
        // mpz_urandomm (r, randState, q);

        // Encyrption : c1 = g^r (mod p)
        // mpz_powm (c1, g, r, p); // random r

        // Encryption : c2 = m * h^r (mod p)
        // mpz_powm (c2, h, r, p);
        // mpz_mul (c2, m, c2);
        // mpz_mod (c2, c2, p);

        // fixed r = 1
        mpz_mul (c2, m, h);
        mpz_mod (c2, c2, p);

        gmp_printf( "%ZX\n", g); // for r = 1
        // gmp_printf( "%ZX\n", c1) // for random r
        gmp_printf( "%ZX\n", c2);
    }

    // Free the multi precision variables
    mpz_clear( p );
    mpz_clear( q );
    mpz_clear( g );
    mpz_clear( h );
    mpz_clear( m );
    mpz_clear ( r );
    mpz_clear ( c1 );
    mpz_clear ( c2 );

    gmp_randclear( randState );
}

/* Perform stage 4:
 *
 * - read each 5-tuple of p, q, g, x and c = (c_1,c_2) from stdin,
 * - compute the ElGamal decryption m, then
 * - write the plaintext m to stdout.
 */

void stage4() {
    // Initialise the required multi precision integer variables
    mpz_t p, q, g, x, c1, c2, m;
    mpz_init ( p );
    mpz_init ( q );
    mpz_init ( g );
    mpz_init ( x );
    mpz_init ( c1 );
    mpz_init ( c2 );
    mpz_init ( m );

    /* For each challenge in the input:
       Read in p, q, g, x, c1 and c2. (%ZX to read in upper-case hex).
       Try reading in an p to detect a challenge.
       Abort if further lines are NOT successfully parsed (malformed challenge).
       Otherwise compute RSA encryption & print result to stdout.
    */
    while (gmp_scanf( "%ZX", p ) == 1){

        if(gmp_scanf( "%ZX", q ) != 1){
            abort();
        }
        if(gmp_scanf( "%ZX", g ) != 1){
            abort();
        }
        if(gmp_scanf( "%ZX", x ) != 1){
            abort();
        }
        if(gmp_scanf( "%ZX", c1 ) != 1){
            abort();
        }
        if(gmp_scanf( "%ZX", c2 ) != 1){
            abort();
        }

        // Decryption : c1^-x * c2 = m
        mpz_neg(x, x);
        mpz_powm(m, c1, x, p);
        mpz_mul (m, m, c2);
        mpz_mod (m, m, p);

        // Print out the decrypted ciphertext
        gmp_printf( "%ZX\n", m);
    }

    // Free the multi precision variables
    mpz_clear( p );
    mpz_clear( q );
    mpz_clear( g );
    mpz_clear( x );
    mpz_clear ( c1 );
    mpz_clear ( c2 );
    mpz_clear ( m );
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
