/******************************************************************************
 * NTRU Cryptography Reference Source Code
 * Copyright (c) 2009-2013, by Security Innovation, Inc. All rights reserved. 
 *
 * ntru_crypto_sha2.c is a component of ntru-crypto.
 *
 * Copyright (C) 2009-2013  Security Innovation
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 *****************************************************************************/
 
/******************************************************************************
 *
 * File: ntru_crypto_sha2.c
 *
 * Contents: Routines implementing the SHA-256 hash calculation.
 *
 *****************************************************************************/
#if defined(linux) || defined(__LINUX__)
#pragma GCC diagnostic ignored "-Wparentheses"
#pragma GCC diagnostic push
#endif

#if defined(linux) && defined(__KERNEL__)
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#else
#include <stdlib.h>
#include <string.h>
#endif
#include "ntru_crypto_sha2.h"
#include "ntru_crypto_msbyte_uint32.h"


/* chaining state elements */

#define H0      state[0]
#define H1      state[1]
#define H2      state[2]
#define H3      state[3]
#define H4      state[4]
#define H5      state[5]
#define H6      state[6]
#define H7      state[7]


/* standard SHA-256 initialization values */

#define H0_SHA256_INIT 0x6a09e667UL
#define H1_SHA256_INIT 0xbb67ae85UL
#define H2_SHA256_INIT 0x3c6ef372UL
#define H3_SHA256_INIT 0xa54ff53aUL
#define H4_SHA256_INIT 0x510e527fUL
#define H5_SHA256_INIT 0x9b05688cUL
#define H6_SHA256_INIT 0x1f83d9abUL
#define H7_SHA256_INIT 0x5be0cd19UL


/* sha2_blk()
 *
 * This routine updates the current hash output (chaining state)
 * by performing SHA-256 on a 512-bit block of data represented
 * as sixteen 32-bit words.
 */

#define RR(a, n)    ( ((a) >> (n)) | ((a) << (32 - (n))) )
#define S0(a)       ( RR((a),  2) ^ RR((a), 13) ^ RR((a), 22) )
#define S1(a)       ( RR((a),  6) ^ RR((a), 11) ^ RR((a), 25) )
#define s0(a)       ( RR((a),  7) ^ RR((a), 18) ^ ((a) >>  3) )
#define s1(a)       ( RR((a), 17) ^ RR((a), 19) ^ ((a) >> 10) )


static void
sha2_blk(
    uint32_t const *data,       //     in - ptr to 16 32-bit word input block
    uint32_t       *state)      // in/out - ptr to 8 32-bit word chaining state
{
    uint32_t A, B, C, D, E, F, G, H;
    uint32_t w[16];

    /* init A - H */

    A = H0; B = H1; C = H2; D = H3; E = H4; F = H5; G = H6; H = H7;

    /* rounds 0 - 15 */

    H += S1(E) + (E & (F ^ G) ^ G) + 0x428A2F98UL + data[ 0]; D += H;
    H += S0(A) + ((A & B) | (C & (A | B)));
    G += S1(D) + (D & (E ^ F) ^ F) + 0x71374491UL + data[ 1]; C += G;
    G += S0(H) + ((H & A) | (B & (H | A)));
    F += S1(C) + (C & (D ^ E) ^ E) + 0xB5C0FBCFUL + data[ 2]; B += F;
    F += S0(G) + ((G & H) | (A & (G | H)));
    E += S1(B) + (B & (C ^ D) ^ D) + 0xE9B5DBA5UL + data[ 3]; A += E;
    E += S0(F) + ((F & G) | (H & (F | G)));
    D += S1(A) + (A & (B ^ C) ^ C) + 0x3956C25BUL + data[ 4]; H += D;
    D += S0(E) + ((E & F) | (G & (E | F)));
    C += S1(H) + (H & (A ^ B) ^ B) + 0x59F111F1UL + data[ 5]; G += C;
    C += S0(D) + ((D & E) | (F & (D | E)));
    B += S1(G) + (G & (H ^ A) ^ A) + 0x923F82A4UL + data[ 6]; F += B;
    B += S0(C) + ((C & D) | (E & (C | D)));
    A += S1(F) + (F & (G ^ H) ^ H) + 0xAB1C5ED5UL + data[ 7]; E += A;
    A += S0(B) + ((B & C) | (D & (B | C)));
    H += S1(E) + (E & (F ^ G) ^ G) + 0xD807AA98UL + data[ 8]; D += H;
    H += S0(A) + ((A & B) | (C & (A | B)));
    G += S1(D) + (D & (E ^ F) ^ F) + 0x12835B01UL + data[ 9]; C += G;
    G += S0(H) + ((H & A) | (B & (H | A)));
    F += S1(C) + (C & (D ^ E) ^ E) + 0x243185BEUL + data[10]; B += F;
    F += S0(G) + ((G & H) | (A & (G | H)));
    E += S1(B) + (B & (C ^ D) ^ D) + 0x550C7DC3UL + data[11]; A += E;
    E += S0(F) + ((F & G) | (H & (F | G)));
    D += S1(A) + (A & (B ^ C) ^ C) + 0x72BE5D74UL + data[12]; H += D;
    D += S0(E) + ((E & F) | (G & (E | F)));
    C += S1(H) + (H & (A ^ B) ^ B) + 0x80DEB1FEUL + data[13]; G += C;
    C += S0(D) + ((D & E) | (F & (D | E)));
    B += S1(G) + (G & (H ^ A) ^ A) + 0x9BDC06A7UL + data[14]; F += B;
    B += S0(C) + ((C & D) | (E & (C | D)));
    A += S1(F) + (F & (G ^ H) ^ H) + 0xC19BF174UL + data[15]; E += A;
    A += S0(B) + ((B & C) | (D & (B | C)));

    /* rounds 16 - 63 */

    w[ 0] = data[ 0] + s0(data[ 1]) + data[ 9] + s1(data[14]);
    H += S1(E) + (E & (F ^ G) ^ G) + 0xE49B69C1UL + w[ 0]; D += H;
    H += S0(A) + ((A & B) | (C & (A | B)));
    w[ 1] = data[ 1] + s0(data[ 2]) + data[10] + s1(data[15]);
    G += S1(D) + (D & (E ^ F) ^ F) + 0xEFBE4786UL + w[ 1]; C += G;
    G += S0(H) + ((H & A) | (B & (H | A)));
    w[ 2] = data[ 2] + s0(data[ 3]) + data[11] + s1(w[ 0]);
    F += S1(C) + (C & (D ^ E) ^ E) + 0x0FC19DC6UL + w[ 2]; B += F;
    F += S0(G) + ((G & H) | (A & (G | H)));
    w[ 3] = data[ 3] + s0(data[ 4]) + data[12] + s1(w[ 1]);
    E += S1(B) + (B & (C ^ D) ^ D) + 0x240CA1CCUL + w[ 3]; A += E;
    E += S0(F) + ((F & G) | (H & (F | G)));
    w[ 4] = data[ 4] + s0(data[ 5]) + data[13] + s1(w[ 2]);
    D += S1(A) + (A & (B ^ C) ^ C) + 0x2DE92C6FUL + w[ 4]; H += D;
    D += S0(E) + ((E & F) | (G & (E | F)));
    w[ 5] = data[ 5] + s0(data[ 6]) + data[14] + s1(w[ 3]);
    C += S1(H) + (H & (A ^ B) ^ B) + 0x4A7484AAUL + w[ 5]; G += C;
    C += S0(D) + ((D & E) | (F & (D | E)));
    w[ 6] = data[ 6] + s0(data[ 7]) + data[15] + s1(w[ 4]);
    B += S1(G) + (G & (H ^ A) ^ A) + 0x5CB0A9DCUL + w[ 6]; F += B;
    B += S0(C) + ((C & D) | (E & (C | D)));
    w[ 7] = data[ 7] + s0(data[ 8]) + w[ 0] + s1(w[ 5]);
    A += S1(F) + (F & (G ^ H) ^ H) + 0x76F988DAUL + w[ 7]; E += A;
    A += S0(B) + ((B & C) | (D & (B | C)));
    w[ 8] = data[ 8] + s0(data[ 9]) + w[ 1] + s1(w[ 6]);
    H += S1(E) + (E & (F ^ G) ^ G) + 0x983E5152UL + w[ 8]; D += H;
    H += S0(A) + ((A & B) | (C & (A | B)));
    w[ 9] = data[ 9] + s0(data[10]) + w[ 2] + s1(w[ 7]);
    G += S1(D) + (D & (E ^ F) ^ F) + 0xA831C66DUL + w[ 9]; C += G;
    G += S0(H) + ((H & A) | (B & (H | A)));
    w[10] = data[10] + s0(data[11]) + w[ 3] + s1(w[ 8]);
    F += S1(C) + (C & (D ^ E) ^ E) + 0xB00327C8UL + w[10]; B += F;
    F += S0(G) + ((G & H) | (A & (G | H)));
    w[11] = data[11] + s0(data[12]) + w[ 4] + s1(w[ 9]);
    E += S1(B) + (B & (C ^ D) ^ D) + 0xBF597FC7UL + w[11]; A += E;
    E += S0(F) + ((F & G) | (H & (F | G)));
    w[12] = data[12] + s0(data[13]) + w[ 5] + s1(w[10]);
    D += S1(A) + (A & (B ^ C) ^ C) + 0xC6E00BF3UL + w[12]; H += D;
    D += S0(E) + ((E & F) | (G & (E | F)));
    w[13] = data[13] + s0(data[14]) + w[ 6] + s1(w[11]);
    C += S1(H) + (H & (A ^ B) ^ B) + 0xD5A79147UL + w[13]; G += C;
    C += S0(D) + ((D & E) | (F & (D | E)));
    w[14] = data[14] + s0(data[15]) + w[ 7] + s1(w[12]);
    B += S1(G) + (G & (H ^ A) ^ A) + 0x06CA6351UL + w[14]; F += B;
    B += S0(C) + ((C & D) | (E & (C | D)));
    w[15] = data[15] + s0(w[ 0]) + w[ 8] + s1(w[13]);
    A += S1(F) + (F & (G ^ H) ^ H) + 0x14292967UL + w[15]; E += A;
    A += S0(B) + ((B & C) | (D & (B | C)));
    w[ 0] = w[ 0] + s0(w[ 1]) + w[ 9] + s1(w[14]);
    H += S1(E) + (E & (F ^ G) ^ G) + 0x27B70A85UL + w[ 0]; D += H;
    H += S0(A) + ((A & B) | (C & (A | B)));
    w[ 1] = w[ 1] + s0(w[ 2]) + w[10] + s1(w[15]);
    G += S1(D) + (D & (E ^ F) ^ F) + 0x2E1B2138UL + w[ 1]; C += G;
    G += S0(H) + ((H & A) | (B & (H | A)));
    w[ 2] = w[ 2] + s0(w[ 3]) + w[11] + s1(w[ 0]);
    F += S1(C) + (C & (D ^ E) ^ E) + 0x4D2C6DFCUL + w[ 2]; B += F;
    F += S0(G) + ((G & H) | (A & (G | H)));
    w[ 3] = w[ 3] + s0(w[ 4]) + w[12] + s1(w[ 1]);
    E += S1(B) + (B & (C ^ D) ^ D) + 0x53380D13UL + w[ 3]; A += E;
    E += S0(F) + ((F & G) | (H & (F | G)));
    w[ 4] = w[ 4] + s0(w[ 5]) + w[13] + s1(w[ 2]);
    D += S1(A) + (A & (B ^ C) ^ C) + 0x650A7354UL + w[ 4]; H += D;
    D += S0(E) + ((E & F) | (G & (E | F)));
    w[ 5] = w[ 5] + s0(w[ 6]) + w[14] + s1(w[ 3]);
    C += S1(H) + (H & (A ^ B) ^ B) + 0x766A0ABBUL + w[ 5]; G += C;
    C += S0(D) + ((D & E) | (F & (D | E)));
    w[ 6] = w[ 6] + s0(w[ 7]) + w[15] + s1(w[ 4]);
    B += S1(G) + (G & (H ^ A) ^ A) + 0x81C2C92EUL + w[ 6]; F += B;
    B += S0(C) + ((C & D) | (E & (C | D)));
    w[ 7] = w[ 7] + s0(w[ 8]) + w[ 0] + s1(w[ 5]);
    A += S1(F) + (F & (G ^ H) ^ H) + 0x92722C85UL + w[ 7]; E += A;
    A += S0(B) + ((B & C) | (D & (B | C)));
    w[ 8] = w[ 8] + s0(w[ 9]) + w[ 1] + s1(w[ 6]);
    H += S1(E) + (E & (F ^ G) ^ G) + 0xA2BFE8A1UL + w[ 8]; D += H;
    H += S0(A) + ((A & B) | (C & (A | B)));
    w[ 9] = w[ 9] + s0(w[10]) + w[ 2] + s1(w[ 7]);
    G += S1(D) + (D & (E ^ F) ^ F) + 0xA81A664BUL + w[ 9]; C += G;
    G += S0(H) + ((H & A) | (B & (H | A)));
    w[10] = w[10] + s0(w[11]) + w[ 3] + s1(w[ 8]);
    F += S1(C) + (C & (D ^ E) ^ E) + 0xC24B8B70UL + w[10]; B += F;
    F += S0(G) + ((G & H) | (A & (G | H)));
    w[11] = w[11] + s0(w[12]) + w[ 4] + s1(w[ 9]);
    E += S1(B) + (B & (C ^ D) ^ D) + 0xC76C51A3UL + w[11]; A += E;
    E += S0(F) + ((F & G) | (H & (F | G)));
    w[12] = w[12] + s0(w[13]) + w[ 5] + s1(w[10]);
    D += S1(A) + (A & (B ^ C) ^ C) + 0xD192E819UL + w[12]; H += D;
    D += S0(E) + ((E & F) | (G & (E | F)));
    w[13] = w[13] + s0(w[14]) + w[ 6] + s1(w[11]);
    C += S1(H) + (H & (A ^ B) ^ B) + 0xD6990624UL + w[13]; G += C;
    C += S0(D) + ((D & E) | (F & (D | E)));
    w[14] = w[14] + s0(w[15]) + w[ 7] + s1(w[12]);
    B += S1(G) + (G & (H ^ A) ^ A) + 0xF40E3585UL + w[14]; F += B;
    B += S0(C) + ((C & D) | (E & (C | D)));
    w[15] = w[15] + s0(w[ 0]) + w[ 8] + s1(w[13]);
    A += S1(F) + (F & (G ^ H) ^ H) + 0x106AA070UL + w[15]; E += A;
    A += S0(B) + ((B & C) | (D & (B | C)));
    w[ 0] = w[ 0] + s0(w[ 1]) + w[ 9] + s1(w[14]);
    H += S1(E) + (E & (F ^ G) ^ G) + 0x19A4C116UL + w[ 0]; D += H;
    H += S0(A) + ((A & B) | (C & (A | B)));
    w[ 1] = w[ 1] + s0(w[ 2]) + w[10] + s1(w[15]);
    G += S1(D) + (D & (E ^ F) ^ F) + 0x1E376C08UL + w[ 1]; C += G;
    G += S0(H) + ((H & A) | (B & (H | A)));
    w[ 2] = w[ 2] + s0(w[ 3]) + w[11] + s1(w[ 0]);
    F += S1(C) + (C & (D ^ E) ^ E) + 0x2748774CUL + w[ 2]; B += F;
    F += S0(G) + ((G & H) | (A & (G | H)));
    w[ 3] = w[ 3] + s0(w[ 4]) + w[12] + s1(w[ 1]);
    E += S1(B) + (B & (C ^ D) ^ D) + 0x34B0BCB5UL + w[ 3]; A += E;
    E += S0(F) + ((F & G) | (H & (F | G)));
    w[ 4] = w[ 4] + s0(w[ 5]) + w[13] + s1(w[ 2]);
    D += S1(A) + (A & (B ^ C) ^ C) + 0x391C0CB3UL + w[ 4]; H += D;
    D += S0(E) + ((E & F) | (G & (E | F)));
    w[ 5] = w[ 5] + s0(w[ 6]) + w[14] + s1(w[ 3]);
    C += S1(H) + (H & (A ^ B) ^ B) + 0x4ED8AA4AUL + w[ 5]; G += C;
    C += S0(D) + ((D & E) | (F & (D | E)));
    w[ 6] = w[ 6] + s0(w[ 7]) + w[15] + s1(w[ 4]);
    B += S1(G) + (G & (H ^ A) ^ A) + 0x5B9CCA4FUL + w[ 6]; F += B;
    B += S0(C) + ((C & D) | (E & (C | D)));
    w[ 7] = w[ 7] + s0(w[ 8]) + w[ 0] + s1(w[ 5]);
    A += S1(F) + (F & (G ^ H) ^ H) + 0x682E6FF3UL + w[ 7]; E += A;
    A += S0(B) + ((B & C) | (D & (B | C)));
    w[ 8] = w[ 8] + s0(w[ 9]) + w[ 1] + s1(w[ 6]);
    H += S1(E) + (E & (F ^ G) ^ G) + 0x748F82EEUL + w[ 8]; D += H;
    H += S0(A) + ((A & B) | (C & (A | B)));
    w[ 9] = w[ 9] + s0(w[10]) + w[ 2] + s1(w[ 7]);
    G += S1(D) + (D & (E ^ F) ^ F) + 0x78A5636FUL + w[ 9]; C += G;
    G += S0(H) + ((H & A) | (B & (H | A)));
    w[10] = w[10] + s0(w[11]) + w[ 3] + s1(w[ 8]);
    F += S1(C) + (C & (D ^ E) ^ E) + 0x84C87814UL + w[10]; B += F;
    F += S0(G) + ((G & H) | (A & (G | H)));
    w[11] = w[11] + s0(w[12]) + w[ 4] + s1(w[ 9]);
    E += S1(B) + (B & (C ^ D) ^ D) + 0x8CC70208UL + w[11]; A += E;
    E += S0(F) + ((F & G) | (H & (F | G)));
    w[12] = w[12] + s0(w[13]) + w[ 5] + s1(w[10]);
    D += S1(A) + (A & (B ^ C) ^ C) + 0x90BEFFFAUL + w[12]; H += D;
    D += S0(E) + ((E & F) | (G & (E | F)));
    w[13] = w[13] + s0(w[14]) + w[ 6] + s1(w[11]);
    C += S1(H) + (H & (A ^ B) ^ B) + 0xA4506CEBUL + w[13]; G += C;
    C += S0(D) + ((D & E) | (F & (D | E)));
    w[14] = w[14] + s0(w[15]) + w[ 7] + s1(w[12]);
    B += S1(G) + (G & (H ^ A) ^ A) + 0xBEF9A3F7UL + w[14]; F += B;
    B += S0(C) + ((C & D) | (E & (C | D)));
    w[15] = w[15] + s0(w[ 0]) + w[ 8] + s1(w[13]);
    A += S1(F) + (F & (G ^ H) ^ H) + 0xC67178F2UL + w[15]; E += A;
    A += S0(B) + ((B & C) | (D & (B | C)));

    /* update H0 - H7 */

    H0 += A;
    H1 += B;
    H2 += C;
    H3 += D;
    H4 += E;
    H5 += F;
    H6 += G;
    H7 += H;

    /* clear temp variables */

    A = B = C = D = E = F = G = H = 0;
    memset(w, 0, sizeof(w));
}


/* ntru_crypto_sha2()
 *
 * This routine provides all operations for a SHA-256 hash,
 * and the use of SHA-256 for DSA signing and key generation.
 * It may be used to initialize, update, or complete a message digest,
 * or any combination of those actions, as determined by the SHA_INIT flag,
 * the in_len parameter, and the SHA_FINISH flag, respectively.
 *
 * When in_len == 0 (no data to hash), the parameter, in, may be NULL.
 * When the SHA_FINISH flag is not set, the parameter, md, may be NULL.
 *
 * Initialization may be standard or use a specified initialization vector,
 * and is indicated by setting the SHA_INIT flag.
 * Setting init = NULL specifies standard initialization.  Otherwise, init
 * points to the array of eight alternate initialization 32-bit words.
 *
 * The hash operation can be updated with any number of input bytes, including
 * zero.
 *
 * The hash operation can be completed with normal padding or with zero
 * padding as required for parts of DSA parameter generation, and is indicated
 * by setting the SHA_FINISH flag.  Using zero padding, indicated by setting
 * the SHA_ZERO_PAD flag, never creates an extra input block because the
 * bit count is not included in the hashed data.
 *
 * Returns SHA_OK on success.
 * Returns SHA_FAIL with corrupted context.
 * Returns SHA_BAD_PARAMETER if  inappropriate NULL pointers are passed.
 * Returns SHA_OVERFLOW if more than 2^64 - 1 bytes are hashed.
 */

uint32_t
ntru_crypto_sha2(
    NTRU_CRYPTO_HASH_ALGID  algid,  //     in - hash algorithm ID
    NTRU_CRYPTO_SHA2_CTX   *c,      // in/out - pointer to SHA-2 context
    uint32_t const         *init,   //     in - pointer to alternate
                                    //          initialization - may be NULL
    uint8_t const          *in,     //     in - pointer to input data -
                                    //          may be NULL if in_len == 0
    uint32_t                in_len, //     in - number of input data bytes
    uint32_t                flags,  //     in - INIT, FINISH, zero-pad flags
    uint8_t                *md)     //    out - address for message digest -
                                    //          may be NULL if not FINISH
{
    uint32_t    in_blk[16];         // input block
    uint32_t    space;
    uint8_t    *d = NULL;

    /* check error conditions */

    if (algid != NTRU_CRYPTO_HASH_ALGID_SHA256)
        SHA_RET(SHA_BAD_PARAMETER)

    if (!c || (in_len && !in) || ((flags & SHA_FINISH) && !md))
        SHA_RET(SHA_BAD_PARAMETER)

    /* initialize context if requested */

    if (flags & SHA_INIT) {

        /* init chaining state */

        if (!init) {                            // standard initialization

            c->state[0] = H0_SHA256_INIT;       // standard SHA-256 init
            c->state[1] = H1_SHA256_INIT;
            c->state[2] = H2_SHA256_INIT;
            c->state[3] = H3_SHA256_INIT;
            c->state[4] = H4_SHA256_INIT;
            c->state[5] = H5_SHA256_INIT;
            c->state[6] = H6_SHA256_INIT;
            c->state[7] = H7_SHA256_INIT;

        } else {
            c->state[0] = init[0];              // alternate initialization
            c->state[1] = init[1];
            c->state[2] = init[2];
            c->state[3] = init[3];
            c->state[4] = init[4];
            c->state[5] = init[5];
            c->state[6] = init[6];
            c->state[7] = init[7];
        }

        /* init bit count and number of unhashed data bytes */

        c->num_bits_hashed[0] = 0;
        c->num_bits_hashed[1] = 0;
        c->unhashed_len = 0;
    }

    /* determine space left in unhashed data buffer */

    if (c->unhashed_len > 63)
        SHA_RET(SHA_FAIL)

    space = 64 - c->unhashed_len;

    /* process input if it exists */

    if (in_len) {

        /* update count of bits hashed */

        {
            uint32_t    bits0, bits1;

            bits0 = in_len << 3;
            bits1 = in_len >> 29;
            if ((c->num_bits_hashed[0] += bits0) < bits0)
                bits1++;
            if ((c->num_bits_hashed[1] += bits1) < bits1) {
                memset((uint8_t *) c, 0, sizeof(NTRU_CRYPTO_SHA2_CTX));
                space = 0;
                memset((char *) in_blk, 0, sizeof(in_blk));
                SHA_RET(SHA_OVERFLOW)
            }
        }

        /* process input bytes */

        if (in_len < space) {

            /* input does not fill block buffer:
             * add input to buffer
             */

            memcpy(c->unhashed + c->unhashed_len, in, in_len);
            c->unhashed_len += in_len;

        } else {
            uint32_t    blks;

            /* input will fill block buffer:
             *  fill unhashed data buffer,
             *  convert to block buffer,
             *  and process block
             */

            in_len -= space;
            for (d = c->unhashed + c->unhashed_len; space; space--)
                *d++ = *in++;
            ntru_crypto_msbyte_2_uint32(in_blk, (uint8_t const *) c->unhashed,
                                        16);
            sha2_blk((uint32_t const *) in_blk, c->state);

            /* process any remaining full blocks */

            for (blks = in_len >> 6; blks--; in += 64) {
                ntru_crypto_msbyte_2_uint32(in_blk, in, 16);
                sha2_blk((uint32_t const *) in_blk, c->state);
            }

            /* put any remaining input in the unhashed data buffer */

            in_len &= 0x3f;
            memcpy(c->unhashed, in, in_len);
            c->unhashed_len = in_len;
        }
    }

    /* complete message digest if requested */

    if (flags & SHA_FINISH) {
        space = 64 - c->unhashed_len;

        /* check padding type */

        if (!(flags & SHA_ZERO_PAD)) {

            /* add 0x80 padding byte to the unhashed data buffer
             * (there is always space since the buffer can't be full)
             */

            d = c->unhashed + c->unhashed_len;
            *d++ = 0x80;
            space--;

            /* check for space for bit count */

            if (space < 8) {

                /* no space for count:
                 *  fill remainder of unhashed data buffer with zeros,
                 *  convert to input block,
                 *  process block,
                 *  fill all but 8 bytes of unhashed data buffer with zeros
                 */

                memset(d, 0, space);
                ntru_crypto_msbyte_2_uint32(in_blk,
                                            (uint8_t const *) c->unhashed, 16);
                sha2_blk((uint32_t const *) in_blk, c->state);
                memset(c->unhashed, 0, 56);

            } else {

                /* fill unhashed data buffer with zeros,
                 *  leaving space for bit count
                 */

                for (space -= 8; space; space--)
                    *d++ = 0;
            }

            /* convert partially filled unhashed data buffer to input block and
             *  add bit count to input block
             */

            ntru_crypto_msbyte_2_uint32(in_blk, (uint8_t const *) c->unhashed,
                                        14);
            in_blk[14] = c->num_bits_hashed[1];
            in_blk[15] = c->num_bits_hashed[0];

        } else {

            /* pad unhashed data buffer with zeros and no bit count and
             *  convert to input block
             */

            memset(c->unhashed + c->unhashed_len, 0, space);
            ntru_crypto_msbyte_2_uint32(in_blk, (uint8_t const *) c->unhashed,
                                        16);
        }

        /* process last block */

        sha2_blk((uint32_t const *) in_blk, c->state);

        /* copy result to message digest buffer */

        ntru_crypto_uint32_2_msbyte(md, c->state, 8);
        
        /* clear context and stack variables */

        memset((uint8_t *) c, 0, sizeof(NTRU_CRYPTO_SHA2_CTX));
        space = 0;
        memset((char *) in_blk, 0, sizeof(in_blk));
    }

    SHA_RET(SHA_OK)
}

#if defined(linux) || defined(__LINUX__)
#pragma GCC diagnostic pop
#endif
