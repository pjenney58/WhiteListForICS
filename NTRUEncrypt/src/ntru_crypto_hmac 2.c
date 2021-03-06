/******************************************************************************
 * NTRU Cryptography Reference Source Code
 * Copyright (c) 2009-2013, by Security Innovation, Inc. All rights reserved. 
 *
 * ntru_crypto_hmac.c is a component of ntru-crypto.
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
 * File: ntru_crypto_hmac.c
 *
 * Contents: Routines implementing the HMAC hash calculation.
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
#include "ntru_crypto_hmac.h"


/* HMAC context */

struct _NTRU_CRYPTO_HMAC_CTX {
    NTRU_CRYPTO_HASH_CTX  hash_ctx;
    uint8_t              *k0;
    uint16_t              blk_len;
    uint16_t              md_len;
};


/* ntru_crypto_hmac_create_ctx
 *
 * This routine creates an HMAC context, setting the hash algorithm and
 * the key to be used.
 *
 * Returns NTRU_CRYPTO_HMAC_OK if successful.
 * Returns NTRU_CRYPTO_HMAC_BAD_ALG if the specified algorithm is not supported.
 * Returns NTRU_CRYPTO_HMAC_BAD_PARAMETER if inappropriate NULL pointers are
 * passed.
 * Returns NTRU_CRYPTO_HMAC_OUT_OF_MEMORY if memory cannot be allocated.
 */

uint32_t
ntru_crypto_hmac_create_ctx(
    NTRU_CRYPTO_HASH_ALGID   algid,   /*  in - the hash algorithm to be used */
    uint8_t const           *key,     /*  in - pointer to the HMAC key */
    uint32_t                 key_len, /*  in - number of bytes in HMAC key */
    NTRU_CRYPTO_HMAC_CTX   **c)       /* out - address for pointer to HMAC
                                               context */
{
    NTRU_CRYPTO_HMAC_CTX *ctx = NULL;
    uint32_t              result;

    /* check parameters */

    if (!c || !key)
        HMAC_RET(NTRU_CRYPTO_HMAC_BAD_PARAMETER);

    *c = NULL;

    /* allocate memory for an HMAC context */
#if defined(linux) && defined(__KERNEL__)
    if ((ctx = (NTRU_CRYPTO_HMAC_CTX*) kmalloc(sizeof(NTRU_CRYPTO_HMAC_CTX), GFP_KERNEL)) ==
        NULL)
        HMAC_RET(NTRU_CRYPTO_HMAC_OUT_OF_MEMORY);
#else
    if ((ctx = (NTRU_CRYPTO_HMAC_CTX*) malloc(sizeof(NTRU_CRYPTO_HMAC_CTX))) ==
            NULL)
        HMAC_RET(NTRU_CRYPTO_HMAC_OUT_OF_MEMORY);
#endif

    /* set the algorithm */

    if (result = ntru_crypto_hash_set_alg(algid, &ctx->hash_ctx)) {
#if defined(linux) && defined(__KERNEL__)
        kfree(ctx);
#else
        free(ctx);
#endif
        HMAC_RET(NTRU_CRYPTO_HMAC_BAD_ALG);
    }

    /* set block length and digest length */

    if ((result = ntru_crypto_hash_block_length(&ctx->hash_ctx,
                                                &ctx->blk_len))  ||
        (result = ntru_crypto_hash_digest_length(&ctx->hash_ctx,
                                                 &ctx->md_len))) {
#if defined(linux) && defined(__KERNEL__)
        kfree(ctx);
#else
        free(ctx);
#endif
        return result;
    }

    /* allocate memory for K0 */
#if defined(linux) && defined(__KERNEL__)
    if ((ctx->k0 = (uint8_t*) kmalloc(ctx->blk_len, GFP_KERNEL)) == NULL) {
        kfree(ctx);
#else
    if ((ctx->k0 = (uint8_t*) malloc(ctx->blk_len)) == NULL) {
        free(ctx);
#endif
        HMAC_RET(NTRU_CRYPTO_HMAC_OUT_OF_MEMORY);
    }

    /* calculate K0 and store in HMAC context */

    memset(ctx->k0, 0, ctx->blk_len);

    /* check if key is too large */

    if (key_len > ctx->blk_len) {

        if (result = ntru_crypto_hash_digest(algid, key, key_len, ctx->k0)) {
            memset(ctx->k0, 0, ctx->blk_len);
#if defined(linux) && defined(__KERNEL__)
            kfree(ctx->k0);
            kfree(ctx);
#else
            free(ctx->k0);
            free(ctx);
#endif
            return result;
        }

    } else
        memcpy(ctx->k0, key, key_len);

    /* return pointer to HMAC context */

    *c = ctx;
    HMAC_RET(NTRU_CRYPTO_HMAC_OK);
}


/* ntru_crypto_hmac_destroy_ctx
 *
 * Destroys an HMAC context.
 *
 * Returns NTRU_CRYPTO_HMAC_OK if successful.
 * Returns NTRU_CRYPTO_HMAC_BAD_PARAMETER if inappropriate NULL pointers are
 * passed.
 */

uint32_t
ntru_crypto_hmac_destroy_ctx(
    NTRU_CRYPTO_HMAC_CTX *c)        /* in/out - pointer to HMAC context */
{
    if (!c || !c->k0)
        HMAC_RET(NTRU_CRYPTO_HMAC_BAD_PARAMETER);

    /* clear key and release memory */

    memset(c->k0, 0, c->blk_len);
#if defined(linux) && defined(__KERNEL__)
    kfree(c->k0);
    kfree(c);
#else
    free(c->k0);
    free(c);
#endif
    
    HMAC_RET(NTRU_CRYPTO_HMAC_OK);
}


/* ntru_crypto_hmac_get_md_len
 *
 * This routine gets the digest length of the HMAC.
 *
 * Returns NTRU_CRYPTO_HMAC_OK on success.
 * Returns NTRU_CRYPTO_HMAC_BAD_PARAMETER if inappropriate NULL pointers are
 * passed.
 */

uint32_t
ntru_crypto_hmac_get_md_len(
    NTRU_CRYPTO_HMAC_CTX const *c,       /*  in - pointer to HMAC context */
    uint16_t                   *md_len)  /* out - address for digest length */
{
    /* check parameters */

    if (!c || !md_len)
        HMAC_RET(NTRU_CRYPTO_HMAC_BAD_PARAMETER);

    /* get digest length */

    *md_len = c->md_len;
    HMAC_RET(NTRU_CRYPTO_HMAC_OK);
}


/* ntru_crypto_hmac_set_key
 *
 * This routine sets a digest-length key into the HMAC context.
 *
 * Returns NTRU_CRYPTO_HMAC_OK on success.
 * Returns NTRU_CRYPTO_HMAC_BAD_PARAMETER if inappropriate NULL pointers are
 * passed.
 */

uint32_t
ntru_crypto_hmac_set_key(
    NTRU_CRYPTO_HMAC_CTX *c,        /*  in - pointer to HMAC context */
    uint8_t const        *key)      /*  in - pointer to new HMAC key */
{
    /* check parameters */

    if (!c || !key)
        HMAC_RET(NTRU_CRYPTO_HMAC_BAD_PARAMETER);

    /* copy key */

    memcpy(c->k0, key, c->md_len);
    HMAC_RET(NTRU_CRYPTO_HMAC_OK);
}


/* ntru_crypto_hmac_init
 *
 * This routine performs standard initialization of the HMAC state.
 *
 * Returns NTRU_CRYPTO_HMAC_OK on success.
 * Returns NTRU_CRYPTO_HASH_FAIL with corrupted context.
 * Returns NTRU_CRYPTO_HMAC_BAD_PARAMETER if inappropriate NULL pointers are
 * passed.
 */

uint32_t
ntru_crypto_hmac_init(
    NTRU_CRYPTO_HMAC_CTX *c)        /* in/out - pointer to HMAC context */
{
    uint32_t    result;
    int         i;

    /* check parameters */

    if (!c)
        HMAC_RET(NTRU_CRYPTO_HMAC_BAD_PARAMETER);

    /* init hash context and compute H(K0 ^ ipad) */

    for (i = 0; i < c->blk_len; i++)
        c->k0[i] ^= 0x36;                           /* K0 ^ ipad */
    if ((result = ntru_crypto_hash_init(&c->hash_ctx))                       ||
        (result = ntru_crypto_hash_update(&c->hash_ctx, c->k0, c->blk_len)))
        return result;

    HMAC_RET(NTRU_CRYPTO_HMAC_OK);
}


/* ntru_crypto_hmac_update
 *
 * This routine processes input data and updates the HMAC hash calculation.
 *
 * Returns NTRU_CRYPTO_HMAC_OK on success.
 * Returns NTRU_CRYPTO_HASH_FAIL with corrupted context.
 * Returns NTRU_CRYPTO_HMAC_BAD_PARAMETER if inappropriate NULL pointers are
 * passed.
 * Returns NTRU_CRYPTO_HASH_OVERFLOW if more than bytes are hashed than the
 *         underlying hash algorithm can handle.
 */

uint32_t
ntru_crypto_hmac_update(
    NTRU_CRYPTO_HMAC_CTX *c,         /* in/out - pointer to HMAC context */
    const uint8_t        *data,      /*     in - pointer to input data */
    uint32_t              data_len)  /*     in - no. of bytes of input data */
{
    uint32_t    result;

    /* check parameters */

    if (!c || (data_len && !data))
        HMAC_RET(NTRU_CRYPTO_HMAC_BAD_PARAMETER);

    if (result = ntru_crypto_hash_update(&c->hash_ctx, data, data_len))
        return result;

    HMAC_RET(NTRU_CRYPTO_HMAC_OK);
}


/* ntru_crypto_hmac_final
 *
 * This routine completes the HMAC hash calculation and returns the
 * message digest.
 *
 * Returns NTRU_CRYPTO_HMAC_OK on success.
 * Returns NTRU_CRYPTO_HASH_FAIL with corrupted context.
 * Returns NTRU_CRYPTO_HMAC_BAD_PARAMETER if inappropriate NULL pointers are
 * passed.
 */

uint32_t
ntru_crypto_hmac_final(
    NTRU_CRYPTO_HMAC_CTX *c,        /* in/out - pointer to HMAC context */
    uint8_t              *md)       /*   out - address for message digest */
{
    uint32_t    result = NTRU_CRYPTO_HMAC_OK;
    int         i;

    /* check parameters */

    if (!c || !md)
        HMAC_RET(NTRU_CRYPTO_HMAC_BAD_PARAMETER);

    /* form K0 ^ opad
     * complete md = H((K0 ^ ipad) || data)
     * compute  md = H((K0 ^ opad) || md)
     * re-form K0
     */

    for (i = 0; i < c->blk_len; i++)
        c->k0[i] ^= (0x36^0x5c);
    if ((result = ntru_crypto_hash_final(&c->hash_ctx, md))                  ||
        (result = ntru_crypto_hash_init(&c->hash_ctx))                       ||
        (result = ntru_crypto_hash_update(&c->hash_ctx, c->k0, c->blk_len))  ||
        (result = ntru_crypto_hash_update(&c->hash_ctx, md, c->md_len))      ||
        (result = ntru_crypto_hash_final(&c->hash_ctx, md))) {
    }
    for (i = 0; i < c->blk_len; i++)
        c->k0[i] ^= 0x5c;
    return result;
}

#if defined(linux) || defined(__LINUX__)
#pragma GCC diagnostic pop
#endif
