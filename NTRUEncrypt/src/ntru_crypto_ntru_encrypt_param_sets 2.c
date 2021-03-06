/******************************************************************************
 * NTRU Cryptography Reference Source Code
 * Copyright (c) 2009-2013, by Security Innovation, Inc. All rights reserved. 
 *
 * ntru_crypto_ntru_param_sets.c is a component of ntru-crypto.
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
 * File: ntru_crypto_ntru_encrypt_param_sets.c
 *
 * Contents: Defines the NTRUEncrypt parameter sets.
 *
 *****************************************************************************/
#if defined(linux) && defined(__KERNEL__)
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#else
#include <stdlib.h>
#include <string.h>
#endif
#include "ntru_crypto_ntru_encrypt_param_sets.h"


/* parameter sets */

static NTRU_ENCRYPT_PARAM_SET ntruParamSets[] = {

    {
        NTRU_EES401EP1,              /* parameter-set id */
        {0x00, 0x02, 0x04},          /* OID */
        0x22,                        /* DER id */
        9,                           /* no. of bits in N (i.e., in an index) */
        401,                         /* N */
        14,                          /* security strength in octets */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        FALSE,                       /* product form */
        113,                         /* df, dr */
        133,                         /* dg */
        60,                          /* maxMsgLenBytes */
        113,                         /* dm0 */
        2005,                        /* 2^c - (2^c mod N) */
        11,                          /* c */
        1,                           /* lLen */
        32,                          /* min. no. of hash calls for IGF-2 */
        9,                           /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        NTRU_EES449EP1,              /* parameter-set id */
        {0x00, 0x03, 0x03},          /* OID */
        0x23,                        /* DER id */
        9,                           /* no. of bits in N (i.e., in an index) */
        449,                         /* N */
        16,                          /* security strength in octets */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        FALSE,                       /* product form */
        134,                         /* df, dr */
        149,                         /* dg */
        67,                          /* maxMsgLenBytes */
        134,                         /* dm0 */
        449,                         /* 2^c - (2^c mod N) */
        9,                           /* c */
        1,                           /* lLen */
        31,                          /* min. no. of hash calls for IGF-2 */
        9,                           /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        NTRU_EES677EP1,              /* parameter-set id */
        {0x00, 0x05, 0x03},          /* OID */
        0x24,                        /* DER id */
        10,                          /* no. of bits in N (i.e., in an index) */
        677,                         /* N */
        24,                          /* security strength in octets */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        FALSE,                       /* product form */
        157,                         /* df, dr */
        225,                         /* dg */
        101,                         /* maxMsgLenBytes */
        157,                         /* dm0 */
        2031,                        /* 2^c - (2^c mod N) */
        11,                          /* c */
        1,                           /* lLen */
        27,                          /* min. no. of hash calls for IGF-2 */
        9,                           /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        NTRU_EES1087EP2,             /* parameter-set id */
        {0x00, 0x06, 0x03},          /* OID */
        0x25,                        /* DER id */
        10,                          /* no. of bits in N (i.e., in an index) */
        1087,                        /* N */
        32,                          /* security strength in octets */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        FALSE,                       /* product form */
        120,                         /* df, dr */
        362,                         /* dg */
        170,                         /* maxMsgLenBytes */
        120,                         /* dm0 */
        7609,                        /* 2^c - (2^c mod N) */
        13,                          /* c */
        1,                           /* lLen */
        25,                          /* min. no. of hash calls for IGF-2 */
        14,                          /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        NTRU_EES541EP1,              /* parameter-set id */
        {0x00, 0x02, 0x05},          /* OID */
        0x26,                        /* DER id */
        10,                          /* no. of bits in N (i.e., in an index) */
        541,                         /* N */
        14,                          /* security strength in octets */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        FALSE,                       /* product form */
        49,                          /* df, dr */
        180,                         /* dg */
        86,                          /* maxMsgLenBytes */
        49,                          /* dm0 */
        3787,                        /* 2^c - (2^c mod N) */
        12,                          /* c */
        1,                           /* lLen */
        15,                          /* min. no. of hash calls for IGF-2 */
        11,                          /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        NTRU_EES613EP1,              /* parameter-set id */
        {0x00, 0x03, 0x04},          /* OID */
        0x27,                        /* DER id */
        10,                          /* no. of bits in N (i.e., in an index) */
        613,                         /* N */
        16,                          /* securuity strength in octets */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        FALSE,                       /* product form */
        55,                          /* df, dr */
        204,                         /* dg */
        97,                          /* maxMsgLenBytes */
        55,                          /* dm0 */
        1839,                        /* 2^c - (2^c mod N) */
        11,                          /* c */
        1,                           /* lLen */
        16,                          /* min. no. of hash calls for IGF-2 */
        13,                          /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        NTRU_EES887EP1,              /* parameter-set id */
        {0x00, 0x05, 0x04},          /* OID */
        0x28,                        /* DER id */
        10,                          /* no. of bits in N (i.e., in an index) */
        887,                         /* N */
        24,                          /* security strength in octets */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        FALSE,                       /* product form */
        81,                          /* df, dr */
        295,                         /* dg */
        141,                         /* maxMsgLenBytes */
        81,                          /* dm0 */
        887,                         /* 2^c - (2^c mod N) */
        10,                          /* c */
        1,                           /* lLen */
        13,                          /* min. no. of hash calls for IGF-2 */
        12,                          /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        NTRU_EES1171EP1,             /* parameter-set id */
        {0x00, 0x06, 0x04},          /* OID */
        0x29,                        /* DER id */
        11,                          /* no. of bits in N (i.e., in an index) */
        1171,                        /* N */
        32,                          /* security strength in octets */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        FALSE,                       /* product form */
        106,                         /* df, dr */
        390,                         /* dg */
        186,                         /* maxMsgLenBytes */
        106,                         /* dm0 */
        3513,                        /* 2^c - (2^c mod N) */
        12,                          /* c */
        1,                           /* lLen */
        20,                          /* min. no. of hash calls for IGF-2 */
        15,                          /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        NTRU_EES659EP1,              /* parameter-set id */
        {0x00, 0x02, 0x06},          /* OID */
        0x2a,                        /* DER id */
        10,                          /* no. of bits in N (i.e., in an index) */
        659,                         /* N */
        14,                          /* security strength in octets */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        FALSE,                       /* product form */
        38,                          /* df, dr */
        219,                         /* dg */
        108,                         /* maxMsgLenBytes */
        38,                          /* dm0 */
        1977,                        /* 2^c - (2^c mod N) */
        11,                          /* c */
        1,                           /* lLen */
        11,                          /* min. no. of hash calls for IGF-2 */
        14,                          /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        NTRU_EES761EP1,              /* parameter-set id */
        {0x00, 0x03, 0x05},          /* OID */
        0x2b,                        /* DER id */
        10,                          /* no. of bits in N (i.e., in an index) */
        761,                         /* N */
        16,                          /* security strength in octets */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        FALSE,                       /* product form */
        42,                          /* df, dr */
        253,                         /* dg */
        125,                         /* maxMsgLenBytes */
        42,                          /* dm0 */
        3805,                        /* 2^c - (2^c mod N) */
        12,                          /* c */
        1,                           /* lLen */
        13,                          /* min. no. of hash calls for IGF-2 */
        16,                          /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        NTRU_EES1087EP1,             /* parameter-set id */
        {0x00, 0x05, 0x05},          /* OID */
        0x2c,                        /* DER id */
        11,                          /* no. of bits in N (i.e., in an index) */
        1087,                        /* N */
        24,                          /* security strength in octets */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        FALSE,                       /* product form */
        63,                          /* df, dr */
        362,                         /* dg */
        178,                         /* maxMsgLenBytes */
        63,                          /* dm0 */
        7609,                        /* 2^c - (2^c mod N) */
        13,                          /* c */
        1,                           /* lLen */
        13,                          /* min. no. of hash calls for IGF-2 */
        14,                          /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        NTRU_EES1499EP1,             /* parameter-set id */
        {0x00, 0x06, 0x05},          /* OID */
        0x2d,                        /* DER id */
        11,                          /* no. of bits in N (i.e., in an index) */
        1499,                        /* N */
        32,                          /* security strength in octets */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        FALSE,                       /* product form */
        79,                          /* df, dr */
        499,                         /* dg */
        247,                         /* maxMsgLenBytes */
        79,                          /* dm0 */
        7495,                        /* 2^c - (2^c mod N) */
        13,                          /* c */
        1,                           /* lLen */
        17,                          /* min. no. of hash calls for IGF-2 */
        19,                          /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        NTRU_EES401EP2,              /* parameter-set id */
        {0x00, 0x02, 0x10},          /* OID */
        0x2e,                        /* DER id */
        9,                           /* no. of bits in N (i.e., in an index) */
        401,                         /* N */
        14,                          /* security strength in octets */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        TRUE,                        /* product form */
        8 + (8 << 8) + (6 << 16),    /* df, dr */
        133,                         /* dg */
        60,                          /* maxMsgLenBytes */
        136,                         /* m(1)_max */
        2005,                        /* 2^c - (2^c mod N) */
        11,                          /* c */
        1,                           /* lLen */
        10,                          /* min. no. of hash calls for IGF-2 */
        6,                           /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        NTRU_EES439EP1,              /* parameter-set id */
        {0x00, 0x03, 0x10},          /* OID */
        0x2f,                        /* DER id */
        9,                           /* no. of bits in N (i.e., in an index) */
        439,                         /* N */
        16,                          /* security strength in octets */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        TRUE,                        /* product form */
        9 + (8 << 8) + (5 << 16),    /* df, dr */
        146,                         /* dg */
        65,                          /* maxMsgLenBytes */
        126,                         /* m(1)_max */
        439,                         /* 2^c - (2^c mod N) */
        9,                           /* c */
        1,                           /* lLen */
        15,                          /* min. no. of hash calls for IGF-2 */
        6,                           /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        NTRU_EES593EP1,              /* parameter-set id */
        {0x00, 0x05, 0x10},          /* OID */
        0x30,                        /* DER id */
        10,                          /* no. of bits in N (i.e., in an index) */
        593,                         /* N */
        24,                          /* security strength in octets */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        TRUE,                        /* product form */
        10 + (10 << 8) + (8 << 16),  /* df, dr */
        197,                         /* dg */
        86,                          /* maxMsgLenBytes */
        90,                          /* m(1)_max */
        1779,                        /* 2^c - (2^c mod N) */
        11,                          /* c */
        1,                           /* lLen */
        12,                          /* min. no. of hash calls for IGF-2 */
        5,                           /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        NTRU_EES743EP1,              /* parameter-set id */
        {0x00, 0x06, 0x10},          /* OID */
        0x31,                        /* DER id */
        10,                          /* no. of bits in N (i.e., in an index) */
        743,                         /* N */
        32,                          /* security strength in octets */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        TRUE,                        /* product form */
        11 + (11 << 8) + (15 << 16), /* df, dr */
        247,                         /* dg */
        106,                         /* maxMsgLenBytes */
        60,                          /* m(1)_max */
        8173,                        /* 2^c - (2^c mod N) */
        13,                          /* c */
        1,                           /* lLen */
        12,                          /* min. no. of hash calls for IGF-2 */
        7,                           /* min. no. of hash calls for MGF-TP-1 */
    },

};

static size_t numParamSets =
                sizeof(ntruParamSets)/sizeof(NTRU_ENCRYPT_PARAM_SET);


/* functions */

/* ntru_encrypt_get_params_with_id
 *
 * Looks up a set of NTRUEncrypt parameters based on the id of the
 * parameter set.
 *
 * Returns a pointer to the parameter set parameters if successful.
 * Returns NULL if the parameter set cannot be found.
 */

NTRU_ENCRYPT_PARAM_SET *
ntru_encrypt_get_params_with_id(
    NTRU_ENCRYPT_PARAM_SET_ID id)   /*  in - parameter-set id */
{
    size_t i;

    for (i = 0; i < numParamSets; i++) {
        if (ntruParamSets[i].id == id) {
            return &(ntruParamSets[i]);
        }
    }
    return NULL;
}


/* ntru_encrypt_get_params_with_OID
 *
 * Looks up a set of NTRUEncrypt parameters based on the OID of the
 * parameter set.
 *
 * Returns a pointer to the parameter set parameters if successful.
 * Returns NULL if the parameter set cannot be found.
 */

NTRU_ENCRYPT_PARAM_SET *
ntru_encrypt_get_params_with_OID(
    uint8_t const *oid)             /*  in - pointer to parameter-set OID */
{
    size_t i;

    for (i = 0; i < numParamSets; i++) {
        if (!memcmp(ntruParamSets[i].OID, oid, 3)) {
            return &(ntruParamSets[i]);
        }
    }
    return NULL;
}


/* ntru_encrypt_get_params_with_DER_id
 *
 * Looks up a set of NTRUEncrypt parameters based on the DER id of the
 * parameter set.
 *
 * Returns a pointer to the parameter set parameters if successful.
 * Returns NULL if the parameter set cannot be found.
 */

NTRU_ENCRYPT_PARAM_SET *
ntru_encrypt_get_params_with_DER_id(
    uint8_t der_id)                 /*  in - parameter-set DER id */
{
    size_t i;

    for (i = 0; i < numParamSets; i++) {
        if (ntruParamSets[i].der_id == der_id) {
            return &(ntruParamSets[i]);
        }
    }
    return NULL;
}


