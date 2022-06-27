/******************************************************************************
 * Aerolock whitelisting reference code for industiral control systems (ICS)
 * Copyright (c) 2012-2022, by Resilient Machines, LLC and Sand Drft Software, LLC, and Peter H. Jenney
 * (r) All rights reserved. 
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

/*
 * signature.c
 *
 *
 * Description
 * --------------
 * Functions to generate HMACs from ELF files.
 *
 *   Deconstruct the ELF header, extract Code Segment and HMAC the contents
 *
 * We use the first method because we can replicate the functionality in the kernel and
 * guarantee that we get "good" HMACs for comparison.
 *
 * Author
 * ------- *
 *  Created on: Oct 2, 2013
 *      Author: Pete Jenney
 */

#include "aerolock.h"

#ifdef __LINUX__
#pragma GCC diagnostic ignored "-Wpointer-sign"
#pragma GCC diagnostic push
#endif

int32_t        __err_code = 1;
static uint8_t __static__sha256key[32] = "";

static int __gen_segment_hmac64(const int8_t* filename, NTRU_CRYPTO_HMAC_CTX* __ctx);
static int __gen_segment_hmac32(const int8_t* filename, NTRU_CRYPTO_HMAC_CTX* __ctx);

/*
 * static uint8_t* __map_file() - returns pointer to memory mapped file
 * @__filename - char*,  the file to map
 * @__len - long*, the length of the mapped region
 */
static uint8_t* __map_file(const int8_t* __filename, long32_t* __len)
{
	struct stat __st;
	int32_t     __fd = 0;
	uint8_t*    __filebuf;

	if(!__filename || !__len)
	{
		syslog(LOG_ERR, "In __map_file(), bogus parameters");
		goto out;
	}

	if (stat(__filename, &__st) != -1)
	{
	    if ((__fd = open(__filename, O_RDONLY)) > 0)
	    {
		    if (((__filebuf = mmap(0, __st.st_size, PROT_READ, MAP_PRIVATE, __fd, 0)) == MAP_FAILED) || !__filebuf)
		    {
			    syslog(LOG_ERR, "In __map_file(), mmap() failed with: %s", strerror(errno));
			    close(__fd);
			    goto out;
            }
			else
			{
				close(__fd);
			}
		}
		else
		{
			syslog(LOG_ERR, "In __map_file(), open() failed with: %s", strerror(errno));
		}
	}
	else
	{
		syslog(LOG_ERR, "In __map_file() - stat() failed (%s) with: %s", __filename, strerror(errno));
		return NULL;
	}

	*__len = __st.st_size;

out:

	return __filebuf;
}

/*
 * static void __unmap_file() - unmaps previously memory mapped file
 * @__filebuf  - unsigned char*,  the buffer to unmap
 * @__len      - long,   the length of the mapped region
 */
static void __unmap_file(uint8_t* __filebuf, ulong32_t __len)
{
	if(__filebuf)
    {
		munmap(__filebuf, __len);
    }
}

static int32_t __gen_segment_hmac64(const int8_t* __filename, NTRU_CRYPTO_HMAC_CTX* __ctx)
{
    Elf64_Ehdr   __file_hdr64;
    Elf64_Phdr*  __prog_hdr64 = NULL;
    uint8_t*     __filebuf    = NULL;
    long32_t     __len        = 0;
    int32_t 	 __i          = 0,
                 __retcode    = 0,
                 __retval     = 0;

    /*
     * Memory map the file. This is not only faster than mallocing buffer and reading the file into it,
     * but it ends up using less memory and the maneuvering through the contents is the same.
     */
    __filebuf = __map_file(__filename, &__len);
    if(!__filebuf)
    {
    	syslog(LOG_ERR, "In __gen_segment_hmac64() - failed on map_file()\n");
        goto out;
    }

    memcpy(&__file_hdr64, __filebuf, sizeof(__file_hdr64));

    /*
     * Make sure that the library were using is the bit length this function supports.  If not pass it to the
     * proper routine.
     */
    if(__file_hdr64.e_ident[EI_CLASS] != 2)
    {
        if(__file_hdr64.e_ident[EI_CLASS] == 1)
        {
            return(__gen_segment_hmac32(__filename, __ctx));
        }

        syslog(LOG_ERR, "__gen_segment_hmac64() - bad EI_CLASS [%d]", (int32_t)__file_hdr64.e_ident);
        goto cleanup_and_leave;
    }

    /*
     * Check for offset sanity
     */
    if(__file_hdr64.e_phoff > __len)
    {
    	syslog(LOG_ERR, "__gen_segment_hmac64() - Insane __file_hdr64.e_phoff!");
    	goto cleanup_and_leave;
    }

    /*
     *  Point to the first program header
     */
    __prog_hdr64 = (Elf64_Phdr*)( __filebuf + __file_hdr64.e_phoff);

    /*
     * Iterate through the program headers looking for PT_LOAD + S + X
     */
    for(__i=0; __i<__file_hdr64.e_phnum; __i++)
    {
        if(__prog_hdr64->p_type == PT_LOAD)
        {
            if(__prog_hdr64->p_flags == (PF_R + PF_X))
            {
            	__retcode = ntru_crypto_hmac_update(__ctx, __filebuf + __prog_hdr64->p_offset, __prog_hdr64->p_filesz);

                if(__retcode != NTRU_CRYPTO_HMAC_OK)
                {
                    syslog(LOG_ERR, "__gen_segment_hmac64() - Internal crypto error (%d) for file %s", __retcode, __filename);
                    goto cleanup_and_leave;
                }

                __retval = 1;
                goto cleanup_and_leave;
            }
        }

        __prog_hdr64++;
    }

    syslog(LOG_ERR, "__gen_segment64() - Failed to locate appropriate program header for %s", __filename);

cleanup_and_leave:
    __unmap_file(__filebuf, __len);
    __filebuf = NULL;

out:
    return __retval;
}


static int32_t __gen_segment_hmac32(const int8_t* __filename, NTRU_CRYPTO_HMAC_CTX* __ctx)
{
    Elf32_Ehdr   __file_hdr32;
    Elf32_Phdr*  __prog_hdr32 = NULL;
    uint8_t*     __filebuf    = NULL;
    long32_t     __len        = 0L;
    int32_t      __i          = 0,
                 __retcode    = 0,
                 __retval     = 0;

    /*
     * Memory map the file. This is not only faster than mallocing buffer and reading the file into it,
     * but it ends up using less memory and the maneuvering through the contents is the same.
     */
    __filebuf = __map_file(__filename, &__len);
    if(!__filebuf)
    {
    	syslog(LOG_ERR, "__gen_segment_hmac32() - failed on map_file()\n");
        goto out;
    }

    memcpy(&__file_hdr32, __filebuf, sizeof(__file_hdr32));

    /*
     * Make sure that the library were using is the bit length this function supports.  If not pass it to the
     * proper routine.
     */
    if(__file_hdr32.e_ident[EI_CLASS] != 1)
    {
        if(__file_hdr32.e_ident[EI_CLASS] == 2)
        {
            return(__gen_segment_hmac64(__filename, __ctx));
        }

        syslog(LOG_ERR, "__gen_segment_hmac32() - bad EI_CLASS [%d]", (int32_t)__file_hdr32.e_ident);
        goto cleanup_and_leave;
    }

    /*
	 * Check for offset sanity
	 */
    if(__file_hdr32.e_phoff > __len)
    {
	    syslog(LOG_ERR, "__gen_segment_hmac32() - Insane __file_hdr32.e_phoff!");
	    goto cleanup_and_leave;
    }

    /*
     *  Point to the first program header
     */
    __prog_hdr32 = (Elf32_Phdr*)( __filebuf + __file_hdr32.e_phoff);

    /*
     * Iterate through the program headers looking for PT_LOAD + S + X
     */
    for(__i=0; __i<__file_hdr32.e_phnum; __i++)
    {
        if(__prog_hdr32->p_type == PT_LOAD)
        {
            if(__prog_hdr32->p_flags == (PF_R + PF_X))
            {
                __retcode = ntru_crypto_hmac_update(__ctx, __filebuf + __prog_hdr32->p_offset, __prog_hdr32->p_filesz);
                if(__retcode != NTRU_CRYPTO_HMAC_OK)
                {
                    syslog(LOG_ERR, "__gen_segment_hmac32() - Internal crypto error (%d) for file %s", __retcode, __filename);
                    goto cleanup_and_leave;
                }

                __retval = 1;
                goto cleanup_and_leave;
            }
        }

        __prog_hdr32++;
    }

    syslog(LOG_ERR, "__gen_segment32() - Failed to locate appropriate program header for file %s", __filename);

cleanup_and_leave:
    __unmap_file(__filebuf, __len);
    __filebuf = NULL;

out:
    return __retval;
}

static int32_t __generate_hmac(const int8_t* __filename, NTRU_CRYPTO_HMAC_CTX* __ctx)
{
    uint8_t*  __hdr      = NULL;
    uint8_t*  __filebuf  = NULL;
    int32_t   __fd       = -1;
    int32_t   __retval   = 0,
    		  __retcode  = 0;
    ulong32_t __len      = 0L;

    __hdr = (uint8_t*)malloc(16);
    if(!__hdr)
    {
    	goto out;
    }

    if((__fd = open(__filename, O_RDONLY)) > 0)
    {
        read(__fd, __hdr, 16);
        close(__fd);
        /*
         *  Need to use the proper header as the offsets in the 64 bit struct are 64 bits
         */
        if(__hdr[EI_MAG0] != 0x7f)
        {
            goto hmac_generic_file;
        }

        switch(__hdr[EI_CLASS])
        {

        case 1:
            __retval = __gen_segment_hmac32(__filename, __ctx);
            break;

        case 2:
            __retval = __gen_segment_hmac64(__filename, __ctx);
            break;

        case 0:
        default:
            goto hmac_generic_file;
            break;
        }

        goto out;
    }
    else
    {
        syslog(LOG_ERR, "__generate_hmac() failed to open() [%s]", __filename);
        goto out;
    }

hmac_generic_file:

    /*
     *  HMAC as plain text
     */
    syslog(LOG_DEBUG, "Bad magic number in %s, HMACing body", __filename);

	__filebuf = __map_file(__filename, &__len);
	if(!__filebuf)
	{
		syslog(LOG_ERR, "In __generate_hmac() - failed on map_file()\n");
		goto out;
	}

    __retcode = ntru_crypto_hmac_update(__ctx, __filebuf, __len);
    if(__retcode != NTRU_CRYPTO_HMAC_OK)
    {
        syslog(LOG_ERR, "__generate_hmac() - internal crypto error (%d)", __retcode);
        goto out;
    }
    else
    {
        __retval = 1;
    }

out:
    if(__hdr)
    {
    	free(__hdr);
    	__hdr = NULL;
    }

    __unmap_file(__filebuf, __len);
    __filebuf = NULL;

    return __retval;
}

/*
 *  Get a signature for the whole collection of executable and dependencies
 */
int32_t __get_signature(const int8_t* __filename, uint8_t* __hmac)
{
    int32_t               retcode = 0;
    struct stat           sb;
    int32_t               __retval = 0;
    NTRU_CRYPTO_HMAC_CTX* __ctx;

    if(!__filename || !__hmac)
    {
        goto out;
    }

    if(__maximum_verbosity)
    {
        syslog(LOG_NOTICE,"aerolock: __get_signature(%s), TID(0x%lx)", __filename, pthread_self());
    }

    if(stat(__filename, &sb) != -1)
    {
        if(sb.st_mode & S_IFDIR)
        {
            syslog(LOG_NOTICE, "aerolock: __get_signature() Trapped directory");
            goto out;
        }
    }
    else
    {
        syslog(LOG_ERR, "aerolock: __get_signature() - file %s doesn't exist", __filename);
        goto out;
    }

    /*
     * Test the cache first to avoid deep library traversals that have already been done.
     */
    if(__lookup_cache(__filename, __hmac))
    {
        __retval = 1;
        goto out;
    }

    if(!__static__sha256key[0])
    {
    	__get_key(__static__sha256key);
    }

    retcode = ntru_crypto_hmac_create_ctx(NTRU_CRYPTO_HASH_ALGID_SHA256, __static__sha256key, 32, &__ctx);
    if(retcode != NTRU_CRYPTO_HMAC_OK)
    {
        syslog(LOG_ERR, "aerolock: __get_signature() - Failed to initialize crypto_context - error (%d)\n",retcode);
        goto out;
    }

    retcode = ntru_crypto_hmac_init(__ctx);
    if(retcode != NTRU_CRYPTO_HMAC_OK)
    {
        syslog(LOG_ERR, "aerolock: __get_signature() - ntru_crypto_hmac_init error: retcode = %d, TID(0x%lx)", retcode, pthread_self());
        goto out_kill_context;
    }

    if(!__generate_hmac(__filename, __ctx))
    {
        ntru_crypto_hmac_final(__ctx, __hmac);
        syslog(LOG_ERR, "aerolock: __get_signature() - failed to generate HMAC for %s, error: %s", __filename, strerror(errno));
        goto out_kill_context;
    }
    else
    {
    	__retval = 1;
    }

    retcode = ntru_crypto_hmac_final(__ctx, __hmac);
    if(retcode != NTRU_CRYPTO_HMAC_OK)
    {
        syslog(LOG_ERR, "aerolock: __get_signature() - failed to finalize HMAC, TID(0x%lx)", pthread_self());
        __retval = 0;
        goto out_kill_context;
    }

    if(!__add_to_cache(__filename, __hmac))
    {
        syslog(LOG_DEBUG, "aerolock: __get_signature() - cache add failure (%s)", __filename);
    }

out_kill_context:
	ntru_crypto_hmac_destroy_ctx(__ctx);

out:
    return __retval;
}

#ifdef __LINUX__
#pragma GCC diagnostic pop
#endif
