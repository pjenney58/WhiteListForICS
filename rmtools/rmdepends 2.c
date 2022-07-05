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
 * rmdepends.c
 *
 *  Created on: Oct 2, 2013
 *      Author: Pete Jenney
 */

#include "aerolock.h"

//static NTRU_CRYPTO_HMAC_CTX* g_CryptoContext = NULL;

int __err_code = 1;
//int rlevel  = 0;
//__pglobal_data p;
int __maximum_verbosity = 0;

static int genhmac64(const char* filename, const char* parent, int depth, NTRU_CRYPTO_HMAC_CTX* __ctx);
static int genhmac32(const char* filename, const char* parent, int depth, NTRU_CRYPTO_HMAC_CTX* __ctx);

// call this function to start a nanosecond-resolution timer
struct timespec __timer_start()
{
    struct timespec start_time;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start_time);
    return start_time;
}

// call this function to end a timer, returning nanoseconds elapsed as a long
long __timer_end(struct timespec start_time)
{
    struct timespec end_time;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end_time);
    long diffInNanos = end_time.tv_nsec - start_time.tv_nsec;
    return diffInNanos;
}

int32_t __get_key(uint8_t* key)
{
    int32_t rc = 0;
    int32_t fd = 0;
    int32_t __retval = 1;

    fd = open(RMI_KEY, O_RDONLY);
    if(fd == -1)
    {
        __retval = 0;
        goto out;
    }

    rc = read(fd, key, 32);
    if(rc != 32)
    {
        perror("read key");
        __retval = 0;
    }

    close(fd);

out:
    return __retval;
}

static int genhmac32(const char* filename, const char* parent, int rlevel, NTRU_CRYPTO_HMAC_CTX* __ctx)
{
    Elf32_Ehdr file_hdr32;
    Elf32_Shdr** section_hdr32 = NULL;
    Elf32_Dyn** dynamic_hdr32 = NULL;
    short i, x;
    short len = 0;
    unsigned char* filebuf = NULL;
    unsigned char* ucp = NULL;

    char* stringTable = NULL;
    char* symbolTable = NULL;
    char* strIndex = NULL;
    int32_t retcode = 0;
    char dashbuf[32] = "";
    int  dashlevel = 0;

    struct stat st;
    int __fd = -1;
    struct timespec __var_sig_time = {0};
    unsigned long   __diff_sig_nanoseconds = 0L;


    __var_sig_time = __timer_start();

    if(stat(filename, &st) != -1)
    {
        if((__fd = open(filename, O_RDONLY)) > 0)
        {
            if((filebuf = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, __fd, 0)) != NULL)
            {
                close(__fd);
            }
        }
    }
    
    if(!filebuf)
    {
        if(__fd > 0)
        {
            close(__fd);
        }

        return 0;
    }
    
    /*
     * Make sure that the library were using is the bit length this function supports.  If not pass it to the
     * proper routine.
     */
    if(filebuf[EI_CLASS] != 1)
    {
        if(filebuf[EI_CLASS] == 2)
        {
            return(genhmac64(filename, parent, rlevel, __ctx));
        }

        return 0;
    }

    ucp = filebuf;

    /*
     * Copy the ELF header and test the magic number
     */
    memcpy(&file_hdr32, ucp, sizeof(file_hdr32));

    /*
     *  Get the section headers if there are any - If there are no section headers then we can generate an HMAC for
     *  what we have in filebuf and just return that
     */
    if (file_hdr32.e_shnum)
    {
        ucp = filebuf + file_hdr32.e_shoff;

        if(ucp)
        {
            section_hdr32 = (Elf32_Shdr**) malloc(file_hdr32.e_shnum * sizeof(Elf32_Shdr*));
            for (i = 0; i < file_hdr32.e_shnum; i++)
            {
                section_hdr32[i] = (Elf32_Shdr*) malloc(sizeof(Elf32_Shdr));
                memcpy(section_hdr32[i], ucp, sizeof(Elf32_Shdr));
                ucp += sizeof(Elf32_Shdr);
            }
        }
    }
    else
    {
        struct stat sb;

        if(stat(filename, &sb) == -1)
        {
            syslog(LOG_ERR, "File stat() error");
            __err_code = 0;
            goto cleanup_and_exit32;
        }

        syslog(LOG_NOTICE, "(%s) No ELF32 section headers, HMACing executable body [%ld bytes]", filename, sb.st_size);

        retcode = ntru_crypto_hmac_update(__ctx, filebuf, sb.st_size);
        if(retcode != NTRU_CRYPTO_HMAC_OK)
        {
            syslog(LOG_ERR, "Internal crypto error (%d)", retcode);
            __err_code = 0;
        }

        goto cleanup_and_exit32;
    }

    /*
     *  String Table is referenced by section_hdr32[file_hdr32.e_shstrndx].sh_offset.  It holds all the names of the
     *  key sections where we can get dependencies and code
     */
    stringTable = (char*) (filebuf + section_hdr32[file_hdr32.e_shstrndx]->sh_offset);
    strIndex = stringTable;

    /*
     * The symbol table resolves symbol names that we may use later
     */
    for (i = 0; i < file_hdr32.e_shnum; i++)
    {
        if (!strcmp(".dynstr", strIndex + section_hdr32[i]->sh_name))
        {
            symbolTable = (char*) (filebuf + section_hdr32[i]->sh_offset);
            break;
        }
    }

    /*
     *  Get the the meat of the matter
     */

    /*
     * strIndex is pointing at the string table and entries look like .table_entry\0
     */
    for (i = 0; i < file_hdr32.e_shnum; i++)
    {
        if (!strcmp(".dynamic", strIndex + section_hdr32[i]->sh_name))
        {
            /*
             *  This is the section that will lead us to the shared libraries
             */
            len = section_hdr32[i]->sh_size / sizeof(Elf32_Dyn);

            ucp = filebuf + section_hdr32[i]->sh_offset;
            dynamic_hdr32 = (Elf32_Dyn**) malloc(len * sizeof(Elf32_Dyn*));

            for (x = 0; x < len; x++)
            {
                dynamic_hdr32[x] = (Elf32_Dyn*) malloc(sizeof(Elf32_Dyn));
                memcpy(dynamic_hdr32[x], ucp, sizeof(Elf32_Dyn));
                ucp += sizeof(Elf32_Dyn);

                if (dynamic_hdr32[x]->d_tag == DT_NEEDED)
                {
                    int j;
                    char objName[256] = "";

                    /*
                     * This gives us the library name but not the path to the library, which is normally
                     * resolved at runtime.
                     */
                    char* objNamep = symbolTable + dynamic_hdr32[x]->d_un.d_val;

                    /*
                     * This gives us the full path to the library on the system from the library cache.  
                     */
                    char* realPath = findLibNode(objNamep);
                    if(realPath)
                    {
                        strcpy(objName, realPath);
                    }

                    /*
                     * Get the .text segment and HMAC it.  All we want at this point is the code.  Later we may
                     * (v2 or v3) use it to implement some ESCAPE technology.
                     */
                    for (j = 0; j < file_hdr32.e_shnum; j++)
                    {
                        if (!strcmp(".text", strIndex + section_hdr32[j]->sh_name))
                        {
                            /*
                             * Add the data to the HMAC collective
                             */
                            retcode = ntru_crypto_hmac_update(__ctx, filebuf + section_hdr32[j]->sh_offset, section_hdr32[j]->sh_size);
                            if(retcode != NTRU_CRYPTO_HMAC_OK)
                            {
                                syslog(LOG_ERR, "Internal crypto error (%d)", retcode);
                                __err_code = 0;
                            }

                            if(objNamep)
                            {
                                for(dashlevel=0; dashlevel < rlevel+1; dashlevel++)
                                {
                                    memcpy(dashbuf + dashlevel, "=", 1);
                                }

                                fprintf(stdout, "%s %s [%d bytes]\n", dashbuf, objNamep, section_hdr32[j]->sh_size);
                            }

                            break;
                        }
                    }

                    /*
                     * Recurse to get all dependencies
                     */
                    if(rlevel < MAX_DEPTH)
                    {
                        genhmac32(objName, filename, rlevel+1, __ctx);
                    }
                }
            }
        }
    }

cleanup_and_exit32:
    /*
     * Clean up and exit
     */

    for (i = 0; i < file_hdr32.e_shnum; i++)
    {
        free(section_hdr32[i]);
    }

    free(section_hdr32);

    for(x = 0; x < len; x++)
    {
        free(dynamic_hdr32[x]);
    }

    free(dynamic_hdr32);

    munmap (filebuf, st.st_size);

    __diff_sig_nanoseconds = __timer_end(__var_sig_time)/1000000;
    fprintf(stdout, "filename: %s processing time: %lums\n", filename, __diff_sig_nanoseconds);
    return __err_code;
}

static int genhmac64(const char* filename, const char* parent, int rlevel, NTRU_CRYPTO_HMAC_CTX* __ctx)
{
    Elf64_Ehdr file_hdr64;
    Elf64_Shdr** section_hdr64 = NULL;
    Elf64_Dyn** dynamic_hdr64 = NULL;
    short i, x;
    short len = 0;
    unsigned char* filebuf = NULL;
    unsigned char* ucp = NULL;

    char* stringTable = NULL;
    char* symbolTable = NULL;
    char* strIndex = NULL;

    int32_t retcode = 0;
    char dashbuf[32] = "";
    int  dashlevel = 0;

    struct stat st;
    int __fd = -1;
    struct timespec __var_sig_time;
    unsigned long   __diff_sig_nanoseconds;

    __var_sig_time = __timer_start();

    if(stat(filename, &st) != -1)
    {
        if((__fd = open(filename, O_RDONLY)) > 0)
        {
            if((filebuf = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, __fd, 0)) != NULL)
            {
                close(__fd);
            }
        }
    }
    
    if(!filebuf)
    {
        if(__fd > 0)
        {
            close(__fd);
        }

        return 0;
    }    

    if(filebuf[EI_CLASS] != 2)
    {
        if(filebuf[EI_CLASS] == 1)
        {
            return(genhmac32(filename, parent, rlevel, __ctx));
        }

        return 0;
    }

    ucp = filebuf;

    /*
     * Copy the ELF header and test the magic number
     */
    memcpy(&file_hdr64, ucp, sizeof(file_hdr64));

    /*
     *  Get the section headers if there are any - If there are no section headers then we can generate an HMAC for
     *  what we have in filebuf and just return that
     */
    if (file_hdr64.e_shnum)
    {
        ucp = filebuf + file_hdr64.e_shoff;

        if(ucp)
        {
            section_hdr64 = (Elf64_Shdr**) malloc(file_hdr64.e_shnum * sizeof(Elf64_Shdr*));
            for (i = 0; i < file_hdr64.e_shnum; i++)
            {
                section_hdr64[i] = (Elf64_Shdr*) malloc(sizeof(Elf64_Shdr));
                memcpy(section_hdr64[i], ucp, sizeof(Elf64_Shdr));
                ucp += sizeof(Elf64_Shdr);
            }
        }
    }
    else
    {
        struct stat sb;

        if(stat(filename, &sb) == -1)
        {
            syslog(LOG_ERR, "File stat() error");
            __err_code = 0;
            goto cleanup_and_exit64;
        }

        retcode = ntru_crypto_hmac_update(__ctx, filebuf, sb.st_size);
        if(retcode != NTRU_CRYPTO_HMAC_OK)
        {
            syslog(LOG_ERR, "Internal crypto error (%d)", retcode);
            __err_code = 0;
        }

        syslog(LOG_NOTICE, "(%s) No ELF64 section headers, HMACing executable body [%ld bytes]", filename, sb.st_size);

        goto cleanup_and_exit64;
    }

    /*
     *  String Table is referenced by section_hdr32[file_hdr32.e_shstrndx].sh_offset.  It holds all the names of the
     *  key sections where we can get dependencies and code
     */
    stringTable = (char*) (filebuf + section_hdr64[file_hdr64.e_shstrndx]->sh_offset);
    strIndex = stringTable;

    /*
     * The symbol table resolves symbol names that we may use later
     */
    for (i = 0; i < file_hdr64.e_shnum; i++)
    {
        if (!strcmp(".dynstr", strIndex + section_hdr64[i]->sh_name))
        {
            symbolTable = (char*) (filebuf + section_hdr64[i]->sh_offset);
            break;
        }
    }

    /*
     *  Get the the meat of the matter
     */

    /*
     * strIndex is pointing at the string table and entries look like .table_entry\0
     */
    for (i = 0; i < file_hdr64.e_shnum; i++)
    {
        if (!strcmp(".dynamic", strIndex + section_hdr64[i]->sh_name))
        {
            /*
             *  This is the section that will lead us to the shared libraries
             */
            len = section_hdr64[i]->sh_size / sizeof(Elf64_Dyn);

            ucp = filebuf + section_hdr64[i]->sh_offset;
            dynamic_hdr64 = (Elf64_Dyn**) malloc(len * sizeof(Elf64_Dyn*));

            for (x = 0; x < len; x++)
            {
                dynamic_hdr64[x] = (Elf64_Dyn*) malloc(sizeof(Elf64_Dyn));
                memcpy(dynamic_hdr64[x], ucp, sizeof(Elf64_Dyn));
                ucp += sizeof(Elf64_Dyn);

                if (dynamic_hdr64[x]->d_tag == DT_NEEDED)
                {
                    int j;
                    char objName[256] = "";
                    char* objNamep = symbolTable + dynamic_hdr64[x]->d_un.d_val;

                    //pthread_mutex_lock(&__lib_search_mutex);
                    char* realPath = findLibNode(objNamep);
                    if(realPath)
                    {
                        strcpy(objName, realPath);
                    }
                    //pthread_mutex_unlock(&__lib_search_mutex);

                    /*
                     * Get the .text segment and HMAC it
                     */
                    for (j = 0; j < file_hdr64.e_shnum; j++)
                    {
                        if (!strcmp(".text", strIndex + section_hdr64[j]->sh_name))
                        {
                            /*
                             * Add the data to the collective
                             */
                            retcode = ntru_crypto_hmac_update(__ctx, filebuf + section_hdr64[j]->sh_offset, section_hdr64[j]->sh_size);

                            if(retcode != NTRU_CRYPTO_HMAC_OK)
                            {
                                syslog(LOG_ERR, "Internal crypto error (%d)", retcode);
                                __err_code = 0;
                            }

                            if(objNamep)
                            {
                                for(dashlevel=0; dashlevel < rlevel; dashlevel++)
                                {
                                    memcpy(dashbuf + dashlevel, "-", 1);
                                }

                                fprintf(stdout, "%s %s [%d bytes]\n", dashbuf, objNamep, section_hdr64[j]->sh_size);
                            }

                            break;
                        }
                    }

                    /*
                     * Recurse to get all dependencies
                     */
                    if(rlevel < MAX_DEPTH)
                    {
                        genhmac64(objName, filename, rlevel+1, __ctx);
                    }
                }
            }
        }
    }

cleanup_and_exit64:
    /*
     * Clean up and exit
     */

    for (i = 0; i < file_hdr64.e_shnum; i++)
    {
        free(section_hdr64[i]);
    }

    free(section_hdr64);

    for(x = 0; x < len; x++)
    {
        free(dynamic_hdr64[x]);
    }

    free(dynamic_hdr64);

    munmap (filebuf, st.st_size);

    __diff_sig_nanoseconds = __timer_end(__var_sig_time)/1000000;
    fprintf(stdout, "filename: %s processing time: %lums\n", filename, __diff_sig_nanoseconds);
    return __err_code;
}

static int generate_hmac(const char* filename, int8_t* parent, NTRU_CRYPTO_HMAC_CTX* __ctx)
{
    unsigned char hdr[16];
    struct stat st;
    unsigned char* filebuf = NULL;
    int32_t retcode;
    int __fd = -1;

    if((__fd = open(filename, O_RDONLY)) > 0)
    {
        read(__fd, hdr, 16);
        close(__fd);
        /*
         *  Need to use the proper header as the offsets in the 64 bit struct are 64 bits
         */
        if(hdr[EI_MAG0] != 0x7f)
        {
            goto hmac_generic_file;
        }

        switch(hdr[EI_CLASS])
        {
        case 1:
            return genhmac32(filename, parent, 0, __ctx);
            break;

        case 2:
            return genhmac64(filename, parent, 0, __ctx);
            break;

        default:
        case 0:
            goto hmac_generic_file;
            break;
        }
    }
    else
    {
    	perror("generate_hmac - open()\n");
        return 0;
    }

    /*
     * TODO: if not already done it, do it now
     */
hmac_generic_file:

    /*
     *  HMAC as executable text
     */

    if(__maximum_verbosity)
    {
        syslog(LOG_NOTICE, "Bad magic number, HMACing executable body [%ld bytes]", st.st_size);
    }

    if(stat(filename, &st) != -1)
    {
        if((__fd = open(filename, O_RDONLY)) > 0)
        {
            if((filebuf = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, __fd, 0)) != NULL)
            {
                close(__fd);
            }
        }
    }
    
    if(!filebuf)
    {
        if(__fd > 0)
        {
            close(__fd);
        }

        return 0;
    }    

    retcode = ntru_crypto_hmac_update(__ctx, filebuf, st.st_size);
    if(retcode != NTRU_CRYPTO_HMAC_OK)
    {
        syslog(LOG_ERR, "Internal crypto error (%d)", retcode);
        return 0;
    }

    munmap (filebuf, st.st_size);
    return 1;
}

/*
 *  Get a signature for the whole collection of executable and dependencies
 */
int __libListInitialized = 0;

int32_t __local_get_signature(int8_t* filename)
{
    int32_t         retcode = 0;
    uint8_t         _hmac[32];
    int8_t          hmac_string[64] = "";
    struct stat     sb;
    uint8_t         sha2key[32];
    NTRU_CRYPTO_HMAC_CTX* __ctx;
    int32_t         __retval = 0;
    struct timespec __var_sig_time;
    ulong32_t       __diff_sig_nanoseconds;

    if(!filename)
    {
        fprintf(stderr, "Bad filename %s\n", (char*)filename);
        goto out;
    }

    fprintf(stdout,"TEST: GetSignature(%s), TID(0x%lx)\n", (char*)filename, pthread_self());

    if(stat((char*)filename, &sb) != -1)
    {
        if(sb.st_mode & S_IFDIR)
        {
            syslog(LOG_NOTICE, "PROC: GetSignature() Trapped directory");
            goto out;
        }
    }

    /*
     *  Extract the contents of ld.so.cache into a local linked list for high speed lookups
     */
    if(!__libListInitialized)
    {
        buildLibList();
        __libListInitialized = 1;
    }

    /*
     * First generate the HMAC silently, then do it with the dependancies expanded
     */
    __maximum_verbosity = 0;

    __var_sig_time = __timer_start();

    retcode = ntru_crypto_hmac_create_ctx(NTRU_CRYPTO_HASH_ALGID_SHA256, sha2key, 32, &__ctx);
	if(retcode != NTRU_CRYPTO_HMAC_OK)
	{
		syslog(LOG_ERR, "aerolock: GetSignature() - Failed to initialize crypto_context - error (%d)\n",retcode);
		goto out;
	}

    retcode = ntru_crypto_hmac_init(__ctx);
    if(retcode != NTRU_CRYPTO_HMAC_OK)
    {
        syslog(LOG_ERR, "ntru_crypto_hmac_init error: retcode = %d", retcode);
        goto out_kill_context;
    }

    /*
     *  Call recursive function here
     */
    if(!generate_hmac((char*)filename,"root",  __ctx))
    {
        syslog(LOG_ERR, "Failed to generate HMAC for %s", (char*)filename);
        goto out_kill_context;
    }

    /*
     * Lock in the HMAC
     */
    retcode = ntru_crypto_hmac_final(__ctx, _hmac);
    if(retcode != NTRU_CRYPTO_HMAC_OK)
    {
        syslog(LOG_ERR, "Failed to finalize HMAC");
        pthread_exit(NULL);
    }

    __diff_sig_nanoseconds = __timer_end(__var_sig_time)/1000000;
    fprintf(stdout, "TEST: Time - Generate Signature(%ldms)\n", __diff_sig_nanoseconds);

out_kill_context:
    ntru_crypto_hmac_destroy_ctx(__ctx);

out:
    return __retval;
}

int main(int ac, char** av)
{
  return __local_get_signature(av[1]);
}

    
