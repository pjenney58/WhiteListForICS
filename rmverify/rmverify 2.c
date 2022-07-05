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
 * main.c
 *
 *  Created on: Oct 1, 2013
 *      Author: Pete Jenney
 */

#ifdef __LINUX__
#pragma GCC diagnostic ignored "-Wpointer-sign"
#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic push
#endif

#include <stdarg.h>
#include "aerolock.h"
#include <time.h>
#include <sys/ioctl.h>
#include <getopt.h>

int recurse_depth = 0;
long filecount = 0;
FILE* fp;

void log_error(const char* error, ...)
{
    char lbuf0[512];
    va_list arglist;

    va_start(arglist, error);
    vsprintf(lbuf0, error, arglist);
    va_end(arglist);

    if(fp)
    {
        fprintf(fp, "%s\n", lbuf0);
    }
}

int open_error_log()
{
    struct tm* tmp;
    time_t time_secs;

    time_secs = time(NULL);
    tmp = localtime(&time_secs);

    fp = fopen("./errors.log", "a+");
    if(fp)
    {
        fprintf(fp, "**** %02d:%02d:%02d - %02d/%02d/%02d\n", tmp->tm_hour, tmp->tm_min, tmp->tm_sec, tmp->tm_mon, tmp->tm_mday, tmp->tm_year);
        return NOERROR;
    }
    
    return ERROR;
}

void close_error_log()
{
    fclose(fp);
}

int32_t validateDB(void)
{
    char objName[256];
    unsigned char hmac1[32], hmac2[32];
    char hmac_string1[128], hmac_string2[128];
    int count = 0;
    int32_t retval = NOERROR;


    if(!__bdb_open())
    {
        goto out;
    }

	while(__bdb_get_next_hmac(objName, hmac1))
	{
		if(__get_signature(objName, hmac2))
		{
			count++;
			if(!memcmp(hmac1, hmac2, 32))
			{
				putchar('+');
			}
			else
			{
				putchar('-');

				memset(hmac_string1, 0, sizeof(hmac_string1));
				memset(hmac_string2, 0, sizeof(hmac_string2));

				__hmac_2_str(hmac1, hmac_string1);
				__hmac_2_str(hmac2, hmac_string2);
				log_error("------------------\nUNIT TEST (validateDB) Invalid HMAC for %s;  \n\tDB: %s \n\tNOW:%s", objName, hmac_string1, hmac_string2);
				retval = ERROR;
			}
		}
	}

    __bdb_close();

out:
    if(retval == ERROR)
    	fprintf(stderr, "\nTest failed - processed %d HMACS\n", count);
    else
    	fprintf(stdout, "\nTest passed - processed %d HMACS\n", count);

	return retval;
}

int32_t validateCache(void)
{
    unsigned char hmac[32];
    char hmac_string[128];
    char name[128];
    int fd = -1;
    int fd2 = -1;
    int rc = -1;
    int32_t retval = ERROR;
    int k, i, j;
    int front, back;

    if((fd = open("/dev/urandom", O_RDONLY)) == -1)
    {
        syslog(LOG_ERR, "UNIT TEST (validateCache) Failed to open /dev/urandom");
        goto out;
    }

    for(j=0; j< 2; j++)
    {
        for(k = 0; k < 64; k++)
        {
            for(i = 0; i < 1024; i++)
            {
                if((rc = read(fd, hmac, 32)) == -1)
                {
                    close(fd);
                    perror("read urandom");
                    syslog(LOG_ERR, "UNIT TEST (validateCache) Failed to read 32 bytes from /dev/urandom");
                    goto out;
                }

                __hmac_2_str(hmac, hmac_string);
                sprintf(name, "/tmp/%d__name__%d", k, i);
                fd2 = creat(name, O_RDWR);
                close(fd2);

                if(!__add_to_cache(name, hmac))
                {
                    //putchar('-');
                    syslog(LOG_ERR, "UNIT TEST (validateCache) Failed on CacheAdd(%s)", name);
                    goto out;
                }
                else
                {
                    //putchar('+');
                }
            }
        }

        for(i = 0; i<1024;i++)
        {
            while((front = rand()) > 63)
                ;

            while((back = rand()) > 1023)
                ;

            sprintf(name, "/tmp/%d__name__%d", front, back);

            if(!__lookup_cache(name, hmac))
            {
                //putchar('-');
                syslog(LOG_ERR, "UNIT TEST (validateCache) failed to find %s", name);
                goto out;
            }
            else
            {
                //putchar('+');
            }
        }

        __rb_flush_cache();
    }

    if(!__load_cache())
    {
        //putchar('-');
        syslog(LOG_ERR, "UNIT TEST (validateCache) failed no loadCache()");
        goto out;
    }
    else
    {
        //putchar('-');
    }

    __rb_flush_cache();

    retval = NOERROR;

out:
	return retval;
}

/*
 * Fill and empty the main HMAC store
 */
int32_t __test_hmac_list()
{
    if(__bdb_open())
    {
	if(__rb_init_hmac_list())
	    __rb_flush_hmacs();

        __bdb_close();
    }

    return 1;
}

#define AL_MAGIC 'k'
#define SET_DEBUG _IO(AL_MAGIC,0xAD01)
#define UNSET_DEBUG _IO(AL_MAGIC,0xAD02)
#define SET_LOCK _IO(AL_MAGIC,0xAD03)
#define UNSET_LOCK _IO(AL_MAGIC,0xAD04)

int32_t test_driver(void)
{
    int fd;
    struct pid_stack __pids;
    int __count = 0;
    int32_t retval = ERROR;

    fd = open("/dev/aerolock", O_RDWR);
    if(fd <= 0)
    {
        log_error("DRIVER:  Failed open\n");
        perror("open");
        goto out;
    }

    //if(ioctl(fd, SET_DEBUG))
    //{
    //    log_error("DRIVER:  Failed ioctl\n");
    //    perror("ioctl");
    //    return ERROR;
    //}

    __count = read(fd, &__pids, sizeof(struct pid_stack));
    if(__count == -1)
    {
        log_error("DRIVER:  Failed read\n");
        perror("read");
        goto out;
    }

    __pids.signal = SIGKILL;

    __count = write(fd, &__pids, sizeof(struct pid_stack));
    if(__count == -1)
    {
        log_error("DRIVER:  Failed write\n");
        perror("write");
        goto out;
    }

    close(fd);

    retval = NOERROR;
out:
    return retval;

}

void ShowSignature(int8_t* filename)
{
    uint8_t hmac[32];
    char hmac_string[64];

    if(__get_signature(filename, hmac))
    {
        __hmac_2_str(hmac, hmac_string);
        printf("%s HMAC = %s\n", filename, hmac_string);
    }
    else
    {
        printf("Failed to generate HMAC for %s, sorry\n", filename);
    }

    return;
}

int  main(int ac, char** av)
{
    int8_t  filename[256];
    int32_t opt;
    int32_t db_only = 0;
    int32_t list_only = 0;
    int32_t gen_hmac = 0;
    int32_t __test__driver = 0;
    int32_t __test_list = 0;

#ifndef __QNX__
    int option_index;
    static struct option long_options[] = {
            {"cache",    no_argument,      0, 'c' },
            {"database", no_argument,      0, 'd' },
            {"driver",   no_argument,      0, 'r' },
            {"generate", required_argument,0, 'g' },
            {"help",     no_argument,      0, 'h' },
            {"verbose",  no_argument,      0, 'v' },
            {"list",  no_argument,         0, 'l' },
            { 0,         0,                0,  0  }
    };


    while((opt = getopt_long(ac, av, "cvdlkhg:",
                        long_options, &option_index)) != -1)
#else
	while((opt = getopt(ac, av, "cvdlkhg:")) != -1)
#endif
    {
        switch(opt)
        {
        case 'c':
            list_only = 1;
            break;

        case 'l':
            __test_list = 1;
            break;

        case 'v':
            __maximum_verbosity = 1;
            break;

        case 'd':
            db_only = 1;
            break;

        case 'g':
            strcpy(filename, optarg);
            gen_hmac = 1;
            break;

        case 'r':
            __test__driver = 1;
            break;

        case 'h':
            fprintf(stdout, "usage: aerolock_verify -cdrg:hv:\n");
            fprintf(stdout, "--cache -c,    Only test cache/list\n");
            fprintf(stdout, "--database -d, Only test database\n");
            fprintf(stdout, "--driver -k,   Test aerolock driver\n");
            fprintf(stdout, "--generate, -g,Generate and print HMAC for file\n");
            fprintf(stdout, "--verbose  -v, Verbose mode, all file information displayed\n");
            fprintf(stdout, "--help -h,     This message\n");
            exit(ERROR);

        default:
            break;
        }
    }

    openlog("rmverify", LOG_NOWAIT | LOG_PID, LOG_USER);
    open_error_log();

    /*
     * Setup signals to manage cache and shutdown
     */
    __set_proc_name(av[0]);
    __setup_signal_handlers();
    __write_pid("rmverify");

	if(__test_list)
    {
       __test_hmac_list();
       goto cleanup_and_exit;
    }

    if(gen_hmac)
    {
    	ShowSignature(filename);
        goto cleanup_and_exit;
    }

    if(__test__driver)
    {
        printf("UNIT TEST (test_driver) %s\n", test_driver() ? "passed" : "failed");
        goto cleanup_and_exit;
    }

    if(db_only)
    {
        printf("Running Database UNIT TEST\n");
        printf("UNIT TEST (validateDB) %s\n", validateDB() ? "passed" : "failed");
        goto cleanup_and_exit;
    }
    else if(list_only)
    {
        printf("Running Cache/list UNIT TEST\n");
        printf("UNIT TEST (validateCache) %s\n", validateCache() ? "passed" : "failed");
        goto cleanup_and_exit;
    }
    else
    {
        printf("Running UNIT TESTS\n");
        printf("UNIT TEST (validateCache) %s\n", validateCache() ? "passed" : "failed");
        printf("UNIT TEST (validateDB) %s\n",    validateDB()    ? "passed" : "failed");
    }

cleanup_and_exit:

    __delete__pid("rmverify");
    close_error_log();
    closelog();

    exit(NOERROR);
}
#ifdef __LINUX__
#pragma GCC diagnostic pop
#endif
