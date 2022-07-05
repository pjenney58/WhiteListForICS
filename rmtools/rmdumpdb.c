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

#include <db.h>
#include "aerolock.h"

#ifndef __QNX__
#include <getopt.h>
#endif

#ifdef __LINUX__
#pragma GCC diagnostic ignored "-Wpointer-sign"
#pragma GCC diagnostic push
#endif

void __dump_database(int8_t* __db_name)
{
	int8_t*  __short_name  = NULL;
	int8_t*  __long_name   = NULL;
	uint8_t* __hmac        = NULL;
	int8_t*  __hmac_string = NULL;

	if(!__db_name)
	{
		goto out;
	}

	fprintf(stdout, "Dumping %s\n", __db_name);

	if((__short_name = (int8_t*)malloc(64)) == NULL)
	{
		goto out;
	}

	if((__long_name = (int8_t*)malloc(128)) == NULL)
	{
		goto out;
	}

	if((__hmac = (uint8_t*)malloc(32)) == NULL)
	{
		goto out;
	}

	if((__hmac_string = (int8_t*)malloc(128)) == NULL)
	{
		goto out;
	}

	if(strstr(__db_name, "names"))
	{
		while(__bdb_get_next_name(__short_name, __long_name))
		{
			fprintf(stdout, "%s : %s\n", __short_name, __long_name);
		}
	}
	else
	{
		while(__bdb_get_next_hmac(__long_name, __hmac))
		{
			__hmac_2_str(__hmac, __hmac_string);
			fprintf(stdout, "%s : %s\n", __long_name, __hmac_string);
		}
	}

out:

	if(__short_name)
	{
		free(__short_name);
		__short_name = NULL;
	}

	if(__long_name)
	{
		free(__long_name);
		__long_name = NULL;
	}

	if(__hmac)
	{
		free(__hmac);
		__hmac = NULL;
	}

	if(__hmac_string)
	{
		free(__hmac_string);
		__hmac_string = NULL;
	}

	return;
}

int __make_driver_file()
{
	uint8_t* buf  = NULL;
	int8_t*  name = NULL;
	struct   stat __st;
	int32_t  retval = 0;

	if((buf = (uint8_t*)malloc(32)) == NULL)
	{
		goto out;
	}

	if((name = (int8_t*)malloc(512)) == NULL)
	{
		goto out;
	}

	if(stat("/var/lib/rmi/hmacs.profile", &__st) != -1)
	{
		retval = unlink("/var/lib/rmi/hmacs.profile");
	}

	if(retval != 0)
	{
		perror("unlink hmacs.profile");
		retval = 0;
		goto out;
	}

	int fd = open("/var/lib/rmi/hmacs.profile", O_CREAT | O_RDWR, S_IRWXU | S_IRWXG);
	if(fd > 0)
	{
		__get_key(buf);
		retval = write(fd, buf, sizeof(buf));
		if(retval != sizeof(buf))
		{
			perror("write key");
			close(fd);
			retval = 0;
			goto out;
		}

		while(__bdb_get_next_hmac(name, buf))
		{
			retval = write(fd, buf, sizeof(buf));
			if(retval != sizeof(buf))
			{
				perror("write hmac");
				close(fd);
				retval = 0;
				goto out;
			}
		}

		close(fd);
		retval = 1;
		goto out;
	}
	else
	{
	    perror("open hmacs.profile");
	}

out:
    if(buf)
    {
    	free(buf);
    	buf = NULL;
    }

    if(name)
    {
    	free(name);
    	name = NULL;
    }

	return retval;
}

void __dump_record(int8_t* __db_name, int8_t* __db_query)
{
	int8_t*  __long_name = NULL;
	uint8_t* __hmac      = NULL;

	if(!__db_name || !__db_query)
	{
		goto out;
	}

	if((__long_name = (int8_t*)malloc(256)) == NULL)
	{
		goto out;
	}

	if((__hmac = (uint8_t*)malloc(32)) == NULL)
	{
		goto out;
	}

	fprintf(stdout, "rmdumpdb: searching for %s in %s\n", __db_query, __db_name);

	if(strstr(__db_name, "names"))
	{
		while(__bdb_get_next_name(__db_query, __long_name))
		{
			fprintf(stdout, "Query returned: %s\n",  __long_name);
		}
#if 0
		if(__bdb_find_long_name(__db_query, __long_name))
			printf("Query returned: %s\n", __long_name);
		else
			printf("Empty set\n");
#endif
	}
	else
	{
		if(__bdb_find_hmac(__db_query, __hmac))
		{
			__hmac_2_str(__hmac, __long_name);
			printf("%s\n", __long_name);
		}

		else
			printf("Empty set\n");
	}

out:
    if(__long_name)
    {
    	free(__long_name);
    	__long_name = NULL;
    }

    if(__hmac)
    {
    	free(__hmac);
    	__hmac = NULL;
    }

    return;
}


int main(int ac, char** av)
{
	int8_t*  __db_name   = NULL;
	int8_t*  __db_search = NULL;
	uint8_t* __sha2key   = NULL;
	int8_t*  __sh2buf    = NULL;
	int32_t  opt;

	if((__db_name = (int8_t*)malloc(256)) == NULL)
	{
		goto out;
	}

	if((__db_search = (int8_t*)malloc(256)) == NULL)
	{
		goto out;
	}

	if((__sha2key = (uint8_t*)malloc(32)) == NULL)
	{
		goto out;
	}

	if((__sh2buf = (int8_t*)malloc(256)) == NULL)
	{
		goto out;
	}

#ifndef __QNX__
    int option_index;
    static struct option long_options[] = {
            {"database", required_argument, 0, 'd' },
            {"find",     required_argument, 0, 'f' },
            {"dump",     no_argument,       0, 'r' },
            {"help",     no_argument,       0, 'h' },
            {"verbose",  no_argument,       0, 'v' },
            {"key",      no_argument,       0, 'k' },
            {"write",    no_argument,       0, 'w' },
            { 0,         0,                 0,  0  }
    };

    while((opt = getopt_long(ac, av, "d:f:hvwr",
                        long_options, &option_index)) != -1)
#else
	while((opt = getopt(ac, av, "d:f:hvwr")) != -1)
#endif
    {
        switch(opt)
        {
        case 'w':
        	__bdb_open();
        	__make_driver_file();
        	__bdb_close();
        	goto out;
        	break;

        case 'k':
        	__get_key(__sha2key);
        	__hmac_2_str(__sha2key, __sh2buf);
        	printf("SHA2KEY: %s\n", __sh2buf);
        	goto out;
        	break;

        case 'r':
        	__bdb_open();
        	__dump_database(__db_name);
        	__bdb_close();
        	goto out;
        	break;

        case 'd':
        	strcpy(__db_name, optarg);
            break;

        case 'f':
            strcpy(__db_search, optarg);
            break;

        case 'v':
            __maximum_verbosity = 1;
            break;

        case 'h':
            fprintf(stdout, "usage: rmdumpdb -d:f:hv\n");
            fprintf(stdout, "--write -w,    Write hmaccs.profile\n");
            fprintf(stdout, "--database -d, Database to query\n");
            fprintf(stdout, "--find -f,     String to find\n");
            fprintf(stdout, "--dump, -r,    String to delete\n");
            fprintf(stdout, "--verbose  -v, Verbose mode, all file information displayed\n");
            fprintf(stdout, "--help -h,     This message\n");
            exit(0);

        default:
            break;
        }
    }

    if(__db_name[0] && __db_search[0])
    {
    	__bdb_open();
    	__dump_record(__db_name, __db_search);
    	__bdb_close();
    }
    else
    {
    	printf("Missing parameter\n");
    }

out:
    if(__db_name)
    {
    	free(__db_name);
    	__db_name = NULL;
    }

    if(__db_search)
	{
		free(__db_search);
		__db_search = NULL;
	}

    if(__sha2key)
	{
		free(__sha2key);
		__sha2key = NULL;
	}

    if(__sh2buf)
	{
		free(__sh2buf);
		__sh2buf = NULL;
	}

    return 0;
}
#ifdef __LINUX__
#pragma GCC diagnostic pop
#endif
