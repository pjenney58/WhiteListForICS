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
 * mlocatecache.c
 *
 *  Created on: Apr 28, 2014
 *      Author: Peter H. Jenney
 */

#include "aerolock.h"

/***************************************************************************************************
 *  Functions for searching the mlocate database
 */
struct db_header
{
  uint8_t magic[8];          /* See DB_MAGIC below */
  uint32_t conf_size;        /* Configuration block size, in big endian */
  uint8_t version;           /* File format version, see DB_VERSION* below */
  uint8_t check_visibility;  /* Check file visibility in locate(1) */
  uint8_t pad[2];            /* 32-bit total alignment */
};

struct db_directory
{
  uint64_t time_sec;
  uint32_t time_nsec;
  uint8_t pad[4];
};

struct db_entry
{
  uint8_t type;
};

#define DB "/var/lib/mlocate/mlocate.db"

char*       locateDB = NULL;
struct stat locateDBstat;
int32_t     locateDBopen = 0;

int32_t openLocateDB()
{
	int32_t fd;

    locateDBopen = 0;

    if(stat(DB, &locateDBstat) != -1)
    {
        if((fd = open(DB, O_RDONLY)) > 0)
        {
            locateDB = mmap(NULL, locateDBstat.st_size, PROT_READ, MAP_SHARED, fd, 0);
            close(fd);

            if(locateDB == MAP_FAILED)
            {
                noLocateDB = 1;
                return ERROR;
            }
        }
    }
    else
    {
        noLocateDB = 1;
        return ERROR;
    }

    if(!locateDB)
    {
        noLocateDB = 1;
        return ERROR;
    }

    locateDBopen = 1;
    return NOERROR;
}

int32_t closeLocateDB()
{
    if(locateDB)
    {
        munmap(locateDB, locateDBstat.st_size);
        locateDBopen = 0;
        locateDB = NULL;
        return NOERROR;
    }

    return ERROR;
}

char pathname[_POSIX_PATH_MAX] = "";
/* static char* cursor; -- Future support for getNextEntry */

char* lookup_pathname(char* target)
{
    unsigned char*      cp1;
    struct stat         sb;
    int32_t             i;
    int8_t*             __env_cwd;
    char                dirname[_POSIX_PATH_MAX] = "/";
    char*               easylist[] = {
    "/bin/",
    "/usr/bin/",
    "/usr/local/bin",
    "/lib/",
    "/usr/lib/",
    "/usr/local/lib",
    "/sbin" ,
    "/usr/sbin",
    "/usr/local/sbin",
    "/etc",
    "/usr/etc",
    "usr/local/etc",
    NULL
    };

    /*
     *  Does the target exist in its current form?
     */
    if(stat(target, &sb) != -1)
    {
        strncpy(pathname, target, _POSIX_PATH_MAX);
        return target;
    }

    /*
     * No it doesn't, try some standard paths next
     */

    for(i=0; easylist[i]!= NULL; i++)
    {
        memset(pathname, 0, sizeof(dirname));
        strncpy(pathname, easylist[i], _POSIX_PATH_MAX);

        cp1 = (unsigned char*)target;

        if(cp1)
        {
            if(*cp1 == '/')
                cp1++;

            strncat(pathname, (char*)cp1, _POSIX_PATH_MAX);
            if(stat(pathname, &sb) != -1)
            {
                return pathname;
            }
        }
    }


    /*
     *  Check a database
     */
    if(*cp1 == '/')
    {
        cp1++;
    }

    if(__bdb_find_long_name((char*)cp1, pathname))
    {
        return pathname;
    }

    return NULL;
}

#if 0
int8_t* __mlocate(int8_t* target)
{
    uint8_t*            cp1 = NULL;
    struct db_header    dbh  = {0};
    struct db_directory dbd  = {0};
    struct stat          sb  = {0};
    int32_t             size = 0;
    int32_t             i;
    int8_t              dirname[_POSIX_PATH_MAX] = "/";

    if(!locateDB)
    {
    	return NULL;
    }

    cp1 = (uint8_t*)(locateDB + sizeof(dbh));
    memcpy((void*)&dbh, locateDB, sizeof(dbh));
    size = ntohl (dbh.conf_size);

    /*
     * Point at the first db directory entry
     */
    cp1 += (size+1);
    memcpy(&dbd, cp1, sizeof(dbd));
    cp1 += sizeof(dbd);

    for(;;)
    {
        if(*cp1 == 2) // entry is a directory
        {
            cp1 += sizeof(struct db_directory);
            if(cp1 >= (uint8_t*)(locateDB + locateDBstat.st_size))
			{
            	cp1 = NULL;
            	goto out;
			}

            strncpy(dirname, (int8_t*)(++cp1), _POSIX_PATH_MAX);
            strncat(dirname, "/", _POSIX_PATH_MAX);

            while(*cp1++) // Scoot up to the next entry
                ;

            cp1--;

            /*
             *  Make sure we're not past the end of the db
             */
            if(cp1 >= (uint8_t*)(locateDB + locateDBstat.st_size))
            {
            	cp1 = NULL;
            	goto out;
            }
        }
        else
        {
            /*
             * Try to match the path or the executable
             */
            strncpy(pathname, dirname, _POSIX_PATH_MAX);
            cp1++;
            if(!cp1)
            {
            	cp1 = NULL;
            	goto out;
            }

            strncat(pathname, (char*)(cp1), _POSIX_PATH_MAX);

            if(cp1 && !strcmp(target, (char*)(cp1+1)) || !strcmp(target, pathname))
            {
                if(*cp1 == '/' && (*(cp1+strlen(target) + 1) == ' '))
                {
                    if(stat(pathname, &sb) != -1)
                    {
                    	cp1 = pathname;
                        goto out;
                        //return(pathname);
                    }
                }
            }
        }

        while(*cp1++) // Scoot up to the next entry
        	;
    }

out:

    return cp1;
}
#endif
