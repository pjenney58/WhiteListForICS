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
 * db.c
 *
 *  
 * Description
 * --------------
 * A set of management routines for Berkley DB used to manage persistance for name/path resolution
 * and storing HMACs generated during setup.
 *
 * Author
 * -------
 * Peter H. Jenney, 
 *
 */

#include <db.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#define RMI_DIR "/var/lib/rmi"

#ifdef __LINUX__
#pragma GCC diagnostic ignored "-Wpointer-sign"
#pragma GCC diagnostic push
#endif

DB_ENV* __aerolock_env = NULL;
DB*     __db_hmacs     = NULL;
DBC*    __hmacs_cursor = NULL;
DB*     __db_names     = NULL;
DBC*    __names_cursor = NULL;
FILE*   __errors       = NULL;
static int32_t __db_is_open = 0;

#define PAGE_SIZE 4096

static int32_t __env_open()
{
	int32_t ret = 0;
	int32_t env_flags;

    ret = db_env_create(&__aerolock_env, 0);
    if (ret != 0)
    {
        syslog(LOG_ERR, "Error creating env handle: %s\n", db_strerror(ret));
        ret = -1;
        goto out;
    }

    /* Open the environment. */
    env_flags = DB_CREATE | DB_INIT_MPOOL | DB_PRIVATE | DB_THREAD;

    ret = __aerolock_env->open(__aerolock_env,   /* DB_ENV ptr */
      RMI_DIR,                                   /* env home directory */
      env_flags,                                 /* Open flags */
      0);

    if (ret != 0)
    {
        syslog(LOG_ERR, "Environment open failed: %s", db_strerror(ret));
        ret = -1;
    }

out:

    return ret;
}

static int32_t __env_close()
{
    __aerolock_env->close(__aerolock_env, 0);
    return 0;
}

static int32_t __db_open(DB** __dbpp, int8_t* __filename)
{
	int32_t  __ret        = 1;  // pessimistic
    uint32_t __open_flags = DB_CREATE | DB_NOMMAP | DB_THREAD;
    DB*      __dbp        = NULL;

    if(!__dbpp || !__filename)
    {
    	goto out;
    }

    __dbp = *__dbpp;

    __ret = db_create(&__dbp, __aerolock_env, 0);
    if(__ret)
    {
        syslog(LOG_ERR, "Failure creating DB: %s\n", db_strerror(__ret));
        __ret = 1;
        goto out;
    }

    __dbp->set_errfile(__dbp, __errors);

    __ret = __dbp->open(__dbp,    /* Pointer to the database */
                    NULL,         /* Txn pointer */
                    __filename,   /* File name */
                    NULL,         /* Logical db name (unneeded) */
                    DB_BTREE,     /* Database type (using btree) */
                    __open_flags, /* Open flags */
                    0);

    if(__ret)
    {
        syslog(LOG_ERR, "Failed to open DB: %s\n", db_strerror(__ret));
        __ret = 1;
        goto out;
    }

    *__dbpp = __dbp;

out:

    return __ret;
}

static int32_t __db_close(DB** __dbpp)
{
    DB* __dbp;

    if(!__dbpp || !*__dbpp)
    {
        goto out;
    }

    __dbp = *__dbpp;
    __dbp->close(__dbp, 0);

out:
    return 0;
}

static int32_t __db_write(DB** __dbpp, int8_t* __k, void* __d, int32_t __l)
{
    DB*     __dbp    = NULL;
    DBT     __key    = {0},
            __data   = {0};
    int32_t __retval = 0;

    if(!__dbpp || !*__dbpp || !__k || !__d)
    {
    	goto out;
    }

    __dbp = *__dbpp;

    //memset(&__key, 0, sizeof(DBT));
    //memset(&__data, 0, sizeof(DBT));

    __key.data = __k;

    __key.size = strlen(__k) + 1;
    __data.data = __d;
    __data.size = __l;

    //ret = dbp->put(dbp, NULL, &__key, &__data, DB_NOOVERWRITE);
    __retval = __dbp->put(__dbp, NULL, &__key, &__data, 0);
    if (__retval && __retval !=  DB_KEYEXIST)
    {
        __dbp->err(__dbp, __retval, "Put failed: %s", __k);
    }

out:

    return __retval;
}

/*
 * __db_read(__dbpp, __k, __d) - search database for __k
 * @__dbpp - BerkeleyDB database pointer
 * @__k    - string to search for
 * @__d    - buffer for return value
 */
static int32_t __db_read(DB** __dbpp, int8_t* __k, void* __d)
{
    DB*      __dbp   = NULL;
    DBT      __key   = {0},
             __data  = {0};
    int32_t  __ret   = 0;
    uint8_t* __buf   = NULL;

    if(!__dbpp || !*__dbpp || !__k || !__d)
    {
    	goto out;
    }

    __dbp = *__dbpp;

    __buf = (uint8_t*)malloc(PAGE_SIZE);
    if(!__buf)
    {
    	goto out;
    }

    //memset(&__key, 0, sizeof(DBT));
    //memset(&__data, 0, sizeof(DBT));

    __key.data   = __k;
    __key.size   = strlen(__k) + 1;    // search function, __k will always be a valid thing to look for
    __data.data  = __buf;
    __data.ulen  = PAGE_SIZE;
    __data.flags = DB_DBT_USERMEM;

    __ret = __dbp->get(__dbp, NULL, &__key, &__data, 0);

    if(__ret && __ret != DB_NOTFOUND)
    {
        __dbp->err(__dbp, __ret, "Get failed: %s", __k);
        goto out;
    }

    if(__ret == DB_NOTFOUND)
    {
        goto out;
    }

    memcpy(__d, __buf, __data.size);

out:

    if(__buf)
    {
    	free(__buf);
    	__buf = NULL;
    }

    return __ret;
}

static int32_t __db_delete_rec(DB** dbpp, int8_t* __k)
{
    DB* dbp          = NULL;
    DBT __key        = {0};
    int32_t __retval = 1;

    if(!dbpp || !*dbpp || __k)
    {
    	goto out;
    }

    dbp = *dbpp;

    //memset(&__key, 0, sizeof(DBT));

    __key.data = __k;
    __key.dlen = strlen(__k) + 1;

    __retval = dbp->del(dbp, NULL, &__key, 0);

out:

    return __retval;
}

int32_t __bdb_open()
{
	int32_t __retval = 1;

    if(__env_open())
    {
        syslog(LOG_ERR, "Error opening aerolock db environmnet\n");
        __retval = 0;
        goto out;
    }

    if(__db_open(&__db_hmacs, "/var/lib/rmi/hmacs.bdb"))
    {
        syslog(LOG_ERR, "Error opening hmacs db\n");
        __retval = 0;
        goto out;
    }

    if(__db_open(&__db_names, "/var/lib/rmi/names.bdb"))
    {
        syslog(LOG_ERR, "Error opening names db\n");
        __retval = 0;
    }

out:

	if(__retval)
	{
		__db_is_open = 1;
	}

    return __retval;
}

int32_t __bdb_close()
{
	if(__db_is_open)
	{
		if(__hmacs_cursor)
		{
			__hmacs_cursor->close(__hmacs_cursor);
		}

		if(__names_cursor)
		{
			__names_cursor->close(__names_cursor);
		}

		__db_close(&__db_names);
		__db_close(&__db_hmacs);
		__env_close();

		__db_is_open = 0;
	}

    return 1;
}

int32_t __bdb_write_hmac(int8_t* __name, uint8_t* __hmac)
{
    return !__db_write(&__db_hmacs, __name, __hmac, 32);
}

int32_t __bdb_find_hmac(int8_t* __name, uint8_t* __hmac)
{
    return !__db_read(&__db_hmacs, __name, __hmac);
}

int32_t __bdb_delete_hmac(int8_t* __name)
{
    return !__db_delete_rec(&__db_hmacs, __name);
}

int32_t __bdb_write_name_pair(int8_t* __short_name, int8_t* __long_name)
{
    return !__db_write(&__db_names, __short_name, __long_name, strlen(__long_name) + 1);
}

int32_t __bdb_find_long_name(int8_t* __short_name, int8_t* __long_name)
{
    return !__db_read(&__db_names, __short_name, __long_name);
}

int32_t __bdb_delete_name(int8_t* __name)
{
    return !__db_delete_rec(&__db_names, __name);
}

int32_t __bdb_get_next_name(int8_t* __short_name, int8_t* __long_name)
{
    DBT     __key    = {0},
    		__data   = {0};
    int32_t __retval = 0;

    if(!__short_name || !__long_name)
    {
    	return 0;
    }

    if(!__names_cursor)
    {
        if(__db_names->cursor(__db_names, NULL, &__names_cursor, 0) != 0)
        {
        	return 0;
        }

        if(*__short_name)  // Position the cursor at the first instance of __short_name
        {
        	__key.data = __short_name;
        	__key.size = strlen(__short_name);

            if(!__names_cursor->c_get(__names_cursor, &__key, &__data, DB_SET))
            {
                memcpy(__long_name,  __data.data, __data.size);
                return 1;
            }
            else
            {
            	return 0;
            }
        }
    }

    //memset(&__key,  0, sizeof(DBT));
    //memset(&__data, 0, sizeof(DBT));

    __retval = __names_cursor->c_get(__names_cursor, &__key, &__data, DB_NEXT_DUP);
    if(!__retval)
    {
        memcpy(__short_name, __key.data,  __key.size);
        memcpy(__long_name,  __data.data, __data.size);
        return 1;
    }

    return 0;
}

int32_t __bdb_get_next_hmac(int8_t* __short_name, uint8_t* __hmac)
{
    DBT __key, __data;
    int32_t __retval = 0;

    if(!__short_name || !__hmac)
    {
    	return 0;
    }

    if(!__hmacs_cursor)
    {
        __db_hmacs->cursor(__db_hmacs, NULL, &__hmacs_cursor, 0);
    }

    memset(&__key,  0, sizeof(DBT));
    memset(&__data, 0, sizeof(DBT));

    __retval = __hmacs_cursor->get(__hmacs_cursor, &__key, &__data, DB_NEXT);
    if(!__retval)
    {
        memcpy(__short_name, __key.data, __key.size);
        memcpy(__hmac,      __data.data, 32);
        return 1;
    }

    return 0;
}

int32_t __bdb_reset_names()
{
	int32_t retval = 0;

    __bdb_close();

    retval = unlink("/var/lib/rmi/names.bdb");
    if(retval)
    {
        syslog(LOG_ERR, "Failed to reset names!");
        return 0;
    }

    return __bdb_open();
}

int32_t __bdb_reset_hmacs()
{
	int32_t retval = 0;

	__bdb_close();

	retval = unlink("/var/lib/rmi/hmacs.bdb");
    if(retval)
    {
        syslog(LOG_ERR, "Failed to reset hmacs!");
        return 0;
    }

    return __bdb_open();
}

#ifdef __LINUX__
#pragma GCC diagnostic pop
#endif
