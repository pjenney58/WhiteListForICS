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
 * 1. Generate a 32 byte key and save it
 * 2. Open DB and generate HMACS for all the default items
 * 3. Execute unit tests
*/

#include "aerolock.h"
#include <sys/stat.h>
#include <pthread.h>
#include <db.h>

#ifndef __QNX__
#include <getopt.h>
#endif

#define __USE_GNU
#define __USE_XOPEN_EXTENDED
#include <ftw.h>

#ifdef __LINUX__
#pragma GCC diagnostic ignored "-Wpointer-sign"
#pragma GCC diagnostic push
#endif

int whitelistEverything = 0;
int whitelistdir = 0;
int updateLocal = 0;
int repopulateExisting = 0;

unsigned char _sha2key[32] = "";

pthread_mutex_t insert_mutex;
pthread_mutex_t list_mutex;

int32_t list(const int8_t* name, const struct stat* status, int32_t type, struct FTW* ftwbuf)
{
    uint8_t hmac[32] = "";
    struct stat sb;

    /* FTW_F    The object is a  file */
    /* FTW_D    ,,    ,,   ,, ,, directory */
    /* FTW_DNR  ,,    ,,   ,, ,, directory that could not be read */
    /* FTW_SL   ,,    ,,   ,, ,, symbolic link */
    /* FTW_NS   The object is NOT a symbolic link and is one for */


    if(stat(name, &sb) == -1)
    {
        syslog(LOG_ERR, "Failed to stat(%s)", name);
        return FTW_CONTINUE;
    }

    /*
     * Check for executable, generate a signature and stuff it in the database if it is
     *
     * Looking for executables was the old way. Now everything counts so we can catch things like extensionless
     * scripts etc.
     */
    if(type == FTW_F || type == FTW_SL)  /* Check for executable, add to database if it is */
    {
        //if(is_executable((char*)name) && (status->st_size > 0))
    	if(status->st_size > 0)
        {
            if(__maximum_verbosity)
            {
                syslog(LOG_INFO, "[list(file)] Adding file %s", name);
            }

            if(__get_signature(name, hmac))
            {
                __bdb_write_hmac((int8_t*)name, hmac);
            }
        }
    }

    return FTW_CONTINUE;
}


/*
 * TODO:  Make a table that has all the files on the system in it
 */
int32_t insert(const char *name, const struct stat *status, int type, struct FTW *ftwbuf)
{
    if(strstr(name, "/proc") || strstr(name, "/tmp"))
    {
        return FTW_CONTINUE;
    }

    //pthread_mutex_lock(&insert_mutex);

    switch( type )
    {
    case FTW_SL: /* Symbolic link */
    case FTW_F:  /* Regular file */

        if(__maximum_verbosity)
        {
            syslog(LOG_INFO,"[insert()] Adding symlink or file %s to local", name);
        }

        __bdb_write_name_pair((int8_t*)name + ftwbuf->base, (int8_t*)name);

        break;

    case FTW_D:
        if(__maximum_verbosity)
        {
            syslog(LOG_INFO, "Directory (%s)\n", name);
        }
        break;

    case FTW_DNR:
        if(__maximum_verbosity)
        {
            syslog(LOG_INFO, "Unreadable directory (%s)\n", name);
        }
        break;

    case FTW_NS:
        if(__maximum_verbosity)
        {
            syslog(LOG_INFO, "Unstatable file (%s)\n", name);
        }
        break;

    case FTW_DP:
        if(__maximum_verbosity)
        {
            syslog(LOG_INFO, "Directory (%s), all subdirs have been visited\n", name);
        }
        break;

    case FTW_SLN:
        if(__maximum_verbosity)
        {
            syslog(LOG_INFO, "Symbolic link naming non-existing file (%s).\n", name);
        }
        break;
    }

    return FTW_CONTINUE;
}

int32_t makelocallist(void)
{
    int32_t retval = NOERROR;

#ifdef __QNX__
    DIR* dirp;
    struct dirent* dp;
    int8_t lbuf[256];
    struct stat st;
#endif

    if(!__bdb_open())
    {
        retval = ERROR;
        goto out;
    }

    __bdb_reset_names();

    fprintf(stderr, "*** makelocallist() -- Processing directory -> / ***\n");

#ifndef __QNX__
    retval = nftw("/", insert, 25, FTW_PHYS | FTW_DEPTH | FTW_MOUNT | FTW_CHDIR);
#else
    if((dirp = opendir("/")) != NULL)
    {
        while((dp = readdir(dirp)) != NULL)
        {
            strcpy(lbuf, "/");
            strcat(lbuf, dp->d_name);
            if(stat(lbuf, &st) != -1)
            {
                if((S_ISDIR(st.st_mode)) && dp->d_name[0]   != '.' &&
                        strcmp(dp->d_name, "proc") && strcmp(dp->d_name, "run") && strcmp(dp->d_name, "tmp") && strcmp(dp->d_name, "dev"))
                {

                    fprintf(stderr, "*** makelocallist() -- Processing directory -> %s ***\n", lbuf);
                    retval = nftw(lbuf, insert, 10, FTW_PHYS | FTW_DEPTH | FTW_MOUNT | FTW_CHDIR);
                }
            }
        }

        closedir(dirp);
    }
#endif

    __bdb_close();

    if(retval == -1)
	{
        retval = ERROR;
	}

    syslog(LOG_INFO, "[Local list] -------------------------------> Run Complete");

 out:

    return(retval != ERROR);
}

int32_t whitelistDisks(void)
{
    DIR* dirp;
    struct dirent* dp;
    char lbuf[256];
    int32_t retval = 0;
#ifdef __QNX__
    struct stat st;
#endif

    if(!__bdb_open())
    {
    	retval = ERROR;
        goto out;
    }

    __bdb_reset_hmacs();

    /*
     * Walk the entire local file system and sign everything
     */
#ifndef __QNX__
    if((dirp = opendir("/")) != NULL)
    {
        while((dp = readdir(dirp)) != NULL)
        {
            if((dp->d_type & DT_DIR ) && dp->d_name[0]   != '.' &&
                    strcmp(dp->d_name, "proc") && strcmp(dp->d_name, "run") && strcmp(dp->d_name, "tmp") && strcmp(dp->d_name, "dev"))
            {
                strcpy(lbuf, "/");
                strcat(lbuf, dp->d_name);
                fprintf(stderr, "*** whitelistdisks() -- Processing directory -> %s ***\n", lbuf);
                retval = nftw(lbuf, list, 10, FTW_PHYS | FTW_DEPTH | FTW_MOUNT | FTW_CHDIR);

                if(retval == -1)
			    {
				    retval = ERROR;
				    goto out;
			    }
            }
        }

        closedir(dirp);
    }
#else
    if((dirp = opendir("/")) != NULL)
    {
        while((dp = readdir(dirp)) != NULL)
        {
            strcpy(lbuf, "/");
            strcat(lbuf, dp->d_name);
            if(stat(lbuf, &st) != -1)
            {
                if((S_ISDIR(st.st_mode)) && dp->d_name[0]   != '.' &&
                        strcmp(dp->d_name, "proc") && strcmp(dp->d_name, "run") && strcmp(dp->d_name, "tmp") && strcmp(dp->d_name, "dev"))
                {

                    fprintf(stderr, "*** whitelistdisks() -- Processing directory -> %s ***\n", lbuf);
                    retval = nftw(lbuf, list, 10, FTW_PHYS | FTW_DEPTH | FTW_MOUNT | FTW_CHDIR);

                    if(retval == -1)
                    {
                    	retval = ERROR;
                    	goto out;
                    }
                }
            }
        }

        closedir(dirp);
    }

#endif

    __bdb_close();

    syslog(LOG_INFO, "[Whitelist] ---------------------------> Run complete");

out:

    return(retval != ERROR);
}

int32_t populateDB(void)
{
    int retval = NOERROR;
    return retval;
}

int32_t  WhiteListDir(int8_t* directory)
{
    int retval = ERROR;

    if(!__bdb_open())
    {
        retval = 1;
        goto out;
    }

    printf("********* Whitelisting %s\n", (char*)directory);
    retval = nftw((char*)directory, list, 10, FTW_PHYS | FTW_DEPTH | FTW_MOUNT | FTW_CHDIR);
    printf("\n--------- Run Complete\n");

    if(retval == -1)
	{
	    retval = ERROR;
	}

    __bdb_close();

out:

    return(retval != ERROR);
}

/*
 * make_driver_file() - build a binary file for the LKD to read in at startup. The format is:
 *
 *                          ----------------------------------
 *                          !  Slot 0 - 32 byte sha2 key     !
 *                          ----------------------------------
 *                          !  Slot 1 - N 32 byte HMAC       !
 *                          ----------------------------------
 */
int32_t __make_driver_file()
{
    uint8_t* buf     = NULL;
    int8_t*  name    = NULL;
    struct stat __st = {0};
    int32_t __retval = ERROR;

    if(!__bdb_open())
    {
        goto out;
    }

   /*
	* PHJ - 20140428
	*
	* MISRA C2011 conflict with secure coding practices.  Secure coding requires that data
	* reside in the heap, not on the stack, so predefined buffers are not allowed.
	*
	* MISRA C2012 Rule 21.3 (Required) forbids the use of dynamic memory allocation.  The rule
	* is Decidable and the decision is to follow Secure coding techniques.
	*/
    if((buf = (uint8_t*)malloc(HMAC256_LEN)) == NULL)
    {
    	goto out;
    }

    if((name = (int8_t*)malloc(PATH_MAX)) == NULL)
    {
    	goto out;
    }

    if(stat("/var/lib/rmi/hmacs.profile", &__st) != -1)
    {
    	__retval = unlink("/var/lib/rmi/hmacs.profile");
    }

    if(__retval != 0)
    {
    	syslog(LOG_ERR, "error deleting hmacs.profile: %s\n", strerror(errno));
        goto out;
    }

    int fd = open("/var/lib/rmi/hmacs.profile", O_CREAT | O_RDWR, S_IRWXU | S_IRWXG);
    if(fd > 0)
    {
        /*
    	 * Get the current key, its the first 32 byte entry in the file
    	 */
        __get_key(buf);

        __retval = write(fd, buf, HMAC256_LEN);
        if(__retval != HMAC256_LEN)
        {
        	__retval = ERROR;
        	syslog(LOG_ERR, "error writing key: %s\n", strerror(errno));
            goto out;
        }

        /*
         * Iterate through all the HMACs in the database and write them to the profile
         */
        while(__bdb_get_next_hmac(name, buf))
        {
            __retval = write(fd, buf, HMAC256_LEN);
            if(__retval != HMAC256_LEN)
            {
            	__retval = ERROR;
                syslog(LOG_ERR, "error writing HMAC: %s\n", strerror(errno));
                goto out;
            }

            memset(buf, 0, HMAC256_LEN);
        }

        /*
         * Get the new file into the system so rmverify won't choke
         */
        if(__get_signature("/var/lib/rmi/hmacs.profile", buf))
        {
            __retval = __bdb_write_hmac((int8_t*)"/var/lib/rmi/hmacs.profile", buf);
        }
    }
    else
    {
    	syslog(LOG_ERR, "error opening hmacs.profile: %s\n", strerror(errno));
    }

    /*
     * PHJ: Interrupt the kernel and make it reload the hmacs.profile!!
     */
out:

	if(fd > 0)
	{
        close(fd);
	}

	__bdb_close();

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

    return __retval;
}


int main(int ac, char** av)
{
    int opt;
    int8_t* directory = NULL;
    int32_t __retval  = NOERROR;

#ifndef __QNX__
    int option_index;
    static struct option long_options[] = {
            {"createkey", no_argument,       0, 'c' },
            {"debug",     no_argument,       0, 'd' },
            {"directory", required_argument, 0, 'r' },
            {"filesystem",no_argument,       0, 'f' },
            {"local",     no_argument,       0, 'l' },
            {"repopulate",no_argument,       0, 'p' },
            {"help",      no_argument,       0, 'h' },
            {"verbose",   no_argument,       0, 'v' },
            { 0,          0,                 0,  0  }
    };

    openlog("rmsetup", LOG_NOWAIT | LOG_PID, LOG_USER);

    while((opt = getopt_long(ac, av, "cdr:flhv",
            long_options, &option_index)) != -1)
#else
    while((opt = getopt(ac, av, "cdr:flhv")) != -1)
#endif
    {
        switch(opt)
        {
        case 'c':
        	__retval = __create_key(_sha2key);
            break;

        case 'p':
            repopulateExisting = 1;
            break;

        case 'l':
            updateLocal = 1;
            break;

        case 'v':
            __maximum_verbosity = 1;
            break;

        case 'f':
            whitelistEverything = 1;
            break;

        case 'h':
            fprintf(stdout, "usage: rmprofiler cdr:fplh\n");
            fprintf(stdout, "--createkey -c, Create a key and exit\n");
            fprintf(stdout, "--debug -d,  White list directory\n");
            fprintf(stdout, "--directory -r,  White list directory\n");
            fprintf(stdout, "--filesystem -f,  Batch white list all executables\n");
            fprintf(stdout, "--local -l,  Update the local database\n");
            fprintf(stdout, "--repopulate -p,  Update the local database\n");
            fprintf(stdout, "--verbose -v, Verbose mode, all file information displayed\n");
            fprintf(stdout, "--help -h, This message\n");
            goto out;

        case 'r':
        	if((directory = (int8_t*)malloc(256)) == NULL)
        	{
        		__retval = ERROR;
        		goto out;
        	}

            strncpy(directory, optarg, 256);
            whitelistdir = 1;
            break;

        default:
            break;
        }
    }

    /*
     * Setup signals to manage cache and shutdown
     */
    __set_proc_name(av[0]);
    __setup_signal_handlers();
    __write_pid("rmsetup");

    if (getuid() != 0)
    {
        fprintf(stderr, "Need to be root!\n");
        __retval = ERROR;
        goto out;
    }

    /*
     * Generate a new sha256 key -- all the other systems will pick it up at runtime
     */
    if(!__create_key(_sha2key))
    {
        __retval = ERROR;
        goto out;
    }

    if(updateLocal)
    {
    	makelocallist();
    }

    if(whitelistdir)
    {
    	WhiteListDir(directory);
    }

    if(whitelistEverything)
    {
    	makelocallist();
    	whitelistDisks();
    }

    if(repopulateExisting)
    {
    	makelocallist();
    	populateDB();
    }

    __make_driver_file();

    __delete__pid("aerolock_setup");

out:

    closelog();

    if(directory)
    {
    	free(directory);
    	directory = NULL;
    }

    return __retval;
}

#ifdef __LINUX__
#pragma GCC diagnostic pop
#endif
