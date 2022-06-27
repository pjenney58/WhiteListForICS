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
 * parse.c
 *
 *  Created on: Mar 27, 2014
 *      Author: Pete Jenney
 */

#ifdef __LINUX__
#pragma GCC diagnostic ignored "-Wpointer-sign"
#pragma GCC diagnostic push
#endif

#include "aerolock.h"

static int8_t* __strip_path(int8_t* __pathname)
{
    int8_t* __cp = NULL;

    if(!__pathname)
    {
        goto out;
    }

    /*
     * Handle ./foo/bar/this
     */
    if(__pathname[0] == '.' && __pathname[1] == '/')
    {
        __pathname++;
    }

    if(strchr(__pathname, '/'))
    {
        __cp = __pathname;
        __cp += strlen(__pathname);

        while(*--__cp !='/')
            ;

        return __cp + 1;
    }

out:
    return __pathname;
}

static int32_t __is_exception(int8_t* __file)
{
    return __lookup_item(__exception_list, __strip_path(__file));
//    return FALSE;
}

/*
 * __is_forbidden() - This one needs its own list because it needs some wildcard processing
 * and the current __rb_tree implementation doesn't support "get next" functionality.
 */
static int32_t __is_forbidden_file(int8_t* __file)
{
    int32_t  __retval     = FALSE;
    int16_t  __i          = 0;
    int8_t*  __cpf        = NULL;
    int8_t*  __cpt        = NULL;
    int8_t*  __buf        = NULL;
    int8_t* __forbidden[] = {
    "/dev/null",
    "/dev/*",
    "/tmp/*",
    "/sys/*",
    "/var/cache/*",
    "/proc/self/*",
    NULL
    };

    if(!__file)
    {
        goto out;
    }

    if((__buf = (int8_t*)malloc(PATH_MAX)) == NULL)
    {
        goto out;
    }

    for(__i=0; __forbidden[__i] != NULL; __i++)
    {
        if((__cpf = strchr(__forbidden[__i], '*')) != NULL)
        {
            memset(__buf, 0, PATH_MAX);
            strncpy(__buf, __forbidden[__i], __cpf - __forbidden[__i]);

            if(strstr(__file, __buf))
            {
                __retval = TRUE;
                goto out;
            }

           __cpf = NULL;
           continue;
        }

        if(!strcmp(__file, __forbidden[__i]))
        {
            __retval = TRUE;
            goto out;
        }
    }

out:

    if(__buf)
    {
        free(__buf);
        __buf = NULL;
    }

    __cpf = __cpt = NULL;

    return __retval;
}


static int32_t __is_shell_command(int8_t* __cmd)
{
    return __lookup_item(__shell_command_list, __cmd);
}

static int32_t __is_escape_sequence(int8_t* __pattern)
{
    // Look for patterns that start like "X???";
    int32_t __retval = FALSE;

    if(!__pattern)
    {
        goto out;
    }

    if((__pattern[0] == 'X')  &&
        isdigit(__pattern[2]) &&
        isdigit(__pattern[1]) &&
        isdigit(__pattern[3]))
    {
        __retval = TRUE;
    }

out:

    return __retval;
}

/*
 * __is_scripting_engine() - verify that the passed file is a known scripting engine
 * @__filename - file to test
 */
static int32_t __is_valid_script_engine(int8_t* __filename)
{
    return __lookup_item(__engine_list, __strip_path(__filename));
}

#if 0
/*
 * __process_subdir()
 *@___dir - the subdir to process
 *@___fd  -
 */
static int32_t __process_subdir(int8_t* __subdir, int32_t __fd, pid_t __pid)
{
    DIR*           __dirp      = NULL;
    struct dirent* __dp        = NULL;
    int32_t        __retval    = NOERROR;
    int8_t*        __long_name = NULL;

    if(!__subdir)
    {
        __retval = ERROR;
        goto out;
    }

    syslog(LOG_DEBUG, "__process_subdir() processing %s", __subdir);

    if((__long_name = (int8_t*)malloc(PATH_MAX)) == NULL)
    {
        __retval = ERROR;
        goto out;
    }

    /*
     * Don't parse root directory
     */
    if(strlen(__subdir) == 1 && *__subdir == '/')
    {
        goto out;
    }

    if((__dirp = opendir(__subdir)) != NULL)
    {
        while((__dp = readdir(__dirp)) != NULL)
        {
            if(__dp->d_type & DT_REG)
            {
                snprintf(__long_name, PATH_MAX, "%s/%s", __subdir, __dp->d_name);
                syslog(LOG_DEBUG, "__process_subdir() level 1 processing %s", __long_name);

#ifndef __TEST_PARSER__
                if(!__valid_hmac(__long_name, 0, __fd, __pid))
                {
                    __retval = ERROR;
                    goto out;
                }
#endif
            }
        }
    }
    else
    {
        syslog(LOG_ERR, "__process_subdir() failed to open directory %s", __subdir);
    }

out:
    if(__long_name)
    {
        free(__long_name);
        __long_name = NULL;
    }

    closedir(__dirp);

    return __retval;
}
#endif

static int32_t __file_is_dir(int8_t* __path)
{
    struct stat __st;
    int32_t     __retval = FALSE;

    if(!__path)
    {
        goto out;
    }

    if(stat(__path, &__st) != -1)
    {
        if(S_ISDIR(__st.st_mode))
        {
            __retval = TRUE;
        }
    }

out:

    return __retval;
}

int32_t __is_java_class(int8_t* __filename)
{
    int32_t            __retval   = FALSE;
    int8_t*            __buf      = NULL;
    int16_t            __fd       = 0;
    uint32_t           __magic    = 0x00000000U;
    struct stat        __sb;
    
    if(!__filename)
    {
        goto done;
    }

    if((__buf = (int8_t*)malloc(256)) == NULL)
    {
        goto done;
    }

    if(__filename)
    {
        strncpy(__buf, __filename, 256);

        syslog(LOG_DEBUG, "1) __is_java_class() - %s", __buf);

        if(stat(__buf, &__sb) == -1)
        {
            strncat(__buf, ".class", 256);
            syslog(LOG_DEBUG, "2) __is_java_class() trying - %s", __buf);

            if(stat(__buf, &__sb) == -1)
            {
                goto done;
            }

            syslog(LOG_DEBUG, "3) __is_java_class() - %s", __buf);

            __fd = open(__buf, O_RDONLY);
            if(__fd > 0)
            {
                if(read(__fd, &__magic, 4) != 4)
                {
                    goto done;
                }

                syslog(LOG_DEBUG, "4) __magic = 0x%X", __magic);
                close(__fd);

                if(__magic == 0xCAFEBABE || __magic == 0xBEBAFECA)
                {
                    __retval = TRUE;
                    syslog(LOG_DEBUG, "5) __is_java_class() - Got java class %s", __filename);
                }
            }
        }
    }

done:

    if(__buf)
    {
        free(__buf);
        __buf = NULL;
    }

   return __retval;
}

#if 0
static int32_t __file_is_executable(int8_t* __path)
{
    struct stat __sb;
    int32_t     __retval = FALSE;

    if(!__path)
    {
        goto out;
    }

    if(stat(__path, &__sb) != -1)
    {
        if(S_ISREG(__sb.st_mode))
        {
            if((__sb.st_mode & S_IXUSR) ||
               (__sb.st_mode & S_IXGRP) ||
               (__sb.st_mode & S_IXOTH))
            {
                __retval = TRUE;
            }
        }
    }

out:
    return __retval;
}
#endif


static int32_t __is_on_path(const int8_t* __src, int8_t* __dest)
{
    int32_t __retval        = FALSE;
    int8_t* __path          = NULL;
    int8_t* __path_token    = NULL;
    int8_t* __path_buf      = NULL;
    int8_t* __path_tok_buf  = NULL;
    struct stat __st;

    if(!__src || !__dest)
    {
        goto out;
    }

    /*
     * PHJ - 20140428
     *
     * MISRA C2012 conflict with secure coding practices.  Secure coding requires that data
     * reside in the heap, not on the stack, so predefined buffers are not allowed.
     *
//     * MISRA C2012 Rule 21.3 (Require/d) forbids the use of dynamic memory allocation.  The rule
     * is Decidable and the decision is to follow Secure coding techniques.
     */
    if((__path_buf = (int8_t*)malloc(PATH_MAX)) == NULL)
    {
        goto out;
    }

    if((__path_tok_buf = (int8_t*)malloc(PATH_MAX)) == NULL)
    {
        goto out;
    }

    /*
     * MISRA C2012 Rule 21.8 Violation. I don't know of any other way to get information from
     * the local environment. The rule is Decidable and the decision is to use the function
     * until there's a MISRA recommendation for alternate methods or one presents itself
     */
    __path = getenv("PATH");
    strncpy(__path_buf, __path, PATH_MAX);
    __path = __path_buf;

    __path_token = strsep((char** restrict)&__path, ":");
    while(__path_token)
    {
        snprintf(__path_buf, PATH_MAX, "%s/%s", __path_token, __src);
        if(stat(__path_buf, &__st) != -1)
        {
            strcpy(__dest, __path_buf);
            __retval = TRUE;
            goto out;
        }

        __path_token = strsep((char ** restrict)&__path, ":");
    }

out:

    if(__path_tok_buf)
    {
        free(__path_tok_buf);
        __path_tok_buf = NULL;
    }

    if(__path_buf)
    {
        free(__path_buf);
        __path_buf = NULL;
    }

    return __retval;
}

static int32_t __find_file(const int8_t* __file, int8_t* __full_path)
{
    struct stat __sb      = {0};
    int32_t     __retval  = FALSE;

    if(!__file || !__full_path)
    {
        goto out;
    }

    if(stat(__file, &__sb) != -1)
    {
        __retval = TRUE;
        strncpy(__full_path, __file, strlen(__file)+1);
        goto out;
    }

    if((__sb.st_mode & S_IFMT) == S_IFLNK)
    {
        if((__retval = readlink(__file, __full_path, 256)) > 0)
        {
            __retval = TRUE;
            __full_path[__retval] = '\0';
            syslog(LOG_WARNING, "__find_file() file %s is a link to %s", __file, __full_path);
            goto out;
        }
        else
        {
            goto out;
        }
    }

    //if(__file && !strchr(__file, '/'))
    //{
        if(__is_on_path(__strip_path(__file), __full_path))
        {
            __retval = TRUE;
            goto out;
        }
    //}

    if(__bdb_find_long_name(__strip_path((int8_t*)__file), __full_path))
    {
        syslog(LOG_DEBUG, "__bdb_find_long_name() for %s found %s", __strip_path((int8_t*)__file), __full_path);
        __retval = TRUE;
        goto out;
    }


out:
    return __retval;
}

static int32_t __last_was_arg_switch = 0;

int32_t __is_arg_switch(int8_t* __arg)   // --report
{
    int32_t __retval = FALSE;

    if(!__arg)
    {
        __last_was_arg_switch = 0;
        goto out;
    }

    if(*__arg == '-')             // avoid /usr/bin/ps | grep red-stop
    {
        __last_was_arg_switch = 2;
        __retval = TRUE;
    }
    else
    {
        if(__last_was_arg_switch > 0)
        {
            __last_was_arg_switch--;
        }
    }

 out:
    return __retval;
}

int32_t __is_arg(int8_t* __arg)   // -- --report /etc/cron.daily or -max-depth  1
{                                 //               ^^^^^^^^^                    ^^
    int32_t __retval = FALSE;

    if(__last_was_arg_switch > 0)
    {
        __retval = TRUE;
        __last_was_arg_switch = 0;
    }

    return __retval;
}

static int8_t* __get_cmdline(pid_t pid, int8_t* __cmdline)
{
    int8_t*   __buf     = NULL;
    int8_t*   __cp      = NULL;
    int8_t*   __retval  = NULL;
    int32_t   __rc      = 0;
    int32_t   __fd1     = 0;
    struct    stat __sb = {0};

    if(!__cmdline)
    {
        goto out;
    }

    __last_was_arg_switch = 0;

    /*
     * PHJ - 20140428
     *
     * MISRA C2012 conflict with secure coding practices.  Secure coding requires that data
     * reside in the heap, not on the stack, so predefined buffers are not allowed.
     *
     * MISRA C2012 Rule 21.3 (Required) forbids the use of dynamic memory allocation.  The rule
     * is Decidable and the decision is apply secure coding techniques.
     */
    if((__buf = (int8_t*)malloc(PATH_MAX)) == NULL)
    {
        goto out;
    }

    snprintf(__buf, PATH_MAX, "/proc/%ld/cmdline", (long)pid);

    if(stat(__buf, &__sb) == -1)
    {
        syslog(LOG_DEBUG, "__get_cmdline() stat failed for %s", __buf);
        goto out;
    }

    __fd1 = open(__buf, O_RDONLY);
    if(__fd1 > 0)
    {
        __rc = read(__fd1, __cmdline, PATH_MAX);

        close(__fd1);

        if(__rc <= 0)
        {
            goto out;
        }
    }
    else
    {
        goto out;
    }

    /*
     *  Change NULLs to spaces so the strtok() logic will work
     */
    __cmdline[__rc] = '\0';

    __cp = (int8_t*)(__cmdline + (__rc-1));

    while(__cp-- > __cmdline)
    {
        if(*__cp == '\0')
        {
            *__cp = 0x20;
        }
    }

    __retval = __cmdline;

out:

    if(__buf)
    {
        free(__buf);
        __buf = NULL;
    }

    return __retval;
}

int32_t __is_pipe_char(int8_t* __char_string)
{
    int32_t __retval = FALSE;

    if(strchr(__char_string, '|') || strchr(__char_string, '&'))
    {
        __retval = TRUE;
    }

    return __retval;
}

int32_t __is_wildcard(int8_t* __char_string)
{
    int32_t __retval = FALSE;

    if(strspn(__char_string, "*!?"))
    {
        __retval = TRUE;
    }

    return __retval;
}

//#define TOKENSPEC " ()|&{}[]:$+<>\\;="
#define TOKENSPEC " (){}[]:$+<>\\;="

/*
 * __valid_cmdline() - break up the command line and return the engine and script in the passed variables
 *@__rmi_cmdline - a [hopefully] reliable command line to parse
 *
 * Example: CMD (test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily ))
 * Should parse to:
 *                 /bin/sh -c        - Scripting engine, already validated bydriver but key for processing scripts
 *                 /usr/bin/test     - Valid Executable, already validated by driver
 *                 /usr/sbin/anacron - Valid Executable, already validated by driver
 *                 /bin/run-parts    - Valid Executable, already validated by driver
 *                 /etc/cron.daily   - DIR, process each directory entry - Valid scripts
 *
 *
 *  BUGS:
 *
 *  2014-07-02 -- this following test case breaks the parser:
 *
 *              parser is working on: /bin/sh -e /etc/NetworkManager/dispatcher.d/01ifupdown eth0 dhcp4-change
 *
 *  2014-06-24 -- this following test case breaks the parser:
 *
 *              parser: is working on: rm -f /opt/aerolock/rmsetup/rmsetup.o
 *
 *    The path does resolve to an actual file, but its transient and not executable.  
 *    __validate_hmac() doesn't care, it just sees a file that's not supposed to be there
 *    and kills the process using it.  A possible solution is to except *.o files, but
 *    the exposure is that an attacker could just name an attack file mumble.o and bypass 
 *    the system.
 *
 *    2014-07-02 -- What should happen above is that the string should be recognized as an argument due
 *    to the -f switch, but for some reason its not.
 *
 *  FIXED: 2014-06-19 --This following test case breaks the parser. The path statement is broken 
 *  up into separate entries and each is processed by the __process_dir() function. It takes too 
 *  much time and needs to be addressed.
 *
 *  sh -c env -i PATH=/usr/bin:/usr/local/bin:/usr/sbin run-parts --lsbsysinit    \
 *  /etc/update-motd.d > /var/run/motd.new
 *
 *     All we care about is if each part of the command path is authorized, if its not then the 
 *     primary engine that launched the script should be killed.  The killing should be taken care 
 *     of as a result of this call, not as part of this call.
 *
 *  2014-04-29 -- Not a script engine, but is confused as one
 *
 *     /bin/sh /usr/bin/xdg-mime query default x-scheme-handler/https
 *                                 ^      ^              ^
 *                              tries to parse these as authorized files
 *
 *
 *  FIXED: 2014-04-29 -- Need to be able to parse command-line arguments collectively
 *
 *  /bin/sh -c [-x /usr/lib/rmi/hmacs.profile] /bin/find / -type f ... -max-depth 1 {} \;
 *                                                          -------    -------------
 *                                                         Ignores -type, parses f
 *                                                         Ignores -max-depth, parses 1
 *
 * this should parse "-type f" and "-max-depth 1" the trouble is that strsep() breaks them into:
 *   -type f -max-depth 1
 *
 * FIXED: 2014-04-29 -- This chokes on the #012; note this is one long string with the 
 *                      delimiters embedded 
 *  awk -v mimetype=x-scheme-handler/https
 *#012    BEGIN {
 *#012        prefix=mimetype "="
 *#012        indefault=0
 *#012        found=0
 *#012    }
 *#012    {
 *#012        if (index($0, "[Default Applications]") == 1) {
 *#012            indefault=1
 *#012        } else if (index($0, "[") == 1) {
 *#012            indefault=0
 *#012        } else if (!found && indefault && index($0, prefix) == 1) {
 *#012            print substr($0, length(prefix) +1, length)
 *#012            found=1
 *#012        }
 *#012    }
 *#012 /home/pete/.local/share/applications/mimeapps.list
 *
 *
 *
 * FIXED: 2014-05-05 -- simple trailing argument chokes system
 *
 *  /bin/sh /usr/lib/ConsoleKit/run-session.d/pam-foreground-compat.ck session_added
 *                                                                     ^^^^^^^^^^^^^
 *                                                                     Bails on this...
 *
 */
static int32_t __valid_script_cmdline(int8_t* __rmi_cmdline, int32_t __fd, pid_t __pid)
{
    int32_t  __retval     = TRUE;
    int8_t*  __cp         = NULL;
    int8_t*  __buf        = NULL;
    int8_t*  __long_name  = NULL;
    int32_t  __have_scripting_engine = FALSE;
    int32_t  __string_has_pipe_char  = FALSE;

    if(!__rmi_cmdline)
    {
        __retval = ERROR;
        goto out;
    }

    syslog(LOG_NOTICE, "level 0 processing %s",__rmi_cmdline );

    /*
     * PHJ - 20140428
     *
     * MISRA C2012 conflict with secure coding practices.  Secure coding requires that data
     * reside in the heap, not on the stack, so predefined buffers are not allowed.
     *
     * MISRA C2012 Rule 21.3 (Required) forbids the use of dynamic memory allocation.  The rule
     * is Decidable and the decision is to follow Secure coding techniques.
     */
    if((__buf = (int8_t*)malloc(PATH_MAX)) == NULL)
    {
        __retval = FALSE;
        goto out;
    }

    if((__long_name = (int8_t*)malloc(PATH_MAX)) == NULL)
    {
        __retval = FALSE;
        goto out;
    }

    if(strspn(__rmi_cmdline, "&|")) // sh -c locale -a | grep -F .utf8
    {
    	__string_has_pipe_char = TRUE;
    }

    /*
     * Save the original command line
     */
    strncpy(__buf, __rmi_cmdline, PATH_MAX);
    __cp = strsep((char** restrict)&__rmi_cmdline, TOKENSPEC);

    while(__cp)
    {
        memset(__long_name, 0, PATH_MAX);
        syslog(LOG_DEBUG, "parser is working on %s", __cp);

        if(__string_has_pipe_char || __is_pipe_char(__cp)) // sh -c locale -a | grep -F .utf8
        {
            syslog(LOG_DEBUG, "parser: got a pipe char, invalidating scripting engine: %s", __cp);
            __have_scripting_engine = FALSE;
        }

        if(__is_exception(__cp))  // '/bin/sh -c make clean' for example
        {
            syslog(LOG_DEBUG, "parser: got an exception, invalidating scripting engine: %s", __cp);
            __have_scripting_engine = FALSE;
        }

        if(__is_wildcard(__cp))
        {
            syslog(LOG_DEBUG, "parser: got a wildcard, invalidating scripting engine: %s", __cp);
            __have_scripting_engine = FALSE;
        }

        /*
         * Determine if the argument is a script engine  cron run-parts /etc/cron.daily
         *                                               ^^^^
         */
        if(!__have_scripting_engine && __is_valid_script_engine(__cp))
        {
            __have_scripting_engine = TRUE;
            syslog(LOG_DEBUG, "parser: got a scripting engine: %s", __cp);
            goto loop;
        }

        if(__have_scripting_engine)    // cron run-parts --report /etc/cron.daily
        {
            if(__is_arg_switch(__cp) || __is_arg(__cp)) // --report /etc/cron.daily or -d
            {                                           // ^                           ^
                goto loop;                              // get the next item
            }

            if(__is_escape_sequence(__cp))  // full passed awk script might embed #012 or the like
            {
                goto loop;
            }

            if(__is_shell_command(__cp))
            {
                syslog(LOG_DEBUG, "parser: %s is a shell command, looping", __cp);
                goto loop;
            }

            if(isdigit(*__cp)) // if the first char is a number e.g. --max-depth 1  -- Abuse case - attacker writes program named 1152
            {                  //                                                ^
                if(__find_file(__cp, __long_name))
                {
                    syslog(LOG_DEBUG, "parser: found file named %s in isdigit()", __cp);
                    goto cont;
                }

                syslog(LOG_DEBUG, "parser: %s is a digit, looping", __cp);
                goto loop;
            }

            if(!__find_file(__cp, __long_name))
            {
                syslog(LOG_DEBUG, "parser: couldn't find file");
                __retval = FALSE; // PHJ this could be an argument too, careful!
                goto out;
            }

cont:
            if(__file_is_dir(__long_name))   //                cron run-parts --report /etc/cron.daily
            {                                // This is a directory full of scripts    ^^^^^^^^^^^^^^^^
                syslog(LOG_DEBUG, "parser: file is a directory, looping");
                //__process_subdir(__long_name, __fd, __pid);
                goto loop;
            }

            if(__is_forbidden_file(__long_name))
            {
                syslog(LOG_DEBUG, "parser: %s is forbidden, looping", __long_name);
                goto loop;
            }

            if(!__valid_hmac(__long_name, 0, __fd, __pid))
            {
                syslog(LOG_DEBUG, "parser: %s is an unauthorized file, exiting with FALSE", __cp);
                __retval = FALSE;  // unauthorized file
                goto out;
            }

            syslog(LOG_DEBUG, "parser: %s is an authorized file, looping", __cp);
            goto loop;
        }

loop:
        __cp = strsep((char** restrict)&__rmi_cmdline, TOKENSPEC);
        if(__cp && !*__cp)  /* This seems to be a bug in strsep, it sometimes gives back a '\0' */
        {
            __cp++;
            //goto loop;  // MISRA C2012 Deviation - Rule 15.2 "The goto statement shall jump to a label declared later in the same function
        }               // The use of it here is to work around a bug in the GNU strsep() function, so it is decided to keep it 
    }

out:

    if(__long_name)
    {
        free(__long_name);
        __long_name = NULL;
    }

    if(__buf)
    {
        free(__buf);
        __buf = NULL;
    }

    syslog(LOG_DEBUG, "parser is returning %d", __retval);
    return __retval;
}

int32_t __process_script(int32_t __fd, PidStack __pids, int8_t* __top_script)
{
    int8_t* __cmdline_buf    = NULL;
    int8_t* __working_script = NULL;
    int32_t __retval         = NOERROR;

    /*
     * PHJ - 20140428
     *
     * MISRA C2012 conflict with secure coding practices.  Secure coding requires that data
     * reside in the heap, not on the stack, so predefined buffers are not allowed.
     *
     * MISRA C2012 Rule 21.3 (Required) forbids the use of dynamic memory allocation.  The rule
     * is Decidable and the decision is to follow Secure coding techniques.
     */
    if((__cmdline_buf = (int8_t*)malloc(PATH_MAX)) == NULL)
    {
        __retval = ERROR;
        goto out;
    }

    if(!__get_cmdline(__pids.pid, __cmdline_buf))
    {
        __retval = ERROR;
        syslog(LOG_ERR, "__process_script() [%ld] failed to get command line!", (long32_t)__pids.pid);
        goto out;
    }

    syslog(LOG_DEBUG, "__get_cmdline() returned %s", __cmdline_buf);

    __working_script = __cmdline_buf;

    if((strlen(__top_script) > strlen(__cmdline_buf)) && !strchr(__cmdline_buf, ' '))
    {
        __working_script = __top_script;
    }


    if(!__valid_script_cmdline(__working_script, __fd, __pids.pid))
    {
        __retval = ERROR;
        __emergency_kill(__fd, __pids);
        syslog(LOG_ERR, "__process_script() [%ld] rogue script killed! %s", (long32_t)__pids.pid, __working_script);
    }

out:

    if(__cmdline_buf)
    {
        free(__cmdline_buf);
        __cmdline_buf = NULL;
    }

    return __retval;
}

#ifdef __TEST_PARSER__
int main(int ac, char** av)
{
    char __buf[256], __engine_buf[256], __script_buf[256];
    int32_t __retval = FALSE;
    int32_t __fd = 0;

    int option_index, opt = 0;
    static struct option long_options[] = {
            {"arg",   required_argument,   0, 'a' },
            { 0,        0,                 0,  0  }
    };

    while((opt = getopt_long(ac, av, "a:", long_options, &option_index)) != -1)
    {
        switch(opt)
        {
        case 'a':
            strcpy(__buf, optarg);

            if(bdb_open())
            {
                if((__fd = open("/dev/aerolock", O_RDWR)) > 0)
                {
                    __retval = __valid_script_cmdline(__buf, __fd);
                    if(!__retval)
                    {
                        fprintf(stderr, "KILLING Engine\n");
                    }

                    close(__fd);
                }

                bdb_close();
            }
        }
    }

    return __retval;
}
#endif

#ifdef __LINUX__
#pragma GCC diagnostic pop
#endif
