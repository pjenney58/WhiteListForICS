#include "aerolock.h"

#ifdef __LINUX__
#include <execinfo.h>
#endif

#ifdef __LINUX__
#pragma GCC diagnostic ignored "-Wpointer-sign"
#pragma GCC diagnostic push
#endif

pthread_mutex_t locate_mutex;

#define MONITOR_MODE     0  /* Observe and record */
#define PROTECTED_MODE   1  /* Observe and protect */
#define TEST_MODE        2  /* Observe and pretend to protect */

int32_t gMode = MONITOR_MODE;
int32_t __driver_mode = 0;


int32_t __debug             = 0;
int32_t __maximum_verbosity = 0;
int32_t __test_mode         = 0;

pthread_key_t __file_desc_key;

/*
 * MISRA 2012 Note -- these time functions are not from stdlib.h
 */
/* call this function to start a nanosecond-resolution timer */
struct timespec __timer_start()
{
    struct timespec __start_time;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &__start_time);
    return __start_time;
}

/* call this function to end a timer, returning nanoseconds elapsed as a long */
long __timer_end(struct timespec __start_time)
{
    struct timespec __end_time;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &__end_time);
    long diffInNanos = __end_time.tv_nsec - __start_time.tv_nsec;
    return diffInNanos;
}

int8_t* __global_proc_name = NULL;

void __set_proc_name(int8_t* __av0)
{
    int8_t* cp = __av0;

    __global_proc_name = (int8_t*)malloc(512);
    if(!__global_proc_name)
    {
        /*
         * It's really bad if we get here -- abort the run
         */
        fprintf(stderr, "panic:  failed to allocate %d bytes for __proc_name -- terminal failure\n", 512);
        exit(1);
    }

    if(cp)
    {
        if(strchr(cp, '/'))
        {
            while(*cp++);     /* Scan to the end of the string */

            while(*cp != '/') /* Back up to the path separator */
            {
                cp--;
            }
        }

        strcpy(__global_proc_name, cp+1);
    }

    return;
}

/*
 * void __release_threads() -- Cancel all threads except self
 */
void __release_threads(void)
{
    int   i;
    pid_t __current_tid;

    if(__global_proc_name)
    {
        free(__global_proc_name);
        __global_proc_name = NULL;
    }

    if(__driver_mode)
    {
        __current_tid = pthread_self();

        for(i=1; i<MAX_THREADS; i++)
        {
            if(__rmi_thread[i] != 0x00000000L &&
               memcmp(&__rmi_thread[i], &__current_tid, sizeof(pthread_t)))
            {
                pthread_cancel(__rmi_thread[i]);
                __rmi_thread[i] = 0x00000000L;
            }
        }
    }

    return;
}

/*
 * MISRA C 2012 RULE 21.5 The standard header file <signal.h> shall not be used.
 *
 * TODO: Don't understand this rule, this is Linux/POSIX, we have to manage signals ...
 */
void __sigaction_handler_terminate(int32_t __signal)
{
    syslog(LOG_NOTICE, "Got SIGTERM, shutting down.");

    __bdb_close();

    __delete__pid(__global_proc_name);

    __rb_flush_hmacs();
    __release_threads();

    sem_post(&__sleep_sem);

    return;
}

void __sigaction_handler_flush_cache(int32_t __signum)
{
#if 0
    /* Flush cache */
    syslog(LOG_NOTICE, "Got SIGHUP, dumping cache");
    __flush_cache();

    return;
#endif

    syslog(LOG_NOTICE, "Got SIGHUP, shutting down.");

    __bdb_close();

    __delete__pid(__global_proc_name);

    __rb_flush_hmacs();
    __release_threads();

    sem_post(&__sleep_sem);

    return;
}

void __sig_action_handler_sigint(int32_t __signum)
{
    syslog(LOG_ALERT, "Got SIGINT, shutting down.");

    __bdb_close();

    __delete__pid(__global_proc_name);

    //__flush_hmacs();
    __rmi_destroy_lists();

    __release_threads();

    sem_post(&__sleep_sem);

    return;
}

void __sig_action_handler_sigsegv(int32_t __signum)
{
    switch(__signum)
    {
    case SEGV_MAPERR:
        syslog(LOG_WARNING, "PROC:[%ld] TID:[0x%08lx] Got SIGSEGV(MAPPER), shutting down.", (long)getpid(), pthread_self());
        break;

    case SEGV_ACCERR:
        syslog(LOG_WARNING, "PROC:[%ld] TID:[0x%08lx] Got SIGSEGV(ACCERR), shutting down.", (long)getpid(), pthread_self());
        break;

    default:
        syslog(LOG_NOTICE, "Got SIGSEGV, shutting down.");
        syslog(LOG_WARNING, "PROC:[%ld] TID:[0x%08lx] Got SIGSEGV, shutting down.", (long)getpid(), pthread_self());
        break;
    }

    __bdb_close();

    __delete__pid(__global_proc_name);

    /*__release_threads(); */
    
    /* Dump Core */
    syslog(LOG_WARNING, "PROC:[%ld] TID:[0x%08lx] Setting up for core dump.", (long)getpid(), pthread_self());

#ifdef __LINUX__
    /*
     * Make the root process dumpable (Linux Specific)
     */
    prctl(PR_SET_DUMPABLE, 1);
#endif

    /*
     * Remove any core size limits
     */
    struct rlimit __core_limits;
    __core_limits.rlim_max = __core_limits.rlim_cur = RLIM_INFINITY;
    setrlimit(RLIMIT_CORE, &__core_limits);

    /*
     * Reset the signal handler to default
     */
    struct sigaction new_action, old_action;
    new_action.sa_handler = SIG_DFL;

    sigemptyset (&new_action.sa_mask);
    new_action.sa_flags = 0;

    sigaction(SIGSEGV, NULL, &old_action);
    if(old_action.sa_handler != SIG_IGN)
    {
        syslog(LOG_WARNING, "PROC:[%ld] TID:[0x%08lx] Reset SIGSEGV handler.", (long)getpid(), pthread_self());
        sigaction(SIGSEGV, &new_action, NULL);
    }

    syslog(LOG_WARNING, "PROC:[%ld] TID:[0x%08lx] Dumping core.", (long)getpid(), pthread_self());
    kill(getpid(), SIGSEGV);

    /* exit(NOERROR); */
    return;
}


void __sig_action_handler_sigtrap(int32_t __signum)
{
    switch(__signum)
    {
    case TRAP_BRKPT:
        syslog(LOG_NOTICE, "Got SIGTRAP(BRKPT), shutting down.");
        break;

    case TRAP_TRACE:
        syslog(LOG_NOTICE, "Got SIGTRAP(TRACE)), shutting down.");
        break;
#if 0
    case TRAP_BRANCH:
        syslog(LOG_NOTICE, "Got SIGTRAP(BRANCH)), shutting down.");
        break;

    case TRAP_HWBKPT:
            syslog(LOG_NOTICE, "Got SIGTRAP(HWBKPT)), shutting down.");
            break;
#endif
    default:
        syslog(LOG_NOTICE, "Got SIGSTRAP, shutting down.");
        break;
    }

    //close(__fd(0));
    __bdb_close();

    __delete__pid(__global_proc_name);

    //__flush_hmacs();
    __rmi_destroy_lists();

    __release_threads();

    sem_post(&__sleep_sem);

    exit(NOERROR);   /* <- TODO: MISRA C 2012 Deviation - can't use exit() */
}

void __sig_action_handler_sigio(int32_t __signum)
{
    switch(__signum)
    {
    case SI_USER:
        syslog(LOG_NOTICE, "Got SIGIO(USER), shutting down.");
        break;

    case SI_TIMER:
        syslog(LOG_NOTICE, "Got SIGIO(TIMER), shutting down.");
        break;

    case SI_MESGQ:
        syslog(LOG_NOTICE, "Got SIGIO(MESGQ), shutting down.");
        break;

    case SI_ASYNCIO:
        syslog(LOG_NOTICE, "Got SIGIO(ASYNCIO), shutting down.");
        break;

#ifndef __QNX__
    case SI_KERNEL:
           syslog(LOG_NOTICE, "Got SIGIO(KERNEL), shutting down.");
           break;

    case SI_SIGIO:
        syslog(LOG_NOTICE, "Got SIGIO(SIGIO), shutting down.");
        break;

    case SI_TKILL:
        syslog(LOG_NOTICE, "Got SIGIO(TKILL), shutting down.");
        break;
#endif

    default:
        syslog(LOG_NOTICE, "Got SIGIO, shutting down.");
        break;
    }

    //close(__fd(0));
    __bdb_close();

    __delete__pid(__global_proc_name);

   // __flush_hmacs();
    __rmi_destroy_lists();

    __release_threads();

    sem_post(&__sleep_sem);

    exit(NOERROR);        /* <- TODO: MISRA C 2012 Deviation - can't use exit() */
}

void __sig_action_handler_sigill(int32_t __signum)
{
    switch(__signum)
    {
    case ILL_ILLOPC:
        syslog(LOG_NOTICE, "Got SIGILL(ILLOPC), shutting down.");
        break;

    case ILL_ILLOPN:
        syslog(LOG_NOTICE, "Got SIGILL(ILLOPN), shutting down.");
        break;

    case ILL_ILLADR:
        syslog(LOG_NOTICE, "Got SIGILL(ILLADR), shutting down.");
        break;

    case ILL_ILLTRP:
        syslog(LOG_NOTICE, "Got SIGIILL(ILLTRP), shutting down.");
        break;

    case ILL_PRVOPC:
        syslog(LOG_NOTICE, "Got SIGILL(PRVOPC), shutting down.");
        break;

    case ILL_PRVREG:
        syslog(LOG_NOTICE, "Got SIGILL(PRVREG), shutting down.");
        break;

    case ILL_COPROC:
        syslog(LOG_NOTICE, "Got SIGILL(COPROC), shutting down.");
        break;

    case ILL_BADSTK:
        syslog(LOG_NOTICE, "Got SIGILL(BADSTK), shutting down.");
        break;

    default:
        syslog(LOG_NOTICE, "Got SIGSILL, shutting down.");
        break;
    }

    //close(__fd(0));
    __bdb_close();

    __delete__pid(__global_proc_name);
    __release_threads();

    sem_post(&__sleep_sem);

    exit(NOERROR);       /* <- TODO: MISRA C 2012 Deviation - can't use exit() */
}

void __setup_signal_handlers()
{
    struct sigaction __new_action, __old_action;

    __new_action.sa_handler = __sigaction_handler_flush_cache;
    sigemptyset (&__new_action.sa_mask);
    __new_action.sa_flags = 0;
    sigaction(SIGHUP, NULL, &__old_action);
    if(__old_action.sa_handler != SIG_IGN)
    {
        sigaction(SIGHUP, &__new_action, NULL);
    }

    __new_action.sa_handler = __sigaction_handler_terminate;
    sigemptyset (&__new_action.sa_mask);
    __new_action.sa_flags = 0;
    sigaction(SIGTERM, NULL, &__old_action);
    if(__old_action.sa_handler != SIG_IGN)
    {
        sigaction(SIGTERM, &__new_action, NULL);
    }

    __new_action.sa_handler = __sig_action_handler_sigint;
    sigemptyset (&__new_action.sa_mask);
    __new_action.sa_flags = 0;
    sigaction(SIGINT, NULL, &__old_action);
    if(__old_action.sa_handler != SIG_IGN)
    {
        sigaction(SIGINT, &__new_action, NULL);
    }

    __new_action.sa_handler = __sig_action_handler_sigsegv;
    sigemptyset (&__new_action.sa_mask);
    __new_action.sa_flags = 0;
    sigaction(SIGSEGV, NULL, &__old_action);
    if(__old_action.sa_handler != SIG_IGN)
    {
        sigaction(SIGSEGV, &__new_action, NULL);
    }

    __new_action.sa_handler = __sig_action_handler_sigtrap;
    sigemptyset (&__new_action.sa_mask);
    __new_action.sa_flags = 0;
    sigaction(SIGTRAP, NULL, &__old_action);
    if(__old_action.sa_handler != SIG_IGN)
    {
        sigaction(SIGTRAP, &__new_action, NULL);
    }

    __new_action.sa_handler = __sig_action_handler_sigio;
    sigemptyset (&__new_action.sa_mask);
    __new_action.sa_flags = 0;
    sigaction(SIGIO, NULL, &__old_action);
    if(__old_action.sa_handler != SIG_IGN)
    {
        sigaction(SIGIO, &__new_action, NULL);
    }

    __new_action.sa_handler = __sig_action_handler_sigill;
    sigemptyset (&__new_action.sa_mask);
    __new_action.sa_flags = 0;
    sigaction(SIGIO, NULL, &__old_action);
    if(__old_action.sa_handler != SIG_IGN)
    {
        sigaction(SIGIO, &__new_action, NULL);
    }

    return;
}

int32_t __write_pid(int8_t* __local_proc_name)
{
    int32_t __fd      = 0;
    int8_t* __buf     = NULL;
    pid_t   __pid     = -1;
    int32_t __retval = NOERROR;

    if(!__local_proc_name)
    {
        __retval = ERROR;
        goto out;
    }

    if((__buf = (int8_t*)malloc(512)) == NULL)
    {
        __retval = ERROR;
        goto out;
    }

    snprintf(__buf, 512, "%s%s.pid", RMI_PID, __local_proc_name);

    if((__fd = open(__buf, O_CREAT|O_RDWR, S_IRWXU|S_IRGRP|S_IWGRP|S_IROTH)) > 0)
    {
        __pid = getpid();
        if(write(__fd, &__pid, sizeof(pid_t)) == -1)
        {
            __retval = ERROR;
            syslog(LOG_ERR, "error writing PID: %s\n", strerror(errno));
        }

        close(__fd);
    }
    else
    {
        __retval = ERROR;
        syslog(LOG_ERR, "error opening pid file: %s\n", strerror(errno));
    }

out:

    if(__buf)
    {
        free(__buf);
        __buf = NULL;
    }

    return __retval;
}

pid_t __read__pid(int8_t* __local_proc_name)
{
    int32_t __fd      = 0;
    int8_t* __buf     = NULL;
    pid_t   __pid     = -1;
    int32_t __retval  = NOERROR;

    if(!__local_proc_name)
    {
        __retval = ERROR;
        goto out;
    }

    if((__buf = (int8_t*)malloc(512)) == NULL)
    {
        __retval = ERROR;
        goto out;
    }

    snprintf(__buf, 512, "%s%s.pid", RMI_PID, __local_proc_name);

    if((__fd = open(__buf, O_RDONLY)) != -1)
    {
        if(read(__fd, &__pid, sizeof(pid_t)) != -1)
        {
            __retval = ERROR;
            close(__fd);
            syslog(LOG_ERR, "error reading pid: %s\n", strerror(errno));
            goto out;
        }

        close(__fd);
        __retval = __pid;
    }
    else
    {
        __retval = ERROR;
        syslog(LOG_ERR, "error opening pid file: %s\n", strerror(errno));
    }

out:

    if(__buf)
    {
        free(__buf);
        __buf = NULL;
    }

    return __retval;
}

int32_t __delete__pid(int8_t* __local_proc_name)
{
    int8_t*  __buf    = NULL;
    int32_t  __retval = NOERROR;

    if(!__local_proc_name)
    {
        __retval = ERROR;
        goto out;
    }

    if((__buf = (int8_t*)malloc(256)) == NULL)
    {
        __retval = ERROR;
        goto out;
    }

    snprintf(__buf, sizeof(__buf), "%s%s.pid", RMI_DIR, __local_proc_name);
    if(unlink(__buf) == -1)
    {
        __retval = ERROR;
    }

    if(__buf)
    {
        free(__buf);
        __buf = NULL;
    }

out:

    return __retval;
}

#if 0
void __print_hmac(const uint8_t* __hmac)
{
    int16_t j;

    if(!__hmac)
    {
        goto out;
    }

    for(j=0; j<HMAC256_LEN; j++)
    {
        printf("%02X", __hmac[j]);
    }

    printf("\n");

out:
    return;
}
#endif

void __hmac_2_str(const uint8_t* __hmac, int8_t* __hmac_string)
{
    if(!__hmac || !__hmac_string)
    {
        goto out;
    }

    sprintf((char*)__hmac_string, "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
                   __hmac[0],__hmac[1],__hmac[2],__hmac[3],__hmac[4],__hmac[5],__hmac[6],__hmac[7],__hmac[8],__hmac[9],__hmac[10],__hmac[11],__hmac[12],__hmac[13],__hmac[14],__hmac[15],__hmac[16],__hmac[17],__hmac[18],__hmac[19],__hmac[20],__hmac[21],__hmac[22],__hmac[23],__hmac[24],__hmac[25],__hmac[26],__hmac[27],__hmac[28],__hmac[29],__hmac[30],__hmac[31]);

out:
   return;
}

#if 0
/* Begin new valid HMAC code */

int32_t __compare_hmac(const uint8_t* __hmac1, const uint8_t* __hmac2)
{
    int32_t i;

    if(!__hmac1)
    {
        return GenericLessThan;
    }

    if(!__hmac2)
    {
        return GenericGreaterThan;
    }

    for(i=0; i<HMAC256_LEN; i++)
    {
        if(__hmac1[i] > __hmac2[i])
        {
            return GenericGreaterThan;
        }

        if(__hmac1[i] < __hmac2[i])
        {
            return GenericLessThan;
        }
    }

    return GenericEqual;
}
#endif

pid_t __valid_name(int8_t* __name, pid_t __pid)
{
    int8_t*     __cp            = NULL;
    pid_t       __retval        = 0L;
    int8_t*     __long_name_buf = NULL;
    struct stat __sb            = {0};

    if(!__name)
    {
        goto out;
    }

    if(stat(__name, &__sb) == -1)
    {
    	syslog(LOG_ERR, "__valid_name() file %s doesn't exist", __name);
    	goto out;
    }

    if((__long_name_buf = (int8_t*)malloc(PAGE_SIZE)) == NULL)
    {
        goto out;
    }

    if(__pid <= 1)  // Don't mess with the init process
    {
        goto out;
    }

    /*
     * Get the file name
     */
    if(strchr(__name, '/'))
    {
    	__cp = __name + strlen(__name);
		while(*__cp != '/')
		{
			__cp--;
		}

		__cp++;  // step over the '/'
    }
    else
    {
    	__cp = __name;
    }

    if(!__lookup_long_name(__cp, __long_name_buf, PAGE_SIZE))
    {
        if(!__test_mode)
        {
            kill(__pid, SIGSTOP);
        }

        syslog(LOG_WARNING, "STOP: __lookup_name(%s)", __name);
        __retval = __pid;
    }

out:

    if(__long_name_buf)
    {
        free(__long_name_buf);
        __long_name_buf = NULL;
    }

    return __retval;
}

int32_t __valid_hmac(int8_t* __pathname, pid_t __stopped_pid, int32_t __fd, pid_t __current_pid)
{
    uint8_t*    __hmac   = NULL;
    int32_t     __retval = NOERROR;
    struct stat __sb     = {0};

    if(!__pathname)
    {
        __retval = ERROR;
        syslog(LOG_ERR, "__valid_hmac() bogus __pathname parameter");
        goto out;
    }

    __hmac = (uint8_t*)malloc(HMAC256_LEN);
    if(!__hmac)
    {
        __retval = ERROR;
        goto out;
    }

    if((stat(__pathname, &__sb)) == -1)
    {
        __retval = NOERROR;  // fail towards availability
        syslog(LOG_ERR, "__valid_hmac() file %s doesn't exist", __pathname);
        goto out;
    }

    if(!__get_signature(__pathname, __hmac))
    {   
        __retval = ERROR;
        syslog(LOG_ERR, "__valid_hmac() failed to __get_signature(%s) - [%s]\n", __pathname, strerror(errno));
        goto out;
    }

    if(!__lookup_hmac(__hmac, __fd, __current_pid))
    {
        __delete_from_cache(__pathname);
        __retval = ERROR;
        syslog(LOG_ERR, "__valid_hmac() %s[%d] is rogue process\n", __pathname, (int32_t)__stopped_pid);
    }
    else if(__stopped_pid)
    {
        kill(__stopped_pid, SIGCONT);
        syslog(LOG_NOTICE, "__valid_hmac() restarted pid %s", __pathname);
    }
    else
    {
    }

out:

    if(__hmac)
    {
        free(__hmac);
        __hmac = NULL;
    }

    return __retval;
}

/*
 * unit test initializer
 */
int32_t __load_cache()
{
    int8_t*  __obj_name = NULL;
    uint8_t* __obj_hmac = NULL;
    int32_t  __retval   = NOERROR;

    if((__obj_name = (int8_t*)malloc(PATH_MAX)) == NULL)
    {
        __retval = ERROR;
        goto out;
    }

    if((__obj_hmac = (uint8_t*)malloc(HMAC256_LEN)) == NULL)
    {
        __retval = ERROR;
        goto out;
    }

    while(__bdb_get_next_hmac(__obj_name, __obj_hmac))
    {
        __retval = __add_to_cache(__obj_name, __obj_hmac);
    }

out:
    if(__obj_name)
    {
        free(__obj_name);
        __obj_name = NULL;
    }

    if(__obj_hmac)
    {
        free(__obj_hmac);
        __obj_hmac =NULL;
    }

    return __retval;
}

int32_t __create_key(unsigned char* __sha2key)
{
    struct stat __sb;
    int32_t     __fd = -1;
    int32_t     __retval = NOERROR;

    if((__fd = open("/dev/urandom", O_RDONLY)) > 0)
    {
        if(read(__fd, __sha2key, SHA256KEY_LEN) == -1)
        {
            __retval = ERROR;
            goto close_and_exit;
        }

        close(__fd);
    }
    else
    {
        __retval = ERROR;
        syslog(LOG_ERR, "error getting random key: %s\n", strerror(errno));
        goto just_exit;
    }

    if(stat(RMI_DIR, &__sb) == -1)
    {
        if(mkdir(RMI_DIR, 0755))
        {
            __retval = ERROR;
            syslog(LOG_ERR, "error making secure directory: %s\n", strerror(errno));
            goto just_exit;
        }
    }

    if((__fd = open(RMI_KEY, O_CREAT|O_RDWR, S_IRWXU|S_IRGRP|S_IWGRP|S_IROTH)) > 0)
    {
        if(write(__fd, __sha2key, SHA256KEY_LEN) != SHA256KEY_LEN)
        {
            __retval = ERROR;
            syslog(LOG_ERR, "error writing key: %s\n", strerror(errno));
            goto close_and_exit;
        }
    }
    else
    {
        __retval = ERROR;
        syslog(LOG_ERR, "error creating secure key: %s\n", strerror(errno));
        goto just_exit;
    }

close_and_exit:
    close(__fd);

just_exit:
    return __retval;
}

int32_t __get_key(unsigned char* __key)
{
    int32_t __fd     = 0;
    int32_t __retval = NOERROR;

    if((__fd = open(RMI_KEY, O_RDONLY)) > 0)
    {
        if(read(__fd, __key, SHA256KEY_LEN) != SHA256KEY_LEN)
        {
            __retval = ERROR;
            syslog(LOG_ERR, "error reading secure key: %s\n", strerror(errno));
        }

        close(__fd);
    }
    else
    {
        __retval = ERROR;
        syslog(LOG_ERR, "error opening secure key: %s\n", strerror(errno));
    }

    return __retval;
}

/*
 *  Process management
 */
int32_t __emergency_kill(int32_t __fd, PidStack __pids)
{
    int32_t __retval = NOERROR;

    if(!__driver_mode)
    {
        if(!__test_mode)
        {
            if(kill(__pids.pid, SIGKILL) == -1)
            {
                __retval = ERROR;
            }
        }
    }
    else
    {
        if(write(__fd, &__pids, sizeof(struct pid_stack)) == -1)
        {
            __retval = ERROR;
        }
    }

    return __retval;
}

int32_t __emergency_stop(int __fd, PidStack __pids)
{
    int32_t __retval = NOERROR;

    if(!__driver_mode)
    {
        if(kill(__pids.pid, SIGSTOP) == -1)
        {
            __retval = ERROR;
        }
    }
    else
    {
        __pids.cmd = PROC_STOP;
        if(write(__fd, &__pids, sizeof(struct pid_stack)) == -1)
        {
            __retval = ERROR;
        }
    }

    return __retval;
}

int32_t __emergency_resume(int __fd, PidStack __pids)
{
    int32_t __retval = NOERROR;

    if(!__driver_mode)
    {
        if(kill(__pids.pid, SIGCONT) == -1)
        {
            __retval = ERROR;
        }
    }
    else
    {
        __pids.cmd = PROC_RESUME;
        if(write(__fd, &__pids, sizeof(struct pid_stack)) == -1)
        {
            __retval = ERROR;
        }
    }

    return __retval;
}
/*
 * PHJ - this is stupid ...
 */
int32_t __is_executable(int8_t* name)
{
    int32_t     i;
    int32_t     __retval    = NOERROR;
    int8_t*     __got_one   = NULL;
    struct stat __sb;
    int8_t*     __scripts[] =
    {
            ".ko",  /* Loadable Kernel Module */
            ".py",  /* Python */
            ".pyc", /* ... */
            ".pl",  /* Perl */
            ".pm",  /* ... */
            ".jar", /* Java */
            ".class"
            ".exe", /* Stray windows executables?? */
            ".com", /* ... */
            ".sys"  /* ... */
            ".sh",  /* Shell script */
            ".csh", /* ... */
            ".ksh", /* ... */
            ".bin", /* Binary file  */
            ".out", /* Old format executable */
            ".htm",
            ".html",
            ".asp",
            ".aspx",
            ".js",
            ".xml",
            ".xsl",
            NULL
    };

    /*
     * Lots of script files are not marked executable, so we'll try and get a hint from the file name
     */
    for(i=0; __scripts[i] != NULL; i++)
    {

script_try_again: /* MISRA 2012 Issue -- can't jump backwards to a label */

        if((__got_one = strstr(name, __scripts[i])))
        {
            /* Make sure its at the end of the string, avoiding program.sys.original.com.mumble or com.java.programname */
            if(*(char*)(__got_one + strlen(__scripts[i])) != '\0')
            {
                name = __got_one + strlen(__scripts[i]);   /* Try again */
                __got_one = NULL;
                goto script_try_again;
            }

            goto out;
        }
    }

    if(stat(name, &__sb) != -1)
    {
        if(__sb.st_mode & S_IFDIR)
        {
            __retval = ERROR;
            goto out;
        }

        if((__sb.st_mode & S_IXUSR) || (__sb.st_mode & S_IXGRP) || (__sb.st_mode & S_IXOTH))
        {
            __retval = NOERROR;
        }
    }

out:
    return __retval;
}

int32_t __validate_runtime_environment(int32_t __fd)
{
    // Read and process the proc directory

    DIR* dir             = NULL;
    struct dirent* __ent = NULL;
    int8_t*  __endptr    = NULL;
    int8_t*  __buf       = NULL;
    int8_t*  __execpath  = NULL;
    uint8_t* __hmac      = NULL;
    int32_t  __retval    = NOERROR;

    if((__execpath = (int8_t*)malloc(PATH_MAX)) == NULL)
    {
        __retval = ERROR;
        goto out;
    }

    if((__buf = (int8_t*)malloc(PATH_MAX)) == NULL)
    {
        __retval = ERROR;
        goto out;
    }

    if((__hmac = (int8_t*)malloc(HMAC256_LEN)) == NULL)
    {
        __retval = ERROR;
        goto out;
    }

    if (!(dir = opendir("/proc")))
    {
        syslog(LOG_ERR, "__validate_runtime_environment() can't open /proc to get running apps");
        __retval = ERROR;
        goto out;
    }

    while ((__ent = readdir(dir)) != NULL)
    {
        long lpid = strtol(__ent->d_name, (char**)&__endptr, 10);
        if (*__endptr != '\0')
        {
            continue;
        }

        /*
         * return values are not NULL terminated
         */
        memset(__execpath, '\0', PATH_MAX);

        snprintf(__buf, PATH_MAX, "/proc/%ld/exe", lpid);
        if((__retval = readlink(__buf, __execpath, PATH_MAX)) != -1)
        {
            __execpath[__retval] = '\0';
            if(__execpath[0])
            {
                syslog(LOG_INFO, "__validate_runtime_environment() reading %s", __execpath);
            }

            if(strstr(__execpath, __global_proc_name))  // don't kill ourselves
            {
                goto close_and_out;
            }

            if(!__get_signature(__execpath, __hmac))
            {
                __retval = ERROR;
                syslog(LOG_ERR, "__validate_runtime_environment() failed to __get_signature(%s) - [%s]\n", __execpath, strerror(errno));
                goto close_and_out;
            }

           if(!__lookup_hmac(__hmac, __fd, (pid_t)lpid))
           {
               __retval = ERROR;
               syslog(LOG_ERR, "__validate_runtime_environment() [%ld] killed rogue running process %s\n",(long32_t)0, __execpath);
               goto close_and_out;
           }
        }
        else
        {
            __retval = ERROR;
        }
    }

close_and_out:

    closedir(dir);

out:

    if(__hmac)
    {
        free(__hmac);
        __hmac = NULL;
    }

    if(__buf)
    {
        free(__buf);
        __buf = NULL;
    }

    if(__execpath)
    {
        free(__execpath);
        __execpath = NULL;
    }

    return __retval;
}

#ifdef __LINUX__
#pragma GCC diagnostic pop
#endif
