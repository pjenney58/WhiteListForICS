/*
 * rmenforcer.c
 *
 * Description
 * -----------
 * A daemon that takes a process ID (PID) from the kernel and tests it for a) if its a scripting engine
 * and b) if the script is valid.  If the script is valid its allowed to execute as normal and if the
 * script is not valid, the scripting engine is killed.
 *
 *  Created on: Oct 2, 2013
 *      Author: Peter H. Jenney
 *
 *  Deployed as
 *
 *  MISRA C 2012 -- The functions in this module map to the "Manage Rogue Scripts" requirement in the Aerolock PRD
 */

#include "aerolock.h"

#ifdef __LINUX__
#pragma GCC diagnostic ignored "-Wpointer-sign"
#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic push
#endif

int32_t  threadcount = 0;
uint32_t __tid = 0;


pthread_mutex_t __write_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t __read_mutex  = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t __io_mutex    = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t __calc_mutex  = PTHREAD_MUTEX_INITIALIZER;


int32_t  __daemonize   = 1;
int32_t  usec_delay  = DEFAULT_DELAY;
uint32_t event_count = 0;

int8_t* get_comm(pid_t __pd, int8_t* __cmdline)
{
    int8_t*     __buf    = NULL;
    struct stat __sb;
    int32_t     __fd     = 0;
    int32_t     __ln     = 0;
    int8_t*     __cp     = NULL;
    int8_t*     __retval = NULL;

    if((__buf = (int8_t*)malloc(512)) == NULL)
    {
    	goto out;
    }

    snprintf(__buf, 512, "/proc/%ld/comm", (long)__pd);

    if(stat(__buf, &__sb) == -1)
    {
        goto out;
    }

    __fd = open(__buf, O_RDONLY);
    if(__fd > 0)
    {
        __ln = read(__fd, __buf, sizeof(__buf));
        close(__fd);

        if(__ln <= 0)
        {
            goto out;
        }

        /*
         * Handle kworker/0:OH etc...
         */
        if((__cp = strchr(__buf, '/')) != NULL)
        {
            *__cp = '\0';
        }

        strcpy(__cmdline, __buf);
        __retval = __cmdline;
    }

out:

    if(__buf)
    {
    	free(__buf);
    	__buf = NULL;
    }

    return __retval;
}

int32_t __handle_proc (struct pid_stack __pids, int32_t __fd0)
{
    int8_t*     __buf      = NULL;
    int8_t*     __path     = NULL;
    int8_t*     __pathp    = NULL;
    int8_t*     __cmdline  = NULL;
    struct stat __sb       = {0};
    int32_t     __rc       = 0;
    pid_t       __stopped  = 0L;
    int32_t     __retval   = NOERROR;

    if(__pids.pid <= 1)  // /sbin/init
    {
        goto out;
    }

    if(__pids.pid == getpid())  // Self
    {
    	goto out;
    }

    /*
   	 * PHJ - 20140428
   	 *
   	 * MISRA C2012 conflict with secure coding practices.  Secure coding requires that data
   	 * reside in the heap, not on the stack, so predefined buffers are not allowed.
   	 *
   	 * MISRA C2012 Rule 21.3 (Required) forbids the use of dynamic memory allocation.  The rule
   	 * is Decidable and the decision is to follow Secure coding techniques.
   	 */
    if((__buf = (int8_t*)malloc(256)) == NULL)
    {
    	__retval = ERROR;
    	goto out;
    }

    if((__path = (int8_t*)malloc(PAGE_SIZE)) == NULL)
    {
    	__retval = ERROR;
    	goto out;
    }

    if((__cmdline = (int8_t*)malloc(1024)) == NULL)
    {
    	__retval = ERROR;
    	goto out;
    }

    /*
     *  There's a lag between when the /proc entry is created and its populated with the proper data.
     *  The parent data is in place during the lag time
     */
    usleep(usec_delay);

    /*
     * Get the /proc pathname, it contains the complete executable file path
     */
    snprintf(__buf, 256, "/proc/%d/exe", __pids.pid);
    
    /*
     * Test for the files existence before proceeding
     */
    if(stat(__buf, &__sb) == -1)
    {
        syslog(LOG_DEBUG, "[%ld] TID:[0x%0lx] Failed to stat %s [ %s ]\n",
                    (long)__pids.pid, (long)pthread_self(), __buf, get_comm(__pids.pid, __cmdline) ? __cmdline : (int8_t*)"Nonexistant");
        /*
         * Fail towards availability
         */
        goto out;
    }

#if 0
    /*
     * VULNERABILITY:  If an attacker builds a huge executable it might be able to run while the system
     * is generating the HMAC.
     *
     * To counter we look at the size of the executable and stop it in its tracks
     * while we generate the HMAC.  We keep it stopped and either kill it should the HMAC be invalid, or
     * re-enable it at the end of the routine.  Work needs to be done here to determine what "huge" means
     * and set representative value.   in debug mode is 1.8MB for example, but most executables
     * seem to be in the 100K or less range.
     */
    if(!__driver_mode)
    {
        if(__sb.st_size > 2097152L)
        {
            __proc_stopped = __emergency_stop(__fd0, __pids);
        }
    }
#endif

    /*
     *   Unwind the link and process the file
     */
    if ((__rc = readlink(__buf, __path, PAGE_SIZE)) != -1)
    {
        /* Not NULL terminated */
        __path[__rc] = '\0';
        __pathp = __path;

		syslog(LOG_DEBUG, "[%ld] TID:[0x%08lx] processing path (%s), we %s in a panic",
				(long)__pids.pid, pthread_self(), __pathp, __pids.cmd == PANIC ? "are" : "are not");

        /*
         * Since we're not in the driver, we need to do all the work that would normally be done
         * in the driver here.
         */
        if(!__driver_mode || __pids.cmd == PANIC)
        {
            /* Kick off the first strike */
            __stopped = __valid_name(__pathp, __pids.pid);

            if(__valid_hmac(__pathp, __stopped, __fd0, __pids.pid))
            {
                syslog(LOG_DEBUG, "[%ld] authorized process %s fd(0x%02x) TID(0x%lx)",
                            (long)__pids.pid, __pathp, __fd0, (long)pthread_self());
            }
            else  /* Invalid HMAC, kill the process */
            {
                syslog(LOG_CRIT, "[%ld] rogue process!! %s fd(0x%02x) TID(0x%lx)",
                                   (long)__pids.pid, __pathp, __fd0, (long)pthread_self());

                if(!__emergency_kill(__fd0, __pids))
                {
                	__retval = ERROR;
                    syslog(LOG_ERR, "failed to kill process [%ld]", (long)__pids.pid);
                }

                __retval = NOERROR; // Its not an error to do the functions job
                goto out;
            }
        }

        /*
         * Check for a scripting engine and a valid script.  If we're not in driver mode this is a
         * secondary activity, otherwise its primary
         */
        if(!__process_script(__fd0, __pids, __pathp))
        {
        	__retval = ERROR;
        }
    }
    else
    {
        syslog(LOG_ERR, "failed to read link %s", __buf);
        __retval = ERROR;
    }

out:
    if(__cmdline)
    {
    	free(__cmdline);
    	__cmdline = NULL;
    }

    if(__path)
    {
    	free(__path);
    	__path = NULL;
    }

    if(__buf)
    {
    	free(__buf);
    	__buf = NULL;
    }

    return __retval;
}


int last_pid = 0;

pid_t __handle_msg(struct cn_msg* __cn_hdr)
{
    struct pid_stack   __pids   = {0};
    struct proc_event* __ev     = NULL;
    pid_t              __retval = 0;

    if(!__cn_hdr)
    {
    	goto out;
    }

    __ev   = (struct proc_event *) __cn_hdr->data;

    if(last_pid == __ev->event_data.fork.child_pid || last_pid == __ev->event_data.exec.process_pid)
    {
        /* syslog(LOG_INFO, "PROC: Blocked duplicate (%ld)", ++event_count); */
        goto out;
    }

    switch (__ev->what)
    {
    case PROC_EVENT_FORK:
    //    syslog(LOG_INFO, "FORK:parent(pid,tgid)=%d, %d child(pid,tgid)= %d, %d",
    //            ev->event_data.fork.parent_pid, ev->event_data.fork.parent_tgid,
    //            ev->event_data.fork.child_pid, ev->event_data.fork.child_tgid);
        

        last_pid = __pids.pid = __ev->event_data.fork.child_pid;
        __handle_proc(__pids, 0);
        break;

    case PROC_EVENT_EXEC:

      //  syslog(LOG_INFO, "EXEC:pid=%d, tgid=%d",
      //          ev->event_data.exec.process_pid,
      //          ev->event_data.exec.process_tgid);


        last_pid = __pids.pid = __ev->event_data.exec.process_pid;
        __handle_proc(__pids, 0);
        break;

    case PROC_EVENT_EXIT:

    /*    syslog(LOG_INFO, "EXIT:pid=%d,%d exit code=%d",
    //            ev->event_data.exit.process_pid,
    //            ev->event_data.exit.process_tgid,
    //            ev->event_data.exit.exit_code);
    */
        break;

    case PROC_EVENT_UID:

    /*    syslog(LOG_INFO, "UID:pid=%d,%d ruid=%d,euid=%d",
    //            ev->event_data.id.process_pid, ev->event_data.id.process_tgid,
    //            ev->event_data.id.r.ruid, ev->event_data.id.e.euid);
    */
        break;

    default:
        break;
    }

    __retval = __pids.pid;

out:

    return __retval;
}

float    __tot_time = 0;
float    __avg_time = 0;
uint32_t __count = 0;

static void* __driver_read(void* __rmi_data)
{
    struct pid_stack  __pids             = {0};
    int32_t           __rc               = 0;
    int32_t           __fd0              = 0;
    struct   timespec __var_time         = {0};
    uint32_t          __diff_nanoseconds = 0U;

    if((__fd0 = open("/dev/aerolock", O_RDWR)) <= 0)
    {
        syslog(LOG_EMERG, "failed to open aerolock driver!!");
        pthread_exit(NULL);
    }

    memset(&__pids, 0, sizeof(struct pid_stack));
    memset(&__var_time, 0, sizeof(struct   timespec));

    if(__debug == 1)
    {
        __pids.cmd = TOGGLE_DEBUG;
        __pids.debug = 1;
        write(__fd0, &__pids, sizeof(struct pid_stack));
    }
    else
    {
        __pids.cmd = TOGGLE_DEBUG;
        __pids.debug = 0;
        write(__fd0, &__pids, sizeof(struct pid_stack));
    }

    while(1)
    {
    	/*
    	 * File descriptor is thread specific so there's no chance of collision, but there
    	 * can be a race condition where multiple threads get the same data from the driver
    	 * and a single PID gets processed by each.  (mutex)
    	 */
    	syslog(LOG_DEBUG, "[0x%08lx] __fd(%d) waiting for read mutex ...", pthread_self(), __fd0);
    	pthread_mutex_lock(&__read_mutex);
    	syslog(LOG_DEBUG, "[0x%08lx] __fd(%d) got read mutex ...", pthread_self(), __fd0);

        __rc = read(__fd0, &__pids, sizeof(struct pid_stack));

        pthread_mutex_unlock(&__read_mutex);


        if(__rc != -1)
        {
            //if(__pids.pid != last_pid && __pids.pid != 0)
        	if(__pids.pid > 0)
            {
                __var_time = __timer_start();

                __handle_proc(__pids, __fd0);

                /*
                 * Globals are not thread specific, so access to them needs to be controlled (mutex)
                 */
                syslog(LOG_DEBUG, "[0x%08lx] __fd(%d) waiting for calc mutex ...", pthread_self(), __fd0);
                pthread_mutex_lock(&__calc_mutex);
                syslog(LOG_DEBUG, "[0x%08lx] __fd(%d) got calc mutex ...", pthread_self(), __fd0);

                __diff_nanoseconds = __timer_end(__var_time);
                __count++;
                __tot_time += (float)__diff_nanoseconds/1000000;
                __avg_time = __tot_time/__count;

                syslog(LOG_DEBUG, "PID:[%ld]: TID:[0x%08lx] Average Time - handle_proc(%03.5fms) count: %u total: %03.5fms this: %03.5fms\n",
                		(long)__pids.pid, pthread_self(), __avg_time, __count, __tot_time, (float)__diff_nanoseconds/1000000);

                pthread_mutex_unlock(&__calc_mutex);
            }
        }
        else
        {
        	syslog(LOG_ERR, "Failed to read from aerolock driver, %s\n", strerror(errno));
        }

        last_pid = __pids.pid;
    }

    return NULL;
}

static void* __run_netlink(void* arg)
{
    int32_t            __error = -1;
    struct sockaddr_nl __main_nla,
                       __kernel_nla,
                       __receiver_nla;
    socklen_t          from_nla_len;
    char               buf[NL_BUFLEN];
    int32_t            __netlink_socket;
    struct nlmsghdr*   __netlink_header;
    struct cn_msg*     __connector_header;
    enum proc_cn_mcast_op *mcop_msg;
    size_t             recv_len = 0;
    struct timespec    __var_time;
    uint32_t           __diff_nanoseconds;
    pid_t              __pid = 0L;

    __use_local_trees = 1;  // No kernel list to call on
    __rb_init_hmac_list();

    setvbuf(stdout, NULL, _IOLBF, 0);

    /* Put the single thread in the stack */
    //__thread_stack[0] = pthread_self();

    syslog(LOG_NOTICE, "initializing netlink/connector interface");
    /*
     * Create an endpoint for communication. Use the kernel user
     * interface device (PF_NETLINK) which is a datagram oriented
     * service (SOCK_DGRAM). The protocol used is the connector
     * protocol (NETLINK_CONNECTOR)
     */
    __netlink_socket = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
    if (__netlink_socket == -1)
    {
        syslog(LOG_EMERG, "netlink_socket error");
        goto close_and_exit;
    }

    __main_nla.nl_family = AF_NETLINK;
    __main_nla.nl_groups = CN_IDX_PROC;
    __main_nla.nl_pid = getpid();

    __kernel_nla.nl_family = AF_NETLINK;
    __kernel_nla.nl_groups = CN_IDX_PROC;
    __kernel_nla.nl_pid = 1;

    /*
     * If it can't bind, then the connector interface isn't enabled.
     * TODO: Jump to the next best event mechanism in the system
     */
    __error = bind(__netlink_socket, (struct sockaddr *) &__main_nla, sizeof(__main_nla));
    if (__error == -1)
    {
        syslog(LOG_EMERG, "netlink_socket binding error");
        goto close_and_exit;
    }

    __netlink_header = (struct nlmsghdr *) buf;
    __connector_header = (struct cn_msg *) NLMSG_DATA(__netlink_header);
    mcop_msg = (enum proc_cn_mcast_op*) &__connector_header->data[0];

    memset(buf, 0, sizeof(buf));
    *mcop_msg = PROC_CONN_MCAST_LISTEN;

    /*
     * fill the netlink header
     */
    __netlink_header->nlmsg_len = SEND_MESSAGE_LEN;
    __netlink_header->nlmsg_type = NLMSG_DONE;
    __netlink_header->nlmsg_flags = 0;
    __netlink_header->nlmsg_seq = 0;
    __netlink_header->nlmsg_pid = getpid();

    /*
     * fill the connector header
     */
    __connector_header->id.idx = CN_IDX_PROC;
    __connector_header->id.val = CN_VAL_PROC;
    __connector_header->seq = 0;
    __connector_header->ack = 0;
    __connector_header->len = sizeof(enum proc_cn_mcast_op);

    if (send(__netlink_socket, __netlink_header, __netlink_header->nlmsg_len, 0) != __netlink_header->nlmsg_len)
    {
        syslog(LOG_EMERG, "failed to send control message");
        goto close_and_exit;
    }

    syslog(LOG_INFO, "reading process events from netlink connector.");

    if (*mcop_msg == PROC_CN_MCAST_IGNORE)
    {
        goto close_and_exit;
    }

    for (;;)
    {
        struct nlmsghdr *nlh = (struct nlmsghdr*) buf;
        memset(buf, 0, sizeof(buf));
        from_nla_len = sizeof(__receiver_nla);
        memcpy(&__receiver_nla, &__kernel_nla, sizeof(__receiver_nla));

        recv_len = recvfrom(__netlink_socket, buf, NL_BUFLEN, 0, (struct sockaddr*) &__receiver_nla, &from_nla_len);

        if (__receiver_nla.nl_pid != 0)
        {
            continue;
        }

        if (recv_len < 1)
        {
            continue;
        }

        while (NLMSG_OK(nlh, recv_len))
        {
            __connector_header = NLMSG_DATA(nlh);
            if (nlh->nlmsg_type == NLMSG_NOOP)
            {
                continue;
            }

            if ((nlh->nlmsg_type == NLMSG_ERROR) || (nlh->nlmsg_type == NLMSG_OVERRUN))
            {
                break;
            }

            __var_time = __timer_start();

            __pid = __handle_msg(__connector_header);

            __diff_nanoseconds = __timer_end(__var_time);
            __count++;
            __tot_time += (__diff_nanoseconds/1000000);
            __avg_time = __tot_time/__count;


            syslog(LOG_NOTICE, "(netlink): [%ld] TID:[0x%08lx] Average Time - handle_proc(%03.5fms)) count: %u total: %03.5fms this: %03.5fms\n",
                     (long)__pid, pthread_self(), __avg_time, __count, __tot_time, (float) __diff_nanoseconds/1000000);

            if (nlh->nlmsg_type == NLMSG_DONE)
            {
                break;
            }

            nlh = NLMSG_NEXT(nlh, recv_len);
        }
    }

close_and_exit:
    close(__netlink_socket);
    pthread_exit(NULL);

    return NULL;
}

int main(int argc, char **argv)
{
    int32_t         rc        = 0;
    int32_t         runatroot = 1;
    int32_t         opt       = 0;
    int32_t         t         = 0;
    pthread_attr_t  __attr;
    int             fd        = 0;
    int __max_threads         = MAX_THREADS;

    int option_index;
    static struct option long_options[] = {
            {"debug",      no_argument,         0, 'd' },
            {"delay",      required_argument,   0, 'u' },
            {"driver",     no_argument,         0, 'm' },
            {"help",       no_argument,         0, 'h' },
            {"root",       no_argument,         0, 'r' },
            {"test",       no_argument,         0, 't' },
            {"threads",    required_argument,   0, 'c' },
            {"verbose",    no_argument,         0, 'v' },
            {"local_list", no_argument, 	    0, 'l' },
            { 0,        0,                      0,  0  }
    };

    __set_proc_name(argv[0]);

    while((opt = getopt_long(argc, argv, "vrmhtldc:u:",
                             long_options, &option_index)) != -1)
    {
        switch(opt)
        {
        case 'l':
        	__use_local_trees = 1;  // Use for servers ...
        	break;

        case 'c':
            __max_threads = atoi(optarg);
            if(__max_threads > MAX_THREADS)
            {
                __max_threads = MAX_THREADS;
            }

            syslog(LOG_NOTICE, "PID:[%ld]: thread count set to %d", (int32_t)getpid(), __max_threads);
            break;

        case 'm':
            __driver_mode = 1;
            break;

        case 'v':
            __maximum_verbosity = 1;
            syslog(LOG_NOTICE, "PID:[%d]: maximum verbosity", (int32_t)getpid());
            break;

        case 'r':
            runatroot = 0;
            break;

        case 'h':
            printf("\n\nusage: rmprofiler -vklmrtu:h\n");
            printf("--verbose,   -v Verbose mode, all file information displayed\n");
            printf("--root,      -r Run at Root Directory '/'\n");
            printf("--test,      -t Run in Test mode (no kill())\n");
            printf("--debug,     -d Run in Debug mode - (Not Daemonized, No Kill)\n");
            printf("--delay,     -u Number of microseconds to delay for /proc read\n");
            printf("--driver,    -m Run using driver instead of netlink interface\n");
            printf("--local_list,-l Use local HMAC list (servers, workstations)\n");
            printf("--help,      -h This message\n\n\n");
            return 0;

        case 't':
            __test_mode = 1;
            __debug = 1;
            __daemonize = 1;
            break;

        case 'd':
            __test_mode = 1;
            __debug = 1;
            __daemonize = 0;
            break;

        case 'u':
            usec_delay = atoi(optarg);
            syslog(LOG_NOTICE, "PID:[%ld]: usec_delay set to %d", (int32_t)getpid(), usec_delay);
            break;

        default:
            break;
        }
    }

    if (getuid() != 0)
    {
        fprintf(stderr, "PID:[%d]: only root can start/stop the fork connector\n",(int32_t)getpid());
        return 0;
    }

    syslog(LOG_NOTICE, "PID:[%d]: system initializing", (int32_t)getpid());

    /*
     * Setup signals to manage cache and shutdown
     */
    __setup_signal_handlers();

	if (__debug || __test_mode || __maximum_verbosity)
	{
		setlogmask(LOG_UPTO(LOG_DEBUG));
	}
	else
	{
		setlogmask(LOG_UPTO(LOG_NOTICE));
	}

    /*
     * TODO: Hide the daemonized program from ps
     */
    if(__daemonize)
    {
        daemon(runatroot, 1);
        openlog(__global_proc_name, LOG_NOWAIT | LOG_PID, LOG_DAEMON);
    }
    else
    {
        openlog(__global_proc_name, LOG_NOWAIT | LOG_PID, LOG_USER);
    }

    /*
     * Open data stores
     */
    if(!__bdb_open())
    {
        exit(0);
    }

    /*
     * Initialize local rb_trees
     */
    __rmi_initialize_lists();

    __write_pid(__global_proc_name);

    if(__driver_mode)
    {
        fd = open("/dev/aerolock", O_RDWR);

        if(fd <= 0)
        {
            if(!__daemonize)
            {
                syslog(LOG_ERR, "%s[%d]: failed to open /dev/aerolock, error: %s\n", __global_proc_name, (int32_t)getpid(),  strerror(errno));
            }

            __driver_mode = 0;
            goto try_netlink_connector;
        }

        __validate_runtime_environment(fd);
        close(fd);

        /*
         * fire off pthreads here
         */
        pthread_attr_init(&__attr);
        pthread_attr_setdetachstate(&__attr, PTHREAD_CREATE_DETACHED);

        for(t = 0; t < __max_threads; t++)
        {
			rc = pthread_create(&__rmi_thread[t], &__attr, __driver_read, NULL);
			if(rc)
			{
				if(!__daemonize)
				{
					syslog(LOG_CRIT, "failed to create thread. Error code: %d", rc);
				}
			}
        }

        pthread_attr_destroy(&__attr);

        /*
         * wait forever -- one of the signal handlers will do the cleanup and exit
         */
        sem_init(&__sleep_sem, 0, 0);
        sem_wait(&__sleep_sem);
        goto out;
    }
    else
    {
try_netlink_connector:
		pthread_create(&__rmi_thread[0], NULL, __run_netlink, NULL);
		pthread_join(__rmi_thread[0], NULL);
    }

out:
    syslog(LOG_NOTICE, "main() exiting!\n");
    __bdb_close();
    closelog();
    return rc;
}
#ifdef __LINUX__
#pragma GCC diagnostic pop
#endif

