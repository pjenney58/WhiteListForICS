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
 * rmprofiler.c
 *
 *  Created on: Sep 27, 2013
 *      Author: Pete Jenney
 */

#ifdef __LINUX__
#pragma GCC diagnostic ignored "-Wpointer-sign"
#pragma GCC diagnostic push
#endif

#include "aerolock.h"

pthread_mutex_t __write_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t read_mutex = PTHREAD_MUTEX_INITIALIZER;
int last_pid = 0;

#define SEND_MESSAGE_LEN (NLMSG_LENGTH(sizeof(struct cn_msg) + \
                       sizeof(enum proc_cn_mcast_op)))
#define RECV_MESSAGE_LEN (NLMSG_LENGTH(sizeof(struct cn_msg) + \
                       sizeof(struct proc_event)))

#define SEND_MESSAGE_SIZE    (NLMSG_SPACE(SEND_MESSAGE_LEN))
#define RECV_MESSAGE_SIZE    (NLMSG_SPACE(RECV_MESSAGE_LEN))

#define max(x,y) ((y)<(x)?(x):(y))
#define min(x,y) ((y)>(x)?(x):(y))

#define BUFF_SIZE (max(max(SEND_MESSAGE_SIZE, RECV_MESSAGE_SIZE), 1024))
#define MIN_RECV_SIZE (min(SEND_MESSAGE_SIZE, RECV_MESSAGE_SIZE))

#define PROC_CN_MCAST_LISTEN (1)
#define PROC_CN_MCAST_IGNORE (2)

//char rootExe[PATH_MAX] = "";
int usec_delay = 250;

int dropProcTable()
{
    __bdb_reset_hmacs();
    return NOERROR;
}

int deauthorizeProcTable()
{
    __bdb_reset_hmacs();
    return NOERROR;
}

void __get_all_running(void)
{
    // Read and process the proc directory

    DIR*           __dir      = NULL;
    struct dirent* __ent      = NULL;
    int8_t*        __endptr   = NULL;
    int8_t*        __buf      = NULL;
    int8_t*        __execpath = NULL;
    uint8_t*       __hmac     = NULL;
    int32_t        __rc       = 0;

    if((__buf = (int8_t*)malloc(512)) == NULL)
    {
        goto out;
    }

    if((__execpath = (int8_t*)malloc(512)) == NULL)
    {
        free(__buf);
        goto out;
    }

    if((__hmac = (int8_t*)malloc(32)) == NULL)
    {
        free(__buf);
        free(__execpath);
        goto out;
    }

    if (!(__dir = opendir("/proc")))
    {
        syslog(LOG_ERR, "Can't open /proc to get running apps");
        goto out;
    }

    while ((__ent = readdir(__dir)) != NULL)
    {
        long lpid = strtol(__ent->d_name, (char**)&__endptr, 10);
        if (*__endptr == '\0')
        {
            syslog(LOG_ERR, "Bogus endptr in __get_all_running()");
            goto out;
        }

        /*
         * return values are not NULL terminated
         */
        memset(__execpath, '\0', 512);

        snprintf(__buf, 512, "/proc/%ld/exe", lpid);
        if ((__rc = readlink(__buf, __execpath, 512)) != -1)
        {
            __execpath[__rc] = '\0';
            if(__execpath[0])
            {
                syslog(LOG_INFO, "Reading %s", __execpath);

                if(__get_signature(__execpath, __hmac))
                {
                    __bdb_write_hmac(__execpath, __hmac);
                }
            }
        }
    }

    closedir(__dir);

out:
    if(__buf)
    {
        free(__buf);
    }

    if(__execpath)
    {
        free(__execpath);
    }

    if(__hmac)
    {
        free(__hmac);
    }

    return;
}


int8_t* __get_cmdline(pid_t __pid, int8_t* __cmd_line)
{
    struct stat __sb     = {0};
    int8_t*     __buf    = NULL;
    uint8_t*    __cp     = NULL;
    int32_t     __fd     = -1;

    if((__buf = (int8_t*)malloc(PATH_MAX)) == NULL)
    {
    	goto out;
    }

    snprintf(__buf, sizeof(__buf), "/etc/%d/cmd", (int32_t)__pid);

    if(stat(__buf, &__sb) == -1)
    {
    	return NULL;
    }

    if((__fd = open(__buf, O_RDONLY)) > 0)
    {
        if(read(__fd, __buf, sizeof(__buf)) > 0)
        {
            syslog(LOG_INFO, "PROC: Commandline %s", __buf);

            __cp = strtok(__buf, " -&|");  // /bin/bash
            __cp = strtok(NULL, " -&|");   // /usr/bin/ls

            if(__cp)
            {
                strncpy(__cmd_line, __cp, strlen(__cp));
                goto out;
            }
        }

        close(__fd);
    }

out:

    if(__buf)
    {
    	free(__buf);
    	__buf = NULL;
    }

    return __cp;
}

int32_t __handle_proc(struct pid_stack pids)
{
    int32_t  __retval  = FALSE;
    int8_t*  __dirname = NULL;
    int8_t*  __exepath = NULL;
    uint8_t* __hmac    = NULL;

    if((__dirname = (int8_t*)malloc(PATH_MAX)) == NULL)
    {
    	goto out;
    }

    if((__exepath = (int8_t*)malloc(PATH_MAX)) == NULL)
    {
    	goto out;
    }

    if((__hmac = (uint8_t*)malloc(HMAC256_LEN)) == NULL)
    {
    	goto out;
    }

    usleep(usec_delay);

    /*
     * /proc/`pid`/exe is a symlink to the full path.  Try and open it, on success the
     * full path is ours.
     */
    snprintf(__dirname, sizeof(__dirname), "/proc/%d/exe", pids.pid);

    if ((__retval = readlink(__dirname, __exepath, sizeof(__exepath))) != -1)
    {
        __exepath[__retval] = '\0';
        syslog(LOG_NOTICE, "PROC: %s pid: [%d] tid: 0x%lx", __exepath, pids.pid, pthread_self());
    }
    else
    {
        goto out;
    }

    if(__exepath[0] && !__lookup_cache(__exepath, __hmac))
    {
        if(__get_signature(__exepath, __hmac))
        {
            __retval = __bdb_write_hmac(__exepath, __hmac);
        }
    }

out:

    if(__hmac)
    {
    	free(__hmac);
    	__hmac = NULL;
    }

    if(__exepath)
    {
    	free(__exepath);
    	__exepath = NULL;
    }

    if(__dirname)
    {
    	free(__dirname);
    	__dirname = NULL;
    }

    return __retval;
}

void __handle_msg(struct cn_msg *cn_hdr)
{
    struct pid_stack pids;
    struct proc_event *ev = (struct proc_event *) cn_hdr->data;



    switch (ev->what)
    {
    case PROC_EVENT_FORK:
        /*
         * /proc/`pid`/exe is a symlink to the full path.  Try and open it, on success the
         * full path is ours.
         */
        pids.pid = ev->event_data.fork.child_pid;
        pids.ppid = ev->event_data.fork.parent_pid;
        pids.exec = 0;

        __handle_proc(pids);
        break;

    case PROC_EVENT_EXEC:
        pids.pid = ev->event_data.fork.child_pid;
        pids.ppid = -1;
        pids.exec = 1;

        __handle_proc(pids);
        break;

/*
    case PROC_EVENT_EXIT:
        syslog(LOG_NOTICE, "EXIT: pid=%d,%d  exit code=%d",
                ev->event_data.exit.process_pid,
                ev->event_data.exit.process_tgid,
                ev->event_data.exit.exit_code);
        break;

    case PROC_EVENT_UID:
        syslog(LOG_NOTICE, "UID:pid=%d,%d ruid=%d,euid=%d",
                ev->event_data.id.process_pid, ev->event_data.id.process_tgid,
                ev->event_data.id.r.ruid, ev->event_data.id.e.euid);
        break;
*/
    default:
        break;
    }
}

void* __driver_read(void* __rmi_data)
{
    struct pid_stack __pids;
    int32_t rc  = 0;
    int32_t fd0 = -1;

    syslog(LOG_INFO, "PROC: Thread 0x%lx starting ...\n", pthread_self());

    if((fd0 = open("/dev/aerolock", O_RDWR)) <= 0)
    {
        syslog(LOG_ERR, "Failed to open rmenforcer driver");
        pthread_exit(NULL);
    }

    __pids.cmd = PROFILING_START;
    write(fd0, &__pids, sizeof(struct pid_stack));

    if(__debug == 1)
    {
        __pids.cmd = TOGGLE_DEBUG;
        __pids.debug = 1;
        write(fd0, &__pids, sizeof(struct pid_stack));

    }
    else
    {
        __pids.cmd = TOGGLE_DEBUG;
        __pids.debug = 0;
        write(fd0, &__pids, sizeof(struct pid_stack));
    }

    while(TRUE)
    {
    	/*
    	 * PHJ - Need a mutex here
    	 */
        rc = read(fd0, &__pids, sizeof(PidStack));
        if(rc != -1)
        {
            if(__pids.pid != last_pid && __pids.pid != 0)
            {
                syslog(LOG_INFO, "PROC:  Processing pid: %d  tid: 0x%lx  fd: 0x%02x", (int32_t)__pids.pid, pthread_self(), fd0);
                __handle_proc(__pids);
            }
        }
        else
        {
            perror("PROC: read()");
        }

        last_pid = __pids.pid;
    }
}

void* __use_netlink( void* __data)
{
    int sk_nl;
    int err;
    struct sockaddr_nl my_nla, kern_nla, from_nla;
    socklen_t from_nla_len;
    char buff[BUFF_SIZE];
    struct nlmsghdr *nl_hdr;
    struct cn_msg *cn_hdr;
    enum proc_cn_mcast_op *mcop_msg;
    size_t recv_len = 0;

    /*
      * Create an endpoint for communication. Use the kernel user
      * interface device (PF_NETLINK) which is a datagram oriented
      * service (SOCK_DGRAM). The protocol used is the connector
      * protocol (NETLINK_CONNECTOR)
      */
     sk_nl = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
     if (sk_nl == -1)
     {
         syslog(LOG_ERR, "socket sk_nl error");
         pthread_exit(NULL);
     }

     my_nla.nl_family = AF_NETLINK;
     my_nla.nl_groups = CN_IDX_PROC;
     my_nla.nl_pid = getpid();

     kern_nla.nl_family = AF_NETLINK;
     kern_nla.nl_groups = CN_IDX_PROC;
     kern_nla.nl_pid = 1;

     err = bind(sk_nl, (struct sockaddr *) &my_nla, sizeof(my_nla));
     if (err == -1)
     {
         syslog(LOG_ERR, "binding sk_nl error");
         close(sk_nl);
         pthread_exit(NULL);
     }

     nl_hdr = (struct nlmsghdr *) buff;
     cn_hdr = (struct cn_msg *) NLMSG_DATA(nl_hdr);
     mcop_msg = (enum proc_cn_mcast_op*) &cn_hdr->data[0];

     syslog(LOG_NOTICE, "sending proc connector: PROC_CN_MCAST_LISTEN... ");
     memset(buff, 0, sizeof(buff));
     *mcop_msg = PROC_CN_MCAST_LISTEN;

     /* fill the netlink header */
     nl_hdr->nlmsg_len = SEND_MESSAGE_LEN;
     nl_hdr->nlmsg_type = NLMSG_DONE;
     nl_hdr->nlmsg_flags = 0;
     nl_hdr->nlmsg_seq = 0;
     nl_hdr->nlmsg_pid = getpid();

     /* fill the connector header */
     cn_hdr->id.idx = CN_IDX_PROC;
     cn_hdr->id.val = CN_VAL_PROC;
     cn_hdr->seq = 0;
     cn_hdr->ack = 0;
     cn_hdr->len = sizeof(enum proc_cn_mcast_op);

     if (send(sk_nl, nl_hdr, nl_hdr->nlmsg_len, 0) != nl_hdr->nlmsg_len)
     {
         syslog(LOG_ERR, "failed to send proc connector mcast ctl op!");
         close(sk_nl);
         pthread_exit(NULL);
     }

     syslog(LOG_INFO, "sent");

     if (*mcop_msg == PROC_CN_MCAST_IGNORE)
     {
         close(sk_nl);
         pthread_exit(NULL);
     }


     for (memset(buff, 0, sizeof(buff)), from_nla_len = sizeof(from_nla);;
             memset(buff, 0, sizeof(buff)), from_nla_len = sizeof(from_nla))
     {
         struct nlmsghdr *nlh = (struct nlmsghdr*) buff;
         memcpy(&from_nla, &kern_nla, sizeof(from_nla));

         recv_len = recvfrom(sk_nl, buff, BUFF_SIZE, 0,
                 (struct sockaddr*) &from_nla, &from_nla_len);

         if (from_nla.nl_pid != 0)
             continue;

         if (recv_len < 1)
             continue;

         while (NLMSG_OK(nlh, recv_len))
         {
             cn_hdr = NLMSG_DATA(nlh);
             if (nlh->nlmsg_type == NLMSG_NOOP)
                 continue;

             if ((nlh->nlmsg_type == NLMSG_ERROR)
                     || (nlh->nlmsg_type == NLMSG_OVERRUN))
                 break;

             __handle_msg(cn_hdr);

             if (nlh->nlmsg_type == NLMSG_DONE)
                 break;
             nlh = NLMSG_NEXT(nlh, recv_len);
         }
     }
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
    uint8_t*    __buf    = NULL;
    int8_t*     __name   = NULL;
    struct stat __st     = {0};
    int32_t     __retval = 1;

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
    if((__buf = (uint8_t*)malloc(HMAC256_LEN)) == NULL)
    {
        goto out;
    }

    if((__name = (int8_t*)malloc(PATH_MAX)) == NULL)
    {
        goto out;
    }

    if(stat(RMI_PROFILE, &__st) != -1)
    {
        __retval = unlink(RMI_PROFILE);
    }

    if(__retval != 0)
    {
        syslog(LOG_ERR, "error deleting hmacs.profile: %s\n", strerror(errno));
        __retval = 0;
        goto out;
    }

    int fd = open("/var/lib/rmi/hmacs.profile", O_CREAT | O_RDWR, S_IRWXU | S_IRWXG);
    if(fd > 0)
    {
        /*
         * Get the current key, its the first 32 byte entry in the file
         */
        __get_key(__buf);

        __retval = write(fd, __buf, SHA256KEY_LEN);
        if(__retval != 32)
        {
            syslog(LOG_ERR, "error writing key: %s\n", strerror(errno));
            __retval = 0;
            goto out;
        }

        /*
         * Iterate through all the HMACs in the database and write them to the profile
         */
        while(__bdb_get_next_hmac(__name, __buf))
        {
            __retval = write(fd, __buf, HMAC256_LEN);
            if(__retval != HMAC256_LEN)
            {
                syslog(LOG_ERR, "error writing HMAC: %s\n", strerror(errno));
                __retval = 0;
                goto out;
            }

            memset(__buf, 0, HMAC256_LEN);
        }

        /*
         * Get the new file into the system so rmverify won't choke
         */
        if(__get_signature(RMI_PROFILE, __buf))
        {
            __bdb_write_hmac((int8_t*)RMI_PROFILE, __buf);
        }

        goto out;
    }
    else
    {
        syslog(LOG_ERR, "error opening hmacs.profile: %s\n", strerror(errno));
    }

    __bdb_close();

out:

    if(fd > 0)
    {
        close(fd);
    }

    if(__buf)
    {
        free(__buf);
        __buf = NULL;
    }

    if(__name)
    {
        free(__name);
        __name = NULL;
    }

    return __retval;
}

int main(int argc, char **argv)
{
    int fd = 0;
    int opt;
    pthread_attr_t  __attr;
    int __max_threads = MAX_THREADS;
    int option_index;
    static struct option long_options[] = {
           {"debug",   no_argument,       0, 'd' },
           {"delay",   required_argument, 0, 'u' },
           {"driver",  no_argument,       0, 'm' },
           {"threads", required_argument, 0, 't' },
           {"help",    no_argument,       0, 'h' },
           {"verbose", no_argument,       0, 'v' },
           { 0,        0,                 0,  0  }
    };


       __driver_mode = 0;
       __debug       = 0;

       while((opt = getopt_long(argc, argv, "vmhdu:t:",
                                long_options, &option_index)) != -1)
       {
           switch (opt)
           {
            case 't':
                __max_threads = atoi(optarg);
                if(__max_threads > MAX_THREADS)
                    __max_threads = MAX_THREADS;

                syslog(LOG_INFO, "Thread count reset to set to %d", __max_threads);
                break;
            case 'd':
                __debug = 1;
                syslog(LOG_INFO, "Debug mode enabled");
                break;

            case 'v':
                __maximum_verbosity = 1;
                break;

            case 'h':
                printf("\n\nusage: rmprofiler -dvrh\n");
                printf("--debug,   -d Debug information output to stdout");
                printf("--verbose, -v Verbose mode, all file information displayed\n");
                printf("--driver   -m Use driver interface\n");
                printf("--delay    -u usec delay for /proc update\n");
                printf("--help     -h This message\n\n");
                exit(0);

            case 'u':
                usec_delay = atoi(optarg);
                syslog(LOG_INFO, "usec_delay set to %d", usec_delay);
                break;

            case 'm':
                __driver_mode = 1;
                break;

            default:
                break;
           }
    }

    if (getuid() != 0)
    {
        printf("Only root can start/stop the fork connector\n");
        exit(ERROR);
    }

    openlog("aerolock_profiler", LOG_NOWAIT | LOG_PID, LOG_USER);

    /*
     *  Setup signal handlers
     */
    __set_proc_name(argv[0]);
    __setup_signal_handlers();
    __write_pid("aerolink_profiler");

    // Start up the database
    if(!__bdb_open())
    {
        exit(0);
    }

    __rb_init_cache();

    deauthorizeProcTable();

    fprintf(stdout, "Profiling current runtime environment, please wait\n");
    __get_all_running();

    setvbuf(stdout, NULL, _IONBF, 0);

    if(__driver_mode)
    {
        int t;

        syslog(LOG_NOTICE, "Initiating driver interface");
        fd = open("/dev/aerolock", O_RDWR);
        if(fd <= 0)
        {
            syslog(LOG_ERR, "Failed to open /dev/aerolock. Error code: %d\n", fd);
            __driver_mode = 0;
            goto try_netlink_connector;
        }

        close(fd);

        // fire off pthreads here
        pthread_attr_init(&__attr);
        pthread_attr_setdetachstate(&__attr, PTHREAD_CREATE_DETACHED);

        for(t = 0; t < __max_threads; t++)
        {
            if(pthread_create(&__rmi_thread[t], &__attr, __driver_read, NULL))
            {
                syslog(LOG_ERR, "Failed to create thread. Error code: %d\n", t);
            }
        }

        pthread_attr_destroy(&__attr);

        sem_init(&__sleep_sem, 0, 0);
        sem_wait(&__sleep_sem);
    }
    else
    {
try_netlink_connector:
		pthread_create(&__rmi_thread[0], NULL, __use_netlink, NULL);
		pthread_join(__rmi_thread[0], NULL);
    }

    __bdb_close();
    __make_driver_file();



    syslog(LOG_NOTICE, "Exiting profiler");
    return 0;
}

#ifdef __LINUX__
#pragma GCC diagnostic pop
#endif

