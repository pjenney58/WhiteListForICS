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
 *  aerolock.h
 *
 *  Created on: Oct 2, 2013
 *      Author: Pete Jenney
 */

#ifndef AEROLOCK_H_
#define AEROLOCK_H_

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <ctype.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef __LINUX__
#include <linux/connector.h>
#include <linux/netlink.h>
#include <linux/cn_proc.h>
#include <linux/elf.h>
#include <sys/prctl.h>  /* Linux Process Control */
#include <getopt.h>
#else
#include <libelf.h>
#include <libelf_int.h>
#endif

#include <syslog.h>
#include <dirent.h>
#include <signal.h>
#include <sys/mman.h>
#include <pthread.h>
#include <errno.h>
#include <time.h>
#include <sys/resource.h>
#include <semaphore.h>

#include "rbtree.h"

extern int     __debug;
extern int32_t __daemonize ;

#define PAGE_SIZE     4096
#define MAX_BUF_LEN   1048576L
#define MAX_THREADS   16
#define DEFAULT_DELAY 0L
#define HMAC256_LEN   32
#define SHA256KEY_LEN 32

pthread_t __rmi_thread[MAX_THREADS];

extern pthread_key_t __file_desc_key;
extern pthread_once_t init_done;

#if 0
void __fd_init(void);
void __fd_destruct(void* var);
int  __fd(int set);
#endif

#ifdef __LINUX__
#define RMI_DIR "/var/lib/rmi"
#define RMI_BKP "/var/lib/rmi/rmi.tar.gz"
#define RMI_DB  "/var/lib/rmi/rmprofile.db3"
#define RMI_KEY "/var/lib/rmi/rmikey.key"
#define RMI_CFG "/var/lib/rmi/rmilist.cfg"
#define RMI_PROFILE "/var/lib/rmi/hmacs.profile"

#else

#define RMI_DIR "/root/rmi"
#define RMI_BKP "/root/rmi.tar.gz"
#define RMI_DB  "/root/rmprofile.db3"
#define RMI_KEY "/root/rmi/rmikey.key"
#define RMI_PROFILE "/var/lib/rmi/hmacs.profile"

#define FTW_CONTINUE 0
#endif

#define RMI_PID "/var/run/"
extern int8_t* __global_proc_name;

sem_t __sleep_sem;

/*
 * Some stuff to support the netlink connection
 */
#define SEND_MESSAGE_LEN (NLMSG_LENGTH(sizeof(struct cn_msg) + \
                       sizeof(enum proc_cn_mcast_op)))
#define RECV_MESSAGE_LEN (NLMSG_LENGTH(sizeof(struct cn_msg) + \
                       sizeof(struct proc_event)))

#define SEND_MESSAGE_SIZE    (NLMSG_SPACE(SEND_MESSAGE_LEN))
#define RECV_MESSAGE_SIZE    (NLMSG_SPACE(RECV_MESSAGE_LEN))

#define max(x,y) ((y)<(x)?(x):(y))
#define min(x,y) ((y)>(x)?(x):(y))

#define NL_BUFLEN (max(max(SEND_MESSAGE_SIZE, RECV_MESSAGE_SIZE), 1024))
#define MIN_RECV_SIZE (min(SEND_MESSAGE_SIZE, RECV_MESSAGE_SIZE))

#define PROC_CONN_MCAST_LISTEN (1)
#define PROC_CONN_MCAST_IGNORE (2)

/*
 * High Resolution Timer (ns)
 */
struct timespec __timer_start();
long __timer_end(struct timespec start_time);

/*
 *  Driver support
 */
extern int __driver_mode;
typedef struct pid_stack
{
    int32_t cmd;
    pid_t   pid;       /* Current */
    pid_t   ppid;      /* Parent */
    pid_t   gtid;      /* Module */
    int32_t create;    /* Creating or dying */
    int32_t exec;
    int32_t signal;
    int32_t debug;
    uint8_t __hmac[32];
} PidStack, *PPidStack;

#define PANIC           0xFE
#define TOGGLE_DEBUG    0x7F
#define PROC_STOP       0x7E
#define PROC_RESUME     0x7D
#define PROFILING_START 0x7C
#define PROFILING_STOP  0x7B
#define LOOKUP_HMAC     0x7A
#define RELOAD_HMCAS    0x79

extern int32_t __use_local_trees;

typedef enum {
    GenericLessThan = -1,
    GenericEqual = 0,
    GenericGreaterThan = 1
} returnValuse;


//extern int32_t __fd(int32_t set);

char* lookup_pathname(char* target);

int32_t __is_executable(int8_t* name);

/* Crypto */
#include <ntru_crypto_hmac.h>

int32_t __get_key(uint8_t* key);
int32_t __create_key(uint8_t* key);

int32_t   __get_signature(const int8_t* filename, uint8_t* _hmac);

int32_t __compare_hmac(const uint8_t* __hmac1, const uint8_t* hmac2);
void    __print_hmac(const uint8_t* __hmac);
void    __hmac_2_str(const uint8_t* __hmac, int8_t* __hmac_string);

extern int noLocateDB;

#define MAX_DEPTH 5

/*
 * Structs for RB Trees trees
 */
struct __item_name
{
    struct rb_node node;
    int8_t*     __file;
    uint8_t     __hmac[32];
    struct stat __st;
};

struct __name_list
{
    struct rb_node node;
    int8_t* __short_name;
    int8_t* __long_name;
};

struct __hmac_list
{
    struct rb_node node;
    uint8_t __hmac[32];
};

/*
 * __item_list - a generic container for list items such as engines or commands.  Data is accessed by specifying
 *               an item type and an item key.  Typically a search function will return return TRUE or FALSE
 */
struct __item_list
{
    struct rb_node __node;
    int32_t        __class_selector;
    int8_t*        __item_name;
};

typedef enum
{
	__empty_list,
	__engine_list,
	__shell_command_list,
	__forbidden_list,
	__exception_list
} __list_itemtype_t;

/*
 * Item management functions
 */
int32_t __lookup_item(__list_itemtype_t __class_selector, int8_t* __item_name);
int32_t __rb_add_to_item_list(struct rb_root* __root, __list_itemtype_t __class_selector, int8_t* __item_name);
int32_t __rb_init_item_list(void);
int32_t __rb_flush_item_list(void);

/*
 * Name resolution functions
 */
int32_t __rb_init_name_list(void);
int32_t __lookup_long_name(int8_t* __name, int8_t* __long_name, int32_t __buf_len);
void    __rb_flush_name_list(void);

/*
 * HMAC resolution functions
 */
int32_t        __rb_init_hmac_list(void);
unsigned char* __lookup_hmac(unsigned char* __hmac, int32_t __fd, pid_t pid);
void __rb_flush_hmacs(void);

/*
 * Cache management functions
 */
int32_t __rb_init_cache(void);
int32_t __lookup_cache(const char* __name, unsigned char* __hmac);
int32_t __add_to_cache(const char* __name, unsigned char* __hmac);
int32_t __delete_from_cache(char* __name);
void    __rb_flush_cache(void);

/*
 * List initializer/destructors
 */
int32_t __rmi_initialize_lists(void);
int32_t __rmi_destroy_lists(void);

/*
 * Utility functions
 */
int32_t buildLibList();
char*   findLibNode(char* name);
int32_t __load_cache(void);

#define ERROR   0
#define NOERROR 1

#define FALSE 0
#define TRUE  1

/*
 * Signal Support
 */
int32_t __write_pid(int8_t* __proc_name);
pid_t   __read__pid(int8_t* __proc_name);
int32_t __delete__pid(int8_t* __procname);
void    __set_proc_name(int8_t* __av0);

void __setup_signal_handlers();

#define WRITE_COMMAND_SHUTDOWN 1
#define WRITE_COMMAND_SIGNAL   2

extern int __maximum_verbosity;
extern int __test_mode;

int32_t __init_hmac_list(void);
int32_t __valid_hmac(int8_t* __pathname, pid_t __stopped_pid, int32_t __fd, pid_t __pid);

int32_t __init_name_list(void);
pid_t   __valid_name(int8_t* __name, pid_t __pid);

/* MISRA C 2012 typedef kludges */
typedef long long32_t;
typedef unsigned long ulong32_t;

/* BDB Implementation -- Trivial databases */
int32_t __bdb_open();
int32_t __bdb_close();
int32_t __bdb_reset_hmacs();
int32_t __bdb_reset_names();

int32_t __bdb_write_hmac(int8_t* __name, uint8_t* __hmac);
int32_t __bdb_find_hmac(int8_t* __name, uint8_t* __hmac);
int32_t __bdb_get_next_hmac(int8_t* __long_name, uint8_t* __hmac);
int32_t __bdb_delete_hmac(int8_t* __name);

int32_t __bdb_write_name_pair(int8_t* __short_name, int8_t* __long_name);
int32_t __bdb_find_long_name(int8_t* __short_name, int8_t* __long_name);
int32_t __bdb_get_next_name(int8_t* __short_name, int8_t* __long_name);
int32_t __bdb_delete_name(int8_t* __name);

// Parsing
int32_t __process_script(int32_t __fd, PidStack __pids, int8_t* __top_script);

// Process Management
int32_t __emergency_kill(int32_t __fd, PidStack __pids);
int32_t __emergency_stop(int __fd, PidStack __pids);
int32_t __emergency_resume(int __fd, PidStack __pids);

int32_t __validate_runtime_environment(int32_t __fd);
#endif
 /* AEROLOCK_H_ */
