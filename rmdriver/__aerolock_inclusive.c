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
 * __aerolock_inclusive.c
 *
 * Description
 * --------------
 * A complete kernel based white listing system that traps fork() and execve() actions and compares
 * them against a known whitelist.  The whitelist is a collection of SHA256 HMACs that are held in an rb_tree.  On each fork() or execve() call,
 * the system generates an HMAC for the task and compares it against the known HMACs.  If there's  match the task completes its startup
 * and if there's no match the task is killed.
 *
 * Author
 * -------
 * Peter H. Jenney
 */

#ifndef __KERNEL__
#  define __KERNEL__
#endif
#ifndef MODULE
#  define MODULE
#endif

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/kfifo.h>
#include <linux/kthread.h>
#include <linux/fcntl.h>
#include <linux/device.h>
#include <linux/pid_namespace.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/cdev.h>
#include <linux/delay.h>
#include <linux/random.h>
#include <linux/fcntl.h>
#include <linux/compiler.h>
#include <linux/posix-clock.h>
#include <linux/time.h>
#include <linux/mm.h>
#include <linux/elf.h>
#include <linux/version.h>
#include "ntru_crypto_hmac.h"

static struct kfifo __read_fifo;
static struct kfifo __kill_fifo;

/*
 * PHJ Implemented in filesys.c
 */
int32_t      file_write(struct file* filp, uint64_t offset, uint8_t* data, uint32_t size);
int32_t      file_read(struct file*  filp, uint64_t offset, uint8_t* data, uint32_t size);
uint32_t     file_llseek(struct file *filp,int64_t offset, int32_t whence);
struct file* file_open(const int8_t* path, int32_t flags, int32_t rights);
void         file_close(struct file* filp);


#if 0
  printk("KEY: %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\n",
      __hmac[0], __hmac[1], __hmac[2], __hmac[3], __hmac[4], __hmac[5], __hmac[6], __hmac[7], __hmac[8], __hmac[9], __hmac[10],__hmac[11],
      __hmac[12],__hmac[13],__hmac[14],__hmac[15],__hmac[16],__hmac[17],__hmac[18],__hmac[19],__hmac[20],__hmac[21],__hmac[22],
      __hmac[23],__hmac[24],__hmac[25],__hmac[26],__hmac[27],__hmac[28],__hmac[29],__hmac[30],__hmac[31]);
#endif



/*
 * MISRA 2012 Issue -- Token Pasting not allowed
 */
int16_t __debug_level = 3;
#define ERROR_LEVEL     (1)
#define WARNING_LEVEL   (2)
#define INFO_LEVEL      (3)
#define DETAIL_LEVEL    (4)
#define rmi_trace(level, fmt, ...) if(level <= __debug_level) printk (fmt, ## __VA_ARGS__)

#define PROFILE "/var/lib/rmi/hmacs.profile"
#define PROC_NAME   "aerolocktaskinfo"
#define RM_VERSION  "0.51"
#define PATH_ALLOC 1024
#define HMAC256_LEN   32
#define SHA256KEY_LEN 32

#define __max(x,y) ((y)<(x)?(x):(y))
#define __min(x,y) ((y)>(x)?(x):(y))

static int __open_count = 0;
struct task_struct* __kill_thread;

/* aerolock driver constructs and variables */
static struct cdev   c_dev;
static struct class* cl;
static dev_t         first;
pid_t                last_pid;

int32_t  __aerolock__enabled = 0;
int32_t  __debug__mode       = 1;
int32_t  __profile_mode      = 0;
uint32_t __hmac_node_count   = 0;

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

#define TOGGLE_DEBUG    0x7F
#define PROC_STOP       0x7E
#define PROC_RESUME     0x7D
#define PROFILING_START 0x7C
#define PROFILING_STOP  0x7B
#define LOOKUP_HMAC     0x7A
#define RELOAD_HMACS    0x79
#define PANIC           0xFE

int32_t  __pid_count = 1;
struct   pid_stack __pids;

//DEFINE_MUTEX(__gen_hmac_mutex);
//DEFINE_MUTEX(__gen_trap_mutex);

DEFINE_SPINLOCK(__kill1_spinlock);
DEFINE_SPINLOCK(__kill2_spinlock);
DEFINE_SPINLOCK(__kill3_spinlock);
DEFINE_SPINLOCK(__kill4_spinlock);
DEFINE_SPINLOCK(__read1_spinlock);
DEFINE_SPINLOCK(__read2_spinlock);
DEFINE_SPINLOCK(__read3_spinlock);

DECLARE_WAIT_QUEUE_HEAD(__read_sleeper);
DECLARE_WAIT_QUEUE_HEAD(__kill_sleeper);
DECLARE_WAIT_QUEUE_HEAD(__random_queue_available);
DECLARE_WAIT_QUEUE_HEAD(__write_queue_available);
DECLARE_WAIT_QUEUE_HEAD(__kill_queue_available);

int32_t    __have_validated_runtime = 0;
#define    __WAIT_TIME__ 100

uint8_t        __sha2key[SHA256KEY_LEN] = "";
struct rb_root __rb_hmacs               = RB_ROOT;
struct rb_root __rb_cache               = RB_ROOT;

/***************************************************************************************************/
/***************** Linux RB Tree Routines - NOTE: Not Portable *************************************/
/***************************************************************************************************/

/************************************ HMAC Cache Functions ****************************************/

struct __hmac_cache_struct
{
    struct rb_node node;
    uint8_t        __hmac[32];
    int8_t*        __path;
};

struct __hmac_cache_struct* __is_in_cache(struct rb_root* __root, int8_t* __path, uint8_t* __hmac)
{
    struct rb_node*               __node   = NULL;
    struct  __hmac_cache_struct*  __retval = NULL;
    struct  __hmac_cache_struct*  __data   = NULL;
    int32_t __result                       = 0;

    if(unlikely(!__root || !__path || !__hmac))
    {
        goto out;
    }

    __node = __root->rb_node;

    while(__node)
    {
        __data = container_of(__node, struct __hmac_cache_struct, node);


        if(!__data || !__data->__path)
        {
            goto out;
        }

        __result = strcmp(__path, __data->__path);
        if(__result < 0)
        {
            __node = __node->rb_left;
        }
        else if(__result > 0)
        {
            __node = __node->rb_right;
        }
        else
        {
            __retval = __data;
            memcpy(__hmac, __data->__hmac, HMAC256_LEN);
            goto out;
        }
    }

out:

    return(__retval);
}

int32_t __add_to_cache(struct rb_root* __root, int8_t* __path, uint8_t* __hmac)
{
    int32_t                      __retcode  = 0;
    int32_t                      __result   = 0;
    struct  rb_node**            __new      = NULL;
    struct  rb_node*             __parent   = NULL;
    struct  __hmac_cache_struct* __new_node = NULL;
    struct  __hmac_cache_struct* __this     = NULL;

    if(unlikely(!__root || !__path || !__hmac))
    {
        goto out;
    }

    __new = &(__root->rb_node);

    /* Figure out where to insert the node */
    while(*__new)
    {
       __this = container_of(*__new, struct __hmac_cache_struct, node);

       if(!__this)
       {
           goto out;
       }

       __result = strcmp(__path, __this->__path);

        __parent = *__new;

        if(__result < 0)
        {
            __new = &((*__new)->rb_left);
        }
        else if (__result > 0)
        {
            __new = &((*__new)->rb_right);
        }
        else
        {   /* Item exists, bail out */
            goto out;
        }
    }

    rmi_trace(INFO_LEVEL, "AEROLOCK: Adding %s to cache\n", __path);
    __new_node = (struct __hmac_cache_struct*)kmalloc( sizeof(struct __hmac_cache_struct), GFP_KERNEL);
    if(!__new_node)
    {
        goto out;
    }

    __new_node->__path = (int8_t*)kmalloc(strlen(__path)+1, GFP_KERNEL);
    if(!__new_node->__path)
    {
        kfree(__new_node);
        goto out;
    }

    strcpy(__new_node->__path, __path);
    memcpy(__new_node->__hmac, __hmac, HMAC256_LEN);

    /* Add new node and rebalance tree */
    rb_link_node(&__new_node->node, __parent, __new);
    rb_insert_color(&__new_node->node, __root);

    __retcode = 1;

out:

    return __retcode;
}


/*
 * int __delete_cache_node() - unlinks and erases a node from the rbTree
 * @ __path: the record key to delete
 */
static int32_t __delete_cache_node(uint8_t* __path)
{
    int32_t                      __retcode           = 0;
    uint8_t                      __hmac[HMAC256_LEN] = "";
    struct  __hmac_cache_struct* __found             = NULL;

    if(unlikely(!__path))
    {
        goto out;
    }

    __found = __is_in_cache( &__rb_cache, __path, __hmac);

    if(likely(__found))
    {
        /* Unlink from tree */
        rb_erase(&__found->node, &__rb_cache);

        /* MISRA C 2012 - Explicitly release path memory */
        if(__found->__path)
        {
            kfree(__found->__path);
            __found->__path = NULL;
        }

        kfree(__found);
        __found = NULL;

        __retcode = 1;
    }

out:

    return(__retcode);
}

/*
 * int __delete_from_cache()
 * @ __path:  the record key to delete
 */
int32_t  __delete_from_cache(int8_t* __path)
{
    return(__delete_cache_node(__path));
}

/*
 * void __flush_cache()  -- Clears the rbTree and releases all memory
 *
 */
void __rb_flush_cache(void)
{
    struct rb_node*             __next = NULL;
    struct __hmac_cache_struct* __ret;
    uint8_t                     __hmac[HMAC256_LEN] = "";

    __next = rb_first(&__rb_cache);

    while(__next)
    {
        __ret = __is_in_cache(&__rb_cache, rb_entry(__next, struct __hmac_cache_struct, node)->__path, __hmac);
        if(__ret)
        {
            __next = rb_next(__next);

            rb_erase(&__ret->node, &__rb_cache);

            if(__ret)
            {
                if(__ret->__path)
                {
                    kfree(__ret->__path);
                    __ret->__path = NULL;
                }

                kfree(__ret);
                __ret = NULL;
            }
        }
    }

    return;
}


/***********************  HMAC Functions *********************************/
/*
 */
struct __hmac_struct
{
    struct rb_node  node;
    uint8_t         __hmac[HMAC256_LEN];
};

struct __hmac_struct* __find_hmac(struct rb_root* __root, uint8_t* __hmac)
{
    struct  rb_node*       __node   = NULL;
    struct  __hmac_struct* __retval = NULL;
    struct  __hmac_struct* __data   = NULL;
    int32_t                __result = 0;

    if(unlikely(!__root || !__hmac))
    {
        goto out;
    }

    __node = __root->rb_node;

    while(__node)
    {
        __data = container_of(__node, struct __hmac_struct, node);

        if(!__data)
        {
            __retval = 0;
            goto out;
        }

        __result = memcmp(__hmac, __data->__hmac, 32);
        if(__result < 0)
        {
            __node = __node->rb_left;
        }
        else if(__result > 0)
        {
            __node = __node->rb_right;
        }
        else
        {
            __retval = __data;
            goto out;
        }
    }

out:

    return(__retval);
}

int32_t __insert_hmac(struct rb_root* __root, struct __hmac_struct* __hmac)
{
    int32_t               __retcode = 1;
    int32_t               __result  = 0;
    struct rb_node**      __new     = NULL;
    struct rb_node*       __parent  = NULL;
    struct __hmac_struct* __this    = NULL;

    if(unlikely(!__root || !__hmac))
    {
        __retcode = FALSE;
        goto out;
    }

    __new = &(__root->rb_node);

    /*
     * Figure out where to insert the node
     */
    while(*__new)
    {
        __this = container_of(*__new, struct __hmac_struct, node);

        if(!__this)
        {
            __retcode = 0;
            goto out;
        }

        __result = memcmp(__hmac->__hmac, __this->__hmac, 32);

        __parent = *__new;

        if(__result < 0)
        {
            __new = &((*__new)->rb_left);
        }
        else if (__result > 0)
        {
            __new = &((*__new)->rb_right);
        }
        else
        {   /* Item exists, bail out */
            __retcode = 0;
            goto out;
        }
    }

    /*
     *  Add new node and rebalance tree
     */
    rb_link_node(&__hmac->node, __parent, __new);
    rb_insert_color(&__hmac->node, __root);

out:

    return __retcode;
}


/*
 * int32_t __delete_node() - unlinks and erases a node from the rbTree
 * @ __hmac: the HMAC to delete
 */
static int32_t __delete_node(uint8_t* __hmac)
{
    int32_t                __retcode = 0;
    struct  __hmac_struct* __found   = NULL;

    if(unlikely(!__hmac))
    {
        goto out;
    }

    __found = __find_hmac( &__rb_hmacs, __hmac);

    if(__found)
    {
        /* Unlink from tree */
        rb_erase(&__found->node, &__rb_hmacs);

        /* MISRA C 2012 - Explicitly release allocated memory */
        kfree(__found);
        __found = NULL;

        __retcode = 1;
    }

out:

    return(__retcode);
}

/*
 * int32_t __delete_from_tree()
 * @ __hmac:  HMAC to remove from tree
 */
int32_t  __delete_from_tree(uint8_t* __hmac)
{
    return(__delete_node(__hmac));
}


void __rb_flush_hmacs(void)
{
    struct rb_node*       __next = NULL;
    struct __hmac_struct* __ret  = NULL;

    __next = rb_first(&__rb_hmacs);

    while(__next)
    {
        __ret = __find_hmac(&__rb_hmacs, rb_entry(__next, struct __hmac_struct, node)->__hmac);
        if(__ret)
        {
            __next = rb_next(__next);

            rb_erase(&__ret->node, &__rb_hmacs);

            if(__ret)
            {
                kfree(__ret);
                __ret = NULL;
            }
        }
    }

    return;
}

int32_t __validate_hmacs(void)
{
    uint8_t      __hmac[HMAC256_LEN]  = "";
    int64_t      __offset             = 0LL;
    int32_t      __retcode            = 1;
    struct file* __fp                 = NULL;

    __fp = file_open(PROFILE, O_RDONLY, 644);
    if(!__fp)
    {
        rmi_trace(ERROR_LEVEL, "AEROLOCK: Error, failed to open file (%s)\n", PROFILE);
        __retcode = 0;
        goto out;
    }

    __retcode = file_read(__fp, __offset, __hmac, HMAC256_LEN);
    if(!__retcode)
    {
        rmi_trace(ERROR_LEVEL, "AEROLOCK: Error, failed to read file (%ld)\n", (long)__offset);
        __retcode = 0;
        goto out;
    }

    if(memcmp(__hmac, __sha2key, SHA256KEY_LEN))
    {
        __retcode = 0;
        goto out;
    }

    __offset += HMAC256_LEN;

    __retcode = file_read(__fp, __offset, __hmac, HMAC256_LEN);
    if(unlikely(!__retcode))
    {
        rmi_trace(ERROR_LEVEL, "AEROLOCK: Error, failed to read file (%ld)\n", (long)__offset);
        __retcode = 0;
        goto out;
    }

    while(__retcode)
    {
        if(!__find_hmac(&__rb_hmacs, __hmac))
        {
            __retcode = 0;
            goto out;
        }

        __retcode = file_read(__fp, __offset, __hmac, HMAC256_LEN);
        __offset += HMAC256_LEN;
    }

    __retcode = 1;

out:

    if(__fp)
    {
        file_close(__fp);
    }

    return(__retcode);
}

int __init_hmac_list(void)
{
    uint8_t               __hmac[HMAC256_LEN] = "";
    int64_t               __offset            = 0LL    ;
    int32_t               __retcode           = 0;
    int32_t               __count             = 0;
    int32_t               __duplicate         = 0;
    struct __hmac_struct* __hn                = NULL;
    struct file*          __fp                = NULL;

    __fp = file_open(PROFILE, O_RDONLY, 644);
    if(!__fp)
    {
        rmi_trace(ERROR_LEVEL, "AEROLOCK: Error, failed to open file %s\n", PROFILE);
        __retcode = 1;
        goto out;
    }

    /*
     * File format
     * -----------
     * 32 Bytes [sha256 key] (item 0)
     * 32 Bytes [HMAC]       (item 1,,n)
     */

    /*
     * PHJ TODO Check for TSS/TPM or ARM TrustZone and get the key from there if it exists
     */

    // Read the sha2key
    __retcode = file_read(__fp, __offset, __sha2key, SHA256KEY_LEN);
    
    if(unlikely(!__retcode))
    {
        rmi_trace(ERROR_LEVEL, "AEROLOCK: Error, failed to read file\n");
        file_close(__fp);
        __retcode = 1;
        goto out;
    }

    __offset += SHA256KEY_LEN;

    __retcode = file_read(__fp, __offset, __hmac, HMAC256_LEN);

    while(__retcode)
    {
        if(__retcode == HMAC256_LEN)
        {
           /*
            * MISRA 2012 Deviation -- Have to allocate nodes from the heap to build the tree
            */
            __hn = (struct __hmac_struct*)kmalloc(sizeof(struct __hmac_struct), GFP_KERNEL);
            if(!__hn)
            {
                file_close(__fp);
                __retcode = 1;
                goto out;
            }

           memcpy(__hn->__hmac, __hmac, HMAC256_LEN);

           if(__insert_hmac(&__rb_hmacs, __hn) == FALSE)  // Node exists if return == FALSE
           {
               kfree(__hn);
               __duplicate++;
           }
           else
           {
              __hmac_node_count++;
           }

            __count++;
            __offset += HMAC256_LEN;
            __retcode = file_read(__fp, __offset, __hmac, HMAC256_LEN);
        }
        else
        {
            rmi_trace(ERROR_LEVEL, "AEROLOCK: Read corruption! __retcode == %d\n", __retcode);
            goto out;
        }
    }

    rmi_trace(INFO_LEVEL,  "AEROLOCK: initialization complete, read %d HMACS with %d duplicates: sizeof(__hmac_struct) == %d\n", __count, __duplicate, sizeof(struct __hmac_struct));
    rmi_trace(INFO_LEVEL,  "AEROLOCK: validating database integrity\n");

    if(!__validate_hmacs())
    {
        rmi_trace(INFO_LEVEL, "AEROLOCK: failed validation\n");
        __retcode = 1;
        goto out;
    }
    else
    {
        rmi_trace(INFO_LEVEL, "AEROLOCK: database integrity confirmed\n");
    }

out:

    if(__fp)
    {
        file_close(__fp);
        __fp = NULL;
    }

    return __retcode;
}

/*********************************************************************************/

int32_t __get_cmdline(struct task_struct* __task, int8_t* __buf)
{
    int32_t           __retval = 0;
    struct mm_struct* __mm = current->mm;

    if(unlikely(!__task || !__buf))
    {
        goto out;
    }

    if(likely(__mm))
    {
        down_read(&__mm->mmap_sem);
        if(copy_from_user(__buf, (int8_t __user*)__mm->arg_start, __mm->arg_end - __mm->arg_start))
        {
            memcpy(__buf, "NoArg", 5);
        }
        up_read(&__mm->mmap_sem);

        __retval = 1;
    }
    else
    {
        rmi_trace(INFO_LEVEL, "AEROLOCK: Failed to get commandline\n");
    }

out:
    return(__retval);
}

int32_t __do_ntru_hmac(unsigned char* __buf, long __len, unsigned char* __hmac)
{
    int32_t __retcode = 1;
    NTRU_CRYPTO_HMAC_CTX*  __crypto_context = NULL;

    if(unlikely(!__buf || !__hmac))
    {
        __retcode = 0;
        goto out;
    }

    __retcode = ntru_crypto_hmac_create_ctx(NTRU_CRYPTO_HASH_ALGID_SHA256, __sha2key, 32, &__crypto_context);
    if(__retcode != NTRU_CRYPTO_HMAC_OK)
    {
        rmi_trace(WARNING_LEVEL, "AEROLOCK: Error, failed to initialize crypto_context - error (%d)\n", __retcode);
        goto out;
    }

    __retcode = ntru_crypto_hmac_init(__crypto_context);
    if(unlikely(__retcode != NTRU_CRYPTO_HMAC_OK))
    {
        ntru_crypto_hmac_destroy_ctx(__crypto_context);
        rmi_trace(WARNING_LEVEL, "AEROLOCK: Error, failed to init HMAC\n");
        goto out_kill_context;
    }

    __retcode = ntru_crypto_hmac_update(__crypto_context, __buf, __len);
    if(unlikely(__retcode != NTRU_CRYPTO_HMAC_OK))
    {
        ntru_crypto_hmac_final(__crypto_context, __hmac);
        ntru_crypto_hmac_destroy_ctx(__crypto_context);
        rmi_trace(WARNING_LEVEL, "AEROLOCK: Error, failed to update HMAC\n");
        goto out_kill_context;
    }

    __retcode = ntru_crypto_hmac_final(__crypto_context, __hmac);
    if(unlikely(__retcode != NTRU_CRYPTO_HMAC_OK))
    {
        ntru_crypto_hmac_destroy_ctx(__crypto_context);
        rmi_trace(WARNING_LEVEL, "AEROLOCK: Error, failed to finalize HMAC\n");
        goto out_kill_context;
    }

    __retcode = 1;

out_kill_context:

    ntru_crypto_hmac_destroy_ctx(__crypto_context);
    __crypto_context = NULL;

out:

    return(__retcode);
}

void* __get_buffer(unsigned long __buflen)
{
    if(likely(__buflen <= KMALLOC_MAX_SIZE))
    {
        return(kmalloc(__buflen, GFP_KERNEL));
    }
    else
    {
        return((void*)__get_free_pages(GFP_KERNEL, get_order(__buflen)));
    }

    return NULL;
}

void __release_buffer(void* __buffer, unsigned long __buflen)
{
    if(!__buffer || __buflen == 0)
    {
        goto out;
    }

    if(likely(__buflen <= KMALLOC_MAX_SIZE))
    {
        kfree(__buffer);
    }
    else
    {
        free_pages((unsigned long)__buffer, get_order(__buflen));
    }

    __buffer = NULL;

out:
    return;
}

/*
 * void __handoff_to_daemon(void) -- the level 2 exception handler.  If memory allocations or 
 * copy_from_user or file read errors occur, this passes the HMAC generation and analysis out 
 * to the user-land daemon to handle. Latency can be an issue in real-time code though the 
 * successful completion of the operation _should_ take priority in this case.
 */
void __handoff_to_daemon(void)
{
    PidStack    __ppid;

    // Send the task out to the daemon for processing
    __ppid.cmd    = PANIC;
    __ppid.pid    = current->pid;
    __ppid.ppid   = current->real_parent->pid;

    if(unlikely(kfifo_is_full(&__read_fifo)))
    {
        while(kfifo_is_full(&__read_fifo))
        {
            rmi_trace(INFO_LEVEL, "AEROLOCK: waiting on full read fifo ...\n");
            interruptible_sleep_on_timeout(&__write_queue_available, __WAIT_TIME__);
        }
            rmi_trace(INFO_LEVEL, "AEROLOCK:  read fifo ready ...\n");
    }

    kfifo_in_spinlocked(&__read_fifo, &__ppid, sizeof(PidStack), &__read1_spinlock);
    wake_up_interruptible(&__read_sleeper);

    rmi_trace(INFO_LEVEL, "AEROLOCK: handing [%ld] off to daemon ...\n", (long)current->pid);

    return;
}

/*
 * __get_hmac_from_file() - the level one exception mechanism for getting an HMAC from the current task.  The
 *                          algorithm mirrors that in GetSignature() and will work with both 32 and 64 bit
 *                          executables.
 * @__path   - The path of the file to process
 * @__cs_buf - The caller supplied buffer for the code segment read
 * @__cs_len - The length of the code segment
 * @__hmac   - The caller supplied buffer for the generated HMAC
 */
int32_t __get_hmac_from_file(int8_t* __path, uint8_t* __cs_buf, unsigned long __cs_len, uint8_t* __hmac)
{
    int32_t      __retval = 0;
    Elf64_Ehdr   __file_hdr64;
    Elf64_Phdr*  __prog_hdr64 = NULL;
    Elf32_Ehdr   __file_hdr32;
    Elf32_Phdr*  __prog_hdr32 = NULL;
    int32_t      __do_64 = 0;
    int32_t      i;
    struct file* __fp;

    /*
     * Make sure we've got valid variables
     */
    if(unlikely(!__path || !__cs_buf || !__cs_len || !__hmac))
    {
        goto out;
    }

    /*
     * Shut the compiler up -- initialize key values
     */
    __file_hdr64.e_phnum = 0;
    __file_hdr64.e_phoff = 0;
    __file_hdr32.e_phnum = 0;
    __file_hdr32.e_phoff = 0;

    /*
     * Quickly open, read and close to do the the code segment extraction
     */
    __fp = file_open(__path,  O_RDONLY, 0);
    if(!__fp)
    {
        rmi_trace(ERROR_LEVEL, "AEROLOCK: file_open() error");
        goto out;
    }

    if(file_read(__fp, 0, __cs_buf, __cs_len) != __cs_len)
    {
        rmi_trace(ERROR_LEVEL, "AEROLOCK: file_read() error, return != __cs_len");
        file_close(__fp);
        goto out;
    }

    file_close(__fp);

    /*
     * Setup for the proper bit length for the binary.
     */
    memcpy(&__file_hdr32, __cs_buf, sizeof(__file_hdr32));

    /*
     * Check for ELF file
     */
    if(unlikely(__file_hdr32.e_ident[EI_MAG0] != 0x7f))
    {
        __retval = __do_ntru_hmac(__cs_buf, __cs_len, __hmac);
        goto out;
    }

    if(__file_hdr32.e_ident[EI_CLASS] != 1)
    {
        if(__file_hdr32.e_ident[EI_CLASS] == 2)
        {
            __do_64 = 1;
        }
    }

    if(!__do_64)
    {
        /*
         * Check for offset insanity
         */
        if(__file_hdr32.e_phoff > __cs_len)
        {
            rmi_trace(ERROR_LEVEL, "AEROLOCK: Error, insane 32 bit e_phoff > __cs_len");
            goto out;
        }

        /*
         *  Point to the first program header
         */
        __prog_hdr32 = (Elf32_Phdr*)( __cs_buf + __file_hdr32.e_phoff);
        if(!__prog_hdr32)
        {
            rmi_trace(ERROR_LEVEL, "AEROLOCK: NULL 32 bit program header--assign");
            goto out;
        }

        /*
         * Iterate through the program headers looking for PT_LOAD + S + X
         */
        for(i = 0; i < __file_hdr32.e_phnum; i++)
        {
            /*
             * Check for offset sanity
             */
            if(__prog_hdr32->p_offset > __cs_len)
            {
                rmi_trace(ERROR_LEVEL, "AEROLOCK: Error, insane __prog_hdr32->p_offset > __cs_len");
                goto out;
            }

            if(__prog_hdr32->p_type == PT_LOAD)
            {
                if(__prog_hdr32->p_flags == (PF_R + PF_X))
                {
                    __retval = __do_ntru_hmac(__cs_buf + __prog_hdr32->p_offset, __prog_hdr32->p_filesz, __hmac);
                    if(!__retval)
                    {
                        rmi_trace(ERROR_LEVEL, "AEROLOCK: Internal cryptography error (%d)", __retval);
                        __retval = 0;
                        goto out;
                    }

                    __retval = 1;
                    goto out;
                }
            }

            __prog_hdr32++;

            if(!__prog_hdr32)
            {
                rmi_trace(ERROR_LEVEL, "AEROLOCK: NULL 32 bit program header--iteration");
                goto out;
            }
        }
    }
    else
    {
        /*
         * Check for offset insanity
         */
        if(__file_hdr64.e_phoff > __cs_len)
        {
            rmi_trace(ERROR_LEVEL, "AEROLOCK: Error, insane 64 bit e_phoff > __cs_len");
            goto out;
        }

        /*
         *  Point to the first program header
         */
        __prog_hdr64 = (Elf64_Phdr*)( __cs_buf + __file_hdr64.e_phoff);
        if(!__prog_hdr64)
        {
            rmi_trace(ERROR_LEVEL, "AEROLOCK: NULL 64 bit program header--assign");
            goto out;
        }

        /*
         * Iterate through the program headers looking for PT_LOAD + S + X
         */
        for(i = 0; i < __file_hdr64.e_phnum; i++)
        {
            /*
             * Check for offset sanity
             */
            if(__prog_hdr64->p_offset > __cs_len)
            {
                rmi_trace(ERROR_LEVEL, "AEROLOCK: Error, insane __prog_hdr64->p_offset > __cs_len");
                goto out;
            }

            if(__prog_hdr64->p_type == PT_LOAD)
            {
                if(__prog_hdr64->p_flags == (PF_R + PF_X))
                {
                    __retval = __do_ntru_hmac(__cs_buf + __prog_hdr64->p_offset, __prog_hdr64->p_filesz, __hmac);
                    if(__retval != NTRU_CRYPTO_HMAC_OK)
                    {
                        rmi_trace(ERROR_LEVEL, "AEROLOCK: Error, internal cryptography failure (%d)", __retval);
                        __retval = 0;
                        goto out;
                    }

                    __retval = 1;
                    goto out;
                }
            }

            __prog_hdr64++;

            if(!__prog_hdr64)
            {
                rmi_trace(ERROR_LEVEL, "AEROLOCK: NULL 64 bit program header--iteration");
                goto out;
            }
        }
    }

out:

    return __retval;
}


unsigned long __get_exe_size(struct file* filp)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)

    unsigned long __size = 0UL;
    off_t __curr = filp->f_pos;

    file_llseek(filp, 0, SEEK_END);
    __size = (unsigned long)filp->f_pos;
    file_llseek(filp, __curr, SEEK_SET);

    return __size;

#else

    return filp->f_inode->i_size;

#endif
}

// PHJ TODO d_path is different prior to 2.6.25, so __get_exec needs to be updated to reflect that

/*
 * __get_exe() - get the actual file path from the memory descriptor VMA.  This function will not work in
 *             kernels before 2.6.12 do to the shape of the d_path() call.
 *
 * @__mm  - The memory descriptor to get the VM from
 * @__buf - a caller supplied buffer to put the path in
 * @__len - the length of the caller supplied buffer
 */
int8_t* __get_exe(struct mm_struct* __mm, int8_t* __buf, int32_t __len, unsigned long *__size)
{
    int8_t* p = NULL;
    struct vm_area_struct* __vma;

    if(unlikely(!__mm || !__buf || __len == 0))
    {
        goto out;
    }

    __vma = __mm->mmap;

    while(__vma)
    {
        if(__vma->vm_file && (__vma->vm_flags & VM_EXEC))
        {
            break;
        }

        __vma = __vma->vm_next;
    }

    if(__vma && __vma->vm_file)
    {
        p = d_path(&__vma->vm_file->f_path, __buf, __len);
        *__size = __get_exe_size(__vma->vm_file);

        if(IS_ERR(p))
        {
            p = NULL;
        }
    }

out:
    return p;
}

/*******************************************************************************************************************
 *  __generate_hmac() - Try and generate an HMAC for the current task.  There are three (3) levels in the algorithm:
 *
 *                              (1) try and extract the code segment directly from the tasks memory descriptor
 *                              (2) try and open the file itself and extract the code segment
 *                              (3) try and send the task to the userland daemon for processing
 *
 *                      The only controversial part of the code is that you're not supposed to open files from the
 *                      kernel, though the kernel does it itself using kernel_read() when loading binaries into
 *                      memory for execution, which is very similar to what we do, so it "should" be safe.
 *
 *  @__task:  real time task* to generate HMAC for (==current)
 *  @__hmac:  variable to fill with generated HMAC
 *
 ********************************************************************************************************************/


int32_t __generate_hmac(struct task_struct* __task, unsigned char* __hmac)
{
    int32_t           __retcode = 1;
    uint8_t*          __buf     = NULL;
    unsigned long     __buflen  = 0UL;
    unsigned long     __readlen = 1UL;
    unsigned long     __offset  = 0UL;
#if 0
    int8_t            __path_buf[PATH_ALLOC] = "";
#endif

    int32_t           __path_len = PATH_ALLOC;

#if 1
    int8_t*           __path_buf = NULL;
#endif
    struct mm_struct* __mm  = current->mm;
    unsigned long     __f_size = 0;
    char*             __path     = NULL;

    if(likely(__mm))
    {
        __buflen  = __mm->end_code -__mm->start_code;
        __offset  = __mm->start_code;

#if 1
        __path_buf = (int8_t*)__get_buffer(PATH_ALLOC);
        if(!__path_buf)
        {
            rmi_trace(ERROR_LEVEL, "Failed to allocate %d bytes for path\n", PATH_ALLOC);
            __handoff_to_daemon();
            __retcode = 0;
            goto out;
        }
#endif

        __path = __get_exe(__mm, __path_buf, __path_len, &__f_size);
        if(!__path)
        {
            rmi_trace(ERROR_LEVEL, "AEROLOCK:  Error, failed to get dentry path");
            __handoff_to_daemon();
            __retcode = 0;
            goto out;
        }

        /*
         *  Check for insane __buflen values -- _f_size is the total file size.
         *  Insanity means that the CS is > file size
         */
        if(__buflen > __f_size)
        {
            rmi_trace(ERROR_LEVEL, "AEROLOCK: Error, file %s has an insane CS size [%ld/%ld], processing level 2 exception\n", __path, __buflen, __f_size);
            __handoff_to_daemon();
            __retcode = 0;
            goto out;
        }

        /*
         * The kernel marks defunct files with (deleted), we can ignore them.
         */
        if(strstr(__path, "(deleted)"))
        {
            __retcode = 0;
            goto out;
        }
        
        /*
         * For some reason the path describes a library rather than an executable. When
         * we ship these off to the daemon it resolves itself.  
         */
        if(strstr(__path, ".so"))
        {
            __handoff_to_daemon();
            __retcode = 0;
            goto out;
        }

        if(__is_in_cache(&__rb_cache, __path, __hmac))
        {
            rmi_trace(INFO_LEVEL, "AEROLOCK: Cache hit for %s\n", __path);
            __retcode = 1;
            goto out;
        }

        if(likely(__buflen > 0))
        {
           /*
            * MISRA C 2012 Deviation -- Code Segments will be variable size and its unknowable
            * how large a buffer is needed to handle every executable on the system. It is also
            * a security issue as an attacker could create a file larger than the preallocated
            * buffer and cause a buffer overflow.
            */
            __buf = (uint8_t*)__get_buffer( __buflen);
            if(likely(__buf))
            {
                /*
                 * Copy the contents of the user space __mm code segment as fast as possible as it seems to be ephemeral
                 */

                 //down_read(&__mm->mmap_sem);
                 __readlen = copy_from_user(__buf, (unsigned char*)__offset, __buflen);
                 //up_read(&__mm->mmap_sem);


                if(__readlen > 0)
                {
                    /* Execute exception code Level 1 - File Read*/
                    rmi_trace(INFO_LEVEL, "AEROLOCK: [%s] copy_from_user missed %ld of %ld bytes\n", current->comm, __readlen, __buflen);
                    if(__path)
                    {
                        rmi_trace(WARNING_LEVEL, "AEROLOCK: Alert, processing level 1 exception for %s [%ld]\n", __path, (long)current->pid);

                        if(!__get_hmac_from_file(__path, __buf, __buflen, __hmac ))
                        {
                            /* Execute exception code Level 2 - Pass to User Space */
                            rmi_trace(ERROR_LEVEL, "AEROLOCK: Error, failed to generate HMAC from file %s, processing level 2 exception\n", __path);
                            __handoff_to_daemon();
                            __retcode = 0;
                        }
                        else
                        {
                            rmi_trace(INFO_LEVEL, "AEROLOCK: [%s]  P<%ld> C<%ld> CS Length: %ld\n",
                                               __path, (long)current->parent->pid, (long)current->pid, __buflen);
                            __retcode = 1;
                        }
                    }
                    else
                    {
                        /* Execute exception code Level 2 - Pass to User Space */
                        rmi_trace(WARNING_LEVEL, "AEROLOCK: Warning, __gen_hmac_from_file failed for %s, processing level 2 exception\n", __path);
                        __handoff_to_daemon();
                        __retcode = 0;
                    }

                    goto out;
                }

                /*
                 * Generate the HMAC and continue
                 */
                if(unlikely(!__do_ntru_hmac(__buf,  __buflen, __hmac)))
                {
                    rmi_trace(INFO_LEVEL, "AEROLOCK: __do_ntru_hmac() failed()\n");
                    __retcode = 0;
                    goto out;
                }

                rmi_trace(INFO_LEVEL, "AEROLOCK: [%s]  P<%ld> C<%ld> CS Length: %ld\n",
                                  current->comm, (long)current->parent->pid, (long)current->pid,  __buflen);

            }
            else
            {
                rmi_trace(INFO_LEVEL, "AEROLOCK: [%s] Buffer allocation failure [%ld], processing level 2 exception\n", current->comm, __buflen);
                __retcode = 0;
                __handoff_to_daemon(); /* Execute exception code */
            }
        }
        else
        {
            rmi_trace(INFO_LEVEL, "AEROLOCK: [%s] Zero length code segment\n", current->comm);
            __retcode = 0;
            __handoff_to_daemon(); /* Execute exception code */
        }
    }
    else
    {
        rmi_trace(INFO_LEVEL, "AEROLOCK: Failed to acquire _mm\n");
        __retcode = 0;
    }

out:
#if 1
    if(__path)
    {
        __release_buffer(__path_buf, PATH_ALLOC);
    }
#endif

    if(__buf)
    {
        __release_buffer(__buf, __buflen);
    }

    return(__retcode);
}

/*
 * void ___validate_hmac()
 * @__task: the task to validate. The __task is equal to `current`
 */
int __validate_hmac(struct task_struct* __task)
{
    int32_t           __retval = 1;
    uint8_t           __hmac[32] = "";
    PidStack          __ppid;
    int8_t            __path_buf[PATH_ALLOC] = "";
    int32_t           __path_len = PATH_ALLOC;
#if 0
    int8_t*           __path_buf;
#endif
    int8_t*           __path;
    struct mm_struct* __mm  = current->mm;
    unsigned long     __f_size = 0;


    if(!__task)
    {
        goto out;
    }

    if(likely(__task->pid > 1 && __task->pid <= PID_MAX_LIMIT)) // Don't bother with kernel init process
    {
        if(likely(__generate_hmac(__task, __hmac)))
        {
            if(__find_hmac(&__rb_hmacs, __hmac) || __profile_mode == 1)  // NULL return means not found
            {
                /*
                 * Add the "good" paths to the cache.
                 */
                if(likely(__mm))
                {
#if 0
                    __path_buf = (int8_t*)__get_buffer(PATH_ALLOC);
                    if(!__path_buf)
                    {
                        rmi_trace(ERROR_LEVEL, "Failed to allocate %d bytes for cache add\n", PATH_MAX);
                        goto next;
                    }
#endif
                    __path = __get_exe(__mm, __path_buf, __path_len, &__f_size);
                    if(__path)
                    {
                        __add_to_cache(&__rb_cache, __path, __hmac);
                    }
#if 0
                    if(__path_buf)
                    {
                        __release_buffer(__path_buf, PATH_ALLOC);
                    }
#endif
                }
#if 0
next:
#endif
                /*
                 * Send the task to the daemon so it can be parsed and dealt with if it's a script
                 */
                __ppid.pid    = __task->pid;
                __ppid.ppid   = __task->real_parent->pid;
                __ppid.exec   = __task->did_exec;

                if(unlikely(kfifo_is_full(&__read_fifo)))
                {
                    while(kfifo_is_full(&__read_fifo))
                    {
                        rmi_trace(INFO_LEVEL, "AEROLOCK: waiting on full read fifo ...\n");
                        interruptible_sleep_on_timeout(&__write_queue_available, __WAIT_TIME__);
                    }
                    rmi_trace(INFO_LEVEL, "AEROLOCK: read fifo ready ...\n");
                    
                }

                rmi_trace(INFO_LEVEL, "AEROLOCK: __validate_hmac queuing task to __read_fifo, pid %ld\n", (long)__ppid.pid);
                kfifo_in_spinlocked(&__read_fifo, &__ppid, sizeof(PidStack), &__read1_spinlock);
                wake_up_interruptible(&__read_sleeper);
            }
            else
            {
                __ppid.pid    = __task->pid;

                if(unlikely(kfifo_is_full(&__kill_fifo)))
                {
                    while(kfifo_is_full(&__kill_fifo))
                    {
                        interruptible_sleep_on_timeout(&__kill_queue_available, __WAIT_TIME__);
                    }
                }

                rmi_trace(WARNING_LEVEL, "AEROLOCK: __validate_hmac queuing task to __kill_fifo, pid %ld\n", (long)__ppid.pid);
                kfifo_in_spinlocked(&__kill_fifo, &__ppid.pid, sizeof(pid_t), &__kill1_spinlock);
                wake_up_interruptible(&__kill_sleeper);
            }
        }
        else
        {
            rmi_trace(INFO_LEVEL, "AEROLOCK: __validate_hmac() failed to generate HMAC!\n");
            __retval = 0;
        }
    }
    else
    {
        rmi_trace(INFO_LEVEL, "AEROLOCK: __validate_hmac() PID out of range!\n");
        __retval = 0;
    }

out:
    return __retval;
}


static ssize_t aerolock_read(struct file* filp, char __user* buf, size_t nbytes, loff_t* ppos)
{
    PidStack  __local;
    int       __retval = 0;

    if(!filp || !buf || !ppos)
    {
        __retval = -EFAULT;
        goto out;
    }

    if (filp->f_flags & O_NONBLOCK)
    {
        rmi_trace(WARNING_LEVEL, "AEROLOCK: Warning, read(): returning -EAGAIN\n");
        __retval = -EAGAIN;
        goto out;
    }

    /*
     * MISRA C 2012 deviation -- We jump backwards to a label for simplicity and clarity
     */
wait_for_next:

    /* 
     * Dequeue items from the __read_fifo. If the __read_fifo is empty, sleep until something
     * shows up and then keep pulling from the queue and passing to userland as
     * fast as possible.
     */
    if(kfifo_is_empty(&__read_fifo))
    {
        wait_event_interruptible(__read_sleeper, !kfifo_is_empty(&__read_fifo));
    }
    
    __retval = kfifo_out_spinlocked(&__read_fifo, &__local, sizeof(PidStack), &__read2_spinlock);
    if(__retval != sizeof(PidStack))
    {
        rmi_trace(INFO_LEVEL, "AEROLOCK: read() - size mismatch for PidStack: %d pid: %ld\n", __retval,(long)__local.pid);
        __retval = -EAGAIN;
        goto out;
    }

    /*
     * Bogus values come down the queue occasionally. Test that what we've gotten is in the range of valid pid values
     */
    if(unlikely(__local.pid <= 0x0001 || __local.pid > PID_MAX_LIMIT))
    {
        rmi_trace(INFO_LEVEL, "AEROLOCK: read() - size parameters out of bounds retval: %d pid: %ld\n", __retval, (long)__local.pid);
        goto wait_for_next;
    }

    rmi_trace(INFO_LEVEL, "AEROLOCK: Sending [%u], we %s in a panic\n", (uint32_t)__local.pid, __local.cmd == PANIC ? "are" : "are not");

    /*
     * Safely copy data out to the caller
     */
    spin_lock(&__read3_spinlock);

    if(copy_to_user(buf, &__local, sizeof(PidStack)))
    {
        rmi_trace(ERROR_LEVEL, "AEROLOCK: Error, read(): returning -EFAULT\n");
        __retval = -EFAULT;
    }

    spin_unlock(&__read3_spinlock);

    __pid_count++;

out:
    return(__retval);
}

int __kill_task(pid_t __pid_to_kill)
{
    int32_t __retval = 0;

    spin_lock(&__kill4_spinlock);

    if(likely(__pid_to_kill > 1UL && __pid_to_kill <= PID_MAX_LIMIT))
    {
        if(kill_pgrp(find_vpid(__pid_to_kill), SIGKILL, 1))
        {
            if(kill_pid(find_vpid(__pid_to_kill), SIGKILL, 1))
            {
                __retval = 1;
            }
        }
    }

    spin_unlock(&__kill4_spinlock);

    return(__retval);
}

int32_t __halt_task(pid_t __pid_to_stop)
{
    int32_t __retval = 0;

    if(likely(__pid_to_stop > 1UL && __pid_to_stop <= PID_MAX_LIMIT))
    {
        if(kill_pgrp(find_vpid(__pid_to_stop), SIGSTOP, 1))
        {
            if(kill_pid(find_vpid(__pid_to_stop), SIGSTOP, 1))
            {
                __retval = 1;
            }
        }
    }

    return(__retval);
}

int __resume_task(pid_t __pid_to_stop)
{
    int32_t __retval = 0;

    if(likely(__pid_to_stop > 1UL && __pid_to_stop <= PID_MAX_LIMIT))
    {
        if(kill_pgrp(find_vpid(__pid_to_stop), SIGCONT, 1))
        {
            if(kill_pid(find_vpid(__pid_to_stop), SIGCONT, 1))
            {
                __retval = 1;
            }
        }
    }

    return(__retval);
}

/*
 * __kill_process() sits on its own thread watching the kill queue.  Once it gets an entry 
 * it executes the appropriate kill command as quickly as it can and then waits for more.
 * @data: unused but required by thread installer
 */ 
static int __kill_process(void* data)
{
    pid_t               __pid_to_kill;
    int                 __retval;

    rmi_trace(INFO_LEVEL, "AEROLOCK: Start __kill_process() thread successfully completed)\n");

    while(1)
    {
        if(kfifo_is_empty(&__kill_fifo))
        {
            rmi_trace(INFO_LEVEL, "AEROLOCK: __kill_process() Blocking\n");
            wait_event_interruptible(__kill_sleeper, !kfifo_is_empty(&__kill_fifo));
        }

        if(unlikely(kthread_should_stop()))
        {
            __retval = 0;
            goto out;
        }

        __retval = kfifo_out_spinlocked(&__kill_fifo, &__pid_to_kill, sizeof(pid_t), &__kill2_spinlock);

        if(!__debug__mode)
        {
            if(__kill_task(__pid_to_kill))
            {
                rmi_trace(ERROR_LEVEL, "AEROLOCK: Error, __kill_process() failed to kill task [%ld]\n", (long)__pid_to_kill);
            }
            else
            {
                rmi_trace(ERROR_LEVEL, "AEROLOCK: Warning, __kill_process() successfully completed (%ld)\n", (long)__pid_to_kill);
            }
        }
    }

out:
    rmi_trace(WARNING_LEVEL, "AEROLOCK: Killed [%ld]\n", (long)__pid_to_kill);
    return(__retval);
}

static ssize_t aerolock_write(struct file* filp, const char __user* buffer, size_t count, loff_t* ppos)
{
    const char __user *p = buffer;
    PidStack   __pids;
    ssize_t    __retval = sizeof(PidStack);

    if(!filp || !buffer || !ppos)
    {
        __retval = -EFAULT;
        goto out;
    }

    __pid_count--;

    if(copy_from_user(&__pids, p, sizeof(PidStack)))
    {
        rmi_trace(ERROR_LEVEL, "AEROLOCK: Error, write(): returning -EFAULT\n");
        __retval = -EFAULT;
        goto out;
    }

    /*
     *  Since ioctl doesn't seem to work, we'll use write to set/unset debug mode
     *  We can use it for other driver communications as needed
     */
    switch(__pids.cmd)
    {
    case TOGGLE_DEBUG:
        __debug__mode = __pids.debug;
        rmi_trace(WARNING_LEVEL, "AEROLOCK: __debug_mode is %s\n", __debug__mode == 1 ? "on" : "off");
        goto out;
        break;

    case PROC_STOP:
       if(__halt_task(__pids.pid))
       {
           rmi_trace(ERROR_LEVEL, "AEROLOCK: Error, failed to halt process, returning -EFAULT for pid %ld\n", (long)__pids.pid);
           __retval = -EFAULT;
       }
       goto out;
       break; 

    case PROC_RESUME:
        if(__resume_task(__pids.pid))
        {
            rmi_trace(ERROR_LEVEL, "AEROLOCK: Error, failed to resume process, returning -EFAULT for pid %ld\n", (long)__pids.pid);
            __retval = -EFAULT;
        }
       goto out;
       break; 

    case PROFILING_START:
        __profile_mode = 1; // Toggle
        rmi_trace(WARNING_LEVEL, "AEROLOCK: Profile mode is now on\n");
        goto out;
        break;

    case PROFILING_STOP:
        __profile_mode = 0; // Toggle
        rmi_trace(WARNING_LEVEL, "AEROLOCK: Profile mode is now off\n");
        goto out;
        break;

    case LOOKUP_HMAC:
        __retval = (__find_hmac(&__rb_hmacs, __pids.__hmac) != NULL);
        // rmi_trace(WARNING_LEVEL, "AEROLOCK: [%ld] Lookup HMAC is returning %d\n", __pids.pid, __retval);
        goto out;

    case RELOAD_HMACS:
        __rb_flush_hmacs();

        if(__init_hmac_list())  // returns 1 on error
        {
            rmi_trace(ERROR_LEVEL, "AEROLOCK: Failed to initialize master hmac, aborting load\n");
            __retval = -ENOMEM;
            goto out;
        }

        __retval = __validate_hmacs();
        break;

    default:
        break;
    }

    if(!__aerolock__enabled)
    {
        rmi_trace(DETAIL_LEVEL, "AEROLOCK: write() FAUX kill_pgrp(%ld, SIGKILL, 1), (Pid Skew = %d)\n", (long)__pids.pid, __pid_count);
    }
    else
    {
        rmi_trace(DETAIL_LEVEL, "AEROLOCK: write() received kill_pgrp(%ld, SIGKILL, 1), (Pid Skew = %d)\n", (long)__pids.pid,  __pid_count);
    }

    /* Enqueue payload */
    if(unlikely(kfifo_is_full(&__kill_fifo)))
    {
        while(kfifo_is_full(&__kill_fifo))
        {
            interruptible_sleep_on_timeout(&__kill_queue_available, __WAIT_TIME__);
        }
    }

    rmi_trace(INFO_LEVEL, "AEROLOCK: write() Queuing PID[%ld] to kill\n", (long)__pids.pid);

    kfifo_in_spinlocked(&__kill_fifo, &__pids.pid, sizeof(pid_t), &__kill3_spinlock);
    wake_up_interruptible(&__kill_sleeper);

out:
    return __retval;
}


/*
 * Do reference counting to make sure only one queue is allocated and destroyed.
 */
static int aerolock_close(struct inode *i, struct file *f)
{

    __open_count--;

    if(__open_count == 0)
    {
        __aerolock__enabled = 0;

    }

    return 0;
}

static int aerolock_open(struct inode *i, struct file *f)
{
    __aerolock__enabled =  1;

    if(__open_count == 0)
    {
        __pid_count = 0;
    }

    /*
     *  Could be lots of threads, so keep a reference count so things don't 
     *  get shut down too early.
     */
    __open_count++;

    return 0;
}

/*=============================== Begin do_fork handlers on exit ========================*/

/*
 *   Handler for kretprobe when an exception occurs.
 *   Right now we only trace an error and don't handle the fault. Trace and dump stack
 *   So it returns 0 and the kernel will do its best to hanlde it.
 */
int probe_handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
    rmi_trace(ERROR_LEVEL, "AEROLOCK: fault_handler: p->addr = 0x%p, trap #%d\n", p->addr, trapnr);

    dump_stack();   /* will add a trace in the system log of the current stack. */

    /* Return 0 because we don't handle the fault. */
    return 0;
}


/* call this function to end a timer, returning nanoseconds elapsed as a long */
long __timer_end(struct timespec start_time)
{
    struct timespec end_time;
    getrawmonotonic(&end_time);
    return(end_time.tv_nsec - start_time.tv_nsec);
}

struct timespec __timer_start(void)
{
    struct timespec start_time;
    getrawmonotonic(&start_time);
    return start_time;
}

/*
 *   Execute when do_fork returns. The return value is the newly created task (== current)
 */
static int ret_do_fork(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct timespec __start_time;
    long            __elapsed = 0L;


#ifdef __DEBUG__
    __path = __get_exe(ri->task->mm, __path_buf, __path_len, &__f_size);

    rmi_trace(INFO_LEVEL, "AEROLOCK: %s - [%ld] ret_do_fork returned %s [%ld]\n",
    __aerolock__enabled ? "Active" : "Passive", (long)ri->task->pid, __path   ? __path : ri->task->comm, __f_size);
#endif

    if(__aerolock__enabled)
    {
        __start_time = __timer_start();

        //__handoff_to_daemon();
        __validate_hmac(ri->task);

        __elapsed = __timer_end(__start_time);

        rmi_trace(WARNING_LEVEL, "AEROLOCK: [%ld] FORK(%s) took %ld.%ldms\n",(long)ri->task->pid, ri->task->comm, __elapsed/1000000, __elapsed%1000000);
    }

    return 0;
}

static struct kretprobe kret_do_fork =
{
    .handler           = ret_do_fork,
    .kp.symbol_name    = "do_fork",
    .kp.fault_handler  = probe_handler_fault,
    .maxactive         = 2*NR_CPUS,            /* Probe up to 2xNR_CPUS instances concurrently. */
};

static int ret_do_execve(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct timespec __start_time;
    long            __elapsed = 0L;


#ifdef __DEBUG__
    __path = __get_exe(ri->task->mm, __path_buf, __path_len, &__f_size);

     rmi_trace(INFO_LEVEL, "AEROLOCK: %s - [%ld] ret_do_execve returned %s [%ld]\n",
    __aerolock__enabled ? "Active" : "Passive", (long)ri->task->pid, __path   ? __path : ri->task->comm, __f_size);
#endif

    if(__aerolock__enabled)
    {
        __start_time = __timer_start();

        //__handoff_to_daemon();
        __validate_hmac(ri->task);

        __elapsed = __timer_end(__start_time);

        rmi_trace(WARNING_LEVEL, "AEROLOCK: [%ld] EXECVE(%s) took %ld.%ldms\n",(long)ri->task->pid, ri->task->comm, __elapsed/1000000, __elapsed%1000000);
    }

    return 0;
}

static struct kretprobe kret_do_execve =
{

    .handler           = ret_do_execve,
    .kp.symbol_name    = "do_execve",
    .kp.fault_handler  = probe_handler_fault,
    .maxactive         = 2*NR_CPUS,           /* Probe up to 2xNR_CPUS instances concurrently. */
};

/* =============================== End do_fork handlers on exit ========================== */

struct task_struct __dummy_task;
struct posix_clock __posix_clk;

static void __exit aerolock_exit_module(void)
{
    rmi_trace(DETAIL_LEVEL, "AEROLOCK: Entering cleanup_module()\n");

    unregister_kretprobe(&kret_do_execve);
    unregister_kretprobe(&kret_do_fork);

    /* cleanup_module is never called if registering failed */
    cdev_del(&c_dev);
    device_destroy(cl, first);
    class_destroy(cl);
    unregister_chrdev_region(first, 1);

    rmi_trace(INFO_LEVEL, "AEROLOCK: Stopping __kill_thread\n");
    __pids.pid = 0; 
    kfifo_in_spinlocked(&__kill_fifo, &__pids.pid, sizeof(pid_t), &__kill3_spinlock);
    kthread_stop(__kill_thread);
    __kill_thread = NULL;
    rmi_trace(INFO_LEVEL, "AEROLOCK: Successfully stopped kill thread\n");

    rmi_trace(INFO_LEVEL, "AEROLOCK: Releasing fifos\n");
    kfifo_free(&__kill_fifo);
    kfifo_free(&__read_fifo);

    rmi_trace(INFO_LEVEL, "AEROLOCK: Flushing rbtrees\n");
    __rb_flush_hmacs();
    __rb_flush_cache();

    rmi_trace(INFO_LEVEL, "AEROLOCK: Exiting cleanup_module()\n");
}

const struct file_operations aerolock_fops =
{
    .owner        = THIS_MODULE,
    .open         = aerolock_open,
    .read         = aerolock_read,
    .write        = aerolock_write,
    .release      = aerolock_close,
};

#include <generated/utsrelease.h>

static int __init aerolock_init_module(void)
{
    int __retval = 0;
    int __iret_do_fork   = -1;
    int __iret_do_execve = -1;

    if (alloc_chrdev_region(&first, 0, 1, "aerolock") < 0)
    {
        __retval = -1;
        goto out;
    }

    if ((cl = class_create(THIS_MODULE, "chardrv")) == NULL )
    {
        unregister_chrdev_region(first, 1);
        __retval = -1;
        goto out;
    }

    if (device_create(cl, NULL, first, NULL, "aerolock") == NULL )
    {
        class_destroy(cl);
        unregister_chrdev_region(first, 1);
        __retval = -1;
        goto out;
    }

    cdev_init(&c_dev, &aerolock_fops);

    if (cdev_add(&c_dev, first, 1) == -1)
    {
        device_destroy(cl, first);
        class_destroy(cl);
        unregister_chrdev_region(first, 1);
        __retval = -1;
        goto out;
    }

    /* Register the interceptors */

    do {
        /* Register hook on the exit of do_fork kernel method */
        if ((__iret_do_fork = register_kretprobe(&kret_do_fork)) < 0)
        {
            rmi_trace(ERROR_LEVEL, "AEROLOCK: Error, register_kretprobe(%s) failed, returned %d\n",
                    kret_do_fork.kp.symbol_name, __iret_do_fork);
            __retval = __iret_do_fork;
            break;
        }

        /* Register hook on the exit of do_execve kernel method */
        if ((__iret_do_execve = register_kretprobe(&kret_do_execve)) < 0)
        {
            rmi_trace(ERROR_LEVEL, "AEROLOCK: Error, register_kretprobe(%s) failed, returned %d\n",
                    kret_do_execve.kp.symbol_name, __iret_do_execve);
            __retval = __iret_do_execve;
            break;
        }

        rmi_trace(INFO_LEVEL, "AEROLOCK: On return of %s at %p, handler addr %p\n",
                kret_do_fork.kp.symbol_name, kret_do_fork.kp.addr,
                kret_do_fork.handler);

    } while (false);

    rmi_trace(INFO_LEVEL, "AEROLOCK: Exiting probe_process_init(), %d = init_module();\n", __retval);

    if (kfifo_alloc(&__read_fifo, PAGE_SIZE*16, GFP_KERNEL))
    {
        rmi_trace(ERROR_LEVEL, "AEROLOCK: Error, open() failed, no queue memory\n");
        __retval = -ENOMEM;
        goto out;
    }

    if (kfifo_alloc(&__kill_fifo, PAGE_SIZE*16, GFP_KERNEL))
    {
        rmi_trace(ERROR_LEVEL, "AEROLOCK: Error, open() failed, no queue memory\n");
        __retval = -ENOMEM;
        goto out;
    }

    rmi_trace(INFO_LEVEL, "AEROLOCK: Creating threads\n");
    __kill_thread = kthread_run(__kill_process, NULL, "kill_queue");
    if(!__kill_thread)
    {
        rmi_trace(ERROR_LEVEL, "AEROLOCK: Error, open() failed, no __kill_thread\n");
        __retval = -EIO;
        goto out;
    }

    /*
     * PHJ  Note: Read in hmacs.profile -- there can be a lot of HMACs in the file.  My Ubuntu 
     * development workstation has close to 200K files and uses 8MiB of RAM. We've cut down on 
     * the overall system usage by making the userland Daemon call the kernel for service, removing 
     * the tree duplication.  Embedded system will have fewer files on them and therefore use less
     * RAM, but we'll need to keep an eye on it.
     *
     * NOTE:  It might make sense to try and memory map the rb_tree to a file to deal with memory 
     * constraints [do_mmap()].
     */
    if(__init_hmac_list())
    {
        rmi_trace(ERROR_LEVEL, "AEROLOCK: Failed to initialize master hmac, aborting load\n");
        __retval = -ENOMEM;
        goto out;
    }

     rmi_trace(WARNING_LEVEL, "AEROLOCK: Version %s-%s\n", RM_VERSION, UTS_RELEASE);
     rmi_trace(WARNING_LEVEL, "AEROLOCK: Using %d HMACS and %d bytes of RAM\n",  __hmac_node_count, __hmac_node_count*sizeof(struct __hmac_struct));
     rmi_trace(WARNING_LEVEL, "AEROLOCK: Profiling mode is %s\n", __profile_mode == 1 ? "on" : "off");
     rmi_trace(WARNING_LEVEL, "AEROLOCK: Debug level %d\n", __debug_level );

out:
    return __retval;
}

module_init(aerolock_init_module);
module_exit(aerolock_exit_module);
MODULE_AUTHOR("Pete Jenney");
MODULE_LICENSE("GPL");
