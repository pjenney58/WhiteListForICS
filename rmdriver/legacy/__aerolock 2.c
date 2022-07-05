
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

#ifndef __KERNEL__
#  define __KERNEL__
#endif
#ifndef MODULE
#  define MODULE
#endif

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/kdev_t.h>
#include <linux/kfifo.h>
#include <linux/kthread.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/pid_namespace.h>
#include <linux/kprobes.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/uaccess.h>
#include <linux/cdev.h>
#include <linux/mm.h>
#include <linux/delay.h>
#include <linux/random.h>

static struct kfifo fifo;
static struct kfifo __kill_fifo;

/*
 *  rmi_access_process_vm() - stole from kernel access_process_vm() because on compile I would get:
 *          WARNING: (aerolock.o/access_process_vm()) undefined!
 *          and sure enough, it would fail t find it on load.
 *  After a while of searching I con'ldnt find any reference to the problem and it wasn't fixing itself
 *  so I copied it out of memory.c, renamed it and moved on.
 */
int rmi_access_process_vm(struct task_struct *tsk, unsigned long addr, void *buf, int len, int write);
struct task_struct* trap_task(long pid);

int iDebugLevel = 2;

#define ERROR_LEVEL     (1)
#define WARNING_LEVEL   (2)
#define INFO_LEVEL      (3)
#define DETAIL_LEVEL    (4)
#define trace(level, fmt, ...) if(level <= iDebugLevel) printk (fmt, ## __VA_ARGS__)

#define PROC_NAME   "aerolocktaskinfo"

//static struct proc_dir_entry* proc_taskinfo = NULL;
wait_queue_head_t __read_sleeper;    // Blocking queue
wait_queue_head_t __kill_sleeper;
wait_queue_head_t __random_queue_available;
wait_queue_head_t __write_queue_available;
wait_queue_head_t __read_queue_available;
wait_queue_head_t __kill_queue_available;

static int __open_count = 0;
struct task_struct* __kill_thread;
struct task_struct* __wait_thread;

// aerolock driver costructs and variables
static struct cdev c_dev;
static struct class *cl;
static dev_t first;
pid_t last_pid;

int flag = 0;
int create = 0;
int exec = 0;
int __aerolock__enabled = 0;
int __debug__mode = 1;


typedef struct pid_stack
{
    int   cmd;
    pid_t pid;        // Current
    pid_t ppid;       // Parent
    pid_t gtid;       // Module
    int   create;     // Creating or dying
    int   exec;
    int   signal;
    int   debug;
} PidStack, *PPidStack;

#define TOGGLE_DEBUG 0x7F
#define PROC_STOP    0x7E
#define PROC_RESUME  0x7D


long __pid_count = 1;
struct pid_stack __pids;

DEFINE_SPINLOCK(__w1_spinlock);
DEFINE_SPINLOCK(__w2_spinlock);
DEFINE_SPINLOCK(__w3_spinlock);
DEFINE_SPINLOCK(__w4_spinlock);
DEFINE_SPINLOCK(__r1_spinlock);
DEFINE_SPINLOCK(__r2_spinlock);
DEFINE_SPINLOCK(__k1_spinlock);
DEFINE_SPINLOCK(__read1_spinlock);

int        __have_validated_runtime = 0;
#define    __WAIT_TIME__ 100


/*
 *  Periodically check the running tasks to make sure that nothing snuck in
 */
int __validate_running_tasks(void)
{
    struct list_head*    __p;
    struct task_struct*  __t;
    struct task_struct* task;
    PidStack            __ppid;

    if(!__aerolock__enabled)
        return 1;
/*
 *  Get /sbin/init and walk the task tree
 */
    task = pid_task(find_vpid(1), PIDTYPE_PID);

    //trace(INFO_LEVEL, "VALIDATE: testing runtime environment\n");

    if(likely(task))
    {
        list_for_each(__p, &task->tasks)
        {
            __t = list_entry(__p, struct task_struct, tasks);

            if(likely(__t && __t->pid > 0x0000 && __t->pid <= 0x8000))
            {
                memset(&__ppid, 0, sizeof(PidStack));
                __ppid.pid    = __t->pid;
                __ppid.ppid   = task->real_parent->pid;
                __ppid.exec   = (__t->did_exec) ? 1 : 0;
                __ppid.create = create;

                flag   = 1;

                //trace(INFO_LEVEL, "VALIDATE Enqueuing %s, pid = %ld\n", __ppid.cmdline, (long)__ppid.pid);

                /*
                 * Enqueue payload here.  Need to spinlock to avoid a backup if the queue is full.
                 */
                //spin_lock(&__w3_spinlock);

                if(kfifo_is_full(&fifo))
                {
                    //trace(INFO_LEVEL, "VALIDATE: Waiting on Queue. Len = %d\n", kfifo_len(&fifo));

                    while(kfifo_is_full(&fifo))
                        interruptible_sleep_on_timeout(&__write_queue_available, __WAIT_TIME__);

                    //trace(INFO_LEVEL, "VALIDATE: Not full event on Queue, here we go... Len = %d\n", kfifo_len(&fifo));
                }

                //trace(INFO_LEVEL, "VALIDATE: Room in Queue, adding. Len = %d\n", kfifo_len(&fifo));
                kfifo_in_spinlocked(&fifo, &__ppid, sizeof(PidStack), &__w4_spinlock);
                wake_up_interruptible(&__read_sleeper);

                //spin_unlock(&__w3_spinlock);

            }
            else
            {
                trace(INFO_LEVEL, "VALIDATE: Pid out of range [%ld]\n", __t->pid);
            }
        }
    }

    return 0;
}

/*
 * Generate a random number and wait on it.  Once there, call validate_running_tasks().  This replaces the old
 * check every 'n' task calls and should make it mode difficult for an attacker to profile.
 */
int  __launch_vtasks(void* data)
{
    unsigned short __s_wait_time;
    unsigned long  __l_wait_time;

    while(1)
    {
        // Get a random sleep time between 0 and 4294967295l jiffies
        get_random_bytes(&__s_wait_time, sizeof(__s_wait_time));
        __l_wait_time = (__s_wait_time *10)/2;
        trace(INFO_LEVEL, "AEROLOCK TIMER: Waiting %lu jiffies\n", __l_wait_time);
        interruptible_sleep_on_timeout(&__random_queue_available, __l_wait_time);

        if(kthread_should_stop())
            return 0;

        trace(INFO_LEVEL, "AEROLOCK TIMER: Done waiting, here we go ...\n");
        __validate_running_tasks();

    }

    return 0;
}

/*
 * trap_task() = Called by our do_fork intercept.  Straight forward action, get the pid and send it to the daemon
 * for hmac generation.  The daemon will return thumbs up or thumbs down at which point we kill the rouge or
 * just leave it alone.
 */
struct task_struct* trap_task(long pid) 
{
    struct task_struct* task = NULL;
    PidStack __ppid;

    if(pid <= 0x0000 || pid > 0x8000)
        return task;

    /*
     * Get the task struct associated with the pid.  This call obviates the need
     * to manually walk the entire task tree looking for the proper one.
     */
    if (unlikely((task = pid_task(find_vpid(pid), PIDTYPE_PID)) == NULL))
    {
        trace(ERROR_LEVEL, "ERROR: pid_task(%ld) returned NULL\n", pid);
        return task;
    }

    if(__aerolock__enabled)
    {
        if(likely(task && task->state == TASK_RUNNING &&
                task->pid >  0x0002                   &&
                task->pid <= 0x8000))
        {
            __ppid.pid    = task->pid;
            __ppid.ppid   = task->real_parent->pid;
            __ppid.create = create;
            __ppid.exec   = task->did_exec;

            //trace(INFO_LEVEL, "TRAPTASK: Enqueuing, pid = %ld (%s)\n", (long)__ppid.pid, task->comm);

            /*
             * Enqueue pointer to payload - this will get picked up by read() and sent to 
             * the daemon for processing.  There are multiple threads making read calls
             * and potentioally thousands of tasks at any given time, hence a queue makes sense.
             * Need to spinlock here to avoid any overflows on a full queue condition
             */
            spin_lock(&__w1_spinlock);

            if(kfifo_is_full(&fifo))
            {
                while(kfifo_is_full(&fifo))
                    interruptible_sleep_on_timeout(&__write_queue_available, __WAIT_TIME__);
            }

            kfifo_in_spinlocked(&fifo, &__ppid, sizeof(PidStack), &__w2_spinlock);
            wake_up_interruptible(&__read_sleeper);

            spin_unlock(&__w1_spinlock);
        }
    }
    else
    {

    //    trace(INFO_LEVEL,
    //            "AEROLOCK: FAUX trap_task(%ld) (%s); (Pid Skew = %ld)\n",
    //            (long )pid, (__ppid.cmdlen > 0) ? __ppid.cmdline : task->comm, __pid_count);
    }

    last_pid = pid;
    return task;
}

static ssize_t aerolock_read(struct file* filp, char __user* buf, size_t nbytes, loff_t* ppos)
{
    PidStack  __local;
    int       retval = 0;

    if (filp->f_flags & O_NONBLOCK)
    {
        trace(WARNING_LEVEL, "AEROLOCK: read(): returning -EAGAIN\n");
        return -EAGAIN;
    }

wait_for_next:


    /* 
     * Dequeue items from the fifo. If the fifo is empty, sleep until something
     * shows up and then keep pulling from the queue and passing to userland as
     * fast as possible.
     */
    if(kfifo_is_empty(&fifo))
    {
        wait_event_interruptible(__read_sleeper, !kfifo_is_empty(&fifo));
    }
    
    retval = kfifo_out_spinlocked(&fifo, &__local, sizeof(PidStack), &__r1_spinlock);

    if(retval != sizeof(PidStack))
    {
        trace(INFO_LEVEL, "AEROLOCK: read() - size mismatch for PidStack: %d pid: %ld\n", retval,(long)__local.pid);
        return -EAGAIN;
    }

    /*
     * Bogus values come down the queue occaisionally. Test that what we've gotten is in the range of valid pid values
     */
    if(__local.pid <= 0x0002 || __local.pid > 0x8000)
    {
        //trace(INFO_LEVEL, "AEROLOCK: read() - size parameters out of bounds retval: %d pid: %ld\n", retval, (long)__local.pid);
        goto wait_for_next;
    }

    if(__local.create)
    {
        spin_lock(&__r2_spinlock);

        if(copy_to_user(buf, &__local, sizeof(PidStack)))
        {
            trace(ERROR_LEVEL, "AEROLOCK: read(): returning -EFAULT\n");
            retval = -EFAULT;
        }

        spin_unlock(&__r2_spinlock);

        __pid_count++;
    }

    return retval;
}


/*
 * __kill_process() sits on its own thread watching the kill queue.  Once it gets an entry 
 * it executes the appropriate kill command as quickly as it can and then waits for more.
 */ 
static int __kill_process(void* data)
{
    struct task_struct* __task;
    pid_t               __pid_to_kill;
    int                 __retval;

    trace(INFO_LEVEL, "AEROLOCK: Start __kill_process() thread successfully completed)\n");

    while(1)
    {
        if(kfifo_is_empty(&__kill_fifo))
        {
            trace(INFO_LEVEL, "AEROLOCK: __kill_process() Blocking\n");
            wait_event_interruptible(__kill_sleeper, !kfifo_is_empty(&__kill_fifo));
        }

        if(kthread_should_stop())
            return 0;

        __retval = kfifo_out_spinlocked(&__kill_fifo, &__pid_to_kill, sizeof(pid_t), &__k1_spinlock);

        trace(INFO_LEVEL, "AEROLOCK: __kill_process() successfully dequeued (%ld)\n", (long)__pid_to_kill);

        if(__pid_to_kill > 0x00002 && __pid_to_kill <= 0x8000)
        {
            __task = pid_task(find_vpid(__pid_to_kill), PIDTYPE_PID);

            trace(INFO_LEVEL, "AEROLOCK: __kill_process() attempting to reaquire task (%ld)\n", (long)__pid_to_kill);
            if(__task)
            {
                trace(INFO_LEVEL, "AEROLOCK: __kill_process() successfully reaquird task (%ld)\n", (long)__pid_to_kill);
                if(__debug__mode)
                {
                    trace(INFO_LEVEL, "AEROLOCK: __kill_process() successfully completed (%ld)\n", (long)__pid_to_kill);
                }
                else
                {
                    if(kill_pgrp(task_pid(__task), SIGKILL, 1))
                        kill_pid(task_pid(__task), SIGKILL, 1);
                }
            }
            else
            {
                trace(ERROR_LEVEL, "AEROLOCK: Failed to reaquire task\n");
            }
        }
    }

    return 0;
}

int __halt_task(pid_t __pid_to_stop)
{
    struct task_struct* __task = pid_task(find_vpid(__pid_to_stop), PIDTYPE_PID);

    if(kill_pgrp(task_pid(__task), SIGSTOP, 1))
        if(kill_pid(task_pid(__task), SIGSTOP, 1))
            return 0;

    return 1;
}

int __resume_task(pid_t __pid_to_stop)
{
    struct task_struct* __task = pid_task(find_vpid(__pid_to_stop), PIDTYPE_PID);

    if(kill_pgrp(task_pid(__task), SIGCONT, 1))
        if(kill_pid(task_pid(__task), SIGCONT, 1))
            return 0;

    return 1;
}

static ssize_t aerolock_write(struct file* filp, const char __user* buffer, size_t count, loff_t* ppos)
{
    const char __user *p = buffer;
    PidStack __pids;

    __pid_count--;

    if(copy_from_user(&__pids, p, sizeof(PidStack)))
    {
        trace(ERROR_LEVEL, "AEROLOCK: write(): returning -EFAULT\n");
        return -EFAULT;
    }

    /*
     *  Since ioctl doesn't seem to work, we'll use write to set/unset debug mode
     *  We can use it for other driver communications as needed
     */
    switch(__pids.cmd)
    {
    case TOGGLE_DEBUG:
        __debug__mode = __pids.debug;
        trace(INFO_LEVEL, "__debug_mode is %s\n", __debug__mode == 1 ? "on" : "off");
        return sizeof(PidStack);
        break;

    case PROC_STOP:
       if(!__halt_task(__pids.pid))
       {
           trace(ERROR_LEVEL, "Failed to halt process, returning -EFAULT for pid %ld\n", (long)__pids.pid);
           return -EFAULT;
       }
       return sizeof(PidStack);
       break; 

    case PROC_RESUME:
        if(!__resume_task(__pids.pid))
        {
            trace(ERROR_LEVEL, "Failed to resume process, returning -EFAULT for pid %ld\n", (long)__pids.pid);
            return -EFAULT;
        }
       return sizeof(PidStack);
       break; 
 

    default:
        break;
    }

    if(!__aerolock__enabled)
    {
        trace(DETAIL_LEVEL, "AEROLOCK: write() FAUX kill_pgrp(%ld, SIGKILL, 1), (Pid Skew = %ld)\n", (long)__pids.pid, __pid_count);
    }
    else
    {
        trace(DETAIL_LEVEL, "AEROLOCK: write() received kill_pgrp(%ld, SIGKILL, 1), (Pid Skew = %ld)\n", (long)__pids.pid,  __pid_count);
    }

    // Enqueue  payload
    if(kfifo_is_full(&__kill_fifo))
    {
        while(kfifo_is_full(&__kill_fifo))
            interruptible_sleep_on_timeout(&__kill_queue_available, __WAIT_TIME__);
    }

    trace(INFO_LEVEL, "AEROLOCK: write() enqueing data\n");
    kfifo_in_spinlocked(&__kill_fifo, &__pids.pid, sizeof(pid_t), &__k1_spinlock);
    wake_up_interruptible(&__kill_sleeper);

    return sizeof(PidStack);
}


/*
 * Do reference counting to make sure only one queue is allocated and destroyed.
 */
static int aerolock_close(struct inode *i, struct file *f)
{
    // trace(INFO_LEVEL, "AEROLOCK: close() called\n");

    __open_count--;

    if(__open_count == 0)
    {
        __aerolock__enabled = 0;

    }

    return 0;
}

static int aerolock_open(struct inode *i, struct file *f)
{
    // trace(INFO_LEVEL, "AEROLOCK: open() called\n");
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

//=============================== Begin do_fork handlers on exit ========================

/*
    Handler for jprobe or kretprobe when an exception occurs.
    Right now we only trace an error and don't handle the fault. Trace and dump stack
    So it returns 0 and the kernel will do its best to hanlde it.
*/
int probe_handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
    trace(ERROR_LEVEL, "fault_handler: p->addr=0x%p, trap #%dn", p->addr, trapnr);

    dump_stack();   // will add a trace in the system log of the current stack.

    // Return 0 because we don't handle the fault.
    return 0;
}

/*
    Execute when do_fork returns. The return value is the newly created PID.
    The PID can be accessed in the regs_return_value(regs) register. We use the PID to find the
    related task before we log data in our circular buffer
*/
static int ret_do_fork(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct task_struct* task;

    create = 1;
    task = trap_task(regs_return_value(regs));

    if(task)
    {
        return 0;
    }
    else
    {
        return 1;
    }
}

static struct kretprobe kret_do_fork =
{
    
    .handler           = ret_do_fork,
    .kp.symbol_name    = "do_fork",
    .kp.fault_handler  = probe_handler_fault,
    // Probe up to 16 instance concurrently.
    .maxactive      = 16,
};

//=============================== End do_fork handlers on exit ==========================

#if 0
//=============================== Begin free_task handlers on entry =====================
/*
    Execute when free_task is called. the only parameter passed is the task_struct being
    terminated. Pass the task to be recorded in the circular buffer.
*/

static void jfree_task(struct task_struct *task)
{
    PidStack __ppid;

    if( __aerolock__enabled)
    {
        flag = 1;
        __ppid.create = create = 0;
        __ppid.pid = task->pid;

        trace(INFO_LEVEL, "AEROLOCK: jfree_task() putting [%d] in Queue. Len = %d\n", task->pid, kfifo_len(&fifo));

retry_free_task:
        if(!kfifo_is_full(&fifo))
        {
            spin_lock(&__w3_spinlock);
            kfifo_in(&fifo, &__ppid, sizeof(PidStack));
            spin_unlock(&__w3_spinlock);
        }
        else
        {
            trace(INFO_LEVEL, "AEROLOCK: jfree_task() waiting in Queue. Len = %d\n", kfifo_len(&fifo));
            udelay(10000);
            goto retry_free_task;
        }
    }

    //wake_up_interruptible(&__read_sleeper);

    // Always end with a call to jprobe_return().
    jprobe_return();
}

static struct jprobe jprobe_free_task =
{
    .entry             = jfree_task,
    .kp.symbol_name    = "free_task",
    .kp.fault_handler  = probe_handler_fault,
    
};
//========================= End free_task handlers on entry =============================
#endif


static void __exit aerolock_exit_module(void)
{
   trace(DETAIL_LEVEL, "Entering cleanup_module()\n");
   
    trace(INFO_LEVEL, "AEROLOCK: Releasing fifos\n");
    kfifo_free(&__kill_fifo);
    kfifo_free(&fifo);



 #if 0
    unregister_jprobe(&jprobe_free_task);
    trace(DETAIL_LEVEL, "unregister_jprobe(0x%p)\n", &jprobe_free_task);
#endif

    unregister_kretprobe(&kret_do_fork);
    trace(INFO_LEVEL, "unregister_kretprobe(0x%p)\n", &kret_do_fork);

    /* cleanup_module is never called if registering failed */
    cdev_del(&c_dev);
    device_destroy(cl, first);
    class_destroy(cl);
    unregister_chrdev_region(first, 1);

    trace(INFO_LEVEL, "AEROLOCK: Stopping __wait_thread\n");
    kthread_stop(__wait_thread);
    __wait_thread = NULL;
    trace(INFO_LEVEL, "AEROLOCK: Successfully stopped thead\n");

    trace(INFO_LEVEL, "AEROLOCK: Stopping __kill_thread\n");
    __pids.pid = 0; 
    kfifo_in_spinlocked(&__kill_fifo, &__pids.pid, sizeof(pid_t), &__k1_spinlock);
    kthread_stop(__kill_thread);
    __kill_thread = NULL;
    trace(INFO_LEVEL, "AEROLOCK: Successfully stopped thead\n");

    trace(INFO_LEVEL, "Exiting cleanup_module()\n");
}

const struct file_operations aerolock_fops =
{
    .owner        = THIS_MODULE,
    .open         = aerolock_open,
    .read         = aerolock_read,
    .write        = aerolock_write,
    .release      = aerolock_close,
};

/*
 *  TODO: locate clone_flags and enable PTRACE_*
 */
static int __init aerolock_init_module(void)
{
    int iRet = 0;
    //int ijprobe_free_task = -1;
    int iret_do_fork = -1;
    // int iproc_file = -1;

    if (alloc_chrdev_region(&first, 0, 1, "aerolock") < 0)
    {
        return -1;
    }

    if ((cl = class_create(THIS_MODULE, "chardrv")) == NULL )
    {
        unregister_chrdev_region(first, 1);
        return -1;
    }

    if (device_create(cl, NULL, first, NULL, "aerolock") == NULL )
    {
        class_destroy(cl);
        unregister_chrdev_region(first, 1);
        return -1;
    }

    cdev_init(&c_dev, &aerolock_fops);

    if (cdev_add(&c_dev, first, 1) == -1)
    {
        device_destroy(cl, first);
        class_destroy(cl);
        unregister_chrdev_region(first, 1);
        return -1;
    }

    // Register the interceptors

    do {
#if 0
        // Register hook on the entry of free_task kernel method
        if ((ijprobe_free_task = register_jprobe(&jprobe_free_task)) < 0)
        {
            trace(ERROR_LEVEL, "register_jprobe(%s) failed, returned %d\n",
                    jprobe_free_task.kp.symbol_name, ijprobe_free_task);
            iRet = ijprobe_free_task;
            break;
        }

        trace(DETAIL_LEVEL, "On call of %s at %p, handler addr %p\n",
                jprobe_free_task.kp.symbol_name,
                jprobe_free_task.kp.addr,
                jprobe_free_task.entry);
#endif

        // Register hook on the exit of do_fork kernel method
        if ((iret_do_fork = register_kretprobe(&kret_do_fork)) < 0)
        {
            trace(ERROR_LEVEL, "register_kretprobe(%s) failed, returned %d\n",
                    kret_do_fork.kp.symbol_name, iret_do_fork);
            iRet = iret_do_fork;
            break;
        }

        trace(INFO_LEVEL, "On return of %s at %p, handler addr %p\n",
                kret_do_fork.kp.symbol_name, kret_do_fork.kp.addr,
                kret_do_fork.handler);

    } while (false);

/*
    spin_lock_init(&__w1_spinlock);
    spin_lock_init(&__w2_spinlock);
    spin_lock_init(&__w3_spinlock);
    spin_lock_init(&__w4_spinlock);
    spin_lock_init(&__r1_spinlock);
    spin_lock_init(&__r2_spinlock);
    spin_lock_init(&__k1_spinlock);
    spin_lock_init(&__read1_spinlock);
*/

    trace(INFO_LEVEL, "Exiting probe_process_init(), %d = init_module();\n", iRet);

    init_waitqueue_head(&__read_sleeper);
    init_waitqueue_head(&__kill_sleeper);
    init_waitqueue_head(&__random_queue_available);
    init_waitqueue_head(&__read_queue_available);
    init_waitqueue_head(&__write_queue_available);
    init_waitqueue_head(&__kill_queue_available);

    trace(INFO_LEVEL, "AEROLOCK: Creating fifos\n");
    if (kfifo_alloc(&fifo, PAGE_SIZE*16, GFP_KERNEL))
    {
        trace(INFO_LEVEL, "AEROLOCK: open() failed, no queue memory\n");
        return -ENOMEM;
    }

    if (kfifo_alloc(&__kill_fifo, PAGE_SIZE*16, GFP_KERNEL))
    {
        trace(INFO_LEVEL, "AEROLOCK: open() failed, no queue memory\n");
        return -ENOMEM;
    }

    trace(INFO_LEVEL, "AEROLOCK: Creating threads\n");
    __kill_thread = kthread_run(__kill_process, NULL, "kill_queue");
    if(!__kill_thread)
    {
        trace(INFO_LEVEL, "AEROLOCK: open() failed, no __kill_thread\n");
        return -EIO;
    }

    __wait_thread = kthread_run(__launch_vtasks, NULL, "wait random");
    if(!__wait_thread)
    {
        trace(INFO_LEVEL, "AEROLOCK: open() failed, no __wait_thread\n");
        return -EIO;
    }

    return iRet;
}

module_init(aerolock_init_module);
module_exit(aerolock_exit_module);
MODULE_AUTHOR("Pete Jenney");
MODULE_LICENSE("GPL");
