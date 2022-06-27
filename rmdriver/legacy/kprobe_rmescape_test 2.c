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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/pid_namespace.h>
#include <linux/kprobes.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>

//#include <ntru/crypto_hmac.h>



#define ERROR_LEVEL     (1)
#define WARNING_LEVEL   (2)
#define INFO_LEVEL      (3)
#define DETAIL_LEVEL    (4)
#define trace(level, fmt, ...) if(level <= iDebugLevel) printk (fmt, ## __VA_ARGS__)

static int iDebugLevel = 3;

/* HMAC key */
static uint8_t const key[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
};

//CRYPTO_HMAC_CTX *c = NULL;

int g_bProtectMode = 0;

long file_size(struct file* file)
{
	//mm_segment_t oldfs;

    //oldfs = get_fs();
    //set_fs(get_ds());

    // fseek(file, SEEK_SET)...
	return 0L;
}

int file_sync(struct file* file)
{
    vfs_fsync(file, 0);
    return 0;
}

int file_write(struct file* file, unsigned long long offset, unsigned char* data, unsigned int size)
{
    mm_segment_t oldfs;
    int ret;

    oldfs = get_fs();
    set_fs(get_ds());

    ret = vfs_write(file, data, size, &offset);

    set_fs(oldfs);
    return ret;
}

int file_read(struct file* file, unsigned long long offset, unsigned char* data, unsigned int size)
{
    mm_segment_t oldfs;
    int ret;

    oldfs = get_fs();
    set_fs(get_ds());

    ret = vfs_read(file, data, size, &offset);

    set_fs(oldfs);
    return ret;
}

void file_close(struct file* file)
{
    filp_close(file, NULL);
}

struct file* file_open(const char* path, int flags, int rights)
{
    struct file* filp = NULL;
    mm_segment_t oldfs;
    int err = 0;

    oldfs = get_fs();
    set_fs(get_ds());
    filp = filp_open(path, flags, rights);
    set_fs(oldfs);

    if(IS_ERR(filp))
    {
        err = PTR_ERR(filp);
        return NULL;
    }

    return filp;
}

int inDB(unsigned char hmac)
{
	// Use rbtree

	return 1;
}

int addToDB(unsigned char hmac)
{
	return 1;
}

int getFileSignature(char* path, unsigned char* hmac)
{
	char* fileData;
	uint32_t fileLen;
	uint32_t retcode;
	struct file* _file;
	struct inode _inode;
	long long offset = 0;
	unsigned char data[8192];
	int retlen = -1;

	// Open file
	_file = file_open(path, 0, 0);
#if 0
	/* HMAC data */
	retcode = crypto_hmac_init(c);
	if (retcode != CRYPTO_HMAC_OK)
	{
		printk("RMEnorcer: error initializing HMAC: %08lx\n", retcode);
		return 0;
	}

	// Read and encrypt a block at a time
	while((retlen = file_read(_file, offset, data, sizeof(data)) != 0))
	{
		retcode = crypto_hmac_update(c, data, retlen);
		if (retcode != CRYPTO_HMAC_OK)
		{
			printk("RMEnorcer: error HMACing data: %08lx\n", retcode);
			return 0;
		}
	}

	retcode = crypto_hmac_final(c, hmac);
	if (retcode != CRYPTO_HMAC_OK)
	{
		printk("RMEnorcer: error completing HMAC: %08lx\n", retcode);
		return 0;
	}
#endif

	return 1;
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
    //return 0;
}

/*
    Execute when do_fork returns. The return value is the newly created PID.
    The PID can be accessed in the ax register. We use the PID to find the
    related task before we log data in our circular buffer
*/
static int ret_do_fork(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    // Didn't find a way to find the task corresponding to a pid.
    // Use helper function to walk task list

	// task_struct defined in sched.h

	/*   char comm[TASK_COMM_LEN];  executable name excluding path
	                     - access with [gs]et_task_comm (which lock it with task_lock())
	                     - initialized normally by setup_new_exec */

	char execPath[TASK_COMM_LEN];
	//unsigned char hmac[SHA_256_MD_LEN];
    struct task_struct *task = find_task_from_pid(regs->ax);

    printk("ret_do_fork");

#if 0
    if(g_bProtectMode)
    {
    	getFileSignature(get_task_com(execPath, task), hmac);
    	if(!inDB(hmac))
    	{
    		terminateTask(task->pid);
    	}
    }
    else
    {
    	getFileSignature(get_task_com(execPath, task), hmac);
    	addToDB(hmac);
    }
#endif

    return 0;
}

static struct kretprobe kret_do_fork = {
    .handler        = ret_do_fork,
    .kp = {
        .symbol_name    = "do_fork",
        .fault_handler  = probe_handler_fault,
    },
    // Probe up to 1 instance concurrently.
    .maxactive      = 1,
};
//=============================== End do_fork handlers on exit ==========================


//=============================== Begin free_task handlers on entry =====================
/*
    Execute when free_task is called. the only parameter passed is the task_struct being
    terminated. Pass the task to be recorded in the circular buffer.
*/
static void jfree_task(struct task_struct *task)
{
    printk("jfree_task");

    // Always end with a call to jprobe_return().
    jprobe_return();
    // return 0;
}

static struct jprobe jprobe_free_task = {
    .entry          = jfree_task,
    .kp = {
        .symbol_name    = "free_task",
        .fault_handler  = probe_handler_fault,
    },
};
//========================= End free_task handlers on entry =============================


int probe_processes_init(void)
{
	int iRet = 0;
	int ijprobe_free_task = -1;
	int iret_do_fork = -1;
	int iproc_file = -1;

	trace(DETAIL_LEVEL, "Entering, init_module(); ");

	//crypto_hmac_create_ctx(CRYPTO_HASH_ALGID_SHA256,key,sizeof(key),&c);

	// Register hook on the entry of free_task kernel method
	if ((ijprobe_free_task = register_jprobe(&jprobe_free_task)) < 0)
	{
		trace(ERROR_LEVEL, "register_jprobe(%s) failed, returned %d\n",
				jprobe_free_task.kp.symbol_name, ijprobe_free_task);
		iRet = ijprobe_free_task;
		break;
	}

	trace(DETAIL_LEVEL, "On call of %s at %p, handler addr %p\n",
			jprobe_free_task.kp.symbol_name, jprobe_free_task.kp.addr,
			jprobe_free_task.entry);

	// Register hook on the exit of do_fork kernel method
	if ((iret_do_fork = register_kretprobe(&kret_do_fork)) < 0)
	{
		trace(ERROR_LEVEL, "register_kretprobe(%s) failed, returned %d\n",
				kret_do_fork.kp.symbol_name, iret_do_fork);
		iRet = iret_do_fork;
		break;
	}

	trace(DETAIL_LEVEL, "On return of %s at %p, handler addr %p\n",
			kret_do_fork.kp.symbol_name, kret_do_fork.kp.addr,
			kret_do_fork.handler);

	return iRet;

}


/*
    Module exit point
    Release all resource acquired during module init
*/
void probe_processes_exit(void)
{
    trace(DETAIL_LEVEL, "Entering cleanup_module()\n");

    //(void) crypto_hmac_destroy_ctx(c);

    // Delete databases


    trace(INFO_LEVEL, "Exiting cleanup_module()\n");
}

module_init(probe_processes_init);
module_exit(probe_processes_exit);

MODULE_AUTHOR("Pete Jenney");
MODULE_LICENSE("GPL");  // Kernel isn't tainted

