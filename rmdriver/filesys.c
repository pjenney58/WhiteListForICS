/*
 *  Kernel file I/O routines
 *  Cobbled together by Pete Jenney, 2013
 *
 *  Copyright (c) 2014 by Resilient Machines, Inc.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/fs.h>

/*
 *  18 May 2014 - MISRA compliance work -- [ISO 26262] sing[e entry and exit for all functions.
 */

struct file* file_open(const int8_t* path, int32_t flags, int32_t rights)
{
    struct file* filp = NULL;
    mm_segment_t oldfs;
    int32_t err = 0;

    if(unlikely(!path))
    {
    	goto out;
    }

    oldfs = get_fs();
    set_fs(get_ds());

    filp = filp_open(path, flags, rights);

    set_fs(oldfs);

    if(IS_ERR(filp)) 
    {
        err = PTR_ERR(filp);
        filp = NULL;
    }

 out:
    return filp;
}

uint32_t file_llseek(struct file *filp, int64_t offset, int32_t whence)
{
    mm_segment_t oldfs;
    uint32_t ret = 0;

    if(unlikely(!filp))
    {
    	goto out;
    }

    oldfs = get_fs();
    set_fs(get_ds());

    ret = (uint32_t)vfs_llseek(filp, offset, whence);

    set_fs(oldfs);

 out:
    return ret;
}

int32_t file_read(struct file* filp, uint64_t offset, uint8_t* data, uint32_t size)
{
    mm_segment_t oldfs;
    int32_t ret = 0;

    if(unlikely(!filp || !data))
    {
    	goto out;
    }

    oldfs = get_fs();
    set_fs(get_ds());

    ret = (int32_t)vfs_read(filp, data, size, &offset);

    set_fs(oldfs);

 out:
    return ret;
}  

int32_t file_write(struct file* filp, uint64_t offset, uint8_t* data, uint32_t size)
{
    mm_segment_t oldfs;
    int32_t ret = 0;

    if(unlikely(!filp || !data))
    {
    	goto out;
    }

    oldfs = get_fs();
    set_fs(get_ds());

    ret = (int32_t)vfs_write(filp, data, size, &offset);

    set_fs(oldfs);

out:
    return ret;
}

void file_close(struct file* filp)
{
    filp_close(filp, NULL);
}
