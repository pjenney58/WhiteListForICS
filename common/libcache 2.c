/*
 * libcache.c
 *
 *  Created on: Apr 28, 2014
 *      Author: Peter H. Jenney
 *      COpyright (c) 2014 by Resilient Machines, Inc.
 */

#include "aerolock.h"

/*****************************************************************************************************************
 *  Functions to extract data from ld.so.cache and create a linked list
 */

int32_t noLocateDB = 0;
#define LIB_DLL       0
#define LIB_ELF       1
#define LIB_ELF_LIBC5 2
#define LIB_ELF_LIBC6 3

#define FUNC_VERS    0
#define FUNC_LDD     1
#define FUNC_LINK    2
#define FUNC_LINK_AND_CALLBACK 3

#define LDSO_CACHE_MAGIC "ld.so-"
#define LDSO_CACHE_MAGIC_LEN (sizeof LDSO_CACHE_MAGIC -1)
#define LDSO_CACHE_VER "1.7.0"
#define LDSO_CACHE_VER_LEN (sizeof LDSO_CACHE_VER -1)

typedef struct {
    char    magic   [LDSO_CACHE_MAGIC_LEN];
    char    version [LDSO_CACHE_VER_LEN];
    int32_t nlibs;
} header_t;

typedef struct {
	int32_t flags;
	int32_t sooffset;
	int32_t liboffset;
} libentry_t;

typedef struct liblist  /* <- TODO: MISRA 2012 C Issue */
{
	int32_t flags;
	int32_t sooffset;
	int32_t liboffset;
    char*   soname;
    char*   libname;
    struct liblist *next;
} liblist_t;

typedef struct libpath  /* <- TODO: MISRA 2012 C Issue */
{
    char libname[256];
    char fullpath[256];
    struct libpath* next;
    struct libpath* prev;
} libpath_t, *plibpath_t;

libpath_t libListHead = {{""}, {""}, NULL, NULL};

char* findLibNode(char* name)
{
    plibpath_t c = &libListHead;

    if(!name)
    {
        return NULL;
    }

    if(c->libname[0])
    {
        if(!strcmp(name, c->libname))
        {
            return(c->fullpath);
        }
    }

    while(c->next && strcmp(name, c->libname))
    {
        c = c->next;
     }

    if(!strcmp(name, c->libname))
    {
        return(c->fullpath);
    }

    return NULL;
}

int32_t insertLibNode(char* name, char* fullpath)
{
    plibpath_t c = &libListHead;

#ifdef __LINUX__
    if(findLibNode(name) != NULL)
    {
        return 1;
    }
#endif

    if(!c->prev)
    {
        strcpy(libListHead.libname, name);
        strcpy(libListHead.fullpath, fullpath);
        libListHead.prev = &libListHead;
        return 0;
    }

    while(c->next && strcmp(name, c->libname))
    {
        c = c->next;
    }

    /*
     * Append new node
     */
    if(!c->next)
    {

        /* MISRA 2012 deviation -- one has to allocate space for a new node */
        c->next = (plibpath_t)malloc(sizeof(libpath_t));
        if(!c->next)
        {
            return 0;
        }

        c->next->prev = c;
        c->next->next = NULL;
        strcpy(c->next->libname, name);
        strcpy(c->next->fullpath, fullpath);
        return 1;
    }
    else  /* Insert node */
    {
        /* MISRA 2012 deviation -- one has to allocate space for a new node */
        plibpath_t tmp = (plibpath_t)malloc(sizeof(libpath_t));
        if(!tmp)
        {
            return 0;
        }

        strcpy(tmp->libname, name);
        strcpy(tmp->fullpath, fullpath);
        tmp->next = c->next;
        tmp->prev = c;
        (tmp->next)->prev = tmp;
        c->next = tmp;
    }

    return 1;
}

#ifdef __LINUX__

int32_t buildLibList()
{
    caddr_t c;
    struct stat st;
    int fd = 0;
    char *strs;
    header_t *header;
    libentry_t *libent;

    if(stat("/etc/ld.so.cache", &st) != -1)
    {
        if((fd = open("/etc/ld.so.cache", O_RDONLY)) > 0)
        {
            if ((c = mmap(0, st.st_size, PROT_READ, MAP_SHARED ,fd, 0)) != (caddr_t)-1)
            {
                close(fd);
                header = (header_t *)c;
                libent = (libentry_t *)(c + sizeof (header_t));

                /* Get the offset to the strings in the file */
                strs = (char *)&libent[header->nlibs];

                for (fd = 0; fd < header->nlibs; fd++)
                {
                    insertLibNode(strs + libent[fd].sooffset, strs + libent[fd].liboffset);
#if 0
                    if(maximumVerbosity)
                    {
                        syslog(LOG_DEBUG, "buildLibList: %s -> %s ", strs + libent[fd].sooffset, strs + libent[fd].liboffset);
                    }
#endif
                }

             munmap (c,st.st_size);

            }
            else
            {
                return 0;
            }
        }
        else
        {
            return 0;
        }
    }
    else
    {
        return 0;
    }

    return 1;
}
#else
#include <ftw.h>

int32_t lib_list(const char *name, const struct stat *status, int type, struct FTW *ftwbuf)
{
    if(type == FTW_F)
    {
        insertLibNode((char*)(name + ftwbuf->base), (char*)name);
    }

    return 0;
}

int32_t buildLibList()
{
    char   ld_lib_path[512];
    char*  lp = NULL;
    int    rc = 0;

    lp = getenv("LD_LIBRARY_PATH");
    if(lp)
    {
        strcpy(ld_lib_path, lp);
    }
    else
    {
        return 0;
    }

    lp = strtok(ld_lib_path, ":");
    if(!lp)
    {
        return 0;
    }

    while(lp)
    {
        nftw(lp, lib_list, 25, FTW_PHYS | FTW_DEPTH);
        lp = strtok(NULL, ":");
    }

    return 1;
}

#endif


