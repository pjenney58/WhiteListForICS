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
 * list.c
 *
 * Description
 * --------------
 *  A collection of  utilities including an rbtree for hmac storage, and an rbtree for the system Cache
 *
 * Author
 * -------
 * Peter H. Jenney, Security Innovation, Inc.
 *
 *
 */


#ifdef __LINUX__
#pragma GCC diagnostic ignored "-Wpointer-sign"
#pragma GCC diagnostic push
#endif

#include "aerolock.h"
//#include <arpa/inet.h>

struct rb_root __rb_name_tree;
struct rb_root __rb_hmac_tree;
struct rb_root __rb_cache_tree;
struct rb_root __rb_item_tree;
struct rb_root __rb_item_tree_engines;
struct rb_root __rb_item_tree_exceptions;
struct rb_root __rb_item_tree_forbidden;
struct rb_root __rb_item_tree_shell_commands;
struct rb_root __rb_lib_list;
int32_t        __use_local_trees = 0;
uint32_t       __node_count = 0;

/*
 * __name_list operations
 */
static int32_t __rb_insert_name(struct rb_root* __root, struct __name_list* __data)
{
    struct rb_node     **__new   = NULL,
                          *__parent = NULL;
    struct __name_list *__this   = NULL;
    int32_t             __result = FALSE;
    int32_t             __retval = FALSE;

    if(!__root || !__data)
    {
        goto out;
    }

    __new = &(__root->rb_node);
    if(!__new)  // Need except here because if it passed through, the function would return TRUE
    {
        goto out;
    }

      /* Figure out where to put new node */
    while (*__new)
    {
        __this = rb_entry(*__new, struct __name_list, node);
        if(!__this)
        {
            goto out;
        }

        __result = strcmp(__data->__short_name, __this->__short_name);

        __parent = *__new;

        if(__result < 0)
        {
            __new = &((*__new)->rb_left);
        }
        else if(__result > 0)
        {
            __new = &((*__new)->rb_right);
        }
        else
        {
            goto out;
        }
    }

    __retval = TRUE;

    /* Add new node and rebalance tree. */
    rb_link_node(&__data->node, __parent, __new);
    rb_insert_color(&__data->node, __root);

out:

    return __retval;
}

static struct __name_list* __rb_lookup_name(struct rb_root* __root, char *__string)
{
    struct rb_node*      __node   = NULL;
    struct __name_list*  __retval = NULL;
    struct  __name_list* __data   = NULL;
    int32_t __result              = 0;

    if(!__root || !__string)
    {
        goto out;
    }

    __node = __root->rb_node;

    while (__node)
    {
        __data = rb_entry(__node, struct __name_list, node);
        if(!__data)
        {
            goto out;
        }

        __result = strcmp(__string, __data->__short_name);

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

    return __retval;
}

int32_t __rb_init_name_list()
{
    int8_t* __short_name       = NULL;
    int8_t* __long_name        = NULL;
    struct  __name_list* __new = NULL;
    int32_t __retval           = FALSE;

    if(__use_local_trees)
    {
        if((__short_name = (int8_t*)malloc(256)) == NULL)
        {
            goto out;
        }

        if((__long_name = (int8_t*)malloc(512)) == NULL)
        {
            goto out;
        }

         __rb_name_tree = RB_ROOT;

         while(__bdb_get_next_name(__short_name, __long_name))
         {
             /* MISRA 2012 deviation -- one has to allocate space for a new node */
             __new = (struct __name_list*)malloc(sizeof(struct __name_list));
             if(!__new)
             {
                goto out;
             }

             /*
              * MISRA 2012 deviation -- filenames are variable length and its more efficient to
              * allocate space on the fly than to rely on  a big fixed length buffer
              */
             __new->__long_name = (char*)malloc(strlen((char*)__long_name) + 1);
             if(!__new->__long_name)
             {
                 goto out;
             }

             __new->__short_name = (char*)malloc(strlen((char*)__short_name) + 1);
             if(!__new->__short_name)
             {
                 goto out;
             }

             strncpy(__new->__short_name, __short_name, strlen((char*)__short_name));
             strncpy(__new->__long_name, __long_name, strlen((char*)__long_name));

             if(!__rb_insert_name(&__rb_name_tree, __new))
             {
                 free(__new->__long_name);
                 __new->__long_name = NULL;

                 free(__new->__short_name);
                 __new->__short_name = NULL;

                 free(__new);
                 __new = NULL;

                 goto out;
             }
         }

         __retval = TRUE;

out:

        if(__short_name)
        {
            free(__short_name);
            __short_name = NULL;
        }

        if(__long_name)
        {
            free(__long_name);
            __long_name = NULL;
        }
    }

    return __retval;
}

void __rb_flush_name_list(void)
{
     struct rb_node*    __next = NULL;
     struct __name_list* __ret = NULL;

    if(__use_local_trees)
    {
        __next = rb_first(&__rb_name_tree);
        while(__next)
        {
            __ret = __rb_lookup_name(&__rb_name_tree, (char*)rb_entry(__next, struct __name_list, node)->__short_name);

            if(__ret)
            {
                __next = rb_next(__next);

                rb_erase(&__ret->node, &__rb_name_tree);

                if(__ret->__long_name)
                {
                    free(__ret->__long_name);
                    __ret->__long_name = NULL;
                }

                if(__ret->__short_name)
                {
                    free(__ret->__short_name);
                    __ret->__short_name = NULL;
                }

                if(__ret)
                {
                    free(__ret);
                    __ret = NULL;
                }

                __node_count--;
            }
        }
    }

    return;
}

/*
 * OPTION: Instead of using an rbtree to represent the name resolution database, the decision was made
 * to do direct calls to the database.  Not using the rbtree saves a ton of memory.
 */
int32_t __lookup_long_name(int8_t* __name, int8_t* __long_name, int32_t __buf_len)
{
    int32_t __retval          = ERROR;
    struct __name_list* __ret = NULL;

    if(!__name | !__long_name)
    {
        goto out;
    }

    if(__use_local_trees)
    {
        __ret = __rb_lookup_name(&__rb_name_tree, __name);
        if(__ret)
        {
            __retval = NOERROR;
            strncpy(__long_name, __ret->__long_name, __buf_len);
        }
    }
    else
    {
         if(__bdb_find_long_name(__name, __long_name))
         {
             __retval = NOERROR;
         }
    }

out:

     return __retval;
}

/*******************************************************************************************/
/*
 * _hmac_list operations
 */
static int32_t __rb_insert_hmac(struct rb_root* __root, struct __hmac_list* __data)
{
      struct rb_node     **__new   = NULL,
                         *__parent = NULL;
      struct __hmac_list *__this   = NULL;
      int32_t             __result = 0;
      int32_t             __retval = FALSE;

      if(!__root || !__data)
      {
          goto out;
      }

      __new   = &(__root->rb_node);
      if(!__new)
      {
          goto out;
      }

      /* Figure out where to put new node */
      while (* __new)
      {
          __this = rb_entry(*__new, struct __hmac_list, node);
          if(!__this)
          {
              goto out;
          }

          __result = memcmp(__data->__hmac, __this->__hmac, HMAC256_LEN);

          __parent = *__new;
          if (__result < 0)
          {
              __new = &((*__new)->rb_left);
          }
          else if (__result > 0)
          {
              __new = &((*__new)->rb_right);
          }
          else
          {
              goto out;
          }
      }

    __retval = TRUE;

    /* Add new node and rebalance tree. */
    rb_link_node(&__data->node, __parent, __new);
    rb_insert_color(&__data->node, __root);

out:

    return __retval;
}

static struct __hmac_list* __rb_lookup_hmac(struct rb_root* __root, uint8_t* __hmac)
{
    struct rb_node*     __node   = NULL;
    struct __hmac_list* __data   = NULL;
    struct __hmac_list* __retval = NULL;
    int32_t             __result = 0;

    if(!__root || !__hmac)
    {
        syslog(LOG_DEBUG, "__rb_lookup_hmac() was passed bogus parameters");
        goto out;
    }

    __node = __root->rb_node;

    while (__node)
    {
        __data = rb_entry(__node, struct __hmac_list, node);
        if(!__data)
        {
            syslog(LOG_DEBUG, "__rb_lookup_hmac() __rb_lookup_hmac() failed to get rb_entry");
            goto out;
        }

        __result = memcmp(__hmac, __data->__hmac, HMAC256_LEN);

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

    return __retval;
}

int32_t __rb_init_hmac_list(void)
{
    uint8_t* __hmac           = NULL;
    int8_t*  __short_name     = NULL;
    struct __hmac_list* __new = NULL;
    int32_t __retval          = TRUE;

    if(__use_local_trees)
    {
        /*
         *  MISRA C2012 deviation - Secure coding requires data be on the heap and not
         *  the stack. Rule 21.3 is Decidable and our decision is to go the secure path.
         */
        __hmac = (uint8_t*)malloc(HMAC256_LEN);
        if(!__hmac)
        {
            __retval = 0;
            goto out;
        }

        __short_name = (int8_t*)malloc(256);
        if(!__short_name)
        {
            __retval = 0;
            goto out;
        }

        __rb_hmac_tree = RB_ROOT;

        while(__bdb_get_next_hmac(__short_name, __hmac))
        {
            /*
             *  MISRA C2012 deviation -- one has to allocate space for a new node. Rule 21.3, the use of dynamic allocation
             * is Required but Decidable and in this case the decision is to use dynamic memory.
             */
            __new = (struct __hmac_list*)malloc(sizeof(struct __hmac_list));
            if(!__new)
            {
                __retval = 0;
                goto out;
            }

            memcpy(__new->__hmac, __hmac, HMAC256_LEN);

            /*
             * Try to insert the new HMAC.  If it already exists, release the new node and
             * address the dangling pointer
             */
            if(!__rb_insert_hmac(&__rb_hmac_tree, __new))
            {
                free(__new);
                __new = NULL;
                goto out;
            }
            else
            {
                __node_count++;
            }
        }
    }

    syslog(LOG_DEBUG, "Inserted %u Nodes", __node_count);

out:
    if(__hmac)
    {
        free(__hmac);
        __hmac = NULL;
    }

    if(__short_name)
    {
        free(__short_name);
        __short_name = NULL;
    }

    return __retval;
}

uint8_t* __lookup_hmac(uint8_t* __hmac, int32_t __fd, pid_t __current_pid)
{
    struct __hmac_list* __ret = NULL;
    PidStack __pids           = {0};
    uint8_t* __retval         = NULL;

    if(!__hmac)
    {
        goto out;
    }

    if(__use_local_trees)
    {
        __ret = __rb_lookup_hmac(&__rb_hmac_tree, __hmac);
        if(__ret)
        {
            __retval = __ret->__hmac;
            goto out;
        }
    }
    else
    {
        syslog(LOG_DEBUG, "__lookup_hmac() TID:[0x%08lx] reaching out to kernel with [%d] for HMAC using fd(0x%X)", pthread_self(), (int32_t)__current_pid, __fd);

        __pids.cmd = LOOKUP_HMAC;
        __pids.pid = __current_pid;
        memcpy(__pids.__hmac, __hmac, HMAC256_LEN);

        if(write(__fd, &__pids, sizeof(__pids)) > 0)
        {
            syslog(LOG_DEBUG, "__lookup_hmac() TID:[0x%08lx] succeeded with (%d) using fd(0x%X)", pthread_self(), (int32_t)__current_pid, __fd);
            __retval = __hmac;
        }
        else
        {
            syslog(LOG_DEBUG, "__lookup_hmac() TID:[0x%08lx] failed with (%d) using fd(0x%X)", pthread_self(), (int32_t)__current_pid, __fd);
        }
    }

out:

    return __retval;
}

void __rb_flush_hmacs(void)
{
     struct rb_node*     __next = NULL;
     struct __hmac_list* __ret  = NULL;

    if(__use_local_trees)
    {
        __next = rb_first(&__rb_hmac_tree);

        while(__next)
        {
            __ret = __rb_lookup_hmac(&__rb_hmac_tree, rb_entry(__next, struct __hmac_list, node)->__hmac);
            if(__ret)
            {
                __next = rb_next(__next);

                rb_erase(&__ret->node, &__rb_hmac_tree);
                if(__ret)
                {
                    free(__ret);
                    __ret = NULL;
                }

                __node_count--;
            }
        }

        syslog(LOG_DEBUG, "Left %u unfreed nodes", __node_count);
    }

    return;
}



/***************************************************************************************************
 * HMAC cache for __get_signature()
 */
static int32_t __rb_insert_cache(struct rb_root* __root, struct __item_name* __data)
{
      struct rb_node     **__new   = NULL,
                         *__parent = NULL;
      struct __item_name *__this   = NULL;
      int32_t            __result  = 0;
      int32_t            __retval  = FALSE;

      if(!__root || !__data)
      {
          goto out;
      }

      __new = &(__root->rb_node);
      if(!__new)
      {
          goto out;
      }

      /* Figure out where to put new node */
      while (*__new)
      {
          __this = rb_entry(*__new, struct __item_name, node);
          if(!__this)
          {
              goto out;
          }

          __result = strcmp(__data->__file, __this->__file);

          __parent = *__new;

          if(__result < 0)
          {
              __new = &((*__new)->rb_left);
          }
          else if(__result > 0)
          {
              __new = &((*__new)->rb_right);
          }
          else
          {
              goto out;
          }
      }

      __retval = TRUE;

      /* Add new node and rebalance tree. */
      rb_link_node(&__data->node, __parent, __new);
      rb_insert_color(&__data->node, __root);

out:

    return __retval;
}

static struct __item_name* __rb_lookup_cache(struct rb_root* __root, const int8_t* __search_string)
{
    struct rb_node*     __node   = NULL;
    struct __item_name* __retval = NULL;
    struct __item_name* __data   = NULL;
    int32_t             __result = 0;

    if(!__root || ! __search_string)
    {
        goto out;
    }

    __node = __root->rb_node;

    while (__node)
    {
        __data = rb_entry(__node, struct __item_name, node);
        if(!__data)
        {
            goto out;
        }

        /*result = strncmp(__search_string, data->__file, strlen(__search_string)); */
        __result = strcmp(__search_string, __data->__file);

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

    return __retval;
}

int32_t __rb_init_cache(void)
{
    __rb_cache_tree = RB_ROOT;
    return 1;
}

int32_t __add_to_cache(const char* __name, unsigned char* __hmac)
{
    int32_t __retval          = FALSE;
    struct __item_name* __new = NULL;

    if(!__name || !__hmac)
    {
        goto out;
    }
    /*
     * MISRA C2012 deviation -- one has to allocate space for a new node. The use of dynamic allocation
     * is Required but Decidable and in this case the decision is to use dynamic memory.
     */
    __new = (struct __item_name* )malloc(sizeof(struct __item_name));
    if(!__new)
    {
        goto out;
    }

    /* 
     * MISRA C2012 deviation -- file lengths are variable length and its more efficient to allocate what we need
     * rather than use a big fixed length buffer. he use of dynamic allocation
     * is Required but Decidable and in this case the decision is to use dynamic memory.
     */
    __new->__file = (char*)malloc(strlen(__name) + 1);
    if(!__new->__file)
    {
        free(__new);
        __new = NULL;
        goto out;
    }

    strncpy(__new->__file, __name, strlen(__name)+1);
    memcpy(__new->__hmac, __hmac, HMAC256_LEN);

    if(!__rb_insert_cache(&__rb_cache_tree, __new))
    {
        free(__new->__file);
        __new->__file = NULL;

        free(__new);
        __new = NULL;

        goto out;
    }

    __retval = TRUE;

out:

    return __retval;
}

int32_t __lookup_cache(const char* __name, unsigned char* __hmac)
{
    struct __item_name* __ret    = NULL;
    int32_t             __retval = FALSE;

    __ret = __rb_lookup_cache(&__rb_cache_tree, __name);
    if(__ret)
    {
        memcpy(__hmac, __ret->__hmac, HMAC256_LEN);
        __retval = TRUE;
    }

    return __retval;
}

static int32_t __delete_node(int8_t* __name)
{
    int32_t              __retval = FALSE;
    struct  __item_name* __found  = NULL;

    if(!__name)
    {
        goto out;
    }

    __found = __rb_lookup_cache(&__rb_cache_tree, __name);

    if(__found)
    {
        /* Unlink from tree */
        rb_erase(&__found->node, &__rb_cache_tree);

        /* Release memory */
        if(__found && __found->__file)
        {
            free(__found->__file);
            __found->__file = NULL;

            free(__found);
            __found = NULL;

            __retval = TRUE;
        }
    }

out:

    return __retval;
}

int32_t __delete_from_cache(char* __name)
{
    return  __delete_node(__name);
}

void __rb_flush_cache(void)
{
    struct rb_node*     __next        = NULL;
    struct __item_name* __rbtree_node = NULL;

    __next = rb_first(&__rb_cache_tree);

    while(__next)
    {
        __rbtree_node = rb_entry(__next, struct __item_name, node);
        if(__rbtree_node)
        {
            __next = rb_next(&__rbtree_node->node);

            rb_erase(&__rbtree_node->node, &__rb_cache_tree);

            if(__rbtree_node->__file)
            {
                free(__rbtree_node->__file);
                __rbtree_node->__file = NULL;
            }

            if(__rbtree_node)
            {
                free(__rbtree_node);
                __rbtree_node = NULL;
            }
        }
    }

    return;
}

/*
 * __item_list management
 */

int8_t* __list_itemtype_string[] =
{
        "engine",
        "shell_command",
        "forbidden",
        "exception",
        NULL
};

int32_t __rb_lookup_item(struct rb_root* __root, __list_itemtype_t __class_selector, int8_t* __item_name)
{
    struct rb_node *    __node         = NULL;
    struct __item_list* __data         = NULL;
    int32_t             __retval       = FALSE;
    int32_t             __result       = 0;

    if(!__root || !__item_name)
    {
        goto out;
    }

    __node = __root->rb_node;

    while (__node)
    {
        __data = rb_entry(__node, struct __item_list, __node);
        if(!__data)
        {
            goto out;
        }

        /*
         * The list will have things like python, sh, java etc. If the parser finds python2.7 and the compare
         * uses the length of the __item_name in the list, then python2.7 will match python and be correct.  Unfortunately
         * this scheme also returns positive for 'shell', finding 'sh', which leads to an error.
         */
        __result = memcmp(__item_name, __data->__item_name, strlen(__data->__item_name));

        /*
         * PHJ need to trap erroneous substrings !!!!
         */

        if (__result < 0)
        {
            __node = __node->rb_left;
        }
        else if(__result > 0)
        {
            __node = __node->rb_right;
        }
        else
        {
			__retval    = TRUE;
			__item_name = __data->__item_name;  // Give the caller a chance to parse the result
			goto out;
        }
    }

out:

    return __retval;
}

int32_t __rb_insert_item(struct rb_root* __root, struct __item_list* __new_item)
{
    int32_t            __retval  = FALSE;
    int32_t            __result  = 0;
    struct rb_node     **__new   = NULL,
                       *__parent = NULL;
    struct __item_list *__this   = NULL;

    if(!__root || !__new_item)
    {
        goto out;
    }

    __new = &(__root->rb_node);
    if(!__new)
    {
        goto out;
    }

    /* Figure out where to put new node */
    while (*__new)
    {
        __this = rb_entry(*__new, struct __item_list, __node);
        if(!__this)
        {
            goto out;
        }

        __result = strcmp(__new_item->__item_name, __this->__item_name);

        __parent = *__new;
        if (__result < 0)
        {
            __new = &((*__new)->rb_left);
        }
        else if (__result > 0)
        {
            __new = &((*__new)->rb_right);
        }
        else
        {
            goto out;
        }
    }

    __retval = TRUE;

    /* Add new node and rebalance tree. */
    rb_link_node(&__new_item->__node, __parent, __new);
    rb_insert_color(&__new_item->__node, __root);

out:

    return __retval;
}

int32_t __rb_add_to_item_list(struct rb_root* __root, __list_itemtype_t __class_selector, int8_t* __new_item_name)
{
    int32_t __retval = TRUE;

     /*
     * MISRA C2012 deviation -- one has to allocate space for a new node. The use of dynamic allocation
     * is Required but Decidable and in this case the decision is to use dynamic memory.
     */
    struct __item_list* __new = (struct __item_list* )malloc(sizeof(struct __item_list));
    if(!__new)
    {
        __retval = FALSE;
        goto out;
    }

    /*
     * MISRA C2012 deviation -- file lengths are variable length and its more efficient to allocate what we need
     * rather than use a big fixed length buffer. he use of dynamic allocation
     * is Required but Decidable and in this case the decision is to use dynamic memory.
     */
    __new->__item_name = (char*)malloc(strlen(__new_item_name) + 1);
    if(!__new->__item_name)
    {
        free(__new);
        __new    = NULL;
        __retval = FALSE;

        goto out;
    }

    memset(__new->__item_name, 0, strlen(__new_item_name) + 1);

    strncpy(__new->__item_name, __new_item_name, strlen(__new_item_name));
    __new->__class_selector = __class_selector;

    if(!__rb_insert_item(__root, __new))
    {
        free(__new->__item_name);
        __new->__item_name = NULL;

        free(__new);
        __new = NULL;

        __retval = FALSE;
    }

out:

    return __retval;
}

int32_t __rb_flush_item_list(void)
{
    return FALSE;
}

/*
 *    File format:
 *
 *    #  - Line is a comment
 *    [Class selector string]
 *    Name String (rep as needed)
 *    EOF
 */
int32_t __rb_init_item_list(void)
{
    int32_t     __retval     = ERROR;
    int32_t     __result     = 0;
    int32_t     __idx        = 0;
    int32_t     __fd         = 0;
    int8_t*     __buf        = NULL;
    int8_t*     __cp         = NULL;
    int8_t*     __string     = NULL;
    struct stat __sb         = {0};
    __list_itemtype_t __lit  = __empty_list;
    struct rb_root*   __root = NULL;

     __rb_item_tree_engines        = RB_ROOT;
     __rb_item_tree_exceptions     = RB_ROOT;
     __rb_item_tree_forbidden      = RB_ROOT;
     __rb_item_tree_shell_commands = RB_ROOT;

     if(stat(RMI_CFG, &__sb) == -1)
     {
         goto out;
     }

    __fd = open(RMI_CFG, O_RDONLY);
    if(__fd > 0)
    {
        __buf = (int8_t*)malloc(__sb.st_size +1);
        if(!__buf)
        {
            goto out;
        }

        memset(__buf, '\0', __sb.st_size + 1);

        __cp = __buf;

        __result = read(__fd, __buf, __sb.st_size);

        // scoot up to the first section
        __cp = strchr(__buf, '[');

        while(__cp)
        {
            if(*__cp == '[')
            {
                __string = __cp + 1;    // [config_section_string]

                while(*__cp != ']')
                {
                    __cp++;
                }

                *__cp = '\0';
                __cp++;

                // determine section
                for(__idx = 0; __list_itemtype_string[__idx] != NULL; __idx++)
                {
                    if(!strcmp(__string, "engine"))
                    {
                        __lit  = __engine_list;
                        __root = &__rb_item_tree_engines;
                    }
                    else if(!strcmp(__string, "shell_command"))
                    {
                        __lit  = __shell_command_list;
                        __root = &__rb_item_tree_shell_commands;
                    }
                    else if(!strcmp(__string, "forbidden"))
                    {
                        __lit  = __forbidden_list;
                        __root = &__rb_item_tree_forbidden;
                    }
                    else if(!strcmp(__string, "exception"))
                    {
                        __lit  = __exception_list;
                        __root = &__rb_item_tree_exceptions;
                    }
                    else
                    {
                        __lit = __empty_list;
                    }

                    if(__lit != __empty_list)
                    {
                        while(*__cp && *__cp != '[')
                        {
                            __string = __cp;

                            // find the end of the string -- they should always end with \n
                            while(*__cp && *__cp != '\n' && *__cp != '[')
                            {
                                __cp++;
                            }

                            if(*__cp && *__cp == '\n')
                            {
                                *__cp = '\0';
                                __cp++;

                                if(strlen(__string) > 1)
                                {
                                    __rb_add_to_item_list(__root, __lit, __string);
                                }
                            }
                        }

                        if(*__cp == '\0')
                        {
                            __cp = NULL;
                        }

                        break;  // break out of the for loop
                    }
                }
            }
        }
    }

out:

    if(__buf)
    {
        free(__buf);
        __buf = NULL;
    }

    if(__fd > 0)
    {
        close(__fd);
        __fd = 0;
    }

    return __retval;
}

int32_t __lookup_item(__list_itemtype_t __class_selector, int8_t* __item_name)
{
	struct rb_root* __root   = {0};
	int32_t         __retval = FALSE;

	switch(__class_selector)
	{
	case __engine_list:
		__root = &__rb_item_tree_engines;
		break;

	case __exception_list:
		__root = &__rb_item_tree_exceptions;
		break;

	case __shell_command_list:
		__root = &__rb_item_tree_shell_commands;
		break;

	case __forbidden_list:
		__root = &__rb_item_tree_forbidden;
		break;

	default:
		goto out;

	}

    __retval = __rb_lookup_item(__root, __class_selector, __item_name);

out:

    return __retval;

}

int32_t __rmi_initialize_lists(void)
{
    __rb_init_hmac_list();
    __rb_init_name_list();
    __rb_init_item_list();
    __rb_init_cache();

    return 1;
}

int32_t __rmi_destroy_lists(void)
{
    __rb_flush_cache();
    __rb_flush_hmacs();
    __rb_flush_name_list();
    __rb_flush_item_list();

    return 1;
}

#ifdef __LINUX__
#pragma GCC diagnostic pop
#endif


