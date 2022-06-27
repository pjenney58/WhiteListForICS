#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xc4e4328b, "module_layout" },
	{ 0xb3eb2c5c, "d_path" },
	{ 0xa475964c, "cdev_del" },
	{ 0xb84acc53, "kmalloc_caches" },
	{ 0x12da5bb2, "__kmalloc" },
	{ 0xabdba397, "cdev_init" },
	{ 0x72df2f2a, "up_read" },
	{ 0x13d0adf7, "__kfifo_out" },
	{ 0x76ebea8, "pv_lock_ops" },
	{ 0xd0d8621b, "strlen" },
	{ 0xc068440e, "__kfifo_alloc" },
	{ 0xc8b57c27, "autoremove_wake_function" },
	{ 0x3fa3578f, "find_vpid" },
	{ 0x9d22af04, "register_kretprobe" },
	{ 0x33f8d9bb, "vfs_llseek" },
	{ 0xde909a57, "device_destroy" },
	{ 0x3a7dfea0, "filp_close" },
	{ 0x7485e15e, "unregister_chrdev_region" },
	{ 0x8ee86ba, "kthread_create_on_node" },
	{ 0xe2d5255a, "strcmp" },
	{ 0xd0f0d945, "down_read" },
	{ 0xece784c2, "rb_first" },
	{ 0xf2516576, "vfs_read" },
	{ 0x2bc95bd4, "memset" },
	{ 0xf97456ea, "_raw_spin_unlock_irqrestore" },
	{ 0x7ce55186, "current_task" },
	{ 0x50eedeb8, "printk" },
	{ 0xdc52de64, "kthread_stop" },
	{ 0x5152e605, "memcmp" },
	{ 0x4d9b652b, "rb_erase" },
	{ 0x2f287f0d, "copy_to_user" },
	{ 0xf0f060b0, "unregister_kretprobe" },
	{ 0xb4390f9a, "mcount" },
	{ 0x1e6d26a8, "strstr" },
	{ 0x655c0e68, "device_create" },
	{ 0x934873, "kill_pid" },
	{ 0x9b27a557, "cdev_add" },
	{ 0x93fca811, "__get_free_pages" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x4292364c, "schedule" },
	{ 0x6b2dc060, "dump_stack" },
	{ 0x4a03e219, "wake_up_process" },
	{ 0x834c1d11, "kmem_cache_alloc_trace" },
	{ 0x67f7403e, "_raw_spin_lock" },
	{ 0x21fb443e, "_raw_spin_lock_irqsave" },
	{ 0xa5526619, "rb_insert_color" },
	{ 0xdb760f52, "__kfifo_free" },
	{ 0x4302d0eb, "free_pages" },
	{ 0xe45f60d8, "__wake_up" },
	{ 0xb3f7646e, "kthread_should_stop" },
	{ 0x68e05d57, "getrawmonotonic" },
	{ 0x37a0cba, "kfree" },
	{ 0x2e60bace, "memcpy" },
	{ 0x622fa02a, "prepare_to_wait" },
	{ 0xd498ddf1, "kill_pgrp" },
	{ 0xe6b3fe21, "interruptible_sleep_on_timeout" },
	{ 0x7ac9bc4, "class_destroy" },
	{ 0x75bb675a, "finish_wait" },
	{ 0xca9360b5, "rb_next" },
	{ 0xf23fcb99, "__kfifo_in" },
	{ 0x362ef408, "_copy_from_user" },
	{ 0x8b70e5e7, "__class_create" },
	{ 0x29537c9e, "alloc_chrdev_region" },
	{ 0xa6549749, "vfs_write" },
	{ 0xe914e41e, "strcpy" },
	{ 0xead28e9a, "filp_open" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "63DFBC5835CEBFFB287866D");
