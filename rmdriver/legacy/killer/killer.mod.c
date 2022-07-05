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
	{ 0x84b3ef83, "module_layout" },
	{ 0x39d636e4, "cdev_del" },
	{ 0x685acc2b, "cdev_init" },
	{ 0xc068440e, "__kfifo_alloc" },
	{ 0x2359df1b, "find_vpid" },
	{ 0x2ad04077, "remove_proc_entry" },
	{ 0xaf4bfea2, "device_destroy" },
	{ 0xcd76c5bb, "mutex_unlock" },
	{ 0x7485e15e, "unregister_chrdev_region" },
	{ 0xa36eb218, "mutex_lock_interruptible" },
	{ 0x50eedeb8, "printk" },
	{ 0x4ea56f9, "_kstrtol" },
	{ 0xb4390f9a, "mcount" },
	{ 0x96d810a9, "device_create" },
	{ 0x8d99d76c, "kill_pid" },
	{ 0xfb745572, "pid_task" },
	{ 0xd1515064, "cdev_add" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0xdb760f52, "__kfifo_free" },
	{ 0x97f9dce6, "proc_create_data" },
	{ 0x2e60bace, "memcpy" },
	{ 0xa4d7a9e1, "kill_pgrp" },
	{ 0x593e116f, "class_destroy" },
	{ 0x942cfb07, "__class_create" },
	{ 0x29537c9e, "alloc_chrdev_region" },
	{ 0x30a80826, "__kfifo_from_user" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "A7A1C68436DF65BB5D418C3");
