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
	{ 0x14522340, "module_layout" },
	{ 0x1fedf0f4, "__request_region" },
	{ 0x42e80c19, "cdev_del" },
	{ 0x4f1939c7, "per_cpu__current_task" },
	{ 0xc45a9f63, "cdev_init" },
	{ 0x69a358a6, "iomem_resource" },
	{ 0xd2037915, "dev_set_drvdata" },
	{ 0xd8e484f0, "register_chrdev_region" },
	{ 0xfa2e111f, "slab_buffer_size" },
	{ 0xc8b57c27, "autoremove_wake_function" },
	{ 0xd691cba2, "malloc_sizes" },
	{ 0xa30682, "pci_disable_device" },
	{ 0x973873ab, "_spin_lock" },
	{ 0x105e2727, "__tracepoint_kmalloc" },
	{ 0xeae3dfd6, "__const_udelay" },
	{ 0x7485e15e, "unregister_chrdev_region" },
	{ 0x1f31615f, "pci_bus_write_config_word" },
	{ 0xffc7c184, "__init_waitqueue_head" },
	{ 0xf85ccdae, "kmem_cache_alloc_notrace" },
	{ 0xea147363, "printk" },
	{ 0x85f8a266, "copy_to_user" },
	{ 0xb4390f9a, "mcount" },
	{ 0x6dcaeb88, "per_cpu__kernel_stack" },
	{ 0x859c6dc7, "request_threaded_irq" },
	{ 0xa6d1bdca, "cdev_add" },
	{ 0x42c8de35, "ioremap_nocache" },
	{ 0xc5aa6d66, "pci_bus_read_config_dword" },
	{ 0x1000e51, "schedule" },
	{ 0x7c61340c, "__release_region" },
	{ 0x68f7c535, "pci_unregister_driver" },
	{ 0xe52947e7, "__phys_addr" },
	{ 0x642e54ac, "__wake_up" },
	{ 0x37a0cba, "kfree" },
	{ 0x33d92f9a, "prepare_to_wait" },
	{ 0xedc03953, "iounmap" },
	{ 0x5f07b9f3, "__pci_register_driver" },
	{ 0x9ccb2622, "finish_wait" },
	{ 0xa12add91, "pci_enable_device" },
	{ 0x3302b500, "copy_from_user" },
	{ 0xa92a43c, "dev_get_drvdata" },
	{ 0x29537c9e, "alloc_chrdev_region" },
	{ 0xf20dabd8, "free_irq" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";

MODULE_ALIAS("pci:v000010B5d00009056sv*sd*bc*sc*i*");

MODULE_INFO(srcversion, "380BBC4008B9A5DC4C82772");

static const struct rheldata _rheldata __used
__attribute__((section(".rheldata"))) = {
	.rhel_major = 6,
	.rhel_minor = 3,
};
