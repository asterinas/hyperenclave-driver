#include <hyperenclave/header.h>
#include <hyperenclave/util.h>
#include <hyperenclave/log.h>

static int __he_kallsyms_init(void);
/*
 * kernel 5.7 doesn't export kallsyms_lookup_name anymore, while alios 5.10
 * still exports it. Here is a hack leveraging the kprobe to retrieve 
 * kallsyms_lookup_name's address.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
kallsyms_lookup_name_t kallsyms_lookup_name_func;
#define kallsyms_lookup_name kallsyms_lookup_name_func

int he_kallsyms_init(void)
{
#ifdef CONFIG_X86_KERNEL_IBT
	BUILD_BUG();
#endif

	struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
	register_kprobe(&kp);
	kallsyms_lookup_name = (kallsyms_lookup_name_t)kp.addr;
	unregister_kprobe(&kp);
	if (!kallsyms_lookup_name)
		return -ENOENT;

	return __he_kallsyms_init();
}

#else

int he_kallsyms_init(void)
{
	return __he_kallsyms_init();
}

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
struct vm_struct *(*__get_vm_area_caller_sym)(unsigned long, unsigned long,
					      unsigned long, unsigned long,
					      void *);
#else
struct vm_struct *(*__get_vm_area_sym)(unsigned long, unsigned long,
				       unsigned long, unsigned long);
#endif

#ifdef CONFIG_DIRECT_KERN_LOGGING
void *safe_print_seq_sym;
typeof(printk_safe_flush) *printk_safe_flush_sym;
#endif

/*
 * WARNING: It's NOT recommended to use this function. The unexported symbols
 * are not stable over different kernel versions.
 */
#define RESOLVE_EXTERNAL_SYMBOL(symbol)                               \
	do {                                                          \
		symbol##_sym = (void *)kallsyms_lookup_name(#symbol); \
		if (!symbol##_sym) {                                  \
			he_err("Can't get symbol %s\n", #symbol);     \
			return -EINVAL;                               \
		}                                                     \
	} while (0)

static int __he_kallsyms_init(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
	extern struct vm_struct *(*__get_vm_area_caller_sym)(
		unsigned long, unsigned long, unsigned long, unsigned long,
		void *);
#else
	extern struct vm_struct *(*__get_vm_area_sym)(
		unsigned long, unsigned long, unsigned long, unsigned long);
#endif
	extern struct e820_table **e820_table_firmware_sym;

	RESOLVE_EXTERNAL_SYMBOL(ioremap_page_range);
	RESOLVE_EXTERNAL_SYMBOL(flush_tlb_kernel_range);
#ifdef CONFIG_ARM
	RESOLVE_EXTERNAL_SYMBOL(__boot_cpu_mode);
#endif
#if defined(CONFIG_ARM) || defined(CONFIG_ARM64)
	RESOLVE_EXTERNAL_SYMBOL(__hyp_stub_vectors);
#endif
	RESOLVE_EXTERNAL_SYMBOL(mmput_async);
	RESOLVE_EXTERNAL_SYMBOL(e820_table_firmware);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
	RESOLVE_EXTERNAL_SYMBOL(__get_vm_area_caller);
#else
	RESOLVE_EXTERNAL_SYMBOL(__get_vm_area);
#endif
#ifdef CONFIG_DIRECT_KERN_LOGGING
	RESOLVE_EXTERNAL_SYMBOL(safe_print_seq);
	RESOLVE_EXTERNAL_SYMBOL(printk_safe_flush);
#endif

#undef RESOLVE_EXTERNAL_SYMBOL
	return 0;
}
