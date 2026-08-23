#ifndef KRW_H
#define KRW_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

/*
 * Dopamine libjailbreak backed KRW layer.
 *
 * Any of these calls assert krw is initialized; the daemon or CLI must call
 * krw_init() first (it is idempotent).
 */

int  krw_init(void);
bool krw_ready(void);

/* Kernel info */
uint64_t krw_kernel_base(void);
uint64_t krw_kernel_slide(void);
uint64_t krw_kernel_physbase(void);
uint64_t krw_kernel_virtbase(void);
uint64_t krw_kernel_virtsize(void);

/* Process helpers */
uint64_t krw_proc_self(void);
uint64_t krw_proc_for_pid(pid_t pid);
uint64_t krw_proc_task(uint64_t proc);
uint32_t krw_proc_pid(uint64_t proc);
uint64_t krw_proc_vnode_for_fd(uint64_t proc, int fd);

/* Raw kernel r/w */
uint64_t krw_read64(uint64_t va);
uint32_t krw_read32(uint64_t va);
uint16_t krw_read16(uint64_t va);
uint8_t  krw_read8(uint64_t va);
uint64_t krw_read_ptr(uint64_t va);
int      krw_read_buf(uint64_t va, void *out, size_t len);

int krw_write64(uint64_t va, uint64_t val);
int krw_write32(uint64_t va, uint32_t val);
int krw_write16(uint64_t va, uint16_t val);
int krw_write8(uint64_t va, uint8_t val);
int krw_write_ptr(uint64_t va, uint64_t ptr, uint16_t salt);
int krw_write_buf(uint64_t va, const void *in, size_t len);

/* Allocation + call */
int  krw_kalloc(uint64_t *addr, size_t size);
int  krw_kfree(uint64_t addr, size_t size);
bool krw_kcall_available(void);
int  krw_kcall(uint64_t *ret, uint64_t func, int argc, const uint64_t *argv);

/* vnode helpers (VISSHADOW = 0x008000) */
#define KRW_VISSHADOW (0x008000ULL)
uint32_t krw_vnode_flags(uint64_t vnode);
int      krw_vnode_set_flag(uint64_t vnode, uint64_t flag, bool set);

#endif /* KRW_H */