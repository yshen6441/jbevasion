#include "krw.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <libjailbreak/libjailbreak.h>

static bool g_krw_ready = false;

int krw_init(void) {
	if (g_krw_ready) return 0;
	int err = jbclient_initialize_primitives();
	g_krw_ready = (err == 0);
	if (!g_krw_ready) {
		fprintf(stderr, "krw: jbclient_initialize_primitives failed (%d)\n", err);
	}
	return g_krw_ready ? 0 : err;
}

bool krw_ready(void) { return g_krw_ready; }

uint64_t krw_kernel_base(void)   { return kconstant(base); }
uint64_t krw_kernel_slide(void)  { return kconstant(slide); }
uint64_t krw_kernel_physbase(void){ return kconstant(physBase); }
uint64_t krw_kernel_virtbase(void){ return kconstant(virtBase); }
uint64_t krw_kernel_virtsize(void){ return kconstant(virtSize); }

uint64_t krw_proc_self(void)        { return proc_self(); }
uint64_t krw_proc_for_pid(pid_t p)  { return proc_find(p); }
uint64_t krw_proc_task(uint64_t p)  { return proc_task(p); }
uint32_t krw_proc_pid(uint64_t p)   { return kread32(p + koffsetof(proc, pid)); }
uint64_t krw_proc_vnode_for_fd(uint64_t p, int fd) { return proc_get_vnode_for_fd(p, fd); }

uint64_t krw_read64(uint64_t va)   { return kread64(va); }
uint32_t krw_read32(uint64_t va)   { return kread32(va); }
uint16_t krw_read16(uint64_t va)   { return kread16(va); }
uint8_t  krw_read8(uint64_t va)    { return kread8(va); }
uint64_t krw_read_ptr(uint64_t va) { return kread_ptr(va); }

int krw_read_buf(uint64_t va, void *out, size_t len) {
	return kreadbuf(va, out, len);
}

int krw_write64(uint64_t va, uint64_t val)  { return kwrite64(va, val); }
int krw_write32(uint64_t va, uint32_t val)  { return kwrite32(va, val); }
int krw_write16(uint64_t va, uint16_t val)  { return kwrite16(va, val); }
int krw_write8(uint64_t va, uint8_t val)    { return kwrite8(va, val); }
int krw_write_ptr(uint64_t va, uint64_t ptr, uint16_t salt) {
	return kwrite_ptr(va, ptr, salt);
}

int krw_write_buf(uint64_t va, const void *in, size_t len) {
	return kwritebuf(va, in, len);
}

int krw_kalloc(uint64_t *addr, size_t size) { return kalloc(addr, size); }
int krw_kfree(uint64_t addr, size_t size)  { return kfree(addr, size); }
bool krw_kcall_available(void) { return is_kcall_available(); }

int krw_kcall(uint64_t *ret, uint64_t func, int argc, const uint64_t *argv) {
	return kcall(ret, func, argc, argv);
}

/* vnode offsets are NOT exported by libjailbreak; keep the verified iOS 16/17
 * arm64e layout here (matches Dopamine/xnu offsets used across the JB scene). */
#define OFF_VNODE_VFLAGS   0x54
#define OFF_VNODE_USECOUNT 0x60
#define OFF_VNODE_IOCOUNT  0x64

uint32_t krw_vnode_flags(uint64_t vnode) {
	if (!vnode) return 0;
	return kread32(vnode + OFF_VNODE_VFLAGS);
}

int krw_vnode_set_flag(uint64_t vnode, uint64_t flag, bool set) {
	if (!vnode) return -1;
	uint32_t flags = kread32(vnode + OFF_VNODE_VFLAGS);
	uint32_t next = set ? (flags | (uint32_t)flag) : (flags & ~(uint32_t)flag);
	return kwrite32(vnode + OFF_VNODE_VFLAGS, next);
}