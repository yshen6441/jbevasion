/*
 * Link-time stub for libjailbreak.dylib (Dopamine).
 *
 * This dylib exists ONLY so the linker can resolve the symbols of the
 * Dopamine libjailbreak API on a build host that does not carry the real
 * library. It is never loaded at runtime on device:
 *
 *   - the tool is linked with -rpath /var/jb/usr/lib and pulls the library
 *     by its install name @rpath/libjailbreak.dylib;
 *   - at runtime dyld finds the REAL /var/jb/usr/lib/libjailbreak.dylib
 *     and binds every symbol from it;
 *   - the stub bodies are never executed.
 *
 * Keep the exported symbol set a superset of what the tool actually uses.
 */
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>

/* --- exported variables --- */
/* Placeholder only: let the linker resolve the symbol; at runtime dyld binds
   the REAL gSystemInfo from /var/jb/usr/lib/libjailbreak.dylib. The stub is
   never executed, so backing it with a large byte buffer is fine. */
unsigned char gSystemInfo[8192];

/* --- libjailbreak.h / primitives.h --- */
int jbclient_initialize_primitives_internal(bool physrwPTE) { (void)physrwPTE; return -1; }
int jbclient_initialize_primitives(void) { return -1; }

int  kreadbuf(uint64_t addr, void *out, size_t size)      { (void)addr; (void)out; (void)size; return -1; }
int  kwritebuf(uint64_t addr, const void *in, size_t size){ (void)addr; (void)in; (void)size; return -1; }
int  physreadbuf(uint64_t pa, void *out, size_t size)     { (void)pa; (void)out; (void)size; return -1; }
int  physwritebuf(uint64_t pa, const void *in, size_t size){(void)pa; (void)in; (void)size; return -1; }

uint64_t kread64(uint64_t va) { (void)va; return 0; }
uint64_t kread_ptr(uint64_t va) { (void)va; return 0; }
uint64_t kread_smrptr(uint64_t va) { (void)va; return 0; }
uint32_t kread32(uint64_t va) { (void)va; return 0; }
uint16_t kread16(uint64_t va) { (void)va; return 0; }
uint8_t  kread8(uint64_t va)  { (void)va; return 0; }

int kwrite64(uint64_t va, uint64_t v)  { (void)va; (void)v; return -1; }
int kwrite_ptr(uint64_t va, uint64_t p, uint16_t salt) { (void)va; (void)p; (void)salt; return -1; }
int kwrite32(uint64_t va, uint32_t v)  { (void)va; (void)v; return -1; }
int kwrite16(uint64_t va, uint16_t v)  { (void)va; (void)v; return -1; }
int kwrite8(uint64_t va, uint8_t v)    { (void)va; (void)v; return -1; }

int kcall(uint64_t *result, uint64_t func, int argc, const uint64_t *argv)
{ (void)result; (void)func; (void)argc; (void)argv; return -1; }

int  kalloc(uint64_t *addr, uint64_t size) { (void)addr; (void)size; return -1; }
int  kfree(uint64_t addr, uint64_t size)  { (void)addr; (void)size; return -1; }
bool is_kcall_available(void) { return false; }

/* --- util.h --- */
uint64_t proc_self(void) { return 0; }
uint64_t task_self(void) { return 0; }
uint64_t proc_find(pid_t pid) { (void)pid; return 0; }
uint64_t proc_task(uint64_t proc) { (void)proc; return 0; }
uint64_t proc_get_vnode_for_fd(uint64_t proc, int fd) { (void)proc; (void)fd; return 0; }
uint64_t proc_ucred(uint64_t proc) { (void)proc; return 0; }

char *get_jbroot(void) { return NULL; }

/* --- jbclient_xpc.h --- */
int jbclient_root_steal_ucred(uint64_t ucredToSteal, uint64_t *orgUcred)
{ (void)ucredToSteal; (void)orgUcred; return -1; }