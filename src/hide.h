#ifndef HIDE_H
#define HIDE_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

int  vnode_hide_init(void);
int  vnode_hide_path(const char *path);
int  vnode_hide_all(void);
int  vnode_restore_path(uint64_t vaddr);
int  vnode_restore_all(void);
int  vnode_hide_cleanup(void);

/* Export/import last hidden vnode data for cross-process persistence */
int  vnode_export_last(uint64_t *vaddr, uint16_t *vtype, uint32_t *usecount, uint32_t *iocount);
int  vnode_import_and_restore(uint64_t vaddr, uint16_t vtype, uint32_t usecount, uint32_t iocount);

int  proc_hide_self(void);
int  proc_platformize(uint64_t proc);
int  proc_clean_csflags(uint64_t proc);

int  proc_hide_pid(pid_t pid);
int  proc_platformize_pid(pid_t pid);
int  proc_clean_csflags_pid(pid_t pid);

#endif