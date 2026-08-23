#ifndef FD_RDIR_H
#define FD_RDIR_H

#include <stdint.h>
#include <sys/types.h>
#include <stdbool.h>

#define JBEVASION_ROOT "/tmp/jbevasion_root"

/* Mount the orig-fs snapshot and prepare the clean root for chroot */
int fd_rdir_prepare(void);

/* Apply fd_rdir chroot to a target PID */
int fd_rdir_apply(pid_t pid);

/* Unmount and clean up */
int fd_rdir_cleanup(void);

/* Low-level: write fd_rdir/fd_cdir + FD_CHROOT into a proc's filedesc */
int fd_rdir_set_for_proc(uint64_t proc, uint64_t clean_vnode);

/* Get the vnode for a path via chdir trick */
uint64_t fd_rdir_get_vnode_for_path(const char *path);

/* Print the resolved filedesc offsets + field values for a PID (debug) */
int fd_rdir_probe(pid_t pid);

#endif