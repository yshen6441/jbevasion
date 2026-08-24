#ifndef FD_RDIR_H
#define FD_RDIR_H

#include <stdint.h>
#include <sys/types.h>
#include <stdbool.h>

#define JBEVASION_ROOT "/tmp/jbevasion_root"

/* A persistent bindfs mount of JBEVASION_ROOT. The mount holds a kernel
   vnode_ref on the fake-root vnode (bind_vfsops.c bindfs_mount), so the
   vnode we store in fd_rdir survives after our process closes its fd. */
#define JBEVASION_HOLDER "/tmp/jbevasion_root_holder"

/* Build the clean fake root at JBEVASION_ROOT by bindfs-binding the real
   root tree, excluding jailbreak paths (/private/preboot, /private/var/jb) */
int fd_rdir_prepare(void);

/* Apply fd_rdir chroot to a target PID */
int fd_rdir_apply(pid_t pid);

/* Unmount the fake root */
int fd_rdir_cleanup(void);

/* Low-level: write fd_rdir/fd_cdir + FD_CHROOT into a proc's filedesc */
int fd_rdir_set_for_proc(uint64_t proc, uint64_t clean_vnode);

/* Get the vnode for a path by opening an fd and reading it from the fileproc */
uint64_t fd_rdir_get_vnode_for_path(const char *path);

/* Print the resolved filedesc offsets + field values for a PID (debug) */
int fd_rdir_probe(pid_t pid);

#endif