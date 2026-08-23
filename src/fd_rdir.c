#include "fd_rdir.h"
#include "krw.h"
#include "hide.h"
#include <libjailbreak/kernel.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/param.h>

/* fs_snapshot_mount() is in <sys/snapshot.h> (iOS 10.3+). Fallback declaration
   in case the Theos SDK doesn't expose it. */
#if __has_include(<sys/snapshot.h>)
#include <sys/snapshot.h>
#else
int fs_snapshot_mount(int dirfd, const char *mountpoint, const char *snapshot, uint32_t flags);
#endif

/* ------------------------------------------------------------------ */
/*  filedesc struct offsets (iOS 17 arm64e, verified against          */
/*  xnu-8792.41.9 bsd/sys/filedesc.h).                                */
/* ------------------------------------------------------------------ */
/*  Layout (arm64e, CONFIG-independent since we anchor on ofiles):    */
/*    lck_mtx_t     fd_lock;        // 0x00  (16 bytes on arm64e)     */
/*    uint8_t       fd_fpdrainwait; // 0x10                           */
/*    uint8_t       fd_flags;       // 0x11  (FD_CHROOT = 0x01)       */
/*    u_short       fd_cmask;       // 0x12                           */
/*    int           fd_nfiles;      // 0x14                           */
/*    ...                                                            */
/*    fileproc    **fd_ofiles;      // off_ofiles_start (runtime)     */
/*    char        *fd_ofileflags;   // +0x08                          */
/*    klist       *fd_knlist;       // +0x10                          */
/*    kqworkq     *fd_wqkqueue;     // +0x18                          */
/*    vnode_t      fd_cdir;         // +0x20                          */
/*    vnode_t      fd_rdir;         // +0x28                          */
/* ------------------------------------------------------------------ */
/*  fd_flags sits in the header, so its offset is fixed:              */
#define OFF_FD_FLAGS 0x11
#define FD_CHROOT    0x01

/*  fd_cdir/fd_rdir live a fixed distance after fd_ofiles. We anchor  */
/*  on libjailbreak's runtime `filedesc.ofiles_start` so the offsets  */
/*  stay correct regardless of CONFIG_PROC_RESOURCE_LIMITS.           */
#define FD_OFILES_TO_CDIR 0x20
#define FD_OFILES_TO_RDIR 0x28

static uint64_t fd_rdir_offs_cdir(void) {
    uint64_t ofiles = koffsetof(filedesc, ofiles_start);
    return ofiles ? ofiles + FD_OFILES_TO_CDIR : 0x50;
}
static uint64_t fd_rdir_offs_rdir(void) {
    uint64_t ofiles = koffsetof(filedesc, ofiles_start);
    return ofiles ? ofiles + FD_OFILES_TO_RDIR : 0x58;
}

/* vnode offsets – same as hide.c, used for usecount bump only */
#define OFF_V_USECOUNT  0x060
#define OFF_V_IOCOUNT   0x064

/* The path where we mount the clean rootfs snapshot */
#define SNAPSHOT_NAME "orig-fs"

/* ------------------------------------------------------------------ */
/*  Helpers                                                           */
/* ------------------------------------------------------------------ */

/* Get the vnode for a path by changing directory and reading fd_cdir.
   This avoids needing a vnode_lookup() kcall. */
uint64_t fd_rdir_get_vnode_for_path(const char *path) {
    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd))) return 0;

    if (chdir(path) != 0) {
        fprintf(stderr, "fd_rdir: chdir(%s) failed: %s\n", path, strerror(errno));
        return 0;
    }

    uint64_t proc = krw_proc_self();
    if (!proc) {
        chdir(cwd);
        return 0;
    }

    uint64_t filedesc = krw_read64(proc + koffsetof(proc, fd));
    if (!filedesc) {
        chdir(cwd);
        return 0;
    }

    uint64_t vp = krw_read64(filedesc + fd_rdir_offs_cdir());

    /* Bump usecount/iocount so the vnode doesn't get recycled while we use it */
    if (vp) {
        uint32_t usecount = krw_read32(vp + OFF_V_USECOUNT);
        uint32_t iocount  = krw_read32(vp + OFF_V_IOCOUNT);
        krw_write32(vp + OFF_V_USECOUNT, usecount + 1);
        krw_write32(vp + OFF_V_IOCOUNT,  iocount + 1);
    }

    chdir(cwd);
    return vp;
}

/* Probe: print the resolved filedesc offsets + live field values for a PID.
   Used to verify the iOS 17 offsets on-device before trusting the chroot. */
int fd_rdir_probe(pid_t pid) {
    uint64_t proc = krw_proc_for_pid(pid);
    if (!proc) {
        fprintf(stderr, "fd_rdir: cannot find pid %d\n", pid);
        return -1;
    }

    uint64_t filedesc = krw_read64(proc + koffsetof(proc, fd));
    if (!filedesc) {
        fprintf(stderr, "fd_rdir: failed to read filedesc from pid %d\n", pid);
        return -1;
    }

    uint64_t off_ofiles = koffsetof(filedesc, ofiles_start);
    uint64_t off_cdir   = 0, off_rdir = 0;
    if (off_ofiles) {
        off_cdir = off_ofiles + FD_OFILES_TO_CDIR;
        off_rdir = off_ofiles + FD_OFILES_TO_RDIR;
    } else {
        off_cdir = 0x50;
        off_rdir = 0x58;
    }

    uint64_t cdir    = krw_read64(filedesc + off_cdir);
    uint64_t rdir    = krw_read64(filedesc + off_rdir);
    uint8_t  flags   = krw_read8(filedesc + OFF_FD_FLAGS);
    pid_t    selfpid = getpid();

    printf("fd_rdir probe (pid %d, proc 0x%llx, filedesc 0x%llx):\n",
           pid, (unsigned long long)proc, (unsigned long long)filedesc);
    printf("  ofiles_start(auto)  = 0x%llx\n", (unsigned long long)off_ofiles);
    printf("  fd_cdir @ 0x%llx    = 0x%llx\n", (unsigned long long)off_cdir, (unsigned long long)cdir);
    printf("  fd_rdir @ 0x%llx    = 0x%llx\n", (unsigned long long)off_rdir, (unsigned long long)rdir);
    printf("  fd_flags @ 0x%llx   = 0x%x (FD_CHROOT=0x%x, %s)\n",
           (unsigned long long)OFF_FD_FLAGS, flags, FD_CHROOT,
           (flags & FD_CHROOT) ? "SET" : "clear");

    /* Sanity: cdir should be a sane kernel pointer and not equal rdir normally.
       Print whether values look plausible. */
    if (cdir == rdir && cdir != 0) {
        printf("  [warn] cdir == rdir: proc is already chrooted\n");
    }
    if (selfpid == pid) {
        printf("  [note] probed self (%d)\n", selfpid);
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Core: write fd_rdir/fd_cdir + FD_CHROOT into a proc's filedesc   */
/* ------------------------------------------------------------------ */
int fd_rdir_set_for_proc(uint64_t proc, uint64_t clean_vnode) {
    if (!proc || !clean_vnode) {
        fprintf(stderr, "fd_rdir: invalid proc or vnode\n");
        return -1;
    }

    uint64_t filedesc = krw_read64(proc + koffsetof(proc, fd));
    if (!filedesc) {
        fprintf(stderr, "fd_rdir: failed to read filedesc from proc\n");
        return -1;
    }

    printf("fd_rdir: proc=0x%llx  filedesc=0x%llx  clean_vnode=0x%llx\n",
           (unsigned long long)proc, (unsigned long long)filedesc,
           (unsigned long long)clean_vnode);
    printf("fd_rdir: off_cdir=0x%llx  off_rdir=0x%llx  off_flags=0x%x\n",
           (unsigned long long)fd_rdir_offs_cdir(),
           (unsigned long long)fd_rdir_offs_rdir(),
           OFF_FD_FLAGS);

    /* Read old values for logging */
    uint64_t old_cdir = krw_read64(filedesc + fd_rdir_offs_cdir());
    uint64_t old_rdir = krw_read64(filedesc + fd_rdir_offs_rdir());
    uint8_t old_flags = krw_read8(filedesc + OFF_FD_FLAGS);

    printf("fd_rdir: old  cdir=0x%llx  rdir=0x%llx  flags=0x%x\n",
           (unsigned long long)old_cdir, (unsigned long long)old_rdir, old_flags);

    /* Write the clean vnode to both cdir and rdir */
    krw_write64(filedesc + fd_rdir_offs_cdir(), clean_vnode);
    krw_write64(filedesc + fd_rdir_offs_rdir(), clean_vnode);

    /* Set FD_CHROOT flag to prevent escape via .. */
    uint8_t new_flags = old_flags | FD_CHROOT;
    krw_write8(filedesc + OFF_FD_FLAGS, new_flags);

    /* Bump usecount on the clean vnode so it stays alive */
    uint32_t usecount = krw_read32(clean_vnode + OFF_V_USECOUNT);
    uint32_t iocount  = krw_read32(clean_vnode + OFF_V_IOCOUNT);
    krw_write32(clean_vnode + OFF_V_USECOUNT, usecount + 1);
    krw_write32(clean_vnode + OFF_V_IOCOUNT,  iocount + 1);

    printf("fd_rdir: wrote cdir=rdir=0x%llx  flags=0x%x (FD_CHROOT set)  "
           "vnode usecount was %u\n",
           (unsigned long long)clean_vnode, new_flags, usecount);

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Snapshot preparation                                              */
/* ------------------------------------------------------------------ */
int fd_rdir_prepare(void) {
    /* Check if already mounted */
    struct stat st;
    if (stat(JBEVASION_ROOT, &st) == 0 && S_ISDIR(st.st_mode)) {
        /* Try to see if it's a mount point by checking if /private exists */
        char testpath[PATH_MAX];
        snprintf(testpath, sizeof(testpath), "%s/private", JBEVASION_ROOT);
        if (stat(testpath, &st) == 0 && S_ISDIR(st.st_mode)) {
            printf("fd_rdir: clean root already mounted at %s\n", JBEVASION_ROOT);
            return 0;
        }
    }

    printf("fd_rdir: preparing clean root at %s\n", JBEVASION_ROOT);

    /* Create the mountpoint directory */
    if (mkdir(JBEVASION_ROOT, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "fd_rdir: mkdir(%s) failed: %s\n",
                JBEVASION_ROOT, strerror(errno));
        return -1;
    }

    /* Open the root filesystem for snapshot operations */
    int root_fd = open("/", O_RDONLY | O_NONBLOCK);
    if (root_fd < 0) {
        fprintf(stderr, "fd_rdir: open(/) failed: %s\n", strerror(errno));
        return -1;
    }

    /* Try to mount the orig-fs snapshot */
    int ret = fs_snapshot_mount(root_fd, JBEVASION_ROOT, SNAPSHOT_NAME, 0);
    if (ret != 0) {
        fprintf(stderr, "fd_rdir: fs_snapshot_mount(%s) failed: %d (%s)\n",
                SNAPSHOT_NAME, ret, strerror(errno));
        close(root_fd);
        return -1;
    }

    close(root_fd);
    printf("fd_rdir: mounted snapshot '%s' at %s\n", SNAPSHOT_NAME, JBEVASION_ROOT);

    /* The clean root snapshot is mounted. Note: the target app will not
       see /var data (its app container) because the snapshot has a clean
       /var. To fix this, we need to hardlink /var files into the snapshot
       using copy_file_in_memory() (KernBypass approach). This is a
       future enhancement. For now, the chroot hides jailbreak files but
       the app may crash if it needs /var data. */

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Apply fd_rdir chroot to a target PID                             */
/* ------------------------------------------------------------------ */
int fd_rdir_apply(pid_t pid) {
    printf("fd_rdir: applying chroot to pid %d\n", pid);

    /* Step 1: Get the clean root vnode */
    uint64_t clean_vnode = fd_rdir_get_vnode_for_path(JBEVASION_ROOT);
    if (!clean_vnode) {
        fprintf(stderr, "fd_rdir: failed to get vnode for %s (run 'jbevasion chroot-prep' first?)\n",
                JBEVASION_ROOT);
        return -1;
    }

    printf("fd_rdir: clean root vnode = 0x%llx\n", (unsigned long long)clean_vnode);

    /* Step 2: Get the target process proc struct */
    uint64_t proc = krw_proc_for_pid(pid);
    if (!proc) {
        fprintf(stderr, "fd_rdir: cannot find pid %d\n", pid);
        return -1;
    }

    printf("fd_rdir: target proc = 0x%llx\n", (unsigned long long)proc);

    /* Step 3: Apply per-process cleanup (platformize, csflags, etc.) */
    proc_hide_pid(pid);

    /* Step 4: Write fd_rdir/fd_cdir + FD_CHROOT */
    int ret = fd_rdir_set_for_proc(proc, clean_vnode);
    if (ret != 0) {
        fprintf(stderr, "fd_rdir: fd_rdir_set_for_proc failed\n");
        return -1;
    }

    printf("fd_rdir: chroot applied to pid %d\n", pid);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Cleanup: unmount the snapshot                                     */
/* ------------------------------------------------------------------ */
int fd_rdir_cleanup(void) {
    printf("fd_rdir: cleaning up\n");

    /* Try to unmount the snapshot – ignore errors if already unmounted */
    int ret = unmount(JBEVASION_ROOT, MNT_FORCE);
    if (ret != 0 && errno != EINVAL && errno != ENOENT) {
        fprintf(stderr, "fd_rdir: unmount(%s) failed: %s\n",
                JBEVASION_ROOT, strerror(errno));
        /* Continue anyway – try rmdir */
    } else {
        printf("fd_rdir: unmounted %s\n", JBEVASION_ROOT);
    }

    ret = rmdir(JBEVASION_ROOT);
    if (ret != 0 && errno != ENOENT) {
        fprintf(stderr, "fd_rdir: rmdir(%s) failed: %s\n",
                JBEVASION_ROOT, strerror(errno));
        return -1;
    }

    printf("fd_rdir: cleanup done\n");
    return 0;
}