#include "fd_rdir.h"
#include "krw.h"
#include "hide.h"
#include <libjailbreak/kernel.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/param.h>

/* ------------------------------------------------------------------ */
/*  Fake-root construction for rootless (Dopamine) jailbreaks.         */
/*                                                                    */
/*  On Dopamine rootless, /var/jb is a symlink to                     */
/*  /private/preboot/<uuid>/jb and the real root tree is otherwise     */
/*  untouched. We therefore build a clean root at JBEVASION_ROOT by    */
/*  bindfs binding every real top-level directory, skipping the        */
/*  jailbreak-relevant subtrees (/private/preboot, /private/var/jb)    */
/*  so a chrooted process sees a pristine system volume.               */
/* ------------------------------------------------------------------ */

/* bindfs is Apple's private bind-mount filesystem, used by Dopamine
   itself (jbctl/src/internal.m). mount data is just the source path
   as a NUL-terminated string pointer. */
#define BINDFS_FSTYPE  "bindfs"
#define MAX_MOUNTS 128

/* libjailbreak API: steal kernel ucred to bypass sandbox for mount */
extern int jbclient_root_steal_ucred(uint64_t ucredToSteal, uint64_t *orgUcred);

static struct {
    char path[PATH_MAX];
} g_mounts[MAX_MOUNTS];
static uint32_t g_mount_count = 0;

static int record_mount(const char *path) {
    if (g_mount_count >= MAX_MOUNTS) {
        fprintf(stderr, "fd_rdir: mount stack full\n");
        return -1;
    }
    strlcpy(g_mounts[g_mount_count].path, path, sizeof(g_mounts[g_mount_count].path));
    g_mount_count++;
    return 0;
}

/* Steal the kernel (pid 0) ucred so the mount() syscall bypasses the
   sandbox. Dopamine uses the same pattern (jbctl/src/internal.m). */
static int mount_unsandboxed(const char *type, const char *dir, int flags, void *data) {
    uint64_t saved = 0;
    int steal_ret = jbclient_root_steal_ucred(0, &saved);
    int r = mount(type, dir, flags, data);
    if (saved) jbclient_root_steal_ucred(saved, NULL);
    if (r != 0) {
        fprintf(stderr, "  [mount_unsandboxed] steal=%d saved=0x%llx errno=%d\n",
                steal_ret, (unsigned long long)saved, errno);
    }
    return r;
}

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
    return ofiles ? ofiles + FD_OFILES_TO_CDIR : 0x48;
}
static uint64_t fd_rdir_offs_rdir(void) {
    uint64_t ofiles = koffsetof(filedesc, ofiles_start);
    return ofiles ? ofiles + FD_OFILES_TO_RDIR : 0x50;
}

/* vnode offsets – same as hide.c, used for usecount bump only */
#define OFF_V_USECOUNT  0x060
#define OFF_V_IOCOUNT   0x064

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

    /* NOTE: on iOS 16+/iOS 17 (xnu-8792) `proc->p_fd` is an INLINE
       struct filedesc, not a pointer. The filedesc lives at
       proc + koffsetof(proc, fd); do NOT dereference it. */
    uint64_t filedesc = proc + koffsetof(proc, fd);
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

    /* iOS 17: proc->p_fd is an inline filedesc, not a pointer */
    uint64_t filedesc = proc + koffsetof(proc, fd);
    if (!filedesc) {
        fprintf(stderr, "fd_rdir: failed to locate filedesc in pid %d proc\n", pid);
        return -1;
    }

    uint64_t off_ofiles = koffsetof(filedesc, ofiles_start);
    uint64_t off_cdir   = 0, off_rdir = 0;
    if (off_ofiles) {
        off_cdir = off_ofiles + FD_OFILES_TO_CDIR;
        off_rdir = off_ofiles + FD_OFILES_TO_RDIR;
    } else {
        off_cdir = 0x48;
        off_rdir = 0x50;
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

    /* iOS 17: proc->p_fd is an inline struct filedesc, not a pointer */
    uint64_t filedesc = proc + koffsetof(proc, fd);
    if (!filedesc) {
        fprintf(stderr, "fd_rdir: failed to locate filedesc in proc\n");
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
/*  Fake-root preparation (bindfs bind mounts)                        */
/* ------------------------------------------------------------------ */

static int mkdir_p(const char *path, mode_t mode) {
    char tmp[PATH_MAX];
    strlcpy(tmp, path, sizeof(tmp));
    size_t len = strlen(tmp);
    if (len > 0 && tmp[len - 1] == '/') tmp[len - 1] = '\0';
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, mode) != 0 && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, mode) != 0 && errno != EEXIST) return -1;
    return 0;
}

/* Bind-mount src onto dst (created if missing). Uses bindfs (Apple's
   private bind-mount filesystem, confirmed working on iOS 17 via
   Dopamine's jbctl/src/internal.m). */
static int bind_mount_dir(const char *src, const char *dst) {
    if (mkdir(dst, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "fd_rdir: mkdir(%s) failed: %s\n", dst, strerror(errno));
        return -1;
    }

    /* bindfs mount data is just a NUL-terminated source path string pointer */
    int ret = mount_unsandboxed(BINDFS_FSTYPE, dst, 0, (void *)src);

    if (ret != 0) {
        fprintf(stderr, "fd_rdir: bindfs mount(%s -> %s) failed: %s\n",
                src, dst, strerror(errno));
        return -1;
    }

    if (record_mount(dst) != 0) {
        unmount(dst, MNT_FORCE);
        return -1;
    }

    printf("fd_rdir: bound %s -> %s\n", src, dst);
    return 0;
}

/* Recreate a real symlink in the fake root. Keeps relative paths intact so
   children resolve within the fake tree. */
static int clone_symlink(const char *src, const char *dst) {
    char target[PATH_MAX];
    ssize_t n = readlink(src, target, sizeof(target) - 1);
    if (n < 0) {
        fprintf(stderr, "fd_rdir: readlink(%s) failed: %s\n", src, strerror(errno));
        return -1;
    }
    target[n] = '\0';

    if (symlink(target, dst) != 0) {
        /* If the current component is a dir from a previous bind, remove it */
        if (errno == EEXIST && rmdir(dst) == 0) {
            if (symlink(target, dst) != 0) {
                fprintf(stderr, "fd_rdir: symlink(%s) failed: %s\n", dst, strerror(errno));
                return -1;
            }
        } else {
            fprintf(stderr, "fd_rdir: symlink(%s -> %s) failed: %s\n",
                    dst, target, strerror(errno));
            return -1;
        }
    }
    printf("fd_rdir: symlink %s -> %s\n", src, target);
    return 0;
}

/* Is this path jailbreak-relevant and must be skipped from the fake root?
   On rootless, /private/preboot holds the boot components + the jb root,
   and (in some setups) /private/var/jb is the actual jailbreak dir. */
static bool skip_path(const char *src) {
    if (strcmp(src, "/private/preboot") == 0) return true;
    if (strcmp(src, "/private/var/jb") == 0) return true;
    return false;
}

/* Bind a single real directory tree into the fake root. If the live path is
   a symlink, clone it; otherwise recurse into subdirs, skipping jailbreak
   paths, and bind mount leaf dirs. */
static int bind_tree(const char *src, const char *dst) {
    struct stat st;
    if (lstat(src, &st) != 0) {
        fprintf(stderr, "fd_rdir: lstat(%s) failed: %s\n", src, strerror(errno));
        return -1;
    }

    if (S_ISLNK(st.st_mode)) return clone_symlink(src, dst);

    if (S_ISDIR(st.st_mode)) {
        if (strcmp(src, "/") == 0) {
            /* Walk top-level entries, cloning symlinks and binding dirs */
            DIR *d = opendir(src);
            if (!d) return -1;
            struct dirent *de;
            while ((de = readdir(d)) != NULL) {
                if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
                char child[PATH_MAX], cchild[PATH_MAX];
                snprintf(child, sizeof(child), "%s%s", src, de->d_name);
                snprintf(cchild, sizeof(cchild), "%s/%s", dst, de->d_name);
                if (skip_path(child)) continue;
                struct stat cst;
                if (lstat(child, &cst) != 0) continue;
                if (S_ISLNK(cst.st_mode)) {
                    clone_symlink(child, cchild);
                } else if (S_ISDIR(cst.st_mode)) {
                    bind_tree(child, cchild);
                } else if (S_ISREG(cst.st_mode)) {
                    if (mkdir_p(cchild, 0755) != 0) continue;
                    bind_mount_dir(child, cchild);
                }
            }
            closedir(d);
            return 0;
        }

        if (strcmp(src, "/private") == 0) {
            /* Special: only mount /private/var (excluding jb) and /private/etc.
               preboot is skipped inside the loop via skip_path(). */
            DIR *d = opendir(src);
            if (!d) return -1;
            struct dirent *de;
            while ((de = readdir(d)) != NULL) {
                if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
                char child[PATH_MAX], cchild[PATH_MAX];
                snprintf(child, sizeof(child), "%s/%s", src, de->d_name);
                snprintf(cchild, sizeof(cchild), "%s/%s", dst, de->d_name);
                if (skip_path(child)) continue;
                struct stat cst;
                if (lstat(child, &cst) != 0) continue;
                if (S_ISLNK(cst.st_mode)) {
                    clone_symlink(child, cchild);
                } else if (S_ISDIR(cst.st_mode)) {
                    bind_tree(child, cchild);
                } else if (S_ISREG(cst.st_mode)) {
                    if (mkdir_p(cchild, 0755) != 0) continue;
                    bind_mount_dir(child, cchild);
                }
            }
            closedir(d);
            return 0;
        }

        if (strcmp(src, "/private/var") == 0) {
            /* Special: exclude /private/var/jb */
            DIR *d = opendir(src);
            if (!d) return -1;
            struct dirent *de;
            while ((de = readdir(d)) != NULL) {
                if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
                char child[PATH_MAX], cchild[PATH_MAX];
                snprintf(child, sizeof(child), "%s/%s", src, de->d_name);
                snprintf(cchild, sizeof(cchild), "%s/%s", dst, de->d_name);
                if (skip_path(child)) continue;
                struct stat cst;
                if (lstat(child, &cst) != 0) continue;
                if (S_ISLNK(cst.st_mode)) {
                    clone_symlink(child, cchild);
                } else if (S_ISDIR(cst.st_mode)) {
                    if (mkdir_p(cchild, 0755) != 0) continue;
                    bind_mount_dir(child, cchild);
                } else if (S_ISREG(cst.st_mode)) {
                    if (mkdir_p(cchild, 0755) != 0) continue;
                    bind_mount_dir(child, cchild);
                }
            }
            closedir(d);
            return 0;
        }

        /* Generic dir: bind as a whole */
        if (mkdir_p(dst, 0755) != 0) return -1;
        return bind_mount_dir(src, dst);
    }

    /* Non-dir, non-symlink (device nodes, fifos): skip. /dev is populated
       dynamically and apps rarely need chrooted device access. */
    return 0;
}

int fd_rdir_prepare(void) {
    /* If the fake root root was previously set up, reuse it (idempotent) */
    struct stat st;
    if (stat(JBEVASION_ROOT, &st) == 0 && S_ISDIR(st.st_mode)) {
        char testpath[PATH_MAX];
        snprintf(testpath, sizeof(testpath), "%s/private", JBEVASION_ROOT);
        if (stat(testpath, &st) == 0 && S_ISDIR(st.st_mode)) {
            printf("fd_rdir: clean root already prepared at %s\n", JBEVASION_ROOT);
            return 0;
        }
    }

    g_mount_count = 0;

    printf("fd_rdir: preparing clean root at %s\n", JBEVASION_ROOT);

    if (mkdir(JBEVASION_ROOT, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "fd_rdir: mkdir(%s) failed: %s\n",
                JBEVASION_ROOT, strerror(errno));
        return -1;
    }

    if (bind_tree("/", JBEVASION_ROOT) != 0) {
        fprintf(stderr, "fd_rdir: bind_tree failed\n");
        fd_rdir_cleanup();
        return -1;
    }

    printf("fd_rdir: clean root prepared (%u mounts)\n", g_mount_count);

    /* Note: /var/private data (app containers) is reachable via the bound
       /private/var/mobile tree, so app-scoped storage survives the chroot.
       /tmp, /etc resolve through cloned symlinks into /private. */

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
/*  Cleanup: unmount the fake root (reverse mount order)              */
/* ------------------------------------------------------------------ */
int fd_rdir_cleanup(void) {
    printf("fd_rdir: cleaning up (%u mounts)\n", g_mount_count);

    for (int i = g_mount_count - 1; i >= 0; i--) {
        int ret = unmount(g_mounts[i].path, MNT_FORCE);
        if (ret != 0 && errno != EINVAL && errno != ENOENT) {
            fprintf(stderr, "fd_rdir: unmount(%s) failed: %s\n",
                    g_mounts[i].path, strerror(errno));
        } else {
            printf("fd_rdir: unmounted %s\n", g_mounts[i].path);
        }
        g_mounts[i].path[0] = '\0';
    }
    g_mount_count = 0;

    printf("fd_rdir: cleanup done\n");
    return 0;
}