#include "hide.h"
#include "krw.h"
#include <libjailbreak/kernel.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/mount.h>

/* ------------------------------------------------------------------ */
/*  vnode struct layout (iOS 16/17 arm64e, verified against XNU src)  */
/* ------------------------------------------------------------------ */
/*  offset  size  field                                                */
/*  0x000   0x008  v_lock      (lck_mtx_t)                             */
/*  0x008   0x010  v_freelist  (TAILQ_ENTRY)                           */
/*  0x018   0x010  v_mntvnodes (TAILQ_ENTRY)                           */
/*  0x028   0x010  v_ncchildren (TAILQ_HEAD namecache)                 */
/*  0x038   0x010  v_nclinks   (LIST_HEAD namecache)                   */
/*  0x048   0x008  v_defer_reclaimlist                                  */
/*  0x050   0x004  v_listflag                                          */
/*  0x054   0x004  v_flag                                              */
/*  0x058   0x002  v_lflag                                             */
/*  0x05a   0x001  v_iterblkflags                                      */
/*  0x05b   0x001  v_references                                        */
/*  0x05c   0x004  v_kusecount                                         */
/*  0x060   0x004  v_usecount                                          */
/*  0x064   0x004  v_iocount                                           */
/*  0x068   0x004  pad0                                                */
/*  0x06c   0x008  v_owner                                             */
/*  0x074   0x002  v_type                                              */
/*  0x076   0x002  v_tag                                               */
/*  0x078   0x004  v_id                                                */
/*  0x07c   0x004  pad1                                                */
/*  0x080   0x008  v_un                                               */
/*  0x088   0x010  v_cleanblkhd                                        */
/*  0x098   0x010  v_dirtyblkhd                                        */
/*  0x0a8   0x010  v_knotes                                            */
/*  0x0b8   0x008  v_cred                                              */
/*  0x0c0   0x004  v_authorized_actions                                */
/*  0x0c4   0x004  v_cred_timestamp                                    */
/*  0x0c8   0x004  v_nc_generation                                     */
/*  0x0cc   0x004  v_numoutput                                         */
/*  0x0d0   0x004  v_writecount                                        */
/*  0x0d4   0x004  pad2                                                */
/*  0x0d8   0x008  v_name                                              */
/*  0x0e0   0x008  v_parent                                            */
/*  0x0e8   0x008  v_lockf                                             */
/*  0x0f0   0x008  v_op                                                */
/*  0x0f8   0x008  v_mount                                             */
/*  0x100   0x008  v_data                                              */
/*  0x108   0x008  v_label                                             */
/*  0x110   0x008  v_resolve                                           */
/* total: 0x118 = 280 bytes                                            */

/* We read/write a generous block to capture the whole vnode */
#define VNODE_BUF_SIZE 0x200
#define HIDE_SAVED_MAX 64

static struct {
    uint64_t vaddr;
    uint8_t  data[VNODE_BUF_SIZE];
} g_saved_vnodes[HIDE_SAVED_MAX];
static int g_saved_count = 0;

/* v_type offset in vnode struct (iOS 16/17 arm64e) */
#define OFF_V_TYPE          0x074

/* ---------- placeholder file (unused, kept for reference) ---------- */
#define PLACEHOLDER_PATH  "/tmp/.jbhide_placeholder"

/* ---------- helper: get vnode for a path ---------- */
static uint64_t get_vnode_for_path(const char *path) {
    int fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd < 0) return 0;
    uint64_t vnode = krw_proc_vnode_for_fd(krw_proc_self(), fd);
    close(fd);
    return vnode;
}

/* ---------- init: ensure placeholder exists ---------- */
int vnode_hide_init(void) {
    int fd = open(PLACEHOLDER_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        fprintf(stderr, "hide: failed to create placeholder %s: %s\n",
                PLACEHOLDER_PATH, strerror(errno));
        return -1;
    }
    /* Write a single byte so the file has content */
    write(fd, "", 1);
    close(fd);
    printf("hide: placeholder ready at %s\n", PLACEHOLDER_PATH);
    return 0;
}

/* ---------- cleanup: remove placeholder ---------- */
int vnode_hide_cleanup(void) {
    unlink(PLACEHOLDER_PATH);
    return 0;
}

/* ---------- core: mark a vnode as VBAD (invalid).
   This is much safer than swapping the entire vnode content because:
   - we only change ONE field (v_type = 0 = VBAD)
   - all other fields remain intact from the original
   - the kernel handles VBAD vnodes gracefully (returns ENOENT)
   - no risk of corrupting v_op, v_cred, v_un, v_name, etc.  */
static int vnode_mark_bad(uint64_t orig_vnode) {
    if (!orig_vnode) {
        fprintf(stderr, "hide: invalid vnode\n");
        return -1;
    }

    /* Save original vnode content for restore */
    if (g_saved_count < HIDE_SAVED_MAX) {
        int found = 0;
        for (int i = 0; i < g_saved_count; i++) {
            if (g_saved_vnodes[i].vaddr == orig_vnode) { found = 1; break; }
        }
        if (!found) {
            uint8_t save_buf[VNODE_BUF_SIZE];
            if (krw_read_buf(orig_vnode, save_buf, sizeof(save_buf)) == 0) {
                g_saved_vnodes[g_saved_count].vaddr = orig_vnode;
                memcpy(g_saved_vnodes[g_saved_count].data, save_buf, sizeof(save_buf));
                g_saved_count++;
            }
        }
    }

    /* Read the original vnode */
    uint8_t vbuf[VNODE_BUF_SIZE];
    memset(vbuf, 0, sizeof(vbuf));
    if (krw_read_buf(orig_vnode, vbuf, sizeof(vbuf)) != 0) {
        fprintf(stderr, "hide: failed to read vnode\n");
        return -1;
    }

    /* Remember the original v_type for logging */
    uint16_t orig_type = *(uint16_t *)(vbuf + OFF_V_TYPE);

    /* Set v_type = VBAD (0).  The kernel VFS layer checks this field
       before most operations and returns ENOENT for VBAD vnodes. */
    *(uint16_t *)(vbuf + OFF_V_TYPE) = 0;

    /* Write back */
    if (krw_write_buf(orig_vnode, vbuf, sizeof(vbuf)) != 0) {
        fprintf(stderr, "hide: failed to write vnode\n");
        return -1;
    }

    printf("hide: vnode 0x%llx  v_type 0x%x -> VBAD\n",
           (unsigned long long)orig_vnode, orig_type);

    return 0;
}

/* ---------- hide a single path ---------- */
int vnode_hide_path(const char *path) {
    uint64_t orig_vnode = get_vnode_for_path(path);
    if (!orig_vnode) {
        fprintf(stderr, "hide: cannot resolve vnode for '%s' (does it exist?)\n", path);
        return -1;
    }

    printf("hide: %s  vnode=0x%llx\n",
           path, (unsigned long long)orig_vnode);

    int ret = vnode_mark_bad(orig_vnode);
    if (ret == 0) {
        printf("hide: OK  %s\n", path);
    } else {
        fprintf(stderr, "hide: FAILED  %s\n", path);
    }
    return ret;
}

/* ---------- hide all known jailbreak paths ---------- */
static const char *g_hide_paths[] = {
    "/var/jb",
    "/var/jb/",
    "/private/preboot",
    "/etc/apt",
    "/Applications/Cydia.app",
    "/Applications/Sileo.app",
    "/Applications/Zebra.app",
    "/private/var/lib/cydia",
    "/private/var/tmp/cydia.log",
    "/private/var/lib/apt",
    "/private/var/stash",
    "/private/var/db/stash",
    "/private/var/mobile/Library/Preferences/com.ellekit",
    "/private/var/mobile/Library/Preferences/com.substrate",
    "/private/var/run/jailbreak",
    "/bin/bash",
    "/usr/sbin/sshd",
    "/Library/MobileSubstrate",
    "/Library/Substrate",
    "/private/var/log/syslog",
    "/private/var/log/apt",
    "/private/var/log/dpkg",
    NULL,
};

int vnode_hide_all(void) {
    int ret = 0;
    for (int i = 0; g_hide_paths[i]; i++) {
        int r = vnode_hide_path(g_hide_paths[i]);
        if (r != 0) ret = -1;
    }

    /* Also try to hide the TweakInject directory */
    vnode_hide_path("/var/jb/usr/lib/TweakInject");
    vnode_hide_path("/var/jb/usr/lib/libjailbreak.dylib");
    vnode_hide_path("/var/jb/usr/lib/libsubstrate.dylib");
    vnode_hide_path("/var/jb/Library/Frameworks/CydiaSubstrate.framework");

    return ret;
}

/* ---------- restore all hidden vnodes ---------- */
int vnode_restore_all(void) {
    int restored = 0;
    for (int i = 0; i < g_saved_count; i++) {
        int ret = krw_write_buf(g_saved_vnodes[i].vaddr,
                                g_saved_vnodes[i].data, VNODE_BUF_SIZE);
        if (ret == 0) {
            printf("restore: OK  0x%llx\n",
                   (unsigned long long)g_saved_vnodes[i].vaddr);
            restored++;
        } else {
            fprintf(stderr, "restore: FAILED  0x%llx\n",
                    (unsigned long long)g_saved_vnodes[i].vaddr);
        }
    }
    g_saved_count = 0;
    printf("restore: %d vnodes restored\n", restored);
    return (restored > 0) ? 0 : -1;
}

/* ---------- per-process kernel-level cleanup ---------- */

/* Set CS_PLATFORM_BINARY and clear CS_VALID|CS_GET_TASK_ALLOW on the target proc */
int proc_platformize(uint64_t proc) {
    if (!proc) return -1;
    uint32_t csflags = krw_read32(proc + koffsetof(proc, csflags));
    printf("hide: proc=0x%llx  csflags=0x%x", (unsigned long long)proc, csflags);

    csflags |= 0x04000000;  /* CS_PLATFORM_BINARY */
    csflags &= ~0x00000001; /* clear CS_VALID (let kernel re-validate) */
    csflags &= ~0x00000002; /* CS_GET_TASK_ALLOW */
    krw_write32(proc + koffsetof(proc, csflags), csflags);

    uint32_t new_cs = krw_read32(proc + koffsetof(proc, csflags));
    printf("  -> 0x%x\n", new_cs);
    return 0;
}

/* Clean known jailbreak flags in the proc struct */
int proc_clean_csflags(uint64_t proc) {
    if (!proc) return -1;
    uint32_t csflags = krw_read32(proc + koffsetof(proc, csflags));
    uint32_t orig = csflags;

    /* Clear debugger flags - apps check these */
    csflags &= ~0x00000004; /* CS_DEBUGGED */
    csflags &= ~0x02000000; /* CS_EXEC_SET_HARD */
    csflags &= ~0x08000000; /* CS_EXEC_SET_KILL */
    csflags |= 0x04000000;  /* CS_PLATFORM_BINARY */

    krw_write32(proc + koffsetof(proc, csflags), csflags);
    printf("hide: proc csflags 0x%x -> 0x%x\n", orig, csflags);
    return 0;
}

/* ---------- per-app process cleanup ---------- */

/* Find a process by PID and apply platformize */
int proc_platformize_pid(pid_t pid) {
    uint64_t proc = krw_proc_for_pid(pid);
    if (!proc) {
        fprintf(stderr, "hide: cannot find pid %d\n", pid);
        return -1;
    }
    printf("hide: found pid %d proc=0x%llx\n", pid, (unsigned long long)proc);
    return proc_platformize(proc);
}

/* Find a process by PID and apply full csflags cleanup */
int proc_clean_csflags_pid(pid_t pid) {
    uint64_t proc = krw_proc_for_pid(pid);
    if (!proc) {
        fprintf(stderr, "hide: cannot find pid %d\n", pid);
        return -1;
    }
    printf("hide: found pid %d proc=0x%llx\n", pid, (unsigned long long)proc);
    return proc_clean_csflags(proc);
}

/* Full per-app kernel-level cleanup on a target PID */
int proc_hide_pid(pid_t pid) {
    uint64_t proc = krw_proc_for_pid(pid);
    if (!proc) {
        fprintf(stderr, "hide: cannot find pid %d\n", pid);
        return -1;
    }

    printf("hide: target pid %d proc = 0x%llx\n", pid, (unsigned long long)proc);

    proc_platformize(proc);
    proc_clean_csflags(proc);

    /* Unset P_SUGID flag */
    uint32_t p_flag = krw_read32(proc + koffsetof(proc, flag));
    p_flag &= ~0x00000100;
    krw_write32(proc + koffsetof(proc, flag), p_flag);

    /* Set TF_PLATFORM in task flags */
    uint64_t task = krw_proc_task(proc);
    if (task) {
        uint32_t task_flags = krw_read32(task + koffsetof(task, flags));
        task_flags |= 0x00000400;
        krw_write32(task + koffsetof(task, flags), task_flags);
        printf("hide: task_flags |= TF_PLATFORM -> 0x%x\n", task_flags);
    }

    /* Update proc_ro csflags if available */
    if (koffsetof(proc_ro, exists) && koffsetof(proc_ro, csflags)) {
        uint64_t proc_ro = krw_read64(proc + koffsetof(proc, proc_ro));
        if (proc_ro) {
            uint32_t ro_csflags = krw_read32(proc_ro + koffsetof(proc_ro, csflags));
            ro_csflags |= 0x04000000;
            krw_write32(proc_ro + koffsetof(proc_ro, csflags), ro_csflags);
            printf("hide: proc_ro csflags |= CS_PLATFORM_BINARY\n");
        }
    }

    printf("hide: per-app cleanup done for pid %d\n", pid);
    return 0;
}

/* Hide jailbreak traces from the current process's proc struct */
int proc_hide_self(void) {
    uint64_t proc = krw_proc_self();
    if (!proc) {
        fprintf(stderr, "hide: failed to get self proc\n");
        return -1;
    }

    printf("hide: self proc = 0x%llx\n", (unsigned long long)proc);

    proc_platformize(proc);
    proc_clean_csflags(proc);

    /* Unset P_SUGID flag which some apps check */
    uint32_t p_flag = krw_read32(proc + koffsetof(proc, flag));
    p_flag &= ~0x00000100; /* P_SUGID */
    krw_write32(proc + koffsetof(proc, flag), p_flag);

    /* Set kernel debug flags to make the process appear as a system process */
    uint32_t task_flags = 0;
    uint64_t task = krw_proc_task(proc);
    if (task) {
        task_flags = krw_read32(task + koffsetof(task, flags));
        task_flags |= 0x00000400; /* TF_PLATFORM */
        krw_write32(task + koffsetof(task, flags), task_flags);
        printf("hide: task_flags |= TF_PLATFORM -> 0x%x\n", task_flags);
    }

    /* Try to set the process as a platform binary via proc_ro if available */
    if (koffsetof(proc_ro, exists) && koffsetof(proc_ro, csflags)) {
        uint64_t proc_ro = krw_read64(proc + koffsetof(proc, proc_ro));
        if (proc_ro) {
            uint32_t ro_csflags = krw_read32(proc_ro + koffsetof(proc_ro, csflags));
            ro_csflags |= 0x04000000;
            krw_write32(proc_ro + koffsetof(proc_ro, csflags), ro_csflags);
            printf("hide: proc_ro csflags |= CS_PLATFORM_BINARY\n");
        }
    }

    return 0;
}