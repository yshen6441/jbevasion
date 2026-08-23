#include "hide.h"
#include "krw.h"
#include <libjailbreak/kernel.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

/* ------------------------------------------------------------------ */
/*  vnode hiding is DEPRECATED – replaced by fd_rdir chroot approach. */
/*  The vnode_mark_bad() approach caused kernel panics on iOS 17 A14  */
/*  (vnode struct offsets may be wrong, or PPL prevents writes).      */
/*  We now use KernBypass-style filedesc->fd_rdir modification.       */
/*  These stub functions are kept for backward compatibility.         */
/* ------------------------------------------------------------------ */

int vnode_hide_init(void) { return 0; }
int vnode_hide_cleanup(void) { return 0; }

int vnode_hide_path(const char *path) {
    printf("hide: vnode hiding is deprecated, use 'jbevasion chroot <pid>' instead\n");
    printf("hide: (path %s will not be hidden via vnode modification)\n", path);
    return -1;
}

int vnode_hide_all(void) {
    printf("hide: vnode hiding is deprecated, use 'jbevasion chroot-prep' + 'jbevasion chroot <pid>' instead\n");
    return -1;
}

int vnode_restore_all(void) {
    printf("restore: vnode hiding is deprecated, nothing to restore\n");
    return 0;
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