#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/sysctl.h>
#include "krw.h"
#include "hide.h"
#include "fd_rdir.h"
#include "apphide.h"
#include "vhide.h"

#include <spawn.h>
#include <sys/wait.h>

extern char **environ;

/* Declared in libjailbreak (jbclient_xpc.h) */
extern int jbclient_dopamine_get_root(void);

#define MACH_HEADER_MAGIC_64 0xfeedfacf

/* Attempt to become root. Tries setuid(0) first; if that fails (uid unchanged),
 * falls back to jbclient_dopamine_get_root() which asks jailbreakd to elevate us. */
__attribute__((constructor))
static void ensure_root(void) {
    uid_t orig = getuid();
    if (orig == 0) return;
    setuid(0);
    setgid(0);
    if (getuid() == 0) return;
    fprintf(stderr, "ensure_root: setuid(0) failed (uid still %d), trying jbclient_dopamine_get_root()\n", getuid());
    int r = jbclient_dopamine_get_root();
    if (r == 0) {
        fprintf(stderr, "ensure_root: jbclient_dopamine_get_root() OK, uid=%d\n", getuid());
    } else {
        fprintf(stderr, "ensure_root: jbclient_dopamine_get_root() failed (%d), uid=%d\n", r, getuid());
    }
}

static void print_usage(void) {
	printf("Usage: jbevasion <command>\n");
	printf("Commands:\n");
	printf("  probe <pid>        Print filedesc offsets + live field values\n");
	printf("  vnode <path>       Resolve a path to its vnode and print flags\n");
	printf("  chroot-prep        Build clean fake root (bindfs bind, skips jb)\n");
	printf("  chroot <pid>       Apply fd_rdir chroot + platformize to target PID\n");
	printf("  unchroot <pid>     Clear FD_CHROOT, restore rdir=NULL on target PID\n");
	printf("  chroot-cleanup     Unmount the fake root\n");
	printf("  diag-mount         Mount(2) diagnostic battery for tmpfs overlay EIO\n");
	printf("  app <pid>          Platformize + clean csflags for a specific PID\n");
	printf("  platformize        Set CS_PLATFORM_BINARY + TF_PLATFORM on self\n");
	printf("  hide               (deprecated) Per-process cleanup only\n");
	printf("  restore            (deprecated) No-op\n");
	printf("  apphide list       List jailbroken apps in /var/jb/Applications\n");
	printf("  apphide <bundleid> Hide one app (move .app + uicache + respring)\n");
	printf("  apphide-known      Hide well-known package managers (Sileo/Cydia/Filza...)\n");
	printf("  apphide-all        Hide every app in /var/jb/Applications\n");
	printf("  apphide-show <id>  Restore one hidden app\n");
	printf("  apphide-showall    Restore all hidden apps\n");
	printf("  apphide-status     Show hidden/visible app status\n");
	printf("  vhide <path>       Hide one path via vnode VBAD (safe targets only)\n");
	printf("  vhide-all          Hide all target paths (built-in + config plist)\n");
	printf("  vhide-showall      Restore all hidden vnodes\n");
	printf("  vhide-status       Show protected rules + per-target VBAD state\n");
	printf("  vhide-reload       Reload /var/jb/Library/Preferences/com.jbevasion.vhide.plist\n");
	printf("  help               Show this message\n");
}

static void print_mach_header(uint64_t base) {
	struct {
		uint32_t magic;
		int32_t  cputype;
		int32_t  cpusubtype;
		uint32_t filetype;
		uint32_t ncmds;
		uint32_t sizeofcmds;
		uint32_t flags;
		uint32_t reserved;
	} mh;
	if (krw_read_buf(base, &mh, sizeof(mh)) != 0) {
		printf("[-] failed to read mach header at 0x%llx\n", (unsigned long long)base);
		return;
	}
	printf("[+] kernel mach_header dump:\n");
	printf("    magic      = 0x%x (%s)\n", mh.magic,
	       mh.magic == MACH_HEADER_MAGIC_64 ? "MH_MAGIC_64 OK" : "MISMATCH");
	printf("    cputype    = 0x%x (arm64e=0x%x)\n", mh.cputype, (int)0x100000c);
	printf("    filetype   = 0x%x\n", mh.filetype);
	printf("    ncmds      = %u\n", mh.ncmds);
	printf("    flags      = 0x%x\n", mh.flags);
}

static int cmd_probe_kernel(void) {
	printf("====================================\n");
	printf(" jbevasion probe (Dopamine KRW)\n");
	printf("====================================\n");

	uid_t uid = getuid();
	printf("[i] running as uid=%d\n", uid);
	if (uid != 0) {
		printf("[-] krw requires root – try 'sudo jbevasion probe' or SSH as root\n");
		return 1;
	}

	int ret = krw_init();
	if (ret != 0) {
		printf("[-] krw_init failed (%d). Is this a Dopamine /var/jb environment?\n", ret);
		return 1;
	}
	printf("[+] primitives initialized\n");

	/* Constant info */
	uint64_t base   = krw_kernel_base();
	uint64_t slide  = krw_kernel_slide();
	uint64_t pbase  = krw_kernel_physbase();
	uint64_t vbase  = krw_kernel_virtbase();
	uint64_t vsize  = krw_kernel_virtsize();
	printf("[+] kernel base    = 0x%llx\n", (unsigned long long)base);
	printf("[+] kernel slide   = 0x%llx\n", (unsigned long long)slide);
	printf("[+] phys base      = 0x%llx\n", (unsigned long long)pbase);
	printf("[+] virt base      = 0x%llx\n", (unsigned long long)vbase);
	printf("[+] virt size      = 0x%llx\n", (unsigned long long)vsize);

	if (base == 0 || slide == 0) {
		printf("[-] kernel base/slide unexpectedly 0\n");
		return 1;
	}

	/* Read mach header to prove kread works */
	print_mach_header(base);

	/* Self process */
	uint64_t myproc = krw_proc_self();
	printf("[+] this_proc = 0x%llx\n", (unsigned long long)myproc);
	if (myproc) {
		uint32_t pid = krw_proc_pid(myproc);
		printf("[+] proc->p_pid = %u (getpid=%d)\n", pid, (int)getpid());
		uint64_t mytask = krw_proc_task(myproc);
		printf("[+] proc->task  = 0x%llx\n", (unsigned long long)mytask);
		int sanity = 0;
		for (int fd = 0; fd < 8; fd++) {
			uint64_t vn = krw_proc_vnode_for_fd(myproc, fd);
			if (vn) sanity++;
		}
		printf("[+] resolved vnodes for fds 0..7 => %d non-zero\n", sanity);
	}

	/* kcall availability */
	printf("[+] kcall available = %s\n", krw_kcall_available() ? "yes" : "no");

	printf("====================================\n");
	printf(" probe OK\n");
	return 0;
}

static int cmd_vnode(const char *path) {
	if (!path) {
		printf("[-] missing path\n");
		return 1;
	}
	int ret = krw_init();
	if (ret != 0) {
		printf("[-] krw_init failed (%d)\n", ret);
		return 1;
	}
	printf("[i] path: %s\n", path);
	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		printf("[-] open failed: %s\n", strerror(errno));
		return 1;
	}
	uint64_t vnode = krw_proc_vnode_for_fd(krw_proc_self(), fd);
	close(fd);
	if (!vnode) {
		printf("[-] failed to resolve vnode\n");
		return 1;
	}
	uint32_t flags = krw_vnode_flags(vnode);
	uint32_t usecount = krw_read32(vnode + 0x60);
	uint32_t iocount = krw_read32(vnode + 0x64);
	printf("[+] vnode   = 0x%llx\n", (unsigned long long)vnode);
	printf("[+] v_flags = 0x%x (VISSHADOW=%u)\n", flags, (flags & KRW_VISSHADOW) ? 1 : 0);
	printf("[+] usecount= %u  iocount=%u\n", usecount, iocount);
	if (usecount == 0 || usecount > 0xFFFF || iocount > 0xFFFF) {
		printf("[-] suspicious counters, offsets may be wrong\n");
		return 1;
	}
	return 0;
}

static int is_numeric(const char *s) {
	if (!s || !*s) return 0;
	while (*s) { if (*s < '0' || *s > '9') return 0; s++; }
	return 1;
}

static int cmd_hide(int argc, char *argv[]) {
	int ret = krw_init();
	if (ret != 0) {
		printf("[-] krw_init failed (%d). Are you root on a Dopamine jailbreak?\n", ret);
		return 1;
	}

	printf("========================================\n");
	printf("  hide is deprecated – use 'chroot' instead\n");
	printf("  Running per-process cleanup only\n");
	printf("========================================\n");

	if (argc >= 3 && is_numeric(argv[2])) {
		pid_t target = (pid_t)atoi(argv[2]);
		proc_hide_pid(target);
		printf("[+] per-process cleanup done for pid %d\n", target);
	} else {
		proc_hide_self();
		printf("[+] per-process cleanup done for self\n");
	}

	return 0;
}

static int cmd_app(int argc, char *argv[]) {
	if (argc < 3) {
		printf("[-] usage: jbevasion app <pid>\n");
		return 1;
	}
	pid_t target = (pid_t)atoi(argv[2]);
	if (target <= 0) {
		printf("[-] invalid pid: %s\n", argv[2]);
		return 1;
	}
	int ret = krw_init();
	if (ret != 0) {
		printf("[-] krw_init failed (%d)\n", ret);
		return 1;
	}
	printf("========================================\n");
	printf("  Per-app kernel-level cleanup for pid %d\n", target);
	printf("========================================\n");
	ret = proc_hide_pid(target);
	if (ret != 0) {
		printf("[-] app cleanup failed\n");
		return 1;
	}
	printf("[+] app cleanup complete for pid %d\n", target);
	return 0;
}

static int cmd_restore(void) {
    printf("========================================\n");
    printf("  restore is deprecated – no-op (fd_rdir chroot is reversible by restarting the process)\n");
    printf("========================================\n");
    vnode_restore_all();
    return 0;
}

static int cmd_chroot_prep(void) {
    int ret = krw_init();
    if (ret != 0) {
        printf("[-] krw_init failed (%d)\n", ret);
        return 1;
    }
    printf("========================================\n");
    printf("  Preparing clean root for fd_rdir chroot\n");
    printf("========================================\n");
    ret = fd_rdir_prepare();
    if (ret != 0) {
        printf("[-] fd_rdir_prepare failed\n");
        return 1;
    }
    printf("[+] clean root ready at %s\n", JBEVASION_ROOT);
    return 0;
}

static int cmd_chroot(int argc, char *argv[]) {
    if (argc < 3) {
        printf("[-] usage: jbevasion chroot <pid>\n");
        return 1;
    }
    pid_t target = (pid_t)atoi(argv[2]);
    if (target <= 0) {
        printf("[-] invalid pid: %s\n", argv[2]);
        return 1;
    }
    int ret = krw_init();
    if (ret != 0) {
        printf("[-] krw_init failed (%d)\n", ret);
        return 1;
    }
    printf("========================================\n");
    printf("  Applying fd_rdir chroot to pid %d\n", target);
    printf("========================================\n");
    ret = fd_rdir_apply(target);
    if (ret != 0) {
        printf("[-] fd_rdir_apply failed\n");
        return 1;
    }
    printf("[+] fd_rdir chroot applied to pid %d\n", target);
    return 0;
}

static int cmd_chroot_cleanup(void) {
    printf("========================================\n");
    printf("  Cleaning up fd_rdir chroot\n");
    printf("========================================\n");
    fd_rdir_cleanup();
    printf("[+] chroot cleanup done\n");
    return 0;
}

static int cmd_diag_mount(void) {
    int ret = krw_init();
    if (ret != 0) {
        printf("[-] krw_init failed (%d)\n", ret);
        return 1;
    }
    ret = fd_rdir_diag_mount();
    if (ret != 0) {
        printf("[-] diag-mount failed\n");
        return 1;
    }
    return 0;
}

static int cmd_unchroot(int argc, char *argv[]) {
    if (argc < 3) {
        printf("[-] usage: jbevasion unchroot <pid>\n");
        return 1;
    }
    pid_t target = (pid_t)atoi(argv[2]);
    if (target <= 0) {
        printf("[-] invalid pid: %s\n", argv[2]);
        return 1;
    }
    int ret = krw_init();
    if (ret != 0) {
        printf("[-] krw_init failed (%d)\n", ret);
        return 1;
    }
    printf("========================================\n");
    printf("  Clearing fd_rdir chroot on pid %d\n", target);
    printf("========================================\n");
    ret = fd_rdir_unchroot(target);
    if (ret != 0) {
        printf("[-] fd_rdir_unchroot failed\n");
        return 1;
    }
    printf("[+] fd_rdir chroot cleared on pid %d\n", target);
    return 0;
}

static int cmd_probe_filedesc(int argc, char *argv[]) {
    if (argc < 3) {
        printf("[-] usage: jbevasion probe <pid>\n");
        return 1;
    }
    pid_t target = (pid_t)atoi(argv[2]);
    if (target <= 0) {
        printf("[-] invalid pid: %s\n", argv[2]);
        return 1;
    }
    int ret = krw_init();
    if (ret != 0) {
        printf("[-] krw_init failed (%d)\n", ret);
        return 1;
    }
    printf("========================================\n");
    printf("  Probing filedesc offsets for pid %d\n", target);
    printf("========================================\n");
    ret = fd_rdir_probe(target);
    if (ret != 0) {
        printf("[-] probe failed\n");
        return 1;
    }
    printf("[+] probe done\n");
    return 0;
}

static int cmd_platformize(void) {
	int ret = krw_init();
	if (ret != 0) {
		printf("[-] krw_init failed (%d)\n", ret);
		return 1;
	}
	return proc_hide_self();
}

static int cmd_vhide(int argc, char *argv[]) {
	int ret = krw_init();
	if (ret != 0) {
		printf("[-] krw_init failed (%d)\n", ret);
		return 1;
	}
	vhide_config_load();
	if (argc >= 3 && strcmp(argv[2], "all") == 0) {
		return vhide_known();
	} else if (argc >= 3 && strcmp(argv[2], "showall") == 0) {
		return vhide_restore_all();
	} else if (argc >= 3 && strcmp(argv[2], "status") == 0) {
		return vhide_status();
	} else if (argc >= 3 && strcmp(argv[2], "reload") == 0) {
		return vhide_config_load();
	} else if (argc >= 3) {
		return vhide_path(argv[2]);
	}
	printf("usage: vhide <path|all|showall|status|reload>\n");
	return 1;
}

static int cmd_respring(void) {
	uid_t uid = getuid();
	if (uid != 0) {
		fprintf(stderr, "respring: requires root\n");
		return 1;
	}
	printf("respring: killing SpringBoard to rescan icon model...\n");

	pid_t pid = 0;
	char *args[4];
	args[0] = "/usr/bin/killall";
	args[1] = "-9";
	args[2] = "SpringBoard";
	args[3] = NULL;
	const char *jb_killall = "/var/jb/usr/bin/killall";
	if (access(jb_killall, X_OK) == 0) {
		/* rootless: real killall lives under /var/jb */
		args[0] = (char *)jb_killall;
	}

	/* killall natively uses SIGKILL-style semantics for respring on iOS:
	 * SIGSEGV is what sbreload/ldrestart use to have SpringBoard restart
	 * without a full device reboot. */
	posix_spawnattr_t attr;
	posix_spawnattr_init(&attr);
	int r = posix_spawn(&pid, args[0], NULL, &attr, args, environ);
	posix_spawnattr_destroy(&attr);
	if (r != 0) {
		fprintf(stderr, "respring: posix_spawn failed: %s\n", strerror(errno));
		return 1;
	}
	int status = 0;
	waitpid(pid, &status, 0);
	printf("respring: SpringBoard restarted (exit=%d)\n", status);
	printf("respring: icons should reflect hidden/restored apps now.\n");
	return 0;
}

int main(int argc, char *argv[]) {
	if (argc < 2) {
		print_usage();
		return 0;
	}
	const char *cmd = argv[1];
	if (strcmp(cmd, "probe") == 0) {
		if (argc >= 3 && is_numeric(argv[2])) {
			return cmd_probe_filedesc(argc, argv);
		}
		return cmd_probe_kernel();
	} else if (strcmp(cmd, "vnode") == 0) {
		return cmd_vnode(argc >= 3 ? argv[2] : NULL);
	} else if (strcmp(cmd, "chroot-prep") == 0) {
		return cmd_chroot_prep();
	} else if (strcmp(cmd, "chroot") == 0) {
		return cmd_chroot(argc, argv);
	} else if (strcmp(cmd, "unchroot") == 0) {
		return cmd_unchroot(argc, argv);
	} else if (strcmp(cmd, "chroot-cleanup") == 0) {
		return cmd_chroot_cleanup();
	} else if (strcmp(cmd, "diag-mount") == 0) {
		return cmd_diag_mount();
	} else if (strcmp(cmd, "hide") == 0) {
		return cmd_hide(argc, argv);
	} else if (strcmp(cmd, "restore") == 0) {
		return cmd_restore();
	} else if (strcmp(cmd, "app") == 0) {
		return cmd_app(argc, argv);
	} else if (strcmp(cmd, "platformize") == 0) {
		return cmd_platformize();
	} else if (strcmp(cmd, "apphide") == 0) {
		int ret = krw_init();
		if (ret != 0) {
			printf("[-] krw_init failed (%d)\n", ret);
			return 1;
		}
		if (argc >= 3 && strcmp(argv[2], "list") == 0) {
			return apphide_list();
		} else if (argc >= 3 && strcmp(argv[2], "all") == 0) {
			return apphide_hide_all();
		} else if (argc >= 3 && strcmp(argv[2], "known") == 0) {
			return apphide_hide_known();
		} else if (argc >= 3 && strcmp(argv[2], "show") == 0) {
			if (argc >= 4) return apphide_unhide(argv[3]);
			return apphide_unhide_all();
		} else if (argc >= 3 && strcmp(argv[2], "showall") == 0) {
			return apphide_unhide_all();
		} else if (argc >= 3 && strcmp(argv[2], "status") == 0) {
			return apphide_status();
		} else if (argc >= 3) {
			return apphide_hide(argv[2]);
		}
		print_usage();
		return 1;
	} else if (strcmp(cmd, "apphide-known") == 0) {
		if (krw_init() != 0) return 1;
		return apphide_hide_known();
	} else if (strcmp(cmd, "apphide-all") == 0) {
		if (krw_init() != 0) return 1;
		return apphide_hide_all();
	} else if (strcmp(cmd, "apphide-list") == 0) {
		return apphide_list();
	} else if (strcmp(cmd, "apphide-show") == 0) {
		if (krw_init() != 0) return 1;
		if (argc >= 3) {
			return apphide_unhide(argv[2]);
		}
		return apphide_unhide_all();
	} else if (strcmp(cmd, "apphide-showall") == 0) {
		if (krw_init() != 0) return 1;
		return apphide_unhide_all();
	} else if (strcmp(cmd, "apphide-status") == 0) {
		return apphide_status();
	} else if (strcmp(cmd, "vhide") == 0) {
		return cmd_vhide(argc, argv);
	} else if (strcmp(cmd, "vhide-all") == 0) {
		if (krw_init() != 0) return 1;
		vhide_config_load();
		return vhide_known();
	} else if (strcmp(cmd, "vhide-showall") == 0) {
		if (krw_init() != 0) return 1;
		return vhide_restore_all();
	} else if (strcmp(cmd, "vhide-status") == 0) {
		vhide_config_load();
		return vhide_status();
	} else if (strcmp(cmd, "vhide-reload") == 0) {
		return vhide_config_load();
	} else if (strcmp(cmd, "respring") == 0) {
		return cmd_respring();
	} else if (strcmp(cmd, "help") == 0 || strcmp(cmd, "-h") == 0) {
		print_usage();
		return 0;
	}
	printf("unknown command: %s\n", cmd);
	print_usage();
	return 1;
}