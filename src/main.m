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

extern int cmd_detect(void);
extern int cmd_shield_test(void);

#define MACH_HEADER_MAGIC_64 0xfeedfacf

static void print_usage(void) {
	printf("Usage: jbevasion <command>\n");
	printf("Commands:\n");
	printf("  probe         Verify the Dopamine KRW primitives end to end\n");
	printf("  vnode <path>  Resolve a path to its vnode and print flags\n");
	printf("  detect        Run jailbreak detection probes (Phase 1)\n");
	printf("  shield test   (deprecated - use 'hide' instead)\n");
	printf("  hide          Hide all jailbreak paths at the vnode level (kernel)\n");
	printf("  hide <path>   Hide a specific path at the vnode level\n");
	printf("  hide <pid>    Hide all jailbreak paths + platformize target PID\n");
	printf("  restore       Restore all hidden vnodes (reboot also works)\n");
	printf("  app <pid>     Platformize + clean csflags for a specific PID\n");
	printf("  platformize   Set CS_PLATFORM_BINARY + TF_PLATFORM on self\n");
	printf("  help          Show this message\n");
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

static int cmd_probe(void) {
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

	if (argc >= 3) {
		if (is_numeric(argv[2])) {
			/* Hide all paths + platformize target PID */
			pid_t target = (pid_t)atoi(argv[2]);
			printf("========================================\n");
			printf("  Hiding all jailbreak paths + app pid %d\n", target);
			printf("========================================\n");
			ret = vnode_hide_all();
			printf("========================================\n");
			printf("  Platformizing pid %d\n", target);
			printf("========================================\n");
			proc_hide_pid(target);
		} else {
			/* Hide a specific path */
			ret = vnode_hide_path(argv[2]);
		}
	} else {
		/* Hide all known paths + self */
		printf("========================================\n");
		printf("  Hiding all jailbreak paths at vnode level\n");
		printf("========================================\n");
		ret = vnode_hide_all();
		printf("========================================\n");
		printf("  Platformizing current process\n");
		printf("========================================\n");
		proc_hide_self();
	}

	if (ret != 0) {
		printf("[-] some paths failed\n");
		return 1;
	}
	printf("[+] vnode hiding complete\n");
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
    int ret = krw_init();
    if (ret != 0) {
        printf("[-] krw_init failed (%d)\n", ret);
        return 1;
    }
    printf("========================================\n");
    printf("  Restoring all hidden vnodes\n");
    printf("========================================\n");
    ret = vnode_restore_all();
    if (ret != 0) {
        printf("[-] nothing to restore or restore failed\n");
        return 1;
    }
    printf("[+] restore complete\n");
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

int main(int argc, char *argv[]) {
	if (argc < 2) {
		print_usage();
		return 0;
	}
	const char *cmd = argv[1];
	if (strcmp(cmd, "probe") == 0) {
		return cmd_probe();
	} else if (strcmp(cmd, "vnode") == 0) {
		return cmd_vnode(argc >= 3 ? argv[2] : NULL);
	} else if (strcmp(cmd, "detect") == 0) {
		return cmd_detect();
	} else if (strcmp(cmd, "shield") == 0 && argc >= 3 && strcmp(argv[2], "test") == 0) {
		return cmd_shield_test();
	} else if (strcmp(cmd, "hide") == 0) {
		return cmd_hide(argc, argv);
	} else if (strcmp(cmd, "restore") == 0) {
		return cmd_restore();
	} else if (strcmp(cmd, "app") == 0) {
		return cmd_app(argc, argv);
	} else if (strcmp(cmd, "platformize") == 0) {
		return cmd_platformize();
	} else if (strcmp(cmd, "help") == 0 || strcmp(cmd, "-h") == 0) {
		print_usage();
		return 0;
	}
	printf("unknown command: %s\n", cmd);
	print_usage();
	return 1;
}