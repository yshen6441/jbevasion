#include "vhide.h"
#include "hide.h"
#include "krw.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

/*
 * Runtime-essential prefixes. A path that matches any of these MUST NOT be
 * hidden: tweak injection resolves libjailbreak / TweakInject / the hooking
 * engines every time a process starts, jailbreakd needs to keep running, and
 * hiding our own binary would make the toggle unspawnable. Hiding any of
 * these = the whole jailbreak environment breaks, so we refuse.
 */
static const char *g_protected_tokens[] = {
	"/usr/lib/libjailbreak",
	"/usr/lib/TweakInject",
	"/usr/lib/libellekit",
	"/usr/lib/libsubstrate",
	"/usr/lib/libhooker",
	"/usr/lib/substitute",
	"/usr/bin/jailbreakd",
	"/usr/bin/launchdhook",
	"/usr/bin/jbevasion",
	NULL,
};

/*
 * Safe default hide targets. These are the classic jailbreak-detection
 * traces that are NOT needed for any tweak/plugin to run, so hiding them
 * can't break the environment. All paths are checked against
 * g_protected_tokens first and skipped if any match.
 */
static const char *g_known_targets[] = {
	"/var/jb/usr/bin/bash",
	"/var/jb/usr/bin/zsh",
	"/var/jb/usr/sbin/sshd",
	"/var/jb/usr/bin/dropbear",
	"/var/jb/usr/bin/frida",
	"/var/jb/usr/bin/frida-server",
	"/var/jb/usr/lib/frida",
	"/var/jb/usr/include/frida-core.h",
	"/var/jb/etc/apt",
	"/var/jb/usr/lib/apt",
	"/var/jb/usr/lib/dpkg",
	"/var/jb/var/lib/dpkg",
	"/var/jb/var/lib/apt",
	"/var/jb/var/cache/apt",
	"/var/jb/var/log/apt",
	"/var/jb/var/log/dpkg",
	"/private/var/log/apt",
	"/private/var/lib/apt",
	"/private/var/lib/dpkg",
	"/private/var/stash",
	"/private/var/db/stash",
	"/private/var/tmp/cydia.log",
	"/private/var/mobile/Library/Preferences/com.ellekit",
	"/private/var/mobile/Library/Preferences/com.substrate",
	NULL,
};

static int is_protected(const char *path) {
	if (!path) return 1;
	for (int i = 0; g_protected_tokens[i]; i++) {
		if (strstr(path, g_protected_tokens[i])) {
			fprintf(stderr, "vhide: refusing to hide %s (matches protected rule '%s')\n",
			        path, g_protected_tokens[i]);
			return 1;
		}
	}
	return 0;
}

static int path_exists(const char *path) {
	struct stat st;
	return stat(path, &st) == 0;
}

int vhide_path(const char *path) {
	if (!path || !*path) {
		fprintf(stderr, "vhide: missing path\n");
		return -1;
	}
	if (is_protected(path)) {
		fprintf(stderr, "vhide: cannot hide protected runtime path %s\n", path);
		return -1;
	}
	if (!path_exists(path)) {
		fprintf(stderr, "vhide: %s does not exist\n", path);
		return -1;
	}
	return vnode_hide_path(path);
}

int vhide_known(void) {
	int hidden = 0, skipped = 0, missing = 0;
	for (int i = 0; g_known_targets[i]; i++) {
		const char *p = g_known_targets[i];
		if (is_protected(p)) {
			skipped++;
			continue;
		}
		if (!path_exists(p)) {
			missing++;
			continue;
		}
		if (vnode_hide_path(p) == 0) hidden++;
		else skipped++;
	}
	printf("vhide: hidden %d target(s), %d missing, %d skipped protected\n",
	       hidden, missing, skipped);
	return 0;
}

int vhide_restore_all(void) {
	return vnode_restore_all();
}

int vhide_status(void) {
	printf("vhide: protected (never hidden) rules:\n");
	for (int i = 0; g_protected_tokens[i]; i++) {
		printf("  %s\n", g_protected_tokens[i]);
	}
	printf("vhide: known targets present on disk:\n");
	for (int i = 0; g_known_targets[i]; i++) {
		uint16_t vtype = 0;
		if (!path_exists(g_known_targets[i])) {
			printf("  [missing] %s\n", g_known_targets[i]);
			continue;
		}
		/* resolve and report vnode type to show VBAD state (needs ready KRW) */
		if (krw_ready()) {
			int fd = open(g_known_targets[i], O_RDONLY | O_NONBLOCK);
			if (fd >= 0) {
				uint64_t vn = krw_proc_vnode_for_fd(krw_proc_self(), fd);
				close(fd);
				if (vn) vtype = krw_read16(vn + 0x74);
			}
		}
		printf("  [%s] %s\n", (vtype == 0) ? "hidden(VBAD)" : "visible", g_known_targets[i]);
	}
	return 0;
}
