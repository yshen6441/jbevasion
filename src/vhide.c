#include "vhide.h"
#include "hide.h"
#include "krw.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <CoreFoundation/CoreFoundation.h>

/*
 * Runtime-essential prefixes. A path that matches any of these MUST NOT be
 * hidden: tweak injection resolves libjailbreak / TweakInject / the hooking
 * engines every time a process starts, jailbreakd needs to keep running, and
 * hiding our own binary would make the toggle unspawnable. Hiding any of
 * these = the whole jailbreak environment breaks, so we refuse.
 */
static const char *g_protected_builtin[] = {
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
 * can't break the environment. All paths are checked against the protected
 * list first and skipped if any match. The on-disk config plist can
 * extend both lists (see vhide_config_load).
 */
static const char *g_targets_builtin[] = {
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

#define VHIDE_CONFIG_PATH "/var/jb/Library/Preferences/com.jbevasion.vhide.plist"

/* Config plist keys */
#define VHIDE_KEY_TARGETS    CFSTR("Targets")
#define VHIDE_KEY_PROTECTED  CFSTR("ProtectedTokens")

#define VHIDE_MAX_CUSTOM 256

static char *g_custom_targets[VHIDE_MAX_CUSTOM];
static int g_custom_target_count = 0;
static char *g_custom_protected[VHIDE_MAX_CUSTOM];
static int g_custom_protected_count = 0;

static int is_protected(const char *path) {
	if (!path) return 1;
	for (int i = 0; g_protected_builtin[i]; i++) {
		if (strstr(path, g_protected_builtin[i])) {
			fprintf(stderr, "vhide: refusing to hide %s (builtin protected '%s')\n",
			        path, g_protected_builtin[i]);
			return 1;
		}
	}
	for (int i = 0; i < g_custom_protected_count; i++) {
		if (strstr(path, g_custom_protected[i])) {
			fprintf(stderr, "vhide: refusing to hide %s (config protected '%s')\n",
			        path, g_custom_protected[i]);
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

static void free_custom(void) {
	for (int i = 0; i < g_custom_target_count; i++) free(g_custom_targets[i]);
	g_custom_target_count = 0;
	for (int i = 0; i < g_custom_protected_count; i++) free(g_custom_protected[i]);
	g_custom_protected_count = 0;
}

static void load_string_array(CFArrayRef arr, char *dest[], int *count) {
	CFIndex n = CFArrayGetCount(arr);
	for (CFIndex i = 0; i < n && *count < VHIDE_MAX_CUSTOM; i++) {
		CFStringRef s = CFArrayGetValueAtIndex(arr, i);
		if (!s || CFGetTypeID(s) != CFStringGetTypeID()) continue;
		CFIndex len = CFStringGetLength(s);
		CFIndex max = CFStringGetMaximumSizeForEncoding(len, kCFStringEncodingUTF8) + 1;
		char *buf = malloc((size_t)max);
		if (!buf) continue;
		if (CFStringGetCString(s, buf, max, kCFStringEncodingUTF8) && *buf) {
			dest[*count] = buf;
			(*count)++;
		} else {
			free(buf);
		}
	}
}

/* Load the config plist: custom Targets + ProtectedTokens extend the
 * built-in lists. Also reported by vhide_status. */
int vhide_config_load(void) {
	free_custom();

	CFDataRef cfdata = NULL;
	{
		FILE *fp = fopen(VHIDE_CONFIG_PATH, "rb");
		if (!fp) {
			fprintf(stderr, "vhide: no config at %s (using built-ins)\n", VHIDE_CONFIG_PATH);
			return 0;
		}
		fseek(fp, 0, SEEK_END);
		long size = ftell(fp);
		fseek(fp, 0, SEEK_SET);
		if (size <= 0) { fclose(fp); return 0; }
		char *data = malloc((size_t)size);
		if (data) {
			size_t got = fread(data, 1, (size_t)size, fp);
			if (got == (size_t)size) {
				cfdata = CFDataCreateWithBytesNoCopy(NULL, (const UInt8 *)data, (CFIndex)size, kCFAllocatorNull);
			}
			free(data);
		}
		fclose(fp);
	}
	if (!cfdata) return 0;

	CFStringRef err = NULL;
	CFPropertyListRef plist = CFPropertyListCreateWithData(NULL, cfdata, kCFPropertyListImmutable, NULL, &err);
	CFRelease(cfdata);
	if (!plist) {
		if (err) CFRelease(err);
		fprintf(stderr, "vhide: failed to parse %s\n", VHIDE_CONFIG_PATH);
		return -1;
	}

	if (CFDictionaryGetTypeID() == CFGetTypeID(plist)) {
		CFDictionaryRef dict = (CFDictionaryRef)plist;
		CFTypeRef v = CFDictionaryGetValue(dict, VHIDE_KEY_TARGETS);
		if (v && CFGetTypeID(v) == CFArrayGetTypeID()) {
			load_string_array((CFArrayRef)v, g_custom_targets, &g_custom_target_count);
		}
		v = CFDictionaryGetValue(dict, VHIDE_KEY_PROTECTED);
		if (v && CFGetTypeID(v) == CFArrayGetTypeID()) {
			load_string_array((CFArrayRef)v, g_custom_protected, &g_custom_protected_count);
		}
	}
	CFRelease(plist);

	printf("vhide: config loaded (%d custom targets, %d custom protected)\n",
	       g_custom_target_count, g_custom_protected_count);
	return 0;
}

int vhide_known(void) {
	int hidden = 0, skipped = 0, missing = 0;
	for (int i = 0; g_targets_builtin[i]; i++) {
		const char *p = g_targets_builtin[i];
		if (is_protected(p)) { skipped++; continue; }
		if (!path_exists(p)) { missing++; continue; }
		if (vnode_hide_path(p) == 0) hidden++;
		else skipped++;
	}
	for (int i = 0; i < g_custom_target_count; i++) {
		const char *p = g_custom_targets[i];
		if (is_protected(p)) { skipped++; continue; }
		if (!path_exists(p)) { missing++; continue; }
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
	printf("vhide: config file %s\n", VHIDE_CONFIG_PATH);
	printf("vhide: builtin protected (never hidden) rules:\n");
	for (int i = 0; g_protected_builtin[i]; i++) {
		printf("  %s\n", g_protected_builtin[i]);
	}
	printf("vhide: custom protected rules:\n");
	if (g_custom_protected_count == 0) {
		printf("  (none - add ProtectedTokens in the config plist)\n");
	}
	for (int i = 0; i < g_custom_protected_count; i++) {
		printf("  %s\n", g_custom_protected[i]);
	}
	printf("vhide: target state (builtin + custom):\n");
	for (int i = 0; g_targets_builtin[i]; i++) {
		uint16_t vtype = 0;
		if (!path_exists(g_targets_builtin[i])) {
			printf("  [missing] %s\n", g_targets_builtin[i]);
			continue;
		}
		if (krw_ready()) {
			int fd = open(g_targets_builtin[i], O_RDONLY | O_NONBLOCK);
			if (fd >= 0) {
				uint64_t vn = krw_proc_vnode_for_fd(krw_proc_self(), fd);
				close(fd);
				if (vn) vtype = krw_read16(vn + 0x74);
			}
		}
		printf("  [%s] %s\n", (vtype == 0) ? "hidden(VBAD)" : "visible", g_targets_builtin[i]);
	}
	for (int i = 0; i < g_custom_target_count; i++) {
		uint16_t vtype = 0;
		if (!path_exists(g_custom_targets[i])) {
			printf("  [missing] %s\n", g_custom_targets[i]);
			continue;
		}
		if (krw_ready()) {
			int fd = open(g_custom_targets[i], O_RDONLY | O_NONBLOCK);
			if (fd >= 0) {
				uint64_t vn = krw_proc_vnode_for_fd(krw_proc_self(), fd);
				close(fd);
				if (vn) vtype = krw_read16(vn + 0x74);
			}
		}
		printf("  [%s] %s\n", (vtype == 0) ? "hidden(VBAD)" : "visible", g_custom_targets[i]);
	}
	return 0;
}