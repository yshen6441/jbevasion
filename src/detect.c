#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include "krw.h"

#define PROBE_SECTION(NAME) \
	printf("\n========================================\n"); \
	printf("  %s\n", NAME); \
	printf("========================================\n")

#define PROBE_FILE(NAME, PATH) do { \
	struct stat st; \
	int ret = stat(PATH, &st); \
	printf("  %-45s %s", NAME, ret == 0 ? "FOUND" : "not found"); \
	if (ret == 0) { \
		printf(" (mode=%o)", st.st_mode & 0777); \
	} \
	printf("\n"); \
} while(0)

#define PROBE_ACCESS(NAME, PATH, MODE) do { \
	int ret = access(PATH, MODE); \
	printf("  %-45s %s\n", NAME, ret == 0 ? "accessible" : "denied"); \
} while(0)

#define PROBE_BOOL(NAME, COND) \
	printf("  %-45s %s\n", NAME, (COND) ? "YES" : "NO")

#define PROBE_INT(NAME, FMT, VAL) \
	printf("  %-45s " FMT "\n", NAME, (VAL))

static void probe_filesystem(void) {
	PROBE_SECTION("File System Checks");

	PROBE_FILE("/var/jb/", "/var/jb");
	PROBE_FILE("/var/jb/usr/bin/su", "/var/jb/usr/bin/su");
	PROBE_FILE("/var/jb/usr/bin/sudo", "/var/jb/usr/bin/sudo");
	PROBE_FILE("/var/jb/usr/bin/sshd", "/var/jb/usr/bin/sshd");
	PROBE_FILE("/var/jb/Library/Frameworks/CydiaSubstrate.framework", "/var/jb/Library/Frameworks/CydiaSubstrate.framework");
	PROBE_FILE("/var/jb/usr/lib/libsubstrate.dylib", "/var/jb/usr/lib/libsubstrate.dylib");
	PROBE_FILE("/var/jb/usr/lib/libjailbreak.dylib", "/var/jb/usr/lib/libjailbreak.dylib");
	PROBE_FILE("/var/jb/usr/lib/TweakInject", "/var/jb/usr/lib/TweakInject");
	PROBE_FILE("/var/jb/usr/lib/tweaks", "/var/jb/usr/lib/tweaks");
	PROBE_FILE("/var/jb/var/mobile/Library/Preferences", "/var/jb/var/mobile/Library/Preferences");
	PROBE_FILE("/var/jb/etc/apt", "/var/jb/etc/apt");
	PROBE_FILE("/var/jb/Applications/Sileo.app", "/var/jb/Applications/Sileo.app");
	PROBE_FILE("/var/jb/Applications/Zebra.app", "/var/jb/Applications/Zebra.app");
	PROBE_FILE("/var/jb/Applications/Cydia.app", "/var/jb/Applications/Cydia.app");

	PROBE_ACCESS("access(/var/jb, F_OK)", "/var/jb", F_OK);
	PROBE_ACCESS("access(/var/jb, R_OK)", "/var/jb", R_OK);
	PROBE_ACCESS("access(/var/jb, X_OK)", "/var/jb", X_OK);

	PROBE_FILE("/private/var/lib/apt", "/private/var/lib/apt");
	PROBE_FILE("/private/var/lib/cydia", "/private/var/lib/cydia");
	PROBE_FILE("/private/var/tmp/cydia.log", "/private/var/tmp/cydia.log");
	PROBE_FILE("/etc/apt", "/etc/apt");
	PROBE_FILE("/Applications/Cydia.app", "/Applications/Cydia.app");
	PROBE_FILE("/Applications/Sileo.app", "/Applications/Sileo.app");

	struct stat st;
	PROBE_BOOL("Check /var/jb is a symlink", false);
	if (lstat("/var/jb", &st) == 0) {
		PROBE_BOOL("Check /var/jb is a symlink", S_ISLNK(st.st_mode));
	}
}

static void probe_dyld(void) {
	PROBE_SECTION("Dyld / Library Checks");

	uint32_t count = _dyld_image_count();
	PROBE_INT("Loaded images count", "%u", count);

	int found = 0;
	for (uint32_t i = 0; i < count; i++) {
		const char *name = _dyld_get_image_name(i);
		if (!name) continue;
		if (strstr(name, "Substrate") || strstr(name, "substrate") ||
			strstr(name, "TweakInject") || strstr(name, "jailbreak") ||
			strstr(name, "CydiaSubstrate") || strstr(name, "MobileSubstrate") ||
			strstr(name, "libhooker") || strstr(name, "JailbreakShield")) {
			printf("  [!] Suspicious dylib: %s\n", name);
			found++;
		}
	}
	PROBE_BOOL("Suspicious loaded dylibs", found > 0);

	void *handle = dlopen("/var/jb/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate", RTLD_NOLOAD);
	PROBE_BOOL("CydiaSubstrate dlopen(RTLD_NOLOAD)", handle != NULL);
	if (handle) dlclose(handle);

	handle = dlopen("/usr/lib/libsubstrate.dylib", RTLD_NOLOAD);
	PROBE_BOOL("libsubstrate.dylib dlopen(RTLD_NOLOAD)", handle != NULL);
	if (handle) dlclose(handle);

	handle = dlopen("/var/jb/usr/lib/libjailbreak.dylib", RTLD_NOLOAD);
	PROBE_BOOL("libjailbreak.dylib dlopen(RTLD_NOLOAD)", handle != NULL);
	if (handle) dlclose(handle);

	handle = dlopen("/var/jb/usr/lib/TweakInject/JailbreakShield.dylib", RTLD_NOLOAD);
	PROBE_BOOL("JailbreakShield.dylib dlopen(RTLD_NOLOAD)", handle != NULL);
	if (handle) dlclose(handle);

	PROBE_BOOL("DYLD_INSERT_LIBRARIES set", getenv("DYLD_INSERT_LIBRARIES") != NULL);
	if (getenv("DYLD_INSERT_LIBRARIES")) {
		printf("  [!] DYLD_INSERT_LIBRARIES = %s\n", getenv("DYLD_INSERT_LIBRARIES"));
	}
	PROBE_BOOL("DYLD_FORCE_FLAT_NAMESPACE set", getenv("DYLD_FORCE_FLAT_NAMESPACE") != NULL);
	PROBE_BOOL("CFPreferencesAppDomain set", getenv("CFPreferencesAppDomain") != NULL);

	(void)dlopen("/var/jb/usr/lib/libsubstrate.dylib", RTLD_NOW);
	handle = dlopen("/var/jb/usr/lib/libsubstrate.dylib", RTLD_NOLOAD);
	PROBE_BOOL("libsubstrate spy-dlopen(NOLOAD) after RTLD_NOW", handle != NULL);
	if (handle) dlclose(handle);
}

static void probe_process(void) {
	PROBE_SECTION("Process / Environment Checks");

	uid_t uid = getuid();
	PROBE_INT("getuid()", "%d", uid);
	PROBE_INT("getgid()", "%d", getgid());
	PROBE_INT("getpid()", "%d", getpid());
	PROBE_INT("getppid()", "%d", getppid());

	const char *home = getenv("HOME");
	PROBE_BOOL("HOME set", home != NULL);
	if (home) printf("  HOME = %s\n", home);

	pid_t child = fork();
	if (child == 0) {
		_exit(0);
	} else if (child > 0) {
		int status;
		waitpid(child, &status, 0);
		PROBE_BOOL("fork() works", true);
	} else {
		PROBE_BOOL("fork() works", false);
	}

	posix_spawnattr_t attr;
	int spawn_ret = posix_spawnattr_init(&attr);
	posix_spawnattr_destroy(&attr);
	PROBE_BOOL("posix_spawnattr_init() works", spawn_ret == 0);
}

static void probe_sysctl(void) {
	PROBE_SECTION("Sysctl Checks");

	char buf[256];
	size_t len = sizeof(buf);

	if (sysctlbyname("kern.version", buf, &len, NULL, 0) == 0) {
		buf[255] = 0;
		buf[80] = 0;
		printf("  kern.version          = %s\n", buf);
	}

	len = sizeof(buf);
	if (sysctlbyname("kern.ostype", buf, &len, NULL, 0) == 0) {
		printf("  kern.ostype           = %s\n", buf);
	}

	len = sizeof(buf);
	if (sysctlbyname("kern.hostname", buf, &len, NULL, 0) == 0) {
		printf("  kern.hostname         = %s\n", buf);
	}

	struct timeval boottime;
	len = sizeof(boottime);
	if (sysctlbyname("kern.boottime", &boottime, &len, NULL, 0) == 0) {
		PROBE_INT("kern.boottime.tv_sec", "%lld", (long long)boottime.tv_sec);
	}

	len = sizeof(buf);
	if (sysctlbyname("kern.procname", buf, &len, NULL, 0) == 0) {
		printf("  kern.procname         = %s\n", buf);
	}

	int csops = 0;
	len = sizeof(csops);
	if (sysctlbyname("security.mac.proc_enforce", &csops, &len, NULL, 0) == 0) {
		PROBE_BOOL("security.mac.proc_enforce", csops != 0);
	}

	int sandbox = 0;
	len = sizeof(sandbox);
	if (sysctlbyname("kern.sandbox", &sandbox, &len, NULL, 0) == 0) {
		PROBE_BOOL("kern.sandbox present", true);
		PROBE_INT("kern.sandbox value", "%d", sandbox);
	} else {
		PROBE_BOOL("kern.sandbox present", false);
	}

	int32_t sbvals[2];
	sbvals[0] = CTL_KERN;
	sbvals[1] = KERN_PROC_ALL;
	len = 0;
	if (sysctl(sbvals, 2, NULL, &len, NULL, 0) == 0) {
		PROBE_INT("KERN_PROC_ALL num procs", "%zu", len / sizeof(struct kinfo_proc));
	}
}

static void probe_sandbox(void) {
	PROBE_SECTION("Sandbox Checks");

	PROBE_ACCESS("access /tmp", "/tmp", R_OK | W_OK);

	PROBE_BOOL("geteuid() == 0", geteuid() == 0);

	int fd = open("/tmp/jbevasion_test", O_CREAT | O_RDWR, 0644);
	if (fd >= 0) {
		PROBE_BOOL("write to /tmp", true);
		close(fd);
		unlink("/tmp/jbevasion_test");
	} else {
		PROBE_BOOL("write to /tmp", false);
	}

	fd = open("/var/mobile/jbevasion_test", O_CREAT | O_RDWR, 0644);
	if (fd >= 0) {
		PROBE_BOOL("write to /var/mobile", true);
		close(fd);
		unlink("/var/mobile/jbevasion_test");
	} else {
		PROBE_BOOL("write to /var/mobile", false);
	}

	PROBE_FILE("/var/mobile/Library/Preferences/com.apple.springboard.plist",
		"/var/mobile/Library/Preferences/com.apple.springboard.plist");

	PROBE_ACCESS("access /var/mobile/Library/Preferences", "/var/mobile/Library/Preferences", R_OK);
}

static void probe_krw(void) {
	PROBE_SECTION("Kernel (KRW) Checks");

	int ret = krw_init();
	if (ret != 0) {
		PROBE_BOOL("krw_init()", false);
		return;
	}
	PROBE_BOOL("krw_init()", true);

	uint64_t base = krw_kernel_base();
	uint64_t slide = krw_kernel_slide();
	PROBE_INT("kernel base", "0x%llx", (unsigned long long)base);
	PROBE_INT("kernel slide", "0x%llx", (unsigned long long)slide);

	uint64_t myproc = krw_proc_self();
	PROBE_BOOL("krw_proc_self()", myproc != 0);
	if (myproc) {
		uint32_t pid = krw_proc_pid(myproc);
		PROBE_INT("proc->p_pid", "%u", pid);
	}

	PROBE_BOOL("kcall available", krw_kcall_available());
}

int cmd_detect(void) {
	printf("========================================\n");
	printf("  jbevasion detect - Phase 1\n");
	printf("  Jailbreak Detection Probe\n");
	printf("========================================\n");

	uid_t uid = getuid();
	printf("\n[i] Running as uid=%d", uid);
	if (uid == 0) printf(" (root)");
	printf("\n[i] Device: iOS 17.0 arm64e (Dopamine 3)\n");

	probe_filesystem();
	probe_dyld();
	probe_process();
	probe_sysctl();
	probe_sandbox();

	if (uid == 0) {
		probe_krw();
	}

	printf("\n========================================\n");
	printf("  Detection probe complete\n");
	printf("========================================\n");
	return 0;
}

int cmd_shield_test(void) {
	printf("========================================\n");
	printf("  JailbreakShield Test\n");
	printf("========================================\n");

	const char *dylib_paths[] = {
		"/var/jb/usr/lib/TweakInject/JailbreakShield.dylib",
		"/usr/lib/TweakInject/JailbreakShield.dylib",
		"JailbreakShield.dylib",
	};
	void *handle = NULL;
	for (size_t i = 0; i < sizeof(dylib_paths) / sizeof(dylib_paths[0]); i++) {
		handle = dlopen(dylib_paths[i], RTLD_LAZY | RTLD_LOCAL);
		if (handle) {
			printf("[+] dlopen'd: %s\n", dylib_paths[i]);
			break;
		}
	}

	if (!handle) {
		printf("[-] Failed to load JailbreakShield.dylib: %s\n", dlerror());
		printf("[-] Check that the dylib is installed at /var/jb/usr/lib/TweakInject/\n");
		return 1;
	}

	int (*shield_install)(void) = dlsym(handle, "shield_install");
	if (!shield_install) {
		printf("[-] dlsym(shield_install) failed: %s\n", dlerror());
		return 1;
	}
	const char *(*shield_engine_name)(void) = dlsym(handle, "shield_engine_name");

	int ret = shield_install();
	if (ret != 0) {
		printf("[-] shield_install failed (%d)\n", ret);
		return 1;
	}

	const char *eng = shield_engine_name ? shield_engine_name() : "unknown";
	printf("[+] Shield installed (engine=%s), running detection probe...\n", eng);
	printf("    If hooks work, /var/jb/ paths will show as 'not found'\n");
	return cmd_detect();
}