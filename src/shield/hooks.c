#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <spawn.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/ldsyms.h>
#include "fishhook.h"
#include "../krw.h"
#include "policy.h"

extern char **environ;

static int g_shield_ready = 0;

/* ---------- file view hooks ---------- */

static int (*orig_stat)(const char *restrict, struct stat *restrict);
static int (*orig_lstat)(const char *restrict, struct stat *restrict);
static int (*orig_stat64)(const char *restrict, struct stat *restrict);
static int (*orig_lstat64)(const char *restrict, struct stat *restrict);
static int (*orig_access)(const char *, int);

static int my_stat(const char *restrict path, struct stat *restrict buf) {
  if (g_shield_ready && path && shield_policy_should_hide(path)) {
    errno = ENOENT;
    return -1;
  }
  return orig_stat ? orig_stat(path, buf) : -1;
}

static int my_lstat(const char *restrict path, struct stat *restrict buf) {
  if (g_shield_ready && path && shield_policy_should_hide(path)) {
    errno = ENOENT;
    return -1;
  }
  return orig_lstat ? orig_lstat(path, buf) : -1;
}

static int my_stat64(const char *restrict path, struct stat *restrict buf) {
  if (g_shield_ready && path && shield_policy_should_hide(path)) {
    errno = ENOENT;
    return -1;
  }
  return orig_stat64 ? orig_stat64(path, buf) : -1;
}

static int my_lstat64(const char *restrict path, struct stat *restrict buf) {
  if (g_shield_ready && path && shield_policy_should_hide(path)) {
    errno = ENOENT;
    return -1;
  }
  return orig_lstat64 ? orig_lstat64(path, buf) : -1;
}

static int my_access(const char *path, int mode) {
  if (g_shield_ready && path && shield_policy_should_hide(path)) {
    errno = ENOENT;
    return -1;
  }
  return orig_access ? orig_access(path, mode) : -1;
}

/* open/openat/fopen paths must also be hidden */
static int (*orig_open)(const char *, int, ...);
static int (*orig_openat)(int, const char *, int, ...);
static FILE *(*orig_fopen)(const char *restrict, const char *restrict);
static int (*orig_fstatat)(int, const char *restrict, struct stat *restrict, int);
static int (*orig_faccessat)(int, const char *, int, int);

static int my_open(const char *path, int flags, ...) {
  int mode = 0;
  if (flags & (O_CREAT | O_EXCL | O_TRUNC)) {
    va_list ap;
    va_start(ap, flags);
    mode = va_arg(ap, int);
    va_end(ap);
  }
  if (g_shield_ready && path && shield_policy_should_hide(path)) {
    errno = ENOENT;
    return -1;
  }
  /* Block sandbox write tests: apps try to write outside sandbox to detect jailbreak */
  if (g_shield_ready && path && (flags & (O_CREAT | O_WRONLY | O_RDWR)) && is_sandbox_write_path(path)) {
    errno = EPERM;
    return -1;
  }
  return orig_open ? orig_open(path, flags, mode) : -1;
}

static int my_openat(int dirfd, const char *path, int flags, ...) {
  int mode = 0;
  if (flags & (O_CREAT | O_EXCL | O_TRUNC)) {
    va_list ap;
    va_start(ap, flags);
    mode = va_arg(ap, int);
    va_end(ap);
  }
  if (g_shield_ready && path && shield_policy_should_hide(path)) {
    errno = ENOENT;
    return -1;
  }
  if (g_shield_ready && path && (flags & (O_CREAT | O_WRONLY | O_RDWR)) && is_sandbox_write_path(path)) {
    errno = EPERM;
    return -1;
  }
  return orig_openat ? orig_openat(dirfd, path, flags, mode) : -1;
}

static FILE *my_fopen(const char *restrict path, const char *restrict mode) {
  if (g_shield_ready && path && shield_policy_should_hide(path)) {
    errno = ENOENT;
    return NULL;
  }
  /* Block sandbox write tests */
  if (g_shield_ready && path && mode && (mode[0] == 'w' || mode[0] == 'a') && is_sandbox_write_path(path)) {
    errno = EPERM;
    return NULL;
  }
  return orig_fopen ? orig_fopen(path, mode) : NULL;
}

static int my_fstatat(int dirfd, const char *restrict path, struct stat *restrict buf, int flag) {
  if (g_shield_ready && path && shield_policy_should_hide(path)) {
    errno = ENOENT;
    return -1;
  }
  return orig_fstatat ? orig_fstatat(dirfd, path, buf, flag) : -1;
}

static int my_faccessat(int dirfd, const char *path, int mode, int flag) {
  if (g_shield_ready && path && shield_policy_should_hide(path)) {
    errno = ENOENT;
    return -1;
  }
  return orig_faccessat ? orig_faccessat(dirfd, path, mode, flag) : -1;
}

/* ---------- behavior layer hooks (Phase 3) ---------- */

static const char *g_sensitive_kw[] = {
    "/TweakInject/",
    "libjailbreak",
    "libsubstrate",
    "CydiaSubstrate",
    "JailbreakShield",
    "Substitute",
    "libhooker",
    NULL,
};

static int str_is_sensitive(const char *s) {
  if (!s) return 0;
  for (int i = 0; g_sensitive_kw[i]; i++) {
    if (strstr(s, g_sensitive_kw[i])) return 1;
  }
  return 0;
}

static const char *(*orig_dyld_get_image_name)(uint32_t);
static void *(*orig_dlopen)(const char *, int);
static void *(*orig_dlsym)(void *, const char *);
static char *(*orig_getenv)(const char *);
static char *(*orig_realpath)(const char *restrict, char *restrict);
static pid_t (*orig_fork)(void);
static int (*orig_posix_spawn)(pid_t *, const char *, const posix_spawn_file_actions_t *, const posix_spawnattr_t *, char *const [], char *const []);
static int (*orig_posix_spawnp)(pid_t *, const char *, const posix_spawn_file_actions_t *, const posix_spawnattr_t *, char *const [], char *const []);
static ssize_t (*orig_readlink)(const char *, char *, size_t);
static int (*orig_dladdr)(const void *, Dl_info *);
static int (*orig_statfs)(const char *, struct statfs *);
static const struct mach_header *(*orig_dyld_get_image_header)(uint32_t);
static uint32_t (*orig_dyld_image_count)(void);
static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t);

/* dyld view: hide sensitive dylib paths from the loaded-images scan */
static const char *my_dyld_get_image_name(uint32_t index) {
  const char *name = orig_dyld_get_image_name ? orig_dyld_get_image_name(index) : NULL;
  if (name && str_is_sensitive(name)) return "";
  return name;
}

/* realpath: prevent symlink resolution (/var/jb -> /private/preboot/...) from bypassing prefix checks */
static char *my_realpath(const char *restrict path, char *restrict resolved) {
  if (g_shield_ready && path && shield_policy_should_hide(path)) {
    errno = ENOENT;
    return NULL;
  }
  char *ret = orig_realpath ? orig_realpath(path, resolved) : NULL;
  if (ret && shield_policy_should_hide(ret)) {
    errno = ENOENT;
    return NULL;
  }
  return ret;
}

/* fork: sandboxed apps cannot fork; return -1 to hide jailbreak fork capability */
static pid_t my_fork(void) {
  errno = EPERM;
  return -1;
}

/* dlopen view: block ALL dlopen of sensitive paths (RTLD_NOLOAD probes AND actual loads) */
static void *my_dlopen(const char *path, int mode) {
  if (path && str_is_sensitive(path)) return NULL;
  return orig_dlopen ? orig_dlopen(path, mode) : NULL;
}

/* dlsym: never reveal jailbreak symbols */
static void *my_dlsym(void *handle, const char *symbol) {
  if (symbol && str_is_sensitive(symbol)) return NULL;
  return orig_dlsym ? orig_dlsym(handle, symbol) : NULL;
}

/* posix_spawn / posix_spawnp: prevent process creation (bypasses fork) */
static int my_posix_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *fa, const posix_spawnattr_t *attr, char *const argv[], char *const envp[]) {
  errno = EPERM;
  return -1;
}
static int my_posix_spawnp(pid_t *pid, const char *file, const posix_spawn_file_actions_t *fa, const posix_spawnattr_t *attr, char *const argv[], char *const envp[]) {
  errno = EPERM;
  return -1;
}

/* readlink: hide symlinks to jailbreak paths */
static ssize_t my_readlink(const char *path, char *buf, size_t bufsize) {
  if (g_shield_ready && path && shield_policy_should_hide(path)) {
    errno = ENOENT;
    return -1;
  }
  return orig_readlink ? orig_readlink(path, buf, bufsize) : -1;
}

/* dladdr: hide sensitive dylib names from address-to-symbol lookups */
static int my_dladdr(const void *addr, Dl_info *info) {
  int ret = orig_dladdr ? orig_dladdr(addr, info) : 0;
  if (ret && info && info->dli_fname && str_is_sensitive(info->dli_fname)) {
    info->dli_fname = "";
  }
  return ret;
}

/* _dyld_get_image_header: hide sensitive dylib Mach-O headers */
static const struct mach_header *my_dyld_get_image_header(uint32_t index) {
  const char *name = orig_dyld_get_image_name ? orig_dyld_get_image_name(index) : NULL;
  if (name && str_is_sensitive(name)) return NULL;
  return orig_dyld_get_image_header ? orig_dyld_get_image_header(index) : NULL;
}

/* _dyld_image_count: exclude our dylib from the count */
static uint32_t my_dyld_image_count(void) {
  uint32_t count = orig_dyld_image_count ? orig_dyld_image_count() : 0;
  if (count == 0) return 0;
  for (uint32_t i = 0; i < count; i++) {
    const char *name = orig_dyld_get_image_name ? orig_dyld_get_image_name(i) : NULL;
    if (name && str_is_sensitive(name)) {
      return count - 1;
    }
  }
  return count;
}

/* statfs: fake read-only rootfs to hide jailbreak */
static int my_statfs(const char *path, struct statfs *buf) {
  int ret = orig_statfs ? orig_statfs(path, buf) : -1;
  if (ret == 0 && buf && path && (strcmp(path, "/") == 0 || shield_policy_should_hide(path))) {
    buf->f_flags |= MNT_RDONLY;
  }
  return ret;
}

/* sysctl: hide jailbreak traces from KERN_PROC and sysctl queries */
static int my_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
  if (namelen >= 2 && name[0] == CTL_KERN && name[1] == KERN_PROC && oldp && oldlenp) {
    size_t orig_len = *oldlenp;
    int ret = orig_sysctl ? orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen) : -1;
    if (ret == 0 && oldp) {
      /* Filter out jailbreak processes */
      char *base = (char *)oldp;
      char *end = base + *oldlenp;
      char *write = base;
      struct kinfo_proc *kp = (struct kinfo_proc *)base;
      int count = (int)(*oldlenp / sizeof(struct kinfo_proc));
      for (int i = 0; i < count; i++) {
        char *pname = kp[i].kp_proc.p_comm;
        int hide = 0;
        if (pname[0]) {
          if (strcmp(pname, "jbevasion") == 0) hide = 1;
          if (strstr(pname, "jailbreak") != NULL) hide = 1;
          if (strstr(pname, "ellekit") != NULL) hide = 1;
          if (strstr(pname, "substrate") != NULL) hide = 1;
          if (strstr(pname, "TweakInject") != NULL) hide = 1;
        }
        if (!hide) {
          if (write != (char *)&kp[i]) {
            memmove(write, &kp[i], sizeof(struct kinfo_proc));
          }
          write += sizeof(struct kinfo_proc);
        }
      }
      *oldlenp = (size_t)(write - base);
    }
    return ret;
  }
  return orig_sysctl ? orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen) : -1;
}

/* environment view: never let DYLD_* leak */
static char *my_getenv(const char *name) {
  if (name && strncmp(name, "DYLD_", 5) == 0) return NULL;
  return orig_getenv ? orig_getenv(name) : NULL;
}

/* ---------- manual dyld struct declarations (private header dyld_images.h not in SDK) ---------- */

struct jb_dyld_image_info {
  const struct mach_header *imageLoadAddress;
  const char *imageFilePath;
  uintptr_t imageFileModDate;
};

struct jb_dyld_all_image_infos {
  uint32_t version;
  uint32_t infoArrayCount;
  const struct jb_dyld_image_info *infoArray;
};

extern const struct jb_dyld_all_image_infos *_dyld_get_all_image_infos(void);

/* proc_self() is in libjailbreak util.h which pulls in jbclient_xpc.h; declare here */
extern uint64_t proc_self(void);

/* ---------- sandbox write test blocking ---------- */

static int is_sandbox_write_path(const char *path) {
  if (!path) return 0;
  /* Common jailbreak detection sandbox write tests */
  if (strncmp(path, "/tmp/", 5) == 0) return 1;
  if (strcmp(path, "/tmp") == 0) return 1;
  if (strncmp(path, "/var/mobile/", 12) == 0) return 1;
  if (strcmp(path, "/var/mobile") == 0) return 1;
  if (strncmp(path, "/etc/", 5) == 0) return 1;
  if (strcmp(path, "/etc") == 0) return 1;
  return 0;
}

/* ---------- KRW: clean dyld_all_image_infos in the kernel-(observable) userspace struct ---------- */

static void krw_clean_dyld_images(void) {
  uint64_t myproc = proc_self();
  if (!myproc) return;

  const struct jb_dyld_all_image_infos *infos = _dyld_get_all_image_infos();
  if (!infos) return;

  /* Read the first 3 fields: version(4) + infoArrayCount(4) + infoArray(8) */
  uint32_t count = 0;
  uint64_t array_addr = 0;
  if (proc_vreadbuf(myproc, (uint8_t *)infos + 4, &count, 4) != 0) return;
  if (proc_vreadbuf(myproc, (uint8_t *)infos + 8, &array_addr, 8) != 0) return;

  if (!array_addr || count == 0) return;

  /* Read the full infoArray entries */
  size_t entry_size = 24;
  size_t buf_size = count * entry_size;
  uint8_t *array_buf = malloc(buf_size);
  if (!array_buf) return;
  if (proc_vreadbuf(myproc, (void *)array_addr, array_buf, buf_size) != 0) {
    free(array_buf);
    return;
  }

  /* Filter: shift non-sensitive entries forward */
  uint32_t write_idx = 0;
  for (uint32_t read_idx = 0; read_idx < count; read_idx++) {
    uint64_t *entry = (uint64_t *)(array_buf + read_idx * entry_size);
    uint64_t path_addr = entry[1]; /* imageFilePath at offset 8 */

    int is_sensitive = 0;
    if (path_addr) {
      char path[256];
      if (proc_vreadbuf(myproc, (void *)path_addr, path, 255) == 0) {
        path[255] = '\0';
        for (int i = 0; g_sensitive_kw[i]; i++) {
          if (strstr(path, g_sensitive_kw[i])) {
            is_sensitive = 1;
            break;
          }
        }
      }
    }

    if (!is_sensitive) {
      if (write_idx != read_idx) {
        memcpy(array_buf + write_idx * entry_size,
               array_buf + read_idx * entry_size, entry_size);
      }
      write_idx++;
    }
  }

  /* Write back the compacted array */
  if (write_idx < count) {
    proc_vwritebuf(myproc, (void *)array_addr, array_buf,
                   write_idx * entry_size);
    /* Update the count via KRW */
    proc_vwritebuf(myproc, (uint8_t *)infos + 4, &write_idx, 4);
  }

  free(array_buf);
}

/* ---------- hook engine: MSHookFunction (ElleKit/Substrate) first, fishhook fallback ---------- */

typedef void (*mshook_fn)(void *symbol, void *replace, void **result);

static mshook_fn g_mshook = NULL;
static int g_engine = 0; /* 0=none, 1=mshook, 2=fishhook */

const char *shield_engine_name(void) {
  switch (g_engine) {
    case 1: return "MSHookFunction (ElleKit)";
    case 2: return "fishhook";
    default: return "none";
  }
}

int shield_is_active(void) { return g_shield_ready; }

/* Resolve MSHookFunction from whatever Substrate/ElleKit provides. */
static int load_mshook(void) {
  if (g_mshook) return 1;
  g_mshook = (mshook_fn)dlsym(RTLD_DEFAULT, "MSHookFunction");
  if (g_mshook) return 1;

  const char *libs[] = {
      "/var/jb/usr/lib/libsubstrate.dylib",
      "/var/jb/usr/lib/substrate/libsubstrate.dylib",
      "/var/jb/usr/lib/libellekit.dylib",
      "/usr/lib/libsubstrate.dylib",
      NULL,
  };
  for (int i = 0; libs[i]; i++) {
    void *h = dlopen(libs[i], RTLD_NOW | RTLD_GLOBAL);
    if (h) {
      g_mshook = (mshook_fn)dlsym(RTLD_DEFAULT, "MSHookFunction");
      if (g_mshook) return 1;
    }
  }
  return 0;
}

static void *mshook_resolve(const char *const *names) {
  for (int i = 0; names[i]; i++) {
    void *p = dlsym(RTLD_DEFAULT, names[i]);
    if (p) return p;
  }
  return NULL;
}

static void hook_one(const char *const *names, void *repl, void **orig_ptr) {
  void *sym = mshook_resolve(names);
  if (sym) {
    g_mshook(sym, repl, orig_ptr);
  }
}

int shield_install(void) {
  if (g_shield_ready) return 0;
  if (getenv("SHIELD_DISABLE")) return -1;

  shield_policy_load_default();

  if (load_mshook()) {
    g_engine = 1;

    const char *stat_n[] = {"stat$INODE64", "stat", "stat64", NULL};
    const char *lstat_n[] = {"lstat$INODE64", "lstat", "lstat64", NULL};
    const char *stat64_n[] = {"stat64", NULL};
    const char *lstat64_n[] = {"lstat64", NULL};
    const char *access_n[] = {"access", NULL};
    const char *open_n[] = {"open", "open$NOCANCEL", NULL};
    const char *openat_n[] = {"openat", "openat$NOCANCEL", NULL};
    const char *fopen_n[] = {"fopen", NULL};
    const char *fstatat_n[] = {"fstatat$INODE64", "fstatat", NULL};
    const char *faccessat_n[] = {"faccessat", NULL};
    const char *dlopen_n[] = {"dlopen", NULL};
    const char *getenv_n[] = {"getenv", NULL};
    const char *dyname_n[] = {"_dyld_get_image_name", NULL};
    const char *realpath_n[] = {"realpath", NULL};
    const char *fork_n[] = {"fork", NULL};
    const char *dlsym_n[] = {"dlsym", NULL};
    const char *posix_spawn_n[] = {"posix_spawn", NULL};
    const char *posix_spawnp_n[] = {"posix_spawnp", NULL};
    const char *readlink_n[] = {"readlink", NULL};
    const char *dladdr_n[] = {"dladdr", NULL};
    const char *statfs_n[] = {"statfs", NULL};
    const char *header_n[] = {"_dyld_get_image_header", NULL};
    const char *imgcount_n[] = {"_dyld_image_count", NULL};
    const char *sysctl_n[] = {"sysctl", NULL};

    hook_one(stat_n,  (void *)my_stat,           (void **)&orig_stat);
    hook_one(lstat_n, (void *)my_lstat,          (void **)&orig_lstat);
    hook_one(stat64_n,(void *)my_stat64,         (void **)&orig_stat64);
    hook_one(lstat64_n,(void *)my_lstat64,       (void **)&orig_lstat64);
    hook_one(access_n,(void *)my_access,         (void **)&orig_access);
    hook_one(open_n,  (void *)my_open,           (void **)&orig_open);
    hook_one(openat_n,(void *)my_openat,         (void **)&orig_openat);
    hook_one(fopen_n, (void *)my_fopen,          (void **)&orig_fopen);
    hook_one(fstatat_n,(void *)my_fstatat,       (void **)&orig_fstatat);
    hook_one(faccessat_n,(void *)my_faccessat,   (void **)&orig_faccessat);
    hook_one(dlopen_n,(void *)my_dlopen,         (void **)&orig_dlopen);
    hook_one(getenv_n,(void *)my_getenv,         (void **)&orig_getenv);
    hook_one(dyname_n,(void *)my_dyld_get_image_name, (void **)&orig_dyld_get_image_name);
    hook_one(realpath_n,(void *)my_realpath,     (void **)&orig_realpath);
    hook_one(fork_n,(void *)my_fork,             (void **)&orig_fork);
    hook_one(posix_spawn_n,(void *)my_posix_spawn, (void **)&orig_posix_spawn);
    hook_one(posix_spawnp_n,(void *)my_posix_spawnp,(void **)&orig_posix_spawnp);
    hook_one(readlink_n,(void *)my_readlink,     (void **)&orig_readlink);
    hook_one(dladdr_n,(void *)my_dladdr,       (void **)&orig_dladdr);
    hook_one(statfs_n,(void *)my_statfs,       (void **)&orig_statfs);
    hook_one(header_n,(void *)my_dyld_get_image_header, (void **)&orig_dyld_get_image_header);
    hook_one(imgcount_n,(void *)my_dyld_image_count,   (void **)&orig_dyld_image_count);
    hook_one(sysctl_n,(void *)my_sysctl,       (void **)&orig_sysctl);
    hook_one(dlsym_n,(void *)my_dlsym,         (void **)&orig_dlsym);

    g_shield_ready = 1;
    return 0;
  }

  /* fishhook fallback; capture real pointers up front so a failed rebind stays safe */
  {
    const char *n1[] = {"stat$INODE64", "stat", "stat64", NULL};
    const char *n2[] = {"lstat$INODE64", "lstat", "lstat64", NULL};
    const char *n3[] = {"access", NULL};
    orig_stat = (int (*)(const char *, struct stat *))mshook_resolve(n1);
    orig_lstat = (int (*)(const char *, struct stat *))mshook_resolve(n2);
    orig_access = (int (*)(const char *, int))mshook_resolve(n3);
  }

  struct rebinding rebindings[] = {
      {"stat",          (void *)my_stat,    NULL},
      {"stat$INODE64",  (void *)my_stat,    NULL},
      {"stat64",        (void *)my_stat64,  NULL},
      {"lstat",         (void *)my_lstat,   NULL},
      {"lstat$INODE64", (void *)my_lstat,   NULL},
      {"lstat64",       (void *)my_lstat64, NULL},
      {"access",        (void *)my_access,  NULL},
  };

  int ret = rebind_symbols(rebindings, sizeof(rebindings) / sizeof(rebindings[0]));
  g_engine = 2;
  g_shield_ready = (ret == 0);
  return ret == 0 ? 0 : -1;
}

/* Auto-install on injection (TweakInject loads the dylib into the target process;
   nobody calls shield_install explicitly in that scenario). */
__attribute__((constructor))
static void jbshield_ctor(void) {
  /* Clean up environ to hide DYLD_INSERT_LIBRARIES from direct access */
  for (char **env = environ; *env; env++) {
    if (strncmp(*env, "DYLD_INSERT_LIBRARIES=", 22) == 0 ||
        strncmp(*env, "DYLD_FORCE_FLAT_NAMESPACE=", 26) == 0) {
      *env[0] = '\0';
    }
  }

  /* Phase 5: kernel-level dyld image hiding via KRW */
  krw_clean_dyld_images();

  int r = shield_install();

  /* debug log proving injection happened */
  char buf[256] = {0};
  int fd = open("/var/mobile/jbshield_pid.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd >= 0) {
    int n = snprintf(buf, sizeof(buf), "pid=%d engine=%s active=%d ret=%d\n",
                     (int)getpid(), shield_engine_name(), shield_is_active(), r);
    if (n > 0) write(fd, buf, (size_t)n);
    close(fd);
  }
}