#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <sys/sysctl.h>
#include "fishhook.h"
#include "policy.h"

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
static int (*orig_fopen)(const char *restrict, const char *restrict);
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
  return orig_openat ? orig_openat(dirfd, path, flags, mode) : -1;
}

static FILE *my_fopen(const char *restrict path, const char *restrict mode) {
  if (g_shield_ready && path && shield_policy_should_hide(path)) {
    errno = ENOENT;
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
static char *(*orig_getenv)(const char *);

/* dyld view: hide sensitive dylib paths from the loaded-images scan */
static const char *my_dyld_get_image_name(uint32_t index) {
  const char *name = orig_dyld_get_image_name ? orig_dyld_get_image_name(index) : NULL;
  if (name && str_is_sensitive(name)) return "";
  return name;
}

/* dlopen view: RTLD_NOLOAD probes for CydiaSubstrate/libsubstrate/etc must fail */
static void *my_dlopen(const char *path, int mode) {
  if (path && (mode & RTLD_NOLOAD) && str_is_sensitive(path)) return NULL;
  return orig_dlopen ? orig_dlopen(path, mode) : NULL;
}

/* environment view: never let DYLD_* leak */
static char *my_getenv(const char *name) {
  if (name && strncmp(name, "DYLD_", 5) == 0) return NULL;
  return orig_getenv ? orig_getenv(name) : NULL;
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
    const char *dyname_n[] = {"_dyld_get_image_name", NULL};
    const char *dlopen_n[] = {"dlopen", NULL};
    const char *getenv_n[] = {"getenv", NULL};

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
    hook_one(dyname_n,(void *)my_dyld_get_image_name, (void **)&orig_dyld_get_image_name);
    hook_one(dlopen_n,(void *)my_dlopen,         (void **)&orig_dlopen);
    hook_one(getenv_n,(void *)my_getenv,         (void **)&orig_getenv);

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