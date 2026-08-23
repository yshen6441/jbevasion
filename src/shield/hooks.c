#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include "fishhook.h"
#include "policy.h"

static int g_shield_ready = 0;

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

/* --- hook engine: MSHookFunction (ElleKit/Substrate) first, fishhook fallback --- */

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

static void *resolve_real(const char **names) {
  for (int i = 0; names[i]; i++) {
    void *p = dlsym(RTLD_DEFAULT, names[i]);
    if (p) return p;
  }
  return NULL;
}

int shield_install(void) {
  if (g_shield_ready) return 0;
  if (getenv("SHIELD_DISABLE")) return -1;

  shield_policy_load_default();

  if (load_mshook()) {
    g_engine = 1;
    void *sym;

    sym = dlsym(RTLD_DEFAULT, "stat$INODE64");
    if (!sym) sym = dlsym(RTLD_DEFAULT, "stat");
    if (!sym) sym = dlsym(RTLD_DEFAULT, "stat64");
    if (sym) g_mshook(sym, (void *)my_stat, (void **)&orig_stat);

    sym = dlsym(RTLD_DEFAULT, "lstat$INODE64");
    if (!sym) sym = dlsym(RTLD_DEFAULT, "lstat");
    if (!sym) sym = dlsym(RTLD_DEFAULT, "lstat64");
    if (sym) g_mshook(sym, (void *)my_lstat, (void **)&orig_lstat);

    sym = dlsym(RTLD_DEFAULT, "stat64");
    if (sym) g_mshook(sym, (void *)my_stat64, (void **)&orig_stat64);

    sym = dlsym(RTLD_DEFAULT, "lstat64");
    if (sym) g_mshook(sym, (void *)my_lstat64, (void **)&orig_lstat64);

    sym = dlsym(RTLD_DEFAULT, "access");
    if (sym) g_mshook(sym, (void *)my_access, (void **)&orig_access);

    g_shield_ready = 1;
    return 0;
  }

  /* fishhook fallback; capture real pointers up front so a failed rebind stays safe */
  {
    const char *n1[] = {"stat$INODE64", "stat", "stat64", NULL};
    const char *n2[] = {"lstat$INODE64", "lstat", "lstat64", NULL};
    const char *n3[] = {"access", NULL};
    orig_stat = (int (*)(const char *, struct stat *))resolve_real(n1);
    orig_lstat = (int (*)(const char *, struct stat *))resolve_real(n2);
    orig_access = (int (*)(const char *, int))resolve_real(n3);
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