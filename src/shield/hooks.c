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

static int my_access(const char *path, int mode) {
  if (g_shield_ready && path && shield_policy_should_hide(path)) {
    errno = ENOENT;
    return -1;
  }
  return orig_access ? orig_access(path, mode) : -1;
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

  {
    const char *n1[] = {"stat$INODE64", "stat", "stat64", NULL};
    const char *n2[] = {"lstat$INODE64", "lstat", "lstat64", NULL};
    const char *n3[] = {"access", NULL};
    orig_stat   = resolve_real(n1);
    orig_lstat  = resolve_real(n2);
    orig_access = resolve_real(n3);
  }

  struct rebinding rebindings[] = {
    {"stat",          (void *)my_stat,   NULL},
    {"stat$INODE64",  (void *)my_stat,   NULL},
    {"stat64",        (void *)my_stat,   NULL},
    {"lstat",         (void *)my_lstat,  NULL},
    {"lstat$INODE64", (void *)my_lstat,  NULL},
    {"lstat64",       (void *)my_lstat,  NULL},
    {"access",        (void *)my_access, NULL},
  };

  int ret = rebind_symbols(rebindings, sizeof(rebindings) / sizeof(rebindings[0]));
  g_shield_ready = (ret == 0);
  return ret;
}

int shield_is_active(void) {
  return g_shield_ready;
}