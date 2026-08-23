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

static int (*orig_stat)(const char *restrict, struct stat *restrict);
static int (*orig_lstat)(const char *restrict, struct stat *restrict);
static int (*orig_stat64)(const char *restrict, struct stat *restrict);
static int (*orig_lstat64)(const char *restrict, struct stat *restrict);
static int (*orig_fstatat)(int, const char *restrict, struct stat *restrict, int);
static int (*orig_access)(const char *, int);
static int (*orig_open)(const char *, int, ...);
static int (*orig_openat)(int, const char *, int, ...);

static int hook_stat_common(const char *restrict path, struct stat *restrict buf,
                            int (*fallback)(const char *restrict, struct stat *restrict)) {
  if (path && shield_policy_should_hide(path)) {
    errno = ENOENT;
    return -1;
  }
  return fallback(path, buf);
}

static int my_stat(const char *restrict path, struct stat *restrict buf) {
  return hook_stat_common(path, buf, orig_stat);
}

static int my_lstat(const char *restrict path, struct stat *restrict buf) {
  return hook_stat_common(path, buf, orig_lstat);
}

static int my_stat64(const char *restrict path, struct stat *restrict buf) {
  return hook_stat_common(path, buf, orig_stat64);
}

static int my_lstat64(const char *restrict path, struct stat *restrict buf) {
  return hook_stat_common(path, buf, orig_lstat64);
}

static int my_fstatat(int fd, const char *restrict path, struct stat *restrict buf, int flag) {
  if (path && shield_policy_should_hide(path)) {
    errno = ENOENT;
    return -1;
  }
  return orig_fstatat(fd, path, buf, flag);
}

static int my_access(const char *path, int mode) {
  if (path && shield_policy_should_hide(path)) {
    errno = ENOENT;
    return -1;
  }
  return orig_access(path, mode);
}

static int my_open(const char *path, int flags, ...) {
  if (path && shield_policy_should_hide(path)) {
    errno = ENOENT;
    return -1;
  }
  return orig_open(path, flags);
}

static int my_openat(int fd, const char *path, int flags, ...) {
  if (path && shield_policy_should_hide(path)) {
    errno = ENOENT;
    return -1;
  }
  return orig_openat(fd, path, flags);
}

__attribute__((constructor)) static void shield_init(void) {
  if (getenv("SHIELD_DISABLE")) return;

  shield_policy_load_default();

  struct rebinding rebindings[] = {
    {"stat",        (void *)my_stat,        (void **)&orig_stat},
    {"lstat",       (void *)my_lstat,       (void **)&orig_lstat},
    {"stat64",      (void *)my_stat64,      (void **)&orig_stat64},
    {"lstat64",     (void *)my_lstat64,     (void **)&orig_lstat64},
    {"fstatat",     (void *)my_fstatat,     (void **)&orig_fstatat},
    {"access",      (void *)my_access,      (void **)&orig_access},
    {"open",        (void *)my_open,        (void **)&orig_open},
    {"openat",      (void *)my_openat,      (void **)&orig_openat},
  };

  int ret = rebind_symbols(rebindings, sizeof(rebindings) / sizeof(rebindings[0]));
  if (ret == 0) {
    fprintf(stderr, "JailbreakShield: loaded (%s)\n", shield_get_current_proc_name());
  } else {
    fprintf(stderr, "JailbreakShield: rebind_symbols failed (%d)\n", ret);
  }
}