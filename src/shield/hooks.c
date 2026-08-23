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

int shield_install(void) {
  if (g_shield_ready) return 0;
  if (getenv("SHIELD_DISABLE")) return -1;

  shield_policy_load_default();

  struct rebinding rebindings[] = {
    {"stat",        (void *)my_stat,        (void **)&orig_stat},
    {"lstat",       (void *)my_lstat,       (void **)&orig_lstat},
    {"stat64",      (void *)my_stat64,      (void **)&orig_stat64},
    {"lstat64",     (void *)my_lstat64,     (void **)&orig_lstat64},
    {"access",      (void *)my_access,      (void **)&orig_access},
  };

  int ret = rebind_symbols(rebindings, sizeof(rebindings) / sizeof(rebindings[0]));
  g_shield_ready = (ret == 0);
  return ret;
}

int shield_is_active(void) {
  return g_shield_ready;
}