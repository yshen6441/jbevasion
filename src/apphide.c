#include "apphide.h"
#include "hide.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <CoreFoundation/CoreFoundation.h>

extern char **environ;

#define JB_APPS_DIR   "/var/jb/Applications"
#define STASH_DIR     "/var/jb/.apphide-stash"

static const char *known_ids[] = {
    "Sileo",
    "Cydia",
    "Zebra",
    "Installer",
    "Filza",
    "FilzaFileManager",
    "NewTerm",
    "NewTerm 2",
    "Terminal",
    "Santander",
    "SantanderFree",
    "iCleaner",
    "iCleanerPro",
    "Cr4shed",
    "Choicy",
    "TrollStore",
    "TrollHelper",
    "TrollDecryptor",
    "AppsManager",
    "AppSyncUnified",
    "ReProvision",
    "ReProvisionReborn",
    NULL,
};

static bool file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

static bool is_dir(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static int ensure_dir(const char *path, mode_t mode) {
    if (is_dir(path)) return 0;
    if (mkdir(path, mode) != 0 && errno != EEXIST) {
        fprintf(stderr, "apphide: mkdir(%s) failed: %s\n", path, strerror(errno));
        return -1;
    }
    return 0;
}

static char *read_bundle_id(const char *app_dir);

static char *read_bundle_id(const char *app_dir) {
    char plist_path[PATH_MAX];
    snprintf(plist_path, sizeof(plist_path), "%s/Info.plist", app_dir);

    FILE *fp = fopen(plist_path, "rb");
    if (!fp) return NULL;
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (size <= 0) { fclose(fp); return NULL; }
    char *data = malloc((size_t)size);
    if (!data) { fclose(fp); return NULL; }
    size_t got = fread(data, 1, (size_t)size, fp);
    fclose(fp);
    if (got != (size_t)size) { free(data); return NULL; }

    CFDataRef cfdata = CFDataCreateWithBytesNoCopy(NULL, (const UInt8 *)data, (CFIndex)size, kCFAllocatorNull);
    if (!cfdata) { free(data); return NULL; }
    CFStringRef err = NULL;
    CFPropertyListRef plist = CFPropertyListCreateWithData(NULL, cfdata, kCFPropertyListImmutable, NULL, &err);
    CFRelease(cfdata);
    if (!plist) { if (err) CFRelease(err); free(data); return NULL; }

    char *ret = NULL;
    if (CFDictionaryGetTypeID() == CFGetTypeID(plist)) {
        CFDictionaryRef dict = (CFDictionaryRef)plist;
        CFStringRef key = CFSTR("CFBundleIdentifier");
        if (CFDictionaryContainsKey(dict, key)) {
            CFStringRef val = CFDictionaryGetValue(dict, key);
            if (val && CFStringGetTypeID() == CFGetTypeID(val)) {
                CFIndex len = CFStringGetLength(val);
                CFIndex max = CFStringGetMaximumSizeForEncoding(len, kCFStringEncodingUTF8) + 1;
                ret = calloc(1, max);
                if (ret) CFStringGetCString(val, ret, max, kCFStringEncodingUTF8);
            }
        }
    }
    CFRelease(plist);
    free(data);
    return ret;
}

static void strip_app_suffix(const char *name, char *out, size_t outsz) {
    size_t n = strlen(name);
    if (n > 4 && strcmp(name + n - 4, ".app") == 0) n -= 4;
    size_t c = (n < outsz - 1) ? n : outsz - 1;
    memcpy(out, name, c);
    out[c] = '\0';
}

static char *find_app_by_id(const char *search_dir, const char *bundle_id) {
    DIR *d = opendir(search_dir);
    if (!d) return NULL;
    char *match = NULL;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        if (strstr(ent->d_name, ".app") == NULL) continue;
        char dpath[PATH_MAX];
        snprintf(dpath, sizeof(dpath), "%s/%s", search_dir, ent->d_name);
        if (!is_dir(dpath)) continue;
        char *bid = read_bundle_id(dpath);
        if (bid) {
            if (strcmp(bid, bundle_id) == 0) {
                match = strdup(dpath);
                free(bid);
                break;
            }
            free(bid);
        } else {
            char base[128];
            strip_app_suffix(ent->d_name, base, sizeof(base));
            if (strcmp(base, bundle_id) == 0) {
                match = strdup(dpath);
                break;
            }
        }
    }
    closedir(d);
    return match;
}

static int move_app(const char *src, const char *dst) {
    if (rename(src, dst) != 0) {
        fprintf(stderr, "apphide: rename(%s, %s) failed: %s\n", src, dst, strerror(errno));
        return -1;
    }
    return 0;
}

static int run_uicache(void) {
    static const char *candidates[] = {
        "/var/jb/usr/bin/uicache",
        "/var/jb/usr/bin/uicache-strapped",
        "/usr/bin/uicache",
        NULL,
    };
    const char *uc = NULL;
    for (int i = 0; candidates[i]; i++) {
        if (access(candidates[i], X_OK) == 0) { uc = candidates[i]; break; }
    }
    if (!uc) {
        fprintf(stderr, "apphide: no uicache found\n");
        return -1;
    }

    pid_t pid = 0;
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_set_persona_np(&attr, 501, 1);
    posix_spawnattr_set_persona_uid_np(&attr, 501);
    posix_spawnattr_set_persona_gid_np(&attr, 501);
    char *args[] = { (char *)uc, "-a", NULL };
    int r = posix_spawn(&pid, uc, NULL, &attr, args, environ);
    posix_spawnattr_destroy(&attr);
    if (r != 0) {
        fprintf(stderr, "apphide: posix_spawn(uicache) failed: %s\n", strerror(r));
        return -1;
    }
    int status = 0;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "apphide: uicache exited with status %d\n",
                WIFEXITED(status) ? WEXITSTATUS(status) : -1);
        return -1;
    }
    return 0;
}

static void respring(void) {
    pid_t pid = 0;
    char *args[4];
    args[0] = "/usr/bin/killall";
    args[1] = "-9";
    args[2] = "SpringBoard";
    args[3] = NULL;
    const char *jb_killall = "/var/jb/usr/bin/killall";
    if (access(jb_killall, X_OK) == 0) args[0] = (char *)jb_killall;
    posix_spawn(&pid, args[0], NULL, NULL, args, environ);
    /* Don't wait — respring kills us too */
}

static void refresh_ls(void) {
    printf("apphide: running uicache -a as mobile...\n");
    run_uicache();
    printf("apphide: respringing SpringBoard...\n");
    respring();
}

static int hide_app_path(const char *app_path) {
    const char *slash = strrchr(app_path, '/');
    const char *name = slash ? slash + 1 : app_path;

    char dst[PATH_MAX];
    snprintf(dst, sizeof(dst), "%s/%s", STASH_DIR, name);
    if (file_exists(dst)) {
        printf("apphide: %s already hidden\n", app_path);
        return 0;
    }

    if (ensure_dir(STASH_DIR, 0755) != 0) return -1;

    /* Mark vnode VBAD so filesystem access fails immediately */
    vnode_hide_path(app_path);

    if (move_app(app_path, dst) != 0) return -1;
    printf("apphide: hidden %s -> %s\n", app_path, dst);
    return 0;
}

static int unhide_by_name(const char *name) {
    char src[PATH_MAX];
    snprintf(src, sizeof(src), "%s/%s", STASH_DIR, name);
    if (!file_exists(src)) {
        fprintf(stderr, "apphide: %s is not in stash\n", name);
        return -1;
    }

    char dst[PATH_MAX];
    snprintf(dst, sizeof(dst), "%s/%s", JB_APPS_DIR, name);

    if (move_app(src, dst) != 0) return -1;

    /* Restore vnode so the app is visible on filesystem again */
    vnode_restore_all();

    printf("apphide: restored %s -> %s\n", name, dst);
    return 0;
}

int apphide_list(void) {
    printf("apphide: apps in %s:\n", JB_APPS_DIR);
    DIR *d = opendir(JB_APPS_DIR);
    if (!d) {
        fprintf(stderr, "apphide: cannot open %s\n", JB_APPS_DIR);
        return -1;
    }
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        if (strstr(ent->d_name, ".app") == NULL) continue;
        char dpath[PATH_MAX];
        snprintf(dpath, sizeof(dpath), "%s/%s", JB_APPS_DIR, ent->d_name);
        if (!is_dir(dpath)) continue;
        char *bid = read_bundle_id(dpath);
        if (bid) {
            printf("  %-25s  %s\n", ent->d_name, bid);
            free(bid);
        } else {
            printf("  %-25s  (no bundle id)\n", ent->d_name);
        }
    }
    closedir(d);

    printf("\napphide: hidden apps:\n");
    d = opendir(STASH_DIR);
    if (d) {
        while ((ent = readdir(d)) != NULL) {
            if (ent->d_name[0] == '.') continue;
            if (strstr(ent->d_name, ".app") != NULL) {
                printf("  %s\n", ent->d_name);
            }
        }
        closedir(d);
    }
    return 0;
}

int apphide_hide(const char *bundle_id) {
    if (!bundle_id || !*bundle_id) {
        fprintf(stderr, "apphide: missing bundle id\n");
        return -1;
    }
    char *app_path = find_app_by_id(JB_APPS_DIR, bundle_id);
    if (!app_path) {
        fprintf(stderr, "apphide: no app with id '%s' found in %s\n", bundle_id, JB_APPS_DIR);
        return -1;
    }
    int rc = hide_app_path(app_path);
    free(app_path);
    if (rc == 0) refresh_ls();
    return rc;
}

int apphide_unhide(const char *bundle_id) {
    if (!bundle_id || !*bundle_id) {
        fprintf(stderr, "apphide: missing bundle id\n");
        return -1;
    }
    char *app_path = find_app_by_id(JB_APPS_DIR, bundle_id);
    if (app_path) {
        printf("apphide: %s is already visible at %s\n", bundle_id, app_path);
        free(app_path);
        return 0;
    }
    int rc = unhide_by_name(bundle_id);
    if (rc == 0) refresh_ls();
    return rc;
}

int apphide_unhide_all(void) {
    DIR *d = opendir(STASH_DIR);
    if (!d) {
        fprintf(stderr, "apphide: no stash dir (%s)\n", STASH_DIR);
        return 0;
    }
    struct dirent *ent;
    char names[128][128];
    int n = 0;
    while ((ent = readdir(d)) != NULL && n < 128) {
        if (ent->d_name[0] == '.') continue;
        if (strstr(ent->d_name, ".app") != NULL) {
            strlcpy(names[n++], ent->d_name, sizeof(names[0]));
        }
    }
    closedir(d);
    for (int i = 0; i < n; i++) {
        unhide_by_name(names[i]);
    }
    printf("apphide: restored %d hidden app(s)\n", n);
    if (n > 0) refresh_ls();
    return 0;
}

int apphide_hide_all(void) {
    DIR *d = opendir(JB_APPS_DIR);
    if (!d) {
        fprintf(stderr, "apphide: cannot open %s\n", JB_APPS_DIR);
        return -1;
    }
    struct dirent *ent;
    int count = 0;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        if (strstr(ent->d_name, ".app") == NULL) continue;
        char dpath[PATH_MAX];
        snprintf(dpath, sizeof(dpath), "%s/%s", JB_APPS_DIR, ent->d_name);
        if (!is_dir(dpath)) continue;
        if (hide_app_path(dpath) == 0) count++;
    }
    closedir(d);
    printf("apphide: hidden %d app(s)\n", count);
    if (count > 0) refresh_ls();
    return 0;
}

int apphide_hide_known(void) {
    char *matched = calloc(1, sizeof(char) * 4096);
    size_t off = 0;
    int count = 0;
    for (int i = 0; known_ids[i]; i++) {
        char *app_path = find_app_by_id(JB_APPS_DIR, known_ids[i]);
        if (app_path) {
            if (hide_app_path(app_path) == 0) {
                const char *bn = strrchr(app_path, '/');
                const char *name = bn ? bn + 1 : app_path;
                size_t need = strlen(name) + 1;
                if (off + need < 4096) {
                    memcpy(matched + off, name, need);
                    off += need;
                }
                count++;
            }
            free(app_path);
        }
    }
    printf("apphide: hidden %d known app(s): %s\n", count, matched);
    free(matched);
    if (count > 0) refresh_ls();
    return 0;
}

int apphide_status(void) {
    printf("apphide: apps in %s:\n", JB_APPS_DIR);
    DIR *d = opendir(JB_APPS_DIR);
    if (!d) {
        fprintf(stderr, "apphide: cannot open %s\n", JB_APPS_DIR);
        return -1;
    }
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        if (strstr(ent->d_name, ".app") == NULL) continue;
        char dpath[PATH_MAX];
        snprintf(dpath, sizeof(dpath), "%s/%s", JB_APPS_DIR, ent->d_name);
        if (!is_dir(dpath)) continue;
        char *bid = read_bundle_id(dpath);
        if (bid) {
            printf("  visible  %-25s  %s\n", ent->d_name, bid);
            free(bid);
        } else {
            printf("  visible  %-25s  (no bundle id)\n", ent->d_name);
        }
    }
    closedir(d);

    printf("\napphide: hidden apps:\n");
    d = opendir(STASH_DIR);
    if (d) {
        while ((ent = readdir(d)) != NULL) {
            if (ent->d_name[0] == '.') continue;
            if (strstr(ent->d_name, ".app") != NULL) {
                printf("  hidden   %s\n", ent->d_name);
            }
        }
        closedir(d);
    }
    return 0;
}

int apphide_refresh_ls(void) {
    printf("apphide: refreshing LaunchServices and respringing...\n");
    refresh_ls();
    return 0;
}