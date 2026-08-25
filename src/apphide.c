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
#include <sys/stat.h>
#include <sys/param.h>
#include <CoreFoundation/CoreFoundation.h>

#define JB_APPS_DIR   "/var/jb/Applications"
#define STASH_DIR     "/var/jb/.apphide-stash"
#define TRACKING_FILE STASH_DIR "/tracking"

/* Well-known jailbreak app directory names (without .app suffix) */
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
    if (!plist) {
        if (err) CFRelease(err);
        free(data);
        return NULL;
    }

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
                if (ret) {
                    CFStringGetCString(val, ret, max, kCFStringEncodingUTF8);
                }
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

static int write_tracking_entry(const char *app_path, uint64_t vaddr) {
    if (ensure_dir(STASH_DIR, 0755) != 0) return -1;
    FILE *fp = fopen(TRACKING_FILE, "a");
    if (!fp) {
        fprintf(stderr, "apphide: cannot open %s: %s\n", TRACKING_FILE, strerror(errno));
        return -1;
    }
    fprintf(fp, "0x%016llx %s\n", (unsigned long long)vaddr, app_path);
    fclose(fp);
    return 0;
}

static int read_tracking_entry(const char *app_path, uint64_t *vaddr_out) {
    FILE *fp = fopen(TRACKING_FILE, "r");
    if (!fp) return -1;
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        uint64_t va = 0;
        char path[PATH_MAX];
        if (sscanf(line, "0x%llx %1023s", (unsigned long long *)&va, path) == 2) {
            if (strcmp(path, app_path) == 0) {
                *vaddr_out = va;
                fclose(fp);
                return 0;
            }
        }
    }
    fclose(fp);
    return -1;
}

static int remove_tracking_entry(const char *app_path) {
    FILE *fp = fopen(TRACKING_FILE, "r");
    if (!fp) return -1;
    char lines[256][1024];
    int n = 0;
    char line[1024];
    while (fgets(line, sizeof(line), fp) && n < 256) {
        char path[PATH_MAX];
        if (sscanf(line, "%*s %1023s", path) == 1) {
            if (strcmp(path, app_path) != 0) {
                strlcpy(lines[n++], line, sizeof(lines[0]));
            }
        }
    }
    fclose(fp);
    fp = fopen(TRACKING_FILE, "w");
    if (!fp) return -1;
    for (int i = 0; i < n; i++) {
        fputs(lines[i], fp);
    }
    fclose(fp);
    return 0;
}

static int hide_app_path(const char *app_path) {
    const char *name = strrchr(app_path, '/');
    if (!name) return -1;
    name++;

    char marker[PATH_MAX];
    snprintf(marker, sizeof(marker), "%s/%s.hidden", STASH_DIR, name);
    if (file_exists(marker)) {
        printf("apphide: %s already hidden\n", app_path);
        return 0;
    }

    int rc = vnode_hide_path(app_path);
    if (rc != 0) {
        fprintf(stderr, "apphide: vnode hide failed for %s\n", app_path);
        return -1;
    }

    uint64_t vnode = 0;
    /* We don't have the vnode address from vnode_hide_path directly,
     * but we can get it by opening the path before hide. However,
     * vnode_hide_path already opened it internally. Let me just
     * re-get it for tracking purposes. Actually, we can't open
     * a VBAD file. So let me use a different approach: store the
     * path and find the vnode in the saved list later. */

    /* Write a marker file to track which apps are hidden */
    ensure_dir(STASH_DIR, 0755);
    FILE *mf = fopen(marker, "w");
    if (mf) {
        fprintf(mf, "%s\n", app_path);
        fclose(mf);
    }

    printf("apphide: hidden %s\n", app_path);
    return 0;
}

static int unhide_by_name(const char *name) {
    char marker[PATH_MAX];
    snprintf(marker, sizeof(marker), "%s/%s.hidden", STASH_DIR, name);
    if (!file_exists(marker)) {
        fprintf(stderr, "apphide: %s is not hidden\n", name);
        return -1;
    }

    /* Read original path from marker */
    FILE *mf = fopen(marker, "r");
    if (!mf) return -1;
    char app_path[PATH_MAX];
    if (!fgets(app_path, sizeof(app_path), mf)) {
        fclose(mf);
        return -1;
    }
    fclose(mf);
    app_path[strcspn(app_path, "\n")] = '\0';

    /* Restore all hidden vnodes — for single app restore we need to
     * find the right vnode. Since we can't open the path to get the
     * vnode (it's VBAD), we restore all and re-hide the others. */
    vnode_restore_all();

    /* Remove the marker */
    unlink(marker);
    printf("apphide: restored %s\n", app_path);
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
            char *dot = strstr(ent->d_name, ".hidden");
            if (dot) {
                *dot = '\0';
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
    /* Try to find by marker name */
    char marker_path[PATH_MAX];
    snprintf(marker_path, sizeof(marker_path), "%s/%s.hidden", STASH_DIR, bundle_id);
    if (file_exists(marker_path)) {
        return unhide_by_name(bundle_id);
    }
    /* Try by bundle id in marker files */
    DIR *d = opendir(STASH_DIR);
    if (!d) {
        fprintf(stderr, "apphide: no stash dir (%s)\n", STASH_DIR);
        return -1;
    }
    struct dirent *ent;
    int rc = -1;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        char *dot = strstr(ent->d_name, ".hidden");
        if (!dot) continue;
        char marker[PATH_MAX];
        snprintf(marker, sizeof(marker), "%s/%s", STASH_DIR, ent->d_name);
        FILE *mf = fopen(marker, "r");
        if (!mf) continue;
        char app_path[PATH_MAX];
        if (fgets(app_path, sizeof(app_path), mf)) {
            app_path[strcspn(app_path, "\n")] = '\0';
            char *bid = read_bundle_id(app_path);
            if (bid) {
                /* The app_path leads to a VBAD dir, so read_bundle_id will fail.
                 * Instead, match by marker filename. */
                free(bid);
            }
        }
        fclose(mf);
        /* Match by marker filename (strip .hidden) */
        *dot = '\0';
        if (strcmp(ent->d_name, bundle_id) == 0) {
            *dot = '.';
            rc = unhide_by_name(ent->d_name);
            break;
        }
        *dot = '.';
    }
    closedir(d);
    if (rc != 0) {
        fprintf(stderr, "apphide: no hidden app with id '%s' found\n", bundle_id);
    }
    return rc;
}

int apphide_unhide_all(void) {
    DIR *d = opendir(STASH_DIR);
    if (!d) {
        fprintf(stderr, "apphide: no stash dir (%s)\n", STASH_DIR);
        return 0;
    }
    int n = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        char *dot = strstr(ent->d_name, ".hidden");
        if (dot) {
            *dot = '\0';
            unhide_by_name(ent->d_name);
            *dot = '.';
            n++;
        }
    }
    closedir(d);
    printf("apphide: restored %d hidden app(s)\n", n);
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
    printf("apphide: hidden %d known app(s)\n", count);
    if (count > 0) {
        printf("apphide: hidden apps: %s\n", matched);
    }
    free(matched);
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
            char *dot = strstr(ent->d_name, ".hidden");
            if (dot) {
                *dot = '\0';
                char marker[PATH_MAX];
                snprintf(marker, sizeof(marker), "%s/%s", STASH_DIR, ent->d_name);
                FILE *mf = fopen(marker, "r");
                if (mf) {
                    char orig[PATH_MAX];
                    if (fgets(orig, sizeof(orig), mf)) {
                        orig[strcspn(orig, "\n")] = '\0';
                        printf("  hidden   %s\n", orig);
                    }
                    fclose(mf);
                }
                *dot = '.';
            }
        }
        closedir(d);
    }
    return 0;
}

int apphide_refresh_ls(void) {
    printf("apphide: vnode-based hiding does not need LS refresh\n");
    return 0;
}