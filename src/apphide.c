#include "apphide.h"

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
#include <sys/wait.h>
#include <spawn.h>
#include <CoreFoundation/CoreFoundation.h>

extern char **environ;

/* JB paths (rootless). The jailbroken apps live here. */
#define JB_APPS_DIR   "/var/jb/Applications"
#define STASH_DIR     "/var/jb/.jbevasion_apphide"
#define MANIFEST_PATH "/var/jb/.jbevasion_apphide/manifest.txt"

/* Bundle identifiers of well-known jailbreak packages. Hiding these is the
 * "one-shot clean desktop" use case. */
static const char *known_ids[] = {
    "org.coolstar.Sileo",
    "com.saurik.Cydia",
    "com.tigisoftware.Filza",
    "ws.hbang.Terminal",
    "com.wizages.aino",
    "org.sparkles.zebra",
    "com.jmillerpc.RocketBootstrap",
    "com.saurik.CydiaStartup",
    "com.opa334.Sileo",
    NULL,
};

/* ------------------------------------------------------------------ */
/*  Small helpers                                                      */
/* ------------------------------------------------------------------ */

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

/* Read the CFBundleIdentifier out of an Info.plist using CoreFoundation.
 * Returns a heap string the caller must free (or NULL on failure). */
static char *read_bundle_id(const char *app_dir) {
    char plist_path[PATH_MAX];
    snprintf(plist_path, sizeof(plist_path), "%s/Info.plist", app_dir);

    FILE *fp = fopen(plist_path, "rb");
    if (!fp) return NULL;
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (size <= 0) {
        fclose(fp);
        return NULL;
    }
    char *data = malloc((size_t)size);
    if (!data) {
        fclose(fp);
        return NULL;
    }
    size_t got = fread(data, 1, (size_t)size, fp);
    fclose(fp);
    if (got != (size_t)size) {
        free(data);
        return NULL;
    }

    CFDataRef cfdata = CFDataCreate(kCFAllocatorDefault, (const uint8_t *)data, got);
    free(data);
    if (!cfdata) return NULL;

    CFPropertyListRef plist = CFPropertyListCreateWithData(
        kCFAllocatorDefault, cfdata, kCFPropertyListImmutable, NULL, NULL);
    CFRelease(cfdata);
    if (!plist || CFGetTypeID(plist) != CFDictionaryGetTypeID()) {
        if (plist) CFRelease(plist);
        return NULL;
    }

    CFStringRef bid = CFDictionaryGetValue(plist, CFSTR("CFBundleIdentifier"));
    char *out = NULL;
    if (bid && CFGetTypeID(bid) == CFStringGetTypeID()) {
        CFIndex len = CFStringGetLength(bid);
        CFIndex max = CFStringGetMaximumSizeForEncoding(len, kCFStringEncodingUTF8) + 1;
        out = malloc((size_t)max);
        if (out) {
            CFStringGetCString(bid, out, max, kCFStringEncodingUTF8);
        }
    }
    CFRelease(plist);
    return out;
}

/* Price of not linking Foundation: get the display name from the directory
 * name, which for /var/jb/Applications children equals "<Name>.app". */
static void strip_app_suffix(const char *name, char *out, size_t outsz) {
    snprintf(out, outsz, "%s", name);
    size_t l = strlen(out);
    if (l > 4 && strcmp(out + l - 4, ".app") == 0)
        out[l - 4] = '\0';
}

/* Look up a child .app directory in a directory that matches bundle id.
 * Returns a heap-allocated "<dir>/<Name>.app" path (or NULL). */
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
            /* If we cannot read the plist, still allow a directory-name match
             * like "Sileo.app", which is handy when the plist parser is off. */
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

/* The vehicle actually doing the hiding. Moved under the name of the bundle
 * to keep manifest parsing trivial. */
static int hide_app_path(const char *app_path) {
    const char *slash = strrchr(app_path, '/');
    const char *name = slash ? slash + 1 : app_path;

    char dst[PATH_MAX];
    snprintf(dst, sizeof(dst), "%s/%s", STASH_DIR, name);
    if (file_exists(dst)) {
        printf("apphide: %s already hidden\n", app_path);
        return 0;
    }

    if (ensure_dir(STASH_DIR, 0700) != 0) return -1;

    if (rename(app_path, dst) != 0) {
        fprintf(stderr, "apphide: rename(%s -> %s) failed: %s\n",
                app_path, dst, strerror(errno));
        return -1;
    }

    /* Record original path in manifest for an exact restore. */
    FILE *mf = fopen(MANIFEST_PATH, "a");
    if (mf) {
        fprintf(mf, "%s\n", app_path);
        fclose(mf);
    }
    printf("apphide: hidden %s -> %s\n", app_path, dst);
    printf("apphide: SpringBoard will drop the icon on next rescan (or respring).\n");
    return 0;
}

static int unhide_by_name(const char *name) {
    char stashed[PATH_MAX];
    snprintf(stashed, sizeof(stashed), "%s/%s", STASH_DIR, name);
    if (!file_exists(stashed)) {
        fprintf(stderr, "apphide: %s is not in the stash\n", name);
        return -1;
    }

    /* Find matching manifest line to restore the original path. */
    char orig[PATH_MAX] = "";
    FILE *mf = fopen(MANIFEST_PATH, "r");
    if (mf) {
        char line[PATH_MAX];
        while (fgets(line, sizeof(line), mf)) {
            size_t l = strlen(line);
            while (l > 0 && (line[l-1] == '\n' || line[l-1] == '\r')) line[--l] = '\0';
            if (l == 0) continue;
            const char *bn = strrchr(line, '/');
            if (bn && strcmp(bn + 1, name) == 0) {
                strlcpy(orig, line, sizeof(orig));
                break;
            }
        }
        fclose(mf);
    }

    if (orig[0] == '\0') {
        /* No manifest entry; re-create from a sensible path so the app is not
         * lost. Prefer /var/jb/Applications since that is the scan dir. */
        snprintf(orig, sizeof(orig), "%s/%s", JB_APPS_DIR, name);
    }

    if (rename(stashed, orig) != 0) {
        fprintf(stderr, "apphide: rename(%s -> %s) failed: %s\n",
                stashed, orig, strerror(errno));
        return -1;
    }
    printf("apphide: restored %s -> %s\n", name, orig);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Public API                                                         */
/* ------------------------------------------------------------------ */

int apphide_list(void) {
    printf("apphide: scanning %s and stash %s\n", JB_APPS_DIR, STASH_DIR);
    printf("%-28s %-28s %s\n", "BUNDLE ID", "NAME", "PATH");

    DIR *d = opendir(JB_APPS_DIR);
    if (!d) {
        printf("apphide: cannot open %s: %s\n", JB_APPS_DIR, strerror(errno));
        return 1;
    }
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        if (strstr(ent->d_name, ".app") == NULL) continue;
        char dpath[PATH_MAX];
        snprintf(dpath, sizeof(dpath), "%s/%s", JB_APPS_DIR, ent->d_name);
        if (!is_dir(dpath)) continue;

        char *bid = read_bundle_id(dpath);
        char base[128];
        strip_app_suffix(ent->d_name, base, sizeof(base));
        printf("%-28s %-28s %s\n", bid ? bid : "(unknown)", base, dpath);
        free(bid);
    }
    closedir(d);

    /* Show what is stashed right now. */
    DIR *sd = opendir(STASH_DIR);
    if (sd) {
        while ((ent = readdir(sd)) != NULL) {
            if (ent->d_name[0] == '.') continue;
            if (strstr(ent->d_name, ".app") != NULL) {
                char s[PATH_MAX];
                snprintf(s, sizeof(s), "%s/%s", STASH_DIR, ent->d_name);
                printf("  (hidden) %-25s -> %s\n", ent->d_name, s);
            }
        }
        closedir(sd);
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
        fprintf(stderr, "apphide: no app with id '%s' found in %s\n",
                bundle_id, JB_APPS_DIR);
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
    /* Try exact bundle id first, then directory-name fallback. */
    char *app_path = find_app_by_id(JB_APPS_DIR, bundle_id);
    if (app_path) {
        /* It is already visible again. */
        printf("apphide: %s is already visible at %s\n", bundle_id, app_path);
        free(app_path);
        return 0;
    }
    return unhide_by_name(bundle_id);
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
    printf("apphide: hidden %d known package manager / tool app(s)\n", count);
    /* Also do the directory-name fallback for the usual suspects, in case the
     * bundle-id read failed but the .app dirs exist. */
    const char *known_names[] = { "Sileo", "Cydia", "Filza", "Zebra", "Saily",
                                  "Terminal", NULL };
    for (int i = 0; known_names[i]; i++) {
        char want[160];
        snprintf(want, sizeof(want), "%s.app", known_names[i]);
        bool already = false;
        for (size_t k = 0; k < off; ) {
            if (strcmp(matched + k, want) == 0) { already = true; break; }
            k += strlen(matched + k) + 1;
        }
        if (already) continue;
        char dpath[PATH_MAX];
        snprintf(dpath, sizeof(dpath), "%s/%s", JB_APPS_DIR, want);
        if (is_dir(dpath)) {
            if (hide_app_path(dpath) == 0) count++;
        }
    }
    free(matched);
    printf("apphide: total hidden: %d\n", count);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Icon resync without rebooting                                     */
/* ------------------------------------------------------------------ */

/* LaunchServices keeps a csstore cache of every registered app. Killing
 * lsd without letting it rewrite the cache means SpringBoard's icon model
 * still lists the (now stashed) apps. We move the csstore files aside so
 * lsd re-builds the launch database from a fresh directory scan. */
static int backup_ls_csstore(void) {
    const char *cache_dir = "/var/mobile/Library/Caches";
    char backup_dir[PATH_MAX];
    snprintf(backup_dir, sizeof(backup_dir), "%s/ls-cache", STASH_DIR);
    ensure_dir(backup_dir, 0700);

    DIR *d = opendir(cache_dir);
    if (!d) {
        /* Nothing to move if caches are not accessible; lsd rebuilds anyway. */
        fprintf(stderr, "apphide: cannot open %s (%s)\n",
                cache_dir, strerror(errno));
        return 0;
    }

    int moved = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        if (strncmp(ent->d_name, "com.apple.LaunchServices-", 26) == 0) {
            char src[PATH_MAX], dst[PATH_MAX];
            snprintf(src, sizeof(src), "%s/%s", cache_dir, ent->d_name);
            snprintf(dst, sizeof(dst), "%s/%s", backup_dir, ent->d_name);
            if (rename(src, dst) == 0) {
                printf("apphide: moved LS cache %s\n", ent->d_name);
                moved++;
            }
        }
    }
    closedir(d);
    printf("apphide: stashed %d LaunchServices csstore cache(s)\n", moved);
    return moved >= 0 ? 0 : -1;
}

/* Kill lsd by bundle id via launchctl so launchd restarts it cleanly.
 * lsd re-registers installed apps on startup, re-scanning /var/jb/Applications
 * which no longer contains the hidden .app bundles. */
static int kill_lsd(void) {
    /* launchctl kickstart is the clean way: restart the service in place. */
    pid_t pid = 0;
    char *args[] = {
        (char *)"/bin/launchctl", "kickstart", "-k",
        "system/com.apple.coreservices.lsd",
        NULL,
    };
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    int r = posix_spawn(&pid, args[0], NULL, &attr, args, environ);
    posix_spawnattr_destroy(&attr);
    if (r != 0) {
        /* Fall back to killing the process directly. */
        fprintf(stderr, "apphide: launchctl kickstart failed, trying killall\n");
        pid = 0;
        char *kill_args[] = { (char *)"/usr/bin/killall", "-9", "lsd", NULL };
        const char *jb_killall = "/var/jb/usr/bin/killall";
        if (access(jb_killall, X_OK) == 0)
            kill_args[0] = (char *)jb_killall;
        posix_spawnattr_init(&attr);
        r = posix_spawn(&pid, kill_args[0], NULL, &attr, kill_args, environ);
        posix_spawnattr_destroy(&attr);
        if (r != 0) {
            fprintf(stderr, "apphide: killall lsd failed: %s\n", strerror(errno));
            return -1;
        }
    }
    return 0;
}

int apphide_resync_icons(void) {
    printf("apphide: resyncing SpringBoard icon model without a full reboot...\n");
    printf("apphide: 1/3 clearing LaunchServices csstore cache\n");
    backup_ls_csstore();

    printf("apphide: 2/3 restarting lsd to re-register apps\n");
    kill_lsd();

    /* Give lsd a moment to build the new launch database, then respring. */
    sleep(2);
    printf("apphide: 3/3 respringing SpringBoard\n");
    pid_t pid = 0;
    char *args[] = { (char *)"/usr/bin/killall", "-SEGV", "SpringBoard", NULL };
    const char *jb_killall = "/var/jb/usr/bin/killall";
    if (access(jb_killall, X_OK) == 0)
        args[0] = (char *)jb_killall;
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    int r = posix_spawn(&pid, args[0], NULL, &attr, args, environ);
    posix_spawnattr_destroy(&attr);
    if (r != 0) {
        fprintf(stderr, "apphide: respring failed: %s\n", strerror(errno));
        return -1;
    }
    printf("apphide: done - icons will reflect the stash on the next screen.\n");
    return 0;
}