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

/* Callback for main.m to install a better LS refresh (ObjC _LSRefresh + respring) */
void (*apphide_ls_refresh_callback)(void) = NULL;

static void refresh_ls_all(void);

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
    "com.wizages.aino",
    "org.sparkles.zebra",
    "com.jmillerpc.RocketBootstrap",
    "com.saurik.CydiaStartup",
    "com.opa334.Sileo",
    NULL,
};

/* Bundle IDs that must never be hidden automatically — losing the terminal
 * leaves the user with no way to run apphide-showall to recover. */
static const char *protect_ids[] = {
    "ws.hbang.Terminal",
    NULL,
};

/* Check if app_path matches any protected bundle ID. */
static bool is_protected_app(const char *app_path) {
    char info_path[PATH_MAX];
    snprintf(info_path, sizeof(info_path), "%s/Info.plist", app_path);
    if (!file_exists(info_path)) return false;
    /* Read CFBundleIdentifier from Info.plist via CoreFoundation. */
    CFStringRef pathStr = CFStringCreateWithCString(
        kCFAllocatorDefault, info_path, kCFStringEncodingUTF8);
    if (!pathStr) return false;
    CFURLRef url = CFURLCreateWithFileSystemPath(
        kCFAllocatorDefault, pathStr, kCFURLPOSIXPathStyle, false);
    CFRelease(pathStr);
    if (!url) return false;
    CFReadStreamRef stream = CFReadStreamCreateWithFile(kCFAllocatorDefault, url);
    CFRelease(url);
    if (!stream) return false;
    CFReadStreamOpen(stream);
    CFPropertyListRef plist = CFPropertyListCreateWithStream(
        kCFAllocatorDefault, stream, 0, kCFPropertyListImmutable, NULL, NULL);
    CFReadStreamClose(stream);
    CFRelease(stream);
    if (!plist || CFDictionaryGetTypeID() != CFGetTypeID(plist)) {
        if (plist) CFRelease(plist);
        return false;
    }
    CFDictionaryRef dict = (CFDictionaryRef)plist;
    CFStringRef key = CFSTR("CFBundleIdentifier");
    CFStringRef val = CFDictionaryGetValue(dict, key);
    bool matched = false;
    if (val && CFStringGetTypeID() == CFGetTypeID(val)) {
        char buf[256];
        if (CFStringGetCString((CFStringRef)val, buf, sizeof(buf),
                               kCFStringEncodingUTF8)) {
            for (int i = 0; protect_ids[i]; i++) {
                if (strcmp(buf, protect_ids[i]) == 0) {
                    matched = true;
                    break;
                }
            }
        }
    }
    CFRelease(plist);
    return matched;
}

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
    if (rc == 0) refresh_ls_all();
    printf("apphide: run 'jbevasion respring' to apply the icon change.\n");
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
    int rc = unhide_by_name(bundle_id);
    if (rc == 0) {
        refresh_ls_all();
        printf("apphide: run 'jbevasion respring' to apply the icon change.\n");
    }
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
    if (n > 0) {
        refresh_ls_all();
        printf("apphide: run 'jbevasion respring' to apply the icon change.\n");
    }
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
        if (is_protected_app(dpath)) {
            printf("apphide: skipping protected app %s\n", ent->d_name);
            continue;
        }
        if (hide_app_path(dpath) == 0) count++;
    }
    closedir(d);
    printf("apphide: hidden %d app(s)\n", count);
    if (count > 0) {
        refresh_ls_all();
        printf("apphide: run 'jbevasion respring' to apply the icon change.\n");
    }
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
                                   NULL };
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
/*  LS registration refresh (icons without reboot)                    */
/* ------------------------------------------------------------------ */

/* Run uicache as the mobile user so LaunchServices rebuilds its
 * per-user registration database from a fresh directory scan of
 * /var/jb/Applications. Bundles we stashed are gone from disk, so they
 * drop out of the icon model. Running as mobile matters: the SpringBoard
 * icon database is the mobile user's LS cache, not root's. */
static int run_uicache(char *const args[], char *errbuf, size_t errsz) {
    pid_t child = fork();
    if (child < 0) {
        fprintf(stderr, "apphide: fork failed: %s\n", strerror(errno));
        return -1;
    }
    if (child == 0) {
        setgid(501);
        setuid(501);
        execv(args[0], args);
        _exit(127);
    }

    int status = 0;
    waitpid(child, &status, 0);

    if (errbuf && errsz) errbuf[0] = '\0';
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        int rc = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        fprintf(stderr, "apphide: uicache exited with status %d\n", rc);
        return rc;
    }
    return 0;
}

static const char *find_uicache(void) {
    static const char *candidates[] = {
        "/var/jb/usr/bin/uicache",
        "/var/jb/usr/bin/uicache-strapped",
        "/usr/bin/uicache",
        NULL,
    };
    for (int i = 0; candidates[i]; i++) {
        if (access(candidates[i], X_OK) == 0)
            return candidates[i];
    }
    return NULL;
}

static void refresh_ls_all(void) {
    /* If main.m installed a better callback (LSApplicationWorkspace _LSRefresh + respring), use it. */
    if (apphide_ls_refresh_callback) {
        apphide_ls_refresh_callback();
        return;
    }
    /* Fallback: uicache -a as mobile. */
    const char *uc = find_uicache();
    if (!uc) {
        fprintf(stderr, "apphide: no uicache found; icon refresh needs a reboot\n");
        return;
    }
    printf("apphide: refreshing LaunchServices with %s -a (as mobile)...\n", uc);
    char *args[] = { (char *)uc, "-a", NULL };
    run_uicache(args, NULL, 0);
}

int apphide_refresh_ls(void) {
    printf("apphide: resyncing LaunchServices registration (safe, no csstore/lsd touch)\n");
    refresh_ls_all();
    printf("apphide: LS refreshed - run 'jbevasion respring' to update icons.\n");
    return 0;
}