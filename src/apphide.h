#ifndef APPHIDE_H
#define APPHIDE_H

#include <stdbool.h>

/* Kernel-level app hiding via vnode VBAD marking.
 * Apps disappear from the filesystem instantly — no uicache or respring needed.
 *
 * Hidden apps are tracked in /var/jb/.apphide-stash/<name>.hidden marker files.
 * Restoring rewrites the original vnode data, making the app reappear.
 */

int apphide_list(void);
int apphide_hide(const char *bundle_id);
int apphide_unhide(const char *bundle_id);
int apphide_hide_all(void);
int apphide_hide_known(void);
int apphide_unhide_all(void);
int apphide_status(void);
int apphide_refresh_ls(void);

#endif