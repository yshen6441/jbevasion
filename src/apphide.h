#ifndef APPHIDE_H
#define APPHIDE_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* App hiding via file move + vnode VBAD + uicache + respring.
 * 1. Mark vnode VBAD so filesystem access fails immediately
 * 2. Move .app to stash directory
 * 3. Run uicache -a as mobile to update LaunchServices database
 * 4. Respring SpringBoard to refresh icon model
 *
 * Hidden apps are parked in /var/jb/.apphide-stash/<name>.app.
 * Restoring reverses the process.
 */

int apphide_list(void);
int apphide_hide(const char *bundle_id);
int apphide_unhide(const char *bundle_id);
int apphide_hide_all(void);
int apphide_hide_known(void);
int apphide_unhide_all(void);
int apphide_status(void);
int apphide_refresh_ls(void);

#ifdef __cplusplus
}
#endif

#endif