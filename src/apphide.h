#ifndef APPHIDE_H
#define APPHIDE_H

#include <stdbool.h>

/* Pure-userland app hiding for rootless (Dopamine) jailbreaks.
 * No kernel memory access, no vnode / mount manipulation.
 *
 * Mechanism:
 *   - Package managers & jailbroken apps live in /var/jb/Applications/*.app
 *   - SpringBoard derives its icon model from LaunchServices, which scans
 *     /var/jb/Applications. Moving a .app out of that tree makes it
 *     disappear from the springboard and from LSApplicationWorkspace.
 *
 * State:
 *   - Hidden .app bundles are parked in /var/jb/.jbevasion_apphide/<name>.app
 *   - A manifest keeps the original absolute path so an unhide can restore
 *     exactly where it came from.
 */

int apphide_list(void);
int apphide_hide(const char *bundle_id);
int apphide_unhide(const char *bundle_id);
int apphide_hide_all(void);
int apphide_hide_known(void);
int apphide_unhide_all(void);

#endif