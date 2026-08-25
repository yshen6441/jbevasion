#ifndef VHIDE_H
#define VHIDE_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * vhide - vnode-level hiding with a runtime-essential whitelist.
 *
 * Unlike raw `vnode_hide_path`, every path is first checked against a set
 * of protected prefixes (libjailbreak, TweakInject, ellekit/substrate,
 * jailbreakd, the jbevasion binary itself). Hiding any of those would break
 * tweak injection or the jailbreak daemons, taking down the whole jailbreak
 * environment. vhide only ever touches "safe" traces that are unrelated to
 * plugin runtime (shells, sshd, frida, apt remnants, logs).
 */

int vhide_known(void);
int vhide_path(const char *path);
int vhide_restore_all(void);
int vhide_status(void);
int vhide_config_load(void);

/* Custom (plist) apphide whitelist: ProtectedApps from the config plist,
 * merged with apphide.c's built-in whitelist at hide time. */
int vhide_protected_app_count(void);
const char *vhide_protected_app_at(int i);

#ifdef __cplusplus
}
#endif

#endif /* VHIDE_H */
