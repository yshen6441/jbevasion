# jbevasion

Jailbreak environment hiding controller for Dopamine (iOS 15-18, arm64/arm64e).

Kernel read/write is provided by Dopamine's `libjailbreak.dylib`
(`/var/jb/usr/lib/libjailbreak.dylib`), resolved at runtime through
`-rpath /var/jb/usr/lib`. The `stub/` directory holds a **link-time only**
dylib so the project builds on hosts without the real library; the stub is
never executed on device.

## What it does

Two components ship in the `.deb`:

1. **`jbevasion` CLI** (setuid root 6755) — CoreFoundation-based app hiding.
   Moves jailbreak apps out of `/var/jb/Applications` into a stash at
   `/var/jb/.apphide-stash/`, marks their vnodes `VBAD` so filesystem access
   fails immediately, persists the vnode state to `.hidden` marker files
   (so restore works across process restarts), refreshes LaunchServices via
   `uicache -a`, and resprings.

2. **`jbevasionCC` tweak** — injects a one-tap eye toggle into Control
   Center (top-left) by hooking
   `CCUIModularControlCenterOverlayViewController -setPresentationState:`.
   Green `eye.fill` = apps visible; orange `eye.slash.fill` = apps hidden.
   Tapping spawns `jbevasion apphide-all` / `apphide-showall`. No external
   Control Center module or CCSupport dependency.

## Install

Build:

```sh
gmake clean
gmake package FINALPACKAGE=1
```

Install the resulting `.deb` with Sileo/Sileo-root or `dpkg -i`, then respring.
Pull down Control Center — the eye toggle appears at top-left.

## CLI usage

```sh
jbevasion apphide list        # list visible + hidden apps
jbevasion apphide status      # hide/visible status for each app
jbevasion apphide-all         # hide every app in /var/jb/Applications
jbevasion apphide-showall     # restore all hidden apps
jbevasion apphide <bundleid>  # hide one app
jbevasion apphide-show <id>   # restore one hidden app
jbevasion apphide-known       # hide well-known package managers
```

Hiding an app is reversible; the `.app` directory is moved back and the
vnode is restored before `uicache` runs.

## KRW API surface

The thin C wrapper in `src/krw.h` / `src/krw.c` exposes a stable interface
independent of the provided primitives. `krw.c` intentionally includes only
`primitives.h` + `kernel.h` from `include/libjailbreak/` (verbatim from
opa334/Dopamine, MIT) — the umbrella `libjailbreak.h` pulls `jbclient_xpc.h`
which requires private Theos SDK headers.

## Layout

| Path | Purpose |
|------|---------|
| `src/main.m` | CLI entry + dispatch |
| `src/apphide.c` | app stash / restore / uicache / marker persistence |
| `src/hide.c` | vnode VBAD primitives + proc platformize/csflags |
| `src/krw.c` | `krw_*` wrapper over libjailbreak |
| `src/fd_rdir.c` | `fd_rdir` chroot experiment (bindfs fake root) |
| `Tweak/Tweak.xm` | Control Center overlay eye toggle |
| `Filter.plist` | SpringBoard-only injection filter |
| `stub/` | link-time stub of libjailbreak for builds |