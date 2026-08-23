# jbevasion

Jailbreak environment hiding controller for Dopamine (iOS 15-18, arm64/arm64e).

Kernel read/write is provided by Dopamine's `libjailbreak.dylib`
(`/var/jb/usr/lib/libjailbreak.dylib`), resolved at runtime through
`-rpath /var/jb/usr/lib`. The `stub/` directory holds a **link-time only**
dylib so the project builds on hosts without the real library; the stub is
never executed on device.

## Build

```sh
gmake clean
gmake package FINALPACKAGE=1
```

Install the resulting `.deb` with Sileo/Sileo-root or `dpkg -i`, then run:

```sh
jbevasion probe
```

## Current state

- `probe` — verifies the KRW primitives end to end (kbase/slide, mach header read, `proc` self, fd→vnode).
- `vnode <path>` — resolves a path to its vnode and prints flags/counters.

More hide modules (filesystem, process, URL scheme, fork probe, …) are next.

## KRW API surface

See `include/libjailbreak/` (verbatim from opa334/Dopamine, MIT). The thin
C wrapper in `src/krw.h` / `src/krw.c` exposes a stable interface independent
of the provided primitives.