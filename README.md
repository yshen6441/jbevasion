# jbevasion

面向 Dopamine（iOS 15-18，arm64/arm64e）的越狱环境隐藏控制器。

内核读写由 Dopamine 的 `libjailbreak.dylib`（`/var/jb/usr/lib/libjailbreak.dylib`）
提供，运行时通过 `-rpath /var/jb/usr/lib` 解析。`stub/` 目录保存一份**仅用于链接期**
的 dylib，让项目可以在没有真实库的主机上完成构建；stub 在设备上永远不会被执行。

## 功能

`.deb` 包内包含两个组件：

1. **`jbevasion` CLI**（setuid root 6755）—— 基于 CoreFoundation 的应用隐藏。
   把越狱应用从 `/var/jb/Applications` 移动到藏身处 `/var/jb/.apphide-stash/`，
   并将其 vnode 标记为 `VBAD`，使文件系统访问立即失败；vnode 状态持久化到
   `.hidden` 标记文件（保证跨进程重启后仍然可以恢复）；通过 `uicache -a`
   刷新 LaunchServices 并 respring。

2. **`jbevasionCC` tweak** —— 在控制中心左上角注入一个一键切换的眼睛按钮，
   通过 hook `CCUIModularControlCenterOverlayViewController -setPresentationState:`
   实现。绿色 `eye.fill` = 应用可见；橙色 `eye.slash.fill` = 应用已隐藏。
   点击会调用 `jbevasion apphide-all` / `apphide-showall`。
   不依赖任何外部控制中心模块或 CCSupport。

## 安装

构建：

```sh
gmake clean
gmake package FINALPACKAGE=1
```

安装生成的 `.deb`（Sileo/Sileo-root 或 `dpkg -i`），然后 respring。
下拉控制中心，左上角就会出现眼睛切换按钮。

## CLI 用法

```sh
jbevasion apphide list        # 列出可见 + 已隐藏的应用
jbevasion apphide status      # 每个应用的隐藏/可见状态
jbevasion apphide-all         # 隐藏 /var/jb/Applications 下所有应用
jbevasion apphide-showall     # 恢复所有隐藏应用
jbevasion apphide <bundleid>  # 隐藏单个应用
jbevasion apphide-show <id>   # 恢复单个隐藏应用
jbevasion apphide-known       # 隐藏知名包管理器
```

隐藏操作可逆：恢复时先把 `.app` 目录移回原处并还原 vnode，再运行 `uicache`。

### vhide：vnode 级痕迹隐藏

`vhide` 用 vnode VBAD 隐藏与插件运行无关的越狱痕迹（bash/sshd/frida/apt 残留等），
同时用**白名单保护**保证越狱环境不瘫痪——任何命中 `libjailbreak`、`TweakInject`、
`ellekit`/`substrate`、`jailbreakd`、`jbevasion` 自身的路径一律拒绝隐藏。

```sh
jbevasion vhide-all         # 隐藏所有目标（内置 + 配置文件）
jbevasion vhide <path>      # 隐藏单个路径（过白名单校验）
jbevasion vhide-showall     # 恢复所有隐藏 vnode
jbevasion vhide-status      # 查看保护规则 + 每个目标的 VBAD 状态
jbevasion vhide-reload      # 重载配置文件
```

#### 配置文件

路径：`/var/jb/Library/Preferences/com.jbevasion.vhide.plist`

```xml
<dict>
    <key>Targets</key>
    <array>
        <string>/var/jb/usr/bin/MyTool</string>
        <string>/var/jb/Applications/SomeApp.app</string>
    </array>
    <key>ProtectedTokens</key>
    <array>
        <string>/var/jb/usr/bin/sileo</string>
    </array>
    <key>ProtectedApps</key>
    <array>
        <string>Cydia</string>
        <string>MyApp</string>
    </array>
</dict>
```

- `Targets`：额外要隐藏的路径，`vhide-all` 时一并处理（需存在且未被保护规则拦截）
- `ProtectedTokens`：你的白名单。目标路径只要包含其中任一子串就永不隐藏。
  内置的运行时必需规则（`libjailbreak`/`TweakInject`/`ellekit`/`substrate`/`jailbreakd`/`jbevasion`）
  始终生效，不会因配置文件而解除
- `ProtectedApps`：**apphide 应用白名单**。按应用名或 Bundle ID 的子串匹配，
  `apphide-all` / `apphide-known` / `apphide <id>` 隐藏时都会跳过这些应用。
  **完全由 plist 控制，无内置白名单**——`ProtectedApps` 为空时所有应用都会被隐藏

## KRW API 接口

`src/krw.h` / `src/krw.c` 中的薄封装层提供一个独立于底层原语的稳定接口。
`krw.c` 有意只包含 `include/libjailbreak/` 中的 `primitives.h` + `kernel.h`
（内容取自 opa334/Dopamine，MIT）——伞形头 `libjailbreak.h` 会引入
`jbclient_xpc.h`，它需要私有 Theos SDK 头文件。

## 目录结构

| 路径 | 用途 |
|------|------|
| `src/main.m` | CLI 入口 + 命令分发 |
| `src/apphide.c` | 应用隐藏/恢复、uicache、标记文件持久化 |
| `src/hide.c` | vnode VBAD 原语、进程 platformize/csflags |
| `src/krw.c` | 封装 libjailbreak 的 `krw_*` 接口 |
| `src/fd_rdir.c` | `fd_rdir` chroot 实验（bindfs 假根） |
| `Tweak/Tweak.xm` | 控制中心 overlay 眼睛按钮 |
| `Filter.plist` | 仅注入 SpringBoard 的过滤配置 |
| `stub/` | 构建期 libjailbreak 的链接占位 |