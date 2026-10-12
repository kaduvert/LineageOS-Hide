# LineageHide — Zygisk module

Hides LineageOS-specific runtime signatures from non-system apps without
touching any system files or removing any services.  System apps (uid < 10000)
always see the full system.

---

## What it hides

| Detection vector | Method | Source |
|---|---|---|
| `ServiceManager.getService("lineagehardware")` etc. | LSPlant hook on `ServiceManager.{getService,checkService,listServices}` | Java layer |
| `ServiceManager.listServices()` — lineage entries | same hook, filtered list | Java layer |
| `/system/addon.d`, `/system/addon.d/50-lineage.sh` | libc `open/stat/access` + `readdir` Dobby hook | Native layer |
| `/system/framework/org.lineageos.platform*.{jar,apk,odex,vdex}` | same | Native layer |
| `/system_ext/etc/init/init.lineage-system_ext.rc` | same | Native layer |
| `/vendor/etc/selinux/vendor_sepolicy.cil` (295× "lineage") | same | Native layer |
| `/system_ext/etc/selinux/system_ext_sepolicy.cil` | same | Native layer |
| `/product/etc/selinux/product_sepolicy.cil` | same | Native layer |
| `/vendor/etc/selinux/vendor_file_contexts` | same | Native layer |
| `/product/overlay/*lineage*.apk` (all ~30 RRO overlays) | `readdir` + name keyword filter | Native layer |
| `/vendor/overlay/*lineage*.apk` | same | Native layer |
| `ANetworkSession::threadLoopEv` ELF scan of `libstagefright.so` | `FileInputStream.open0` + `RandomAccessFile.open0` RegisterNatives | Java layer |
| `getInstalledPackages()` → `org.lineageos.jelly` | LSPlant hook on `ApplicationPackageManager` | Java layer |
| `getPackageInfo("org.lineageos.jelly")` | same | Java layer |
| `File.exists("/system/addon.d")` etc. | `UnixFileSystem.getBooleanAttributes0` RegisterNatives | Java layer |
| `File.list("/product/overlay")` | `UnixFileSystem.list` RegisterNatives | Java layer |

**Not currently hidden** (low signal, complex to intercept safely):
- `__system_property_get` native calls for build props  
  → use a separate Magisk module to spoof props (e.g. MagiskHide Props Config)
- `Runtime.exec("getprop")` — shell-based prop scan
- Native `ioctl(BINDER_WRITE_READ)` — direct Binder syscall callers  
  (all known detection SDKs go through the Java layer or libc)

---

## Build

### Prerequisites

```
git clone --recurse-submodules https://github.com/you/LineageHide
```

Or after a plain clone:
```
git submodule update --init --recursive
```

Required tools:
- Android NDK r25c+ (`ANDROID_NDK_HOME` or `NDK` env var)
- CMake 3.22+, Ninja
- Python 3.6+ (for `tools/gen_dex.py`)

After submodules are initialised, copy `zygisk.hpp` into place:
```bash
cp native/libs/zygisk/module/jni/zygisk.hpp native/libs/zygisk/zygisk.hpp
```

### One command

```bash
./build.sh           # produces lineagehide.zip  (Release)
./build.sh Debug     # debug build
```

The script:
1. Runs `tools/gen_dex.py` → `module/assets/hooks.dex`
2. Builds `lineagehide.so` for arm64-v8a, armeabi-v7a, x86_64, x86
3. Packages everything into `lineagehide.zip`

Flash `lineagehide.zip` via Magisk → reboot.

---

## Allowlist

Apps listed in `/data/adb/modules/lineagehide/allowlist.conf` are **not**
hooked — they see the full LineageOS environment.  One package name per line;
lines starting with `#` are comments.

```
# /data/adb/modules/lineagehide/allowlist.conf
com.termux
# org.example.myapp
```

Changes take effect immediately for new app launches (no reboot needed) because
the companion process re-reads the file on every connection.

---

## Architecture

```
lineagehide.zip
├── zygisk/
│   ├── arm64-v8a.so      ← loaded by Zygisk into every app process
│   ├── armeabi-v7a.so
│   ├── x86_64.so
│   └── x86.so
├── assets/
│   └── hooks.dex         ← DEX with Hooks + Native stub classes
├── module.prop
└── allowlist.conf        ← created on install, empty by default
```

### Hook layers

**Layer 1 — Native libc (Dobby inline hooks)**  
Hooks `open`, `openat`, `stat`, `lstat`, `fstatat`, `access`, `faccessat`,
`opendir`, `fdopendir`, `closedir`, `readdir`, `readdir64`, `getdents64`
in `libc.so`.  Returns `ENOENT` for hidden paths; filters hidden names from
directory reads.  Covers NDK callers that bypass the Java layer entirely.

**Layer 2 — RegisterNatives replacement**  
Replaces `java.io.UnixFileSystem.getBooleanAttributes0` and `.list` (backing
`File.exists/isFile/isDir/canRead/list/listFiles`), plus
`FileInputStream.open0` and `RandomAccessFile.open0`.  Backs up the originals
via `dlsym` and calls through for non-hidden paths.

**Layer 3 — LSPlant ART hooks via hooks.dex**  
Hooks `ServiceManager.{getService,checkService,listServices}` and
`ApplicationPackageManager.{getPackageInfo,getApplicationInfo,
getInstalledPackages,getInstalledApplications,getPackagesForUid}`.

The `hooks.dex` contains two classes:
- `io.github.lineagehide.Native` — all methods declared `native`; their
  implementations are registered by the `.so` via `RegisterNatives` at hook
  install time (filtering logic lives entirely in C++).
- `io.github.lineagehide.Hooks` — thin wrappers used as LSPlant callback
  targets; each method just calls `Native.<same_method>`.

Backup methods returned by `LSPlant::Hook` are stored as JNI global refs.
When a hooked method is not hidden, the C++ implementation calls the backup
via `Method.invoke()` (reflection).

---

## Detected by — not yet hidden

The module targets the two specific detection outputs shown in the original
report.  If a new detection SDK finds a new signal, the relevant filter list
in `filter_lists.h` can be extended and the module rebuilt without changing
any hook machinery.
