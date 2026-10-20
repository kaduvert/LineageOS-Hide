#include "native_hooks.h"
#include "filter_lists.h"
#include "logging.h"

#include <dlfcn.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <mutex>
#include <unordered_map>
#include <string>
#include <sys/syscall.h>
#include <unistd.h>

// Dobby public API
#include "dobby.h"

// ── helpers ─────────────────────────────────────────────────────────────────

static bool hook(void* sym, void* replace, void** backup) {
    if (!sym) return false;
    int r = DobbyHook(sym, replace, backup);
    return r == 0;
}

static void* find_sym(const char* lib, const char* sym) {
    void* h = dlopen(lib, RTLD_NOW | RTLD_NOLOAD);
    if (!h) h = dlopen(lib, RTLD_NOW);
    void* s = h ? dlsym(h, sym) : nullptr;
    if (!s) s = dlsym(RTLD_DEFAULT, sym);
    return s;
}

// ── Directory path tracking (for readdir filtering) ──────────────────────────
// We track DIR* → path so we can build full paths for readdir entries.
// The map is only populated by hook_opendir/hook_fdopendir.

namespace {
    std::mutex g_dir_mutex;
    std::unordered_map<DIR*, std::string> g_dir_paths;

    void dir_track(DIR* d, const char* path) {
        if (!d) return;
        std::lock_guard lock(g_dir_mutex);
        g_dir_paths[d] = path ? path : "";
    }
    void dir_untrack(DIR* d) {
        if (!d) return;
        std::lock_guard lock(g_dir_mutex);
        g_dir_paths.erase(d);
    }
    std::string dir_path(DIR* d) {
        std::lock_guard lock(g_dir_mutex);
        auto it = g_dir_paths.find(d);
        return it != g_dir_paths.end() ? it->second : "";
    }
}

// ── open / openat ─────────────────────────────────────────────────────────────

static int (*orig_open)(const char*, int, ...) = nullptr;
static int (*orig_openat)(int, const char*, int, ...) = nullptr;

// On AArch64, variadic args land in integer registers after the fixed args,
// so our "fixed-arg" hook captures mode_t correctly in r2/r3.
static int hook_open(const char* path, int flags, mode_t mode) {
    if (filter::is_hidden_path(path)) {
        errno = ENOENT;
        return -1;
    }
    return reinterpret_cast<int(*)(const char*, int, mode_t)>(orig_open)(path, flags, mode);
}

static int hook_openat(int dirfd, const char* path, int flags, mode_t mode) {
    if (path && filter::is_hidden_path(path)) {
        errno = ENOENT;
        return -1;
    }
    // Resolve relative paths for the filter when dirfd != AT_FDCWD
    // (rare for detection tools — skip for now)
    return reinterpret_cast<int(*)(int, const char*, int, mode_t)>(orig_openat)(
        dirfd, path, flags, mode);
}

// ── stat family ──────────────────────────────────────────────────────────────

static int (*orig_stat)(const char*, struct stat*)        = nullptr;
static int (*orig_lstat)(const char*, struct stat*)       = nullptr;
static int (*orig_fstatat)(int, const char*, struct stat*, int) = nullptr;
// stat64 variants (some apps link these explicitly)
static int (*orig_stat64)(const char*, struct stat64*)    = nullptr;
static int (*orig_lstat64)(const char*, struct stat64*)   = nullptr;

static int hook_stat(const char* path, struct stat* buf) {
    if (filter::is_hidden_path(path)) { errno = ENOENT; return -1; }
    return orig_stat(path, buf);
}
static int hook_lstat(const char* path, struct stat* buf) {
    if (filter::is_hidden_path(path)) { errno = ENOENT; return -1; }
    return orig_lstat(path, buf);
}
static int hook_fstatat(int dirfd, const char* path, struct stat* buf, int flags) {
    if (path && filter::is_hidden_path(path)) { errno = ENOENT; return -1; }
    return orig_fstatat(dirfd, path, buf, flags);
}
static int hook_stat64(const char* path, struct stat64* buf) {
    if (filter::is_hidden_path(path)) { errno = ENOENT; return -1; }
    return orig_stat64(path, buf);
}
static int hook_lstat64(const char* path, struct stat64* buf) {
    if (filter::is_hidden_path(path)) { errno = ENOENT; return -1; }
    return orig_lstat64(path, buf);
}

// ── access / faccessat ───────────────────────────────────────────────────────

static int (*orig_access)(const char*, int)              = nullptr;
static int (*orig_faccessat)(int, const char*, int, int) = nullptr;

static int hook_access(const char* path, int mode) {
    if (filter::is_hidden_path(path)) { errno = ENOENT; return -1; }
    return orig_access(path, mode);
}
static int hook_faccessat(int dirfd, const char* path, int mode, int flags) {
    if (path && filter::is_hidden_path(path)) { errno = ENOENT; return -1; }
    return orig_faccessat(dirfd, path, mode, flags);
}

// ── opendir / fdopendir / closedir ──────────────────────────────────────────

static DIR* (*orig_opendir)(const char*)  = nullptr;
static DIR* (*orig_fdopendir)(int)        = nullptr;
static int  (*orig_closedir)(DIR*)        = nullptr;

static DIR* hook_opendir(const char* path) {
    // Don't hide the directory itself — let it be opened, but filter entries.
    DIR* d = orig_opendir(path);
    if (d) dir_track(d, path);
    return d;
}
static DIR* hook_fdopendir(int fd) {
    DIR* d = orig_fdopendir(fd);
    if (d) {
        // Reconstruct path from /proc/self/fd/<fd>
        char buf[256]; char link[64];
        snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
        ssize_t n = readlink(link, buf, sizeof(buf)-1);
        if (n > 0) { buf[n]='\0'; dir_track(d, buf); }
        else dir_track(d, "");
    }
    return d;
}
static int hook_closedir(DIR* d) {
    dir_untrack(d);
    return orig_closedir(d);
}

// ── readdir / readdir64 ───────────────────────────────────────────────────────
// Strategy: skip entries whose full path (dir_path + "/" + d_name) or whose
// d_name alone contains a hidden keyword.

static struct dirent*   (*orig_readdir)(DIR*)   = nullptr;
static struct dirent64* (*orig_readdir64)(DIR*) = nullptr;

static struct dirent* hook_readdir(DIR* d) {
    std::string base = dir_path(d);
    for (;;) {
        struct dirent* e = orig_readdir(d);
        if (!e) return nullptr;
        // Quick name check
        if (filter::is_hidden_dirent_name(e->d_name)) continue;
        // Full-path check when we know the parent
        if (!base.empty()) {
            std::string full = base + "/" + e->d_name;
            if (filter::is_hidden_path(full.c_str())) continue;
        }
        return e;
    }
}
static struct dirent64* hook_readdir64(DIR* d) {
    std::string base = dir_path(d);
    for (;;) {
        struct dirent64* e = orig_readdir64(d);
        if (!e) return nullptr;
        if (filter::is_hidden_dirent_name(e->d_name)) continue;
        if (!base.empty()) {
            std::string full = base + "/" + e->d_name;
            if (filter::is_hidden_path(full.c_str())) continue;
        }
        return e;
    }
}

// ── getdents64 (syscall level) ────────────────────────────────────────────────
// Some detection tools call getdents64 directly or via syscall().
// We hook the libc wrapper __getdents64 / getdents64.

struct linux_dirent64 {
    uint64_t d_ino;
    int64_t  d_off;
    uint16_t d_reclen;
    uint8_t  d_type;
    char     d_name[];
};

static ssize_t (*orig_getdents64)(int, void*, size_t) = nullptr;

static ssize_t hook_getdents64(int fd, void* dirp, size_t count) {
    ssize_t n = orig_getdents64(fd, dirp, count);
    if (n <= 0) return n;

    // Reconstruct directory path
    char link[64], pathbuf[256]; pathbuf[0]='\0';
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t r = readlink(link, pathbuf, sizeof(pathbuf)-1);
    if (r > 0) pathbuf[r] = '\0';

    // Walk entries and compact-remove hidden ones
    char* buf  = (char*)dirp;
    char* end  = buf + n;
    char* dst  = buf;
    char* src  = buf;

    while (src < end) {
        auto* e = (linux_dirent64*)src;
        src += e->d_reclen;

        bool hide = filter::is_hidden_dirent_name(e->d_name);
        if (!hide && pathbuf[0]) {
            std::string full = std::string(pathbuf) + "/" + e->d_name;
            hide = filter::is_hidden_path(full.c_str());
        }
        if (!hide) {
            if (dst != (char*)e) memmove(dst, e, e->d_reclen);
            dst += e->d_reclen;
        }
    }
    return (ssize_t)(dst - buf);
}

// ── install all hooks ─────────────────────────────────────────────────────────

void native_hooks::install() {
    const char* libc = "libc.so";

#define HOOK(sym, replace, backup) do { \
    void* _s = find_sym(libc, sym); \
    if (!_s) { LOGW("sym not found: %s", sym); break; } \
    if (!hook(_s, (void*)(replace), (void**)&(backup))) \
        LOGW("hook failed: %s", sym); \
    else LOGD("hooked %s", sym); \
} while(0)

    HOOK("open",       hook_open,       orig_open);
    HOOK("openat",     hook_openat,     orig_openat);
    HOOK("stat",       hook_stat,       orig_stat);
    HOOK("__stat",     hook_stat,       orig_stat);        // bionic alias
    HOOK("lstat",      hook_lstat,      orig_lstat);
    HOOK("fstatat",    hook_fstatat,    orig_fstatat);
    HOOK("stat64",     hook_stat64,     orig_stat64);
    HOOK("lstat64",    hook_lstat64,    orig_lstat64);
    HOOK("access",     hook_access,     orig_access);
    HOOK("faccessat",  hook_faccessat,  orig_faccessat);
    HOOK("opendir",    hook_opendir,    orig_opendir);
    HOOK("fdopendir",  hook_fdopendir,  orig_fdopendir);
    HOOK("closedir",   hook_closedir,   orig_closedir);
    HOOK("readdir",    hook_readdir,    orig_readdir);
    HOOK("readdir64",  hook_readdir64,  orig_readdir64);
    HOOK("getdents64", hook_getdents64, orig_getdents64);

#undef HOOK

    LOGI("Native file-system hooks installed");
}
