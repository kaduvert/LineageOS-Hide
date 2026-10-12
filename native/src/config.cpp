#include "config.h"
#include "logging.h"
#include <fstream>
#include <mutex>
#include <unistd.h>
#include <sys/socket.h>

namespace Config {

static std::unordered_set<std::string> g_allowlist;
static std::mutex g_mutex;
static bool g_loaded = false;

void load() {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_allowlist.clear();
    std::ifstream f(ALLOWLIST_PATH);
    if (!f.is_open()) {
        LOGI("No allowlist found at %s (all non-system apps will be hooked)", ALLOWLIST_PATH);
        g_loaded = true;
        return;
    }
    std::string line;
    while (std::getline(f, line)) {
        // Strip whitespace and skip comments
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ' || line.back() == '\t'))
            line.pop_back();
        if (line.empty() || line[0] == '#') continue;
        g_allowlist.insert(line);
        LOGD("Allowlisted: %s", line.c_str());
    }
    LOGI("Allowlist loaded: %zu entries", g_allowlist.size());
    g_loaded = true;
}

bool is_allowlisted(const std::string& pkg) {
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_allowlist.count(pkg) > 0;
}

// ---------------------------------------------------------------------------
// Companion process handler
//
// Protocol (called from preAppSpecialize via api->connectCompanion()):
//   Client sends:  uint32_t name_len  +  name_len bytes (package name UTF-8)
//   Server sends:  uint8_t result     (1 = allowlisted, 0 = not)
// ---------------------------------------------------------------------------
static void read_exact(int fd, void* buf, size_t n) {
    size_t done = 0;
    while (done < n) {
        ssize_t r = read(fd, (char*)buf + done, n - done);
        if (r <= 0) return;
        done += r;
    }
}

static void write_exact(int fd, const void* buf, size_t n) {
    size_t done = 0;
    while (done < n) {
        ssize_t r = write(fd, (const char*)buf + done, n - done);
        if (r <= 0) return;
        done += r;
    }
}

void companion_handler(int client_fd) {
    // (Re)load allowlist on each companion connection so hot-edits take effect
    load();

    uint32_t name_len = 0;
    read_exact(client_fd, &name_len, 4);
    if (name_len == 0 || name_len > 512) {
        uint8_t r = 0;
        write_exact(client_fd, &r, 1);
        return;
    }
    std::string pkg(name_len, '\0');
    read_exact(client_fd, pkg.data(), name_len);

    uint8_t result = is_allowlisted(pkg) ? 1 : 0;
    write_exact(client_fd, &result, 1);
}

} // namespace Config
