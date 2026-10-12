#pragma once
#include <string>
#include <unordered_set>

namespace Config {

// Path to the allowlist file inside the Magisk module directory.
// One package name per line.  Packages listed here can see all LineageOS
// signatures normally (they are effectively exempted from all hooks).
inline constexpr const char* ALLOWLIST_PATH =
    "/data/adb/modules/lineagehide/allowlist.conf";

// Load (or reload) the allowlist from disk.  Thread-safe.
void load();

// Returns true if pkg is in the allowlist.
bool is_allowlisted(const std::string& pkg);

// Companion-side handler: receives a package name string over the socket,
// sends back 1 byte: 1 = allowlisted, 0 = not allowlisted.
void companion_handler(int client_fd);

} // namespace Config
