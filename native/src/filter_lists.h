#pragma once
#include <string_view>
#include <array>
#include <cstring>

namespace filter {

// ---------------------------------------------------------------------------
// Services — any service whose name equals one of these or contains "lineage"
// is nulled out from getService/checkService and stripped from listServices.
// ---------------------------------------------------------------------------
inline constexpr std::array HIDDEN_SERVICES {
    std::string_view{"profile"},
    std::string_view{"lineageglobalactions"},
    std::string_view{"lineagehardware"},
    std::string_view{"lineagehealth"},
    std::string_view{"lineagelivedisplay"},
    std::string_view{"lineagetrust"},
    std::string_view{"vendor.lineage.health.IChargingControl/default"},
    std::string_view{"vendor.lineage.health.IFastCharge/default"},
    std::string_view{"vendor.lineage.livedisplay.IPictureAdjustment/default"},
    std::string_view{"vendor.lineage.livedisplay.IPictureAdjustment"},
    std::string_view{"vendor.lineage.trust.ITrustInterface/default"},
    std::string_view{"vendor.lineage.hardware.IGpuService/default"},
};

// ---------------------------------------------------------------------------
// Packages — hide from PackageManager queries
// ---------------------------------------------------------------------------
inline constexpr std::array HIDDEN_PACKAGES {
    std::string_view{"org.lineageos.jelly"},
    // add more explicit entries here if a detector queries them by name
};

// ---------------------------------------------------------------------------
// Exact file/directory paths that must vanish from all file-system calls
// ---------------------------------------------------------------------------
inline constexpr std::array HIDDEN_EXACT_PATHS {
    // Framework JARs / compiled artifacts
    std::string_view{"/system/framework/org.lineageos.platform-res.apk"},
    std::string_view{"/system/framework/org.lineageos.platform.jar"},
    std::string_view{"/system/framework/oat/arm64/org.lineageos.platform.vdex"},
    std::string_view{"/system/framework/oat/arm64/org.lineageos.platform.odex"},
    // Custom ROM OTA hook directory
    std::string_view{"/system/addon.d"},
    // SELinux CIL policy files scanned for "hal_lineage" / ".lineage"
    std::string_view{"/vendor/etc/selinux/vendor_sepolicy.cil"},
    std::string_view{"/system_ext/etc/selinux/system_ext_sepolicy.cil"},
    std::string_view{"/product/etc/selinux/product_sepolicy.cil"},
    std::string_view{"/vendor/etc/selinux/vendor_file_contexts"},
    // LineageOS-specific init scripts
    std::string_view{"/system_ext/etc/init/init.lineage-system_ext.rc"},
    std::string_view{"/system/system_ext/etc/init/init.lineage-system_ext.rc"},
};

// ---------------------------------------------------------------------------
// Substring keywords — any absolute path or entry name containing any of
// these tokens is hidden.  Catches all ~40 auto-generated RRO overlays
// (…__lineage_sargo__auto_generated_rro_product.apk etc.) without needing
// an exhaustive list.
// ---------------------------------------------------------------------------
inline constexpr std::array HIDDEN_PATH_KEYWORDS {
    std::string_view{"lineage"},
    std::string_view{"addon.d"},
};

// ---------------------------------------------------------------------------
// Predicates
// ---------------------------------------------------------------------------

inline bool is_hidden_service(const char* name) {
    if (!name) return false;
    for (auto& s : HIDDEN_SERVICES)
        if (s == name) return true;
    return strstr(name, "lineage") != nullptr;
}

inline bool is_hidden_package(const char* pkg) {
    if (!pkg) return false;
    for (auto& p : HIDDEN_PACKAGES)
        if (p == pkg) return true;
    // Prefix match
    return strncmp(pkg, "org.lineageos.", 14) == 0 ||
           strncmp(pkg, "lineageos.", 10) == 0;
}

inline bool is_hidden_path(const char* path) {
    if (!path) return false;
    for (auto& e : HIDDEN_EXACT_PATHS)
        if (e == path) return true;
    // Prefix check: /system/addon.d/anything
    if (strncmp(path, "/system/addon.d/", 16) == 0) return true;
    // Keyword scan
    for (auto& kw : HIDDEN_PATH_KEYWORDS)
        if (strstr(path, kw.data())) return true;
    return false;
}

// Lighter check used by readdir — just the entry d_name
inline bool is_hidden_dirent_name(const char* name) {
    if (!name || name[0] == '\0' || name[0] == '.') return false;
    for (auto& kw : HIDDEN_PATH_KEYWORDS)
        if (strstr(name, kw.data())) return true;
    return false;
}

} // namespace filter
