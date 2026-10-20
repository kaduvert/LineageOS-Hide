/*
 * LineageHide — Zygisk module
 *
 * Hides LineageOS-specific runtime signatures (services, packages,
 * files, SELinux artefacts, ELF symbols) from non-system, non-allowlisted
 * apps.  System apps (uid < 10000) are never affected.
 */

#include <sys/types.h>   // dev_t/ino_t used by zygisk.hpp (must come first)
#include "zygisk.hpp"
#include "hook_manager.h"
#include "config.h"
#include "logging.h"

#include <cstring>
#include <string>
#include <unistd.h>
#include <sys/socket.h>

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

// ── Companion process ────────────────────────────────────────────────────────
// Runs as root; answers allowlist queries from the module.

static void companion_main(int client_fd) {
    Config::companion_handler(client_fd);
}

// ── Module class ─────────────────────────────────────────────────────────────

class LineageHideModule : public zygisk::ModuleBase {
public:
    void onLoad(Api* api, JNIEnv* env) override {
        this->api = api;
        this->env = env;
    }

    // preAppSpecialize: we only have the package name here (not the JVM).
    // Ask the companion whether this package is allowlisted.
    void preAppSpecialize(AppSpecializeArgs* args) override {
        if (!args || !args->nice_name) {
            skip = true;
            return;
        }

        const char* raw = env->GetStringUTFChars(args->nice_name, nullptr);
        if (raw) { pkg = raw; env->ReleaseStringUTFChars(args->nice_name, raw); }
        uid = args->uid;

        // System processes never get hooked
        if (uid < 10000) { skip = true; return; }

        // Ask companion whether this package is allowlisted
        int companion = api->connectCompanion();
        if (companion < 0) {
            // Companion unavailable — default to hooking (safer)
            skip = false;
        } else {
            // Send package name
            uint32_t len = (uint32_t)pkg.size();
            write(companion, &len, 4);
            write(companion, pkg.data(), len);
            // Receive answer
            uint8_t result = 0;
            read(companion, &result, 1);
            close(companion);
            if (result == 1) {
                LOGI("%s is allowlisted — skipping hooks", pkg.c_str());
                skip = true;
            }
        }
    }

    void postAppSpecialize(const AppSpecializeArgs*) override {
        if (skip) {
            // Free the library — no hooks needed for this process
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        LOGI("Hiding LineageOS from: %s (uid=%d)", pkg.c_str(), uid);

        // Module directory (holds assets/hooks.dex and allowlist.conf)
        static constexpr const char* MODULE_DIR = "/data/adb/modules/lineagehide";

        hook_manager::install(env, MODULE_DIR);
    }

    // System server is never hooked
    void preServerSpecialize(ServerSpecializeArgs*) override {
        api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

private:
    Api*    api  = nullptr;
    JNIEnv* env  = nullptr;
    std::string pkg;
    int     uid  = 0;
    bool    skip = false;
};

REGISTER_ZYGISK_MODULE(LineageHideModule)
REGISTER_ZYGISK_COMPANION(companion_main)
