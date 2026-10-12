#include "hook_manager.h"
#include "native_hooks.h"
#include "java_hooks.h"
#include "logging.h"
#include <string>

void hook_manager::install(JNIEnv* env, const char* module_dir) {
    LOGI("Installing hooks (module_dir=%s)", module_dir);

    // 1. libc file-system hooks — broadest coverage, no Java dependency
    native_hooks::install();

    // 2. Java-level hooks (RegisterNatives + LSPlant via hooks.dex)
    std::string dex = std::string(module_dir) + "/assets/hooks.dex";
    java_hooks::install(env, dex.c_str());

    LOGI("Hook installation complete");
}
