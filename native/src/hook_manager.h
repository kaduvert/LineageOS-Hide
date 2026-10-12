#pragma once
#include <jni.h>

namespace hook_manager {
// Called once from postAppSpecialize.
// Installs both native (libc) and Java-level hooks.
void install(JNIEnv* env, const char* module_dir);
}
