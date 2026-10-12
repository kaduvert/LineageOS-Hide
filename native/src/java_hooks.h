#pragma once
#include <jni.h>

namespace java_hooks {

// Install all Java-level hooks.
// Must be called from postAppSpecialize with a valid JNIEnv.
// dex_path: absolute path to hooks.dex inside the module directory.
void install(JNIEnv* env, const char* dex_path);

} // namespace java_hooks
