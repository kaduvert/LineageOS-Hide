#pragma once
namespace native_hooks {
// Install all libc-level hooks (open, stat, access, readdir family).
// Must be called once per process from postAppSpecialize.
void install();
}
