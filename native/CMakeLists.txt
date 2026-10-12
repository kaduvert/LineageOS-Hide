cmake_minimum_required(VERSION 3.22.1)
project(LineageHide VERSION 1.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Build options ────────────────────────────────────────────────────────────
# Aggressive size reduction + hardening
add_compile_options(
    -fvisibility=hidden
    -ffunction-sections -fdata-sections
    -O2
    -Wall -Wextra
    -fstack-protector-strong
)
add_link_options(
    -Wl,--gc-sections
    -Wl,-z,norelro          # avoid PLT entries for our own exports
    -Wl,--hash-style=gnu
)

# ── Zygisk API (header-only) ─────────────────────────────────────────────────
# Clone from: https://github.com/topjohnwu/zygisk-module-sample
# and copy zygisk.hpp here, or add the repo as a submodule.
add_library(zygisk INTERFACE)
target_include_directories(zygisk INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/libs/zygisk)

# ── Dobby (inline-hook engine) ───────────────────────────────────────────────
# git submodule add https://github.com/jmpews/Dobby libs/dobby
set(DOBBY_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(DOBBY_DEBUG        OFF CACHE BOOL "" FORCE)
add_subdirectory(libs/dobby EXCLUDE_FROM_ALL)

# ── LSPlant (ART method hooking) ─────────────────────────────────────────────
# git submodule add https://github.com/LSPosed/LSPlant libs/lsplant
# LSPlant needs lsplant.hpp (include) and lsplant.cpp (source)
add_library(lsplant STATIC
    libs/lsplant/lsplant/src/main/jni/lsplant.cpp
)
target_include_directories(lsplant PUBLIC
    libs/lsplant/lsplant/src/main/jni/include
    libs/lsplant/lsplant/src/main/jni
)
target_link_libraries(lsplant PUBLIC dobby log)
target_compile_options(lsplant PRIVATE -fvisibility=default)

# ── Main module .so ──────────────────────────────────────────────────────────
add_library(lineagehide SHARED
    src/main.cpp
    src/hook_manager.cpp
    src/native_hooks.cpp
    src/java_hooks.cpp
    src/config.cpp
)

target_include_directories(lineagehide PRIVATE
    src
    libs/dobby/include
    libs/lsplant/lsplant/src/main/jni/include
)

target_link_libraries(lineagehide PRIVATE
    zygisk
    dobby
    lsplant
    log
    android
)

# Strip debug symbols from the final .so
if(CMAKE_BUILD_TYPE STREQUAL "Release" OR NOT DEFINED CMAKE_BUILD_TYPE)
    add_custom_command(TARGET lineagehide POST_BUILD
        COMMAND ${CMAKE_STRIP} --strip-unneeded
            $<TARGET_FILE:lineagehide>
        COMMENT "Stripping lineagehide.so"
    )
endif()

# ── Output naming ────────────────────────────────────────────────────────────
# Magisk Zygisk modules expect the .so at zygisk/<ABI>.so
set_target_properties(lineagehide PROPERTIES
    OUTPUT_NAME "${ANDROID_ABI}"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/zygisk"
)
