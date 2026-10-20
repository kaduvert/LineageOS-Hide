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
    -Wl,-z,norelro          # avoid RELRO so the GOT stays writable for hooks
    -Wl,--hash-style=gnu
)

# ── Zygisk API (header-only) ─────────────────────────────────────────────────
# From: https://github.com/topjohnwu/zygisk-module-sample (submodule).
# The header lives at module/jni/zygisk.hpp; both that path and the submodule
# root are on the include path so either layout works.
add_library(zygisk INTERFACE)
target_include_directories(zygisk INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/libs/zygisk
    ${CMAKE_CURRENT_SOURCE_DIR}/libs/zygisk/module/jni
)

# ── Dobby (inline-hook engine) ───────────────────────────────────────────────
# git submodule: https://github.com/jmpews/Dobby
# We link dobby_static: a Zygisk module ships exactly one <ABI>.so, so a
# runtime dependency on libdobby.so is not an option.
set(DOBBY_DEBUG OFF CACHE BOOL "" FORCE)
add_subdirectory(libs/dobby EXCLUDE_FROM_ALL)

# ── LSPlant (ART method hooking) ─────────────────────────────────────────────
# git submodule: https://github.com/LSPosed/LSPlant — pinned to v6.4.
# NOTE: LSPlant master has migrated to C++23 modules (import std; etc.) and can
# no longer be compiled as a plain translation unit; keep the submodule pinned
# to the v6.4 tag.
#
# LSPlant needs its dex_builder companion (slicer + parallel-hashmap), which is
# a recursive submodule at lsplant/src/main/jni/external/dex_builder.
set(LSPLANT_JNI_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libs/lsplant/lsplant/src/main/jni)
set(DEX_BUILDER_DIR ${LSPLANT_JNI_DIR}/external/dex_builder)

add_library(dex_builder STATIC
    ${DEX_BUILDER_DIR}/dex_builder.cc
    ${DEX_BUILDER_DIR}/dex_helper.cc
    ${DEX_BUILDER_DIR}/slicer/reader.cc
    ${DEX_BUILDER_DIR}/slicer/writer.cc
    ${DEX_BUILDER_DIR}/slicer/dex_ir.cc
    ${DEX_BUILDER_DIR}/slicer/common.cc
    ${DEX_BUILDER_DIR}/slicer/dex_format.cc
    ${DEX_BUILDER_DIR}/slicer/dex_utf8.cc
    ${DEX_BUILDER_DIR}/slicer/dex_bytecode.cc
    ${DEX_BUILDER_DIR}/slicer/sha1.cpp
)
target_include_directories(dex_builder PUBLIC
    ${DEX_BUILDER_DIR}/include
    ${DEX_BUILDER_DIR}/external/parallel_hashmap
)
target_link_libraries(dex_builder PUBLIC z log)

add_library(lsplant STATIC
    ${LSPLANT_JNI_DIR}/lsplant.cc
)
target_include_directories(lsplant PUBLIC
    ${LSPLANT_JNI_DIR}/include
    ${LSPLANT_JNI_DIR}
)
target_link_libraries(lsplant PUBLIC dex_builder log)

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
    ${LSPLANT_JNI_DIR}/include
)

target_link_libraries(lineagehide PRIVATE
    zygisk
    dobby_static
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
# Magisk Zygisk modules expect the .so at zygisk/<ABI>.so (no "lib" prefix)
set_target_properties(lineagehide PROPERTIES
    PREFIX ""
    OUTPUT_NAME "${ANDROID_ABI}"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/zygisk"
)
