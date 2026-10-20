/*
 * java_hooks.cpp — Java-level LineageOS hiding for LineageHide Zygisk module.
 *
 * Layer 1 (RegisterNatives):
 *   java.io.UnixFileSystem.getBooleanAttributes0  → File.exists/isFile/canRead
 *   java.io.UnixFileSystem.list                   → File.list/listFiles
 *   java.io.FileInputStream.open0                 → raw file opens
 *   java.io.RandomAccessFile.open0                → raw file opens
 *
 * Layer 2 (LSPlant ART hooks via hooks.dex):
 *   ServiceManager.{getService, checkService, listServices}
 *   ApplicationPackageManager.{getPackageInfo, getApplicationInfo,
 *     getInstalledPackages, getInstalledApplications, getPackagesForUid}
 *
 * The hooks.dex Hooks class acts as LSPlant callback.
 * Each Hooks.* method calls Native.* which is registered here via
 * RegisterNatives — all filtering logic is in C++.
 */

#include "java_hooks.h"
#include "filter_lists.h"
#include "logging.h"

#include <dlfcn.h>
#include <cstring>
#include <cstdio>
#include <string>
#include <vector>
#include <unistd.h>

#include "lsplant.hpp"
#include "dobby.h"

// ── Globals ────────────────────────────────────────────────────────────────

static jmethodID g_method_invoke = nullptr;   // java.lang.reflect.Method.invoke()

// LSPlant backup methods (global refs to java.lang.reflect.Method objects)
static jobject g_bk_smGetService          = nullptr;
static jobject g_bk_smCheckService        = nullptr;
static jobject g_bk_smListServices        = nullptr;
static jobject g_bk_smListServicesInt     = nullptr;
static jobject g_bk_pmGetPkgInfo          = nullptr;
static jobject g_bk_pmGetAppInfo          = nullptr;
static jobject g_bk_pmGetInstalledPkgs    = nullptr;
static jobject g_bk_pmGetInstalledApps    = nullptr;
static jobject g_bk_pmGetPkgsForUid       = nullptr;

// RegisterNatives originals
static int     (*orig_getBoolAttr)(JNIEnv*, jobject, jobject) = nullptr;
static jobject (*orig_list)(JNIEnv*, jobject, jobject)        = nullptr;
static void    (*orig_fis_open0)(JNIEnv*, jobject, jstring, jboolean) = nullptr;
static void    (*orig_raf_open0)(JNIEnv*, jobject, jstring, jint)     = nullptr;

// ── Utility: call a backup method (LSPlant original) via reflection ────────

static jobject call_backup(JNIEnv* env, jobject backup,
                            jobject thiz,
                            const std::vector<jobject>& args) {
    if (!backup || !g_method_invoke) return nullptr;
    jclass objCls = env->FindClass("java/lang/Object");
    jobjectArray jargs = env->NewObjectArray((jsize)args.size(), objCls, nullptr);
    for (int i = 0; i < (int)args.size(); i++)
        env->SetObjectArrayElement(jargs, i, args[i]);
    jobject r = env->CallObjectMethod(backup, g_method_invoke, thiz, jargs);
    env->DeleteLocalRef(jargs);
    if (env->ExceptionCheck()) { env->ExceptionClear(); return nullptr; }
    return r;
}

// Box a jint as java.lang.Integer
static jobject box_int(JNIEnv* env, jint v) {
    jclass ic = env->FindClass("java/lang/Integer");
    jmethodID vo = env->GetStaticMethodID(ic, "valueOf", "(I)Ljava/lang/Integer;");
    return env->CallStaticObjectMethod(ic, vo, v);
}

// ── Native method implementations (io.github.lineagehide.Native) ──────────

static jobject N_smGetService(JNIEnv* env, jclass, jstring name) {
    if (!name) return nullptr;
    const char* nm = env->GetStringUTFChars(name, nullptr);
    bool hide = filter::is_hidden_service(nm);
    env->ReleaseStringUTFChars(name, nm);
    if (hide) return nullptr;
    return call_backup(env, g_bk_smGetService, nullptr, {name});
}

static jobject N_smCheckService(JNIEnv* env, jclass, jstring name) {
    if (!name) return nullptr;
    const char* nm = env->GetStringUTFChars(name, nullptr);
    bool hide = filter::is_hidden_service(nm);
    env->ReleaseStringUTFChars(name, nm);
    if (hide) return nullptr;
    return call_backup(env, g_bk_smCheckService, nullptr, {name});
}

static jobject filter_service_array(JNIEnv* env, jobject raw) {
    if (!raw) return nullptr;
    auto* arr = (jobjectArray)raw;
    jsize n = env->GetArrayLength(arr);
    std::vector<jstring> kept; kept.reserve(n);
    for (jsize i = 0; i < n; i++) {
        auto s = (jstring)env->GetObjectArrayElement(arr, i);
        if (!s) continue;
        const char* nm = env->GetStringUTFChars(s, nullptr);
        bool hide = filter::is_hidden_service(nm);
        env->ReleaseStringUTFChars(s, nm);
        if (!hide) kept.push_back(s); else env->DeleteLocalRef(s);
    }
    jclass sc = env->FindClass("java/lang/String");
    jobjectArray out = env->NewObjectArray((jsize)kept.size(), sc, nullptr);
    for (jsize i = 0; i < (jsize)kept.size(); i++)
        env->SetObjectArrayElement(out, i, kept[i]);
    return out;
}

static jobject N_smListServices(JNIEnv* env, jclass) {
    return filter_service_array(env, call_backup(env, g_bk_smListServices, nullptr, {}));
}

static jobject N_smListServicesInt(JNIEnv* env, jclass, jint prio) {
    jobject p = box_int(env, prio);
    jobject r = call_backup(env, g_bk_smListServicesInt, nullptr, {p});
    env->DeleteLocalRef(p);
    return filter_service_array(env, r);
}

static bool pkg_hidden(JNIEnv* env, jstring pkg) {
    if (!pkg) return false;
    const char* nm = env->GetStringUTFChars(pkg, nullptr);
    bool h = filter::is_hidden_package(nm);
    env->ReleaseStringUTFChars(pkg, nm);
    return h;
}

static void throw_nnfe(JNIEnv* env, jstring pkg) {
    const char* nm = env->GetStringUTFChars(pkg, nullptr);
    jclass exc = env->FindClass("android/content/pm/PackageManager$NameNotFoundException");
    if (exc) env->ThrowNew(exc, nm);
    env->ReleaseStringUTFChars(pkg, nm);
}

static jobject filter_pkg_list(JNIEnv* env, jobject list) {
    if (!list) return nullptr;
    jclass listCls = env->FindClass("java/util/List");
    jmethodID sz   = env->GetMethodID(listCls, "size",   "()I");
    jmethodID get  = env->GetMethodID(listCls, "get",    "(I)Ljava/lang/Object;");
    jmethodID rem  = env->GetMethodID(listCls, "remove", "(I)Ljava/lang/Object;");
    jclass piCls  = env->FindClass("android/content/pm/PackageInfo");
    jfieldID piPkg = env->GetFieldID(piCls, "packageName", "Ljava/lang/String;");
    jclass aiCls  = env->FindClass("android/content/pm/ApplicationInfo");
    jfieldID aiPkg = env->GetFieldID(aiCls, "packageName", "Ljava/lang/String;");
    int n = env->CallIntMethod(list, sz);
    for (int i = n-1; i >= 0; i--) {
        jobject item = env->CallObjectMethod(list, get, i);
        if (!item) continue;
        jstring name = nullptr;
        if      (env->IsInstanceOf(item, piCls)) name = (jstring)env->GetObjectField(item, piPkg);
        else if (env->IsInstanceOf(item, aiCls)) name = (jstring)env->GetObjectField(item, aiPkg);
        if (name && pkg_hidden(env, name)) env->CallObjectMethod(list, rem, i);
        env->DeleteLocalRef(item);
    }
    return list;
}

static jobject N_pmGetPackageInfo(JNIEnv* env, jclass, jobject thiz, jstring pkg, jint f) {
    if (pkg_hidden(env, pkg)) { throw_nnfe(env, pkg); return nullptr; }
    jobject fb = box_int(env, f);
    jobject r = call_backup(env, g_bk_pmGetPkgInfo, thiz, {pkg, fb});
    env->DeleteLocalRef(fb); return r;
}

static jobject N_pmGetApplicationInfo(JNIEnv* env, jclass, jobject thiz, jstring pkg, jint f) {
    if (pkg_hidden(env, pkg)) { throw_nnfe(env, pkg); return nullptr; }
    jobject fb = box_int(env, f);
    jobject r = call_backup(env, g_bk_pmGetAppInfo, thiz, {pkg, fb});
    env->DeleteLocalRef(fb); return r;
}

static jobject N_pmGetInstalledPackages(JNIEnv* env, jclass, jobject thiz, jint f) {
    jobject fb = box_int(env, f);
    jobject r = call_backup(env, g_bk_pmGetInstalledPkgs, thiz, {fb});
    env->DeleteLocalRef(fb); return filter_pkg_list(env, r);
}

static jobject N_pmGetInstalledApps(JNIEnv* env, jclass, jobject thiz, jint f) {
    jobject fb = box_int(env, f);
    jobject r = call_backup(env, g_bk_pmGetInstalledApps, thiz, {fb});
    env->DeleteLocalRef(fb); return filter_pkg_list(env, r);
}

static jobject N_pmGetPackagesForUid(JNIEnv* env, jclass, jobject thiz, jint uid) {
    jobject ub = box_int(env, uid);
    jobject r = call_backup(env, g_bk_pmGetPkgsForUid, thiz, {ub});
    env->DeleteLocalRef(ub);
    if (!r) return nullptr;
    auto* arr = (jobjectArray)r;
    jsize n = env->GetArrayLength(arr);
    std::vector<jstring> kept; kept.reserve(n);
    for (jsize i = 0; i < n; i++) {
        auto s = (jstring)env->GetObjectArrayElement(arr, i);
        if (!s) continue;
        if (!pkg_hidden(env, s)) kept.push_back(s); else env->DeleteLocalRef(s);
    }
    jclass sc = env->FindClass("java/lang/String");
    jobjectArray out = env->NewObjectArray((jsize)kept.size(), sc, nullptr);
    for (jsize i = 0; i < (jsize)kept.size(); i++)
        env->SetObjectArrayElement(out, i, kept[i]);
    return out;
}

// ── Layer 1 — RegisterNatives for java.io classes ─────────────────────────

static int hook_getBoolAttr(JNIEnv* env, jobject /*fs*/, jobject file) {
    jclass fc = env->FindClass("java/io/File");
    jmethodID gp = env->GetMethodID(fc, "getAbsolutePath", "()Ljava/lang/String;");
    jstring ps = (jstring)env->CallObjectMethod(file, gp);
    bool hide = false;
    if (ps) {
        const char* p = env->GetStringUTFChars(ps, nullptr);
        hide = filter::is_hidden_path(p);
        env->ReleaseStringUTFChars(ps, p);
    }
    if (hide) return 0;
    return orig_getBoolAttr ? orig_getBoolAttr(env, nullptr, file) : 0;
}

static jobject hook_list(JNIEnv* env, jobject fs, jobject file) {
    jobject raw = orig_list ? orig_list(env, fs, file) : nullptr;
    if (!raw) return nullptr;
    auto* arr = (jobjectArray)raw;
    jsize n = env->GetArrayLength(arr);
    std::vector<jstring> kept; kept.reserve(n);
    for (jsize i = 0; i < n; i++) {
        auto s = (jstring)env->GetObjectArrayElement(arr, i);
        if (!s) continue;
        const char* nm = env->GetStringUTFChars(s, nullptr);
        bool hide = filter::is_hidden_dirent_name(nm);
        env->ReleaseStringUTFChars(s, nm);
        if (!hide) kept.push_back(s); else env->DeleteLocalRef(s);
    }
    jclass sc = env->FindClass("java/lang/String");
    jobjectArray out = env->NewObjectArray((jsize)kept.size(), sc, nullptr);
    for (jsize i = 0; i < (jsize)kept.size(); i++)
        env->SetObjectArrayElement(out, i, kept[i]);
    return out;
}

static void hook_fis_open0(JNIEnv* env, jobject thiz, jstring path, jboolean ap) {
    if (path) {
        const char* p = env->GetStringUTFChars(path, nullptr);
        bool h = filter::is_hidden_path(p);
        env->ReleaseStringUTFChars(path, p);
        if (h) { jclass e = env->FindClass("java/io/FileNotFoundException");
                 if (e) env->ThrowNew(e, "No such file or directory"); return; }
    }
    if (orig_fis_open0) orig_fis_open0(env, thiz, path, ap);
}

static void hook_raf_open0(JNIEnv* env, jobject thiz, jstring path, jint mode) {
    if (path) {
        const char* p = env->GetStringUTFChars(path, nullptr);
        bool h = filter::is_hidden_path(p);
        env->ReleaseStringUTFChars(path, p);
        if (h) { jclass e = env->FindClass("java/io/FileNotFoundException");
                 if (e) env->ThrowNew(e, "No such file or directory"); return; }
    }
    if (orig_raf_open0) orig_raf_open0(env, thiz, path, mode);
}

static void* find_jni_sym(const char* sym) {
    static const char* libs[] = {"libopenjdk.so","libjavacore.so",nullptr};
    for (const char** l = libs; *l; l++) {
        void* h = dlopen(*l, RTLD_NOW|RTLD_NOLOAD);
        if (!h) h = dlopen(*l, RTLD_NOW);
        if (!h) continue;
        void* s = dlsym(h, sym); if (s) return s;
    }
    return dlsym(RTLD_DEFAULT, sym);
}

static void install_register_natives(JNIEnv* env) {
    orig_getBoolAttr = (int(*)(JNIEnv*,jobject,jobject))
        find_jni_sym("Java_java_io_UnixFileSystem_getBooleanAttributes0");
    orig_list = (jobject(*)(JNIEnv*,jobject,jobject))
        find_jni_sym("Java_java_io_UnixFileSystem_list");
    orig_fis_open0 = (void(*)(JNIEnv*,jobject,jstring,jboolean))
        find_jni_sym("Java_java_io_FileInputStream_open0");
    orig_raf_open0 = (void(*)(JNIEnv*,jobject,jstring,jint))
        find_jni_sym("Java_java_io_RandomAccessFile_open0");

    // UnixFileSystem
    jclass fsCls = env->FindClass("java/io/UnixFileSystem");
    if (fsCls) {
        JNINativeMethod m[] = {
            {"getBooleanAttributes0","(Ljava/io/File;)I",               (void*)hook_getBoolAttr},
            {"list",                 "(Ljava/io/File;)[Ljava/lang/String;",(void*)hook_list},
        };
        if (env->RegisterNatives(fsCls, m, 2) == 0)
            LOGD("UnixFileSystem natives replaced");
        else { env->ExceptionClear(); LOGW("UnixFileSystem RegisterNatives failed"); }
        env->DeleteLocalRef(fsCls);
    } else { env->ExceptionClear(); }

    // FileInputStream
    jclass fisCls = env->FindClass("java/io/FileInputStream");
    if (fisCls) {
        JNINativeMethod m[] = {{"open0","(Ljava/lang/String;Z)V",(void*)hook_fis_open0}};
        if (env->RegisterNatives(fisCls, m, 1) != 0) env->ExceptionClear();
        else LOGD("FileInputStream.open0 replaced");
        env->DeleteLocalRef(fisCls);
    } else { env->ExceptionClear(); }

    // RandomAccessFile
    jclass rafCls = env->FindClass("java/io/RandomAccessFile");
    if (rafCls) {
        JNINativeMethod m[] = {{"open0","(Ljava/lang/String;I)V",(void*)hook_raf_open0}};
        if (env->RegisterNatives(rafCls, m, 1) != 0) env->ExceptionClear();
        else LOGD("RandomAccessFile.open0 replaced");
        env->DeleteLocalRef(rafCls);
    } else { env->ExceptionClear(); }
}

// ── Layer 2 — LSPlant hooks ────────────────────────────────────────────────

static void lsplant_hook_one(JNIEnv* env,
                              jclass tcls, const char* tnm, const char* tsig, bool is_static,
                              jclass hcls, const char* hnm,
                              jobject* backup) {
    jmethodID tmid = is_static
        ? env->GetStaticMethodID(tcls, tnm, tsig)
        : env->GetMethodID(tcls, tnm, tsig);
    if (!tmid) { env->ExceptionClear(); LOGW("target not found: %s %s", tnm, tsig); return; }

    jmethodID hmid = env->GetStaticMethodID(hcls, hnm, tsig);
    if (!hmid) { env->ExceptionClear(); LOGW("hook method not found: %s", hnm); return; }

    jobject target   = env->ToReflectedMethod(tcls, tmid, is_static ? JNI_TRUE : JNI_FALSE);
    jobject hook_mth = env->ToReflectedMethod(hcls, hmid, JNI_TRUE);

    jobject bk = lsplant::Hook(env, target, hook_mth, hook_mth);
    if (!bk) { LOGW("LSPlant::Hook failed for %s", tnm); return; }
    *backup = env->NewGlobalRef(bk);
    LOGD("Hooked: %s", tnm);
}

static void install_lsplant_hooks(JNIEnv* env, jclass hooks_cls) {
    jclass smCls = env->FindClass("android/os/ServiceManager");
    if (smCls) {
        lsplant_hook_one(env, smCls,"getService",
            "(Ljava/lang/String;)Landroid/os/IBinder;",true,
            hooks_cls,"smGetService",  &g_bk_smGetService);
        lsplant_hook_one(env, smCls,"checkService",
            "(Ljava/lang/String;)Landroid/os/IBinder;",true,
            hooks_cls,"smCheckService",&g_bk_smCheckService);
        lsplant_hook_one(env, smCls,"listServices",
            "()[Ljava/lang/String;",true,
            hooks_cls,"smListServices",   &g_bk_smListServices);
        lsplant_hook_one(env, smCls,"listServices",
            "(I)[Ljava/lang/String;",true,
            hooks_cls,"smListServicesInt",&g_bk_smListServicesInt);
        env->DeleteLocalRef(smCls);
    } else { env->ExceptionClear(); LOGW("ServiceManager class not found"); }

    jclass pmCls = env->FindClass("android/app/ApplicationPackageManager");
    if (pmCls) {
        // Instance methods: sig must match the target exactly;
        // LSPlant prepends 'this' to the callback automatically for instance methods
        lsplant_hook_one(env,pmCls,"getPackageInfo",
            "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;",false,
            hooks_cls,"pmGetPackageInfo",&g_bk_pmGetPkgInfo);
        lsplant_hook_one(env,pmCls,"getApplicationInfo",
            "(Ljava/lang/String;I)Landroid/content/pm/ApplicationInfo;",false,
            hooks_cls,"pmGetApplicationInfo",&g_bk_pmGetAppInfo);
        lsplant_hook_one(env,pmCls,"getInstalledPackages",
            "(I)Ljava/util/List;",false,
            hooks_cls,"pmGetInstalledPackages",&g_bk_pmGetInstalledPkgs);
        lsplant_hook_one(env,pmCls,"getInstalledApplications",
            "(I)Ljava/util/List;",false,
            hooks_cls,"pmGetInstalledApps",&g_bk_pmGetInstalledApps);
        lsplant_hook_one(env,pmCls,"getPackagesForUid",
            "(I)[Ljava/lang/String;",false,
            hooks_cls,"pmGetPackagesForUid",&g_bk_pmGetPkgsForUid);
        env->DeleteLocalRef(pmCls);
    } else { env->ExceptionClear(); LOGW("ApplicationPackageManager not found"); }
}

// ── Main entry ────────────────────────────────────────────────────────────

void java_hooks::install(JNIEnv* env, const char* dex_path) {
    // Layer 1 is independent of LSPlant
    install_register_natives(env);

    // Init LSPlant using Dobby as the inline-hook backend
    lsplant::InitInfo info{
        .inline_hooker = [](void* target, void* hooker) -> void* {
            void* backup = nullptr;
            if (DobbyHook(target, hooker, &backup) != 0) return nullptr;
            return backup;
        },
        .inline_unhooker = [](void* func) -> bool {
            return DobbyDestroy(func) == 0;
        },
        .art_symbol_resolver = [](std::string_view sym) -> void* {
            static void* la = dlopen("libart.so", RTLD_NOW|RTLD_NOLOAD);
            return la ? dlsym(la, std::string(sym).c_str()) : nullptr;
        },
        .art_symbol_prefix_resolver = [](std::string_view) -> void* { return nullptr; },
    };
    if (!lsplant::Init(env, info)) {
        LOGE("LSPlant init failed — service/package hooks skipped");
        return;
    }

    // Load hooks.dex
    FILE* fp = fopen(dex_path, "rb");
    if (!fp) { LOGE("hooks.dex not found at %s", dex_path); return; }
    fseek(fp,0,SEEK_END); long dsz=ftell(fp); fseek(fp,0,SEEK_SET);
    std::vector<char> dbuf(dsz);
    fread(dbuf.data(),1,dsz,fp); fclose(fp);

    // Wrap as ByteBuffer
    jclass bbCls = env->FindClass("java/nio/ByteBuffer");
    jmethodID wrap = env->GetStaticMethodID(bbCls,"wrap","([B)Ljava/nio/ByteBuffer;");
    jbyteArray arr = env->NewByteArray(dsz);
    env->SetByteArrayRegion(arr,0,dsz,(const jbyte*)dbuf.data());
    jobject bb = env->CallStaticObjectMethod(bbCls,wrap,arr);
    env->DeleteLocalRef(arr);

    // Get app ClassLoader
    jclass threadCls = env->FindClass("java/lang/Thread");
    jobject thread = env->CallStaticObjectMethod(threadCls,
        env->GetStaticMethodID(threadCls,"currentThread","()Ljava/lang/Thread;"));
    jobject parent_cl = env->CallObjectMethod(thread,
        env->GetMethodID(threadCls,"getContextClassLoader","()Ljava/lang/ClassLoader;"));
    env->DeleteLocalRef(thread);

    // Load via InMemoryDexClassLoader (API 26+) or DexClassLoader fallback
    jclass clsLoader = nullptr;
    jclass imdc = env->FindClass("dalvik/system/InMemoryDexClassLoader");
    if (imdc) {
        clsLoader = (jclass)env->NewObject(imdc,
            env->GetMethodID(imdc,"<init>",
                "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V"),
            bb, parent_cl);
    } else {
        env->ExceptionClear();
        // Write temp file
        char tmp[64]; snprintf(tmp,sizeof(tmp),"/data/local/tmp/lh_%d.dex",getpid());
        FILE* tf = fopen(tmp,"wb");
        if (tf) { fwrite(dbuf.data(),1,dsz,tf); fclose(tf); }
        jclass dcl = env->FindClass("dalvik/system/DexClassLoader");
        clsLoader = (jclass)env->NewObject(dcl,
            env->GetMethodID(dcl,"<init>",
                "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V"),
            env->NewStringUTF(tmp), env->NewStringUTF("/data/local/tmp"),
            nullptr, parent_cl);
        unlink(tmp);
    }
    env->DeleteLocalRef(bb);

    if (!clsLoader || env->ExceptionCheck()) {
        env->ExceptionClear(); LOGE("Failed to create DEX class loader"); return;
    }

    // loadClass helper
    jmethodID loadCls = env->GetMethodID(env->FindClass("java/lang/ClassLoader"),
        "loadClass","(Ljava/lang/String;)Ljava/lang/Class;");

    auto load = [&](const char* cn) -> jclass {
        jstring n = env->NewStringUTF(cn);
        jclass c = (jclass)env->CallObjectMethod((jobject)clsLoader, loadCls, n);
        env->DeleteLocalRef(n);
        if (env->ExceptionCheck()) { env->ExceptionClear(); return nullptr; }
        return c;
    };

    jclass nativeCls = load("io.github.lineagehide.Native");
    jclass hooksCls  = load("io.github.lineagehide.Hooks");
    if (!nativeCls || !hooksCls) { LOGE("Failed to load hook classes"); return; }

    // Cache Method.invoke
    jclass methCls = env->FindClass("java/lang/reflect/Method");
    g_method_invoke = env->GetMethodID(methCls,"invoke",
        "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;");

    // Register C++ implementations for Native.*
    JNINativeMethod nm[] = {
        {"smGetService",           "(Ljava/lang/String;)Ljava/lang/Object;",              (void*)N_smGetService},
        {"smCheckService",         "(Ljava/lang/String;)Ljava/lang/Object;",              (void*)N_smCheckService},
        {"smListServices",         "()Ljava/lang/Object;",                                (void*)N_smListServices},
        {"smListServicesInt",      "(I)Ljava/lang/Object;",                               (void*)N_smListServicesInt},
        {"pmGetPackageInfo",       "(Ljava/lang/Object;Ljava/lang/String;I)Ljava/lang/Object;",(void*)N_pmGetPackageInfo},
        {"pmGetApplicationInfo",   "(Ljava/lang/Object;Ljava/lang/String;I)Ljava/lang/Object;",(void*)N_pmGetApplicationInfo},
        {"pmGetInstalledPackages", "(Ljava/lang/Object;I)Ljava/lang/Object;",             (void*)N_pmGetInstalledPackages},
        {"pmGetInstalledApps",     "(Ljava/lang/Object;I)Ljava/lang/Object;",             (void*)N_pmGetInstalledApps},
        {"pmGetPackagesForUid",    "(Ljava/lang/Object;I)Ljava/lang/Object;",             (void*)N_pmGetPackagesForUid},
    };
    if (env->RegisterNatives(nativeCls, nm, sizeof(nm)/sizeof(nm[0])) != 0) {
        env->ExceptionClear();
        LOGE("RegisterNatives failed for Native class");
        return;
    }
    LOGD("Native JNI methods registered");

    // Layer 2: install LSPlant hooks
    install_lsplant_hooks(env, hooksCls);
    LOGI("Java hooks installed");
}
