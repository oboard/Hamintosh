#include "napi/native_api.h"
#include <dlfcn.h>
#include <string>
#include <hilog/log.h>

namespace {
void *cacheHandle = nullptr;
void *runtimeHandle = nullptr;

napi_value Load(napi_env env, napi_callback_info info)
{
    size_t argc = 1, size = 0;
    napi_value argument;
    napi_get_cb_info(env, info, &argc, &argument, nullptr, nullptr);
    char name[64] {};
    if (argc != 1 || napi_get_value_string_utf8(env, argument, name, sizeof(name), &size) != napi_ok ||
        std::string(name) != "libhm_ioscache.so") {
        napi_throw_type_error(env, nullptr, "Expected the ioscache HSP library name");
        return nullptr;
    }
    dlerror();
    if (!cacheHandle) cacheHandle = dlopen(name, RTLD_NOW | RTLD_GLOBAL);
    if (!cacheHandle) {
        const char *error = dlerror();
        const auto message = std::string("Signed HSP cache dlopen failed: ") + (error ? error : "unknown");
        OH_LOG_Print(LOG_APP, LOG_ERROR, 0x484d, "HarmoniosLoad", "%{public}s", message.c_str());
        napi_throw_error(env, nullptr, message.c_str()); return nullptr;
    }
    Dl_info origin {};
    const auto symbol = dlsym(cacheHandle, "hm_ios_cache_descriptor_end");
    if (symbol) dladdr(symbol, &origin);
    OH_LOG_Print(LOG_APP, LOG_INFO, 0x484d, "HarmoniosLoad", "Preloaded cache ELF: %{public}s symbol=%{public}p",
        origin.dli_fname ? origin.dli_fname : "unknown", symbol);
    if (!runtimeHandle) runtimeHandle = dlopen("libharmonios.so", RTLD_NOW | RTLD_LOCAL);
    if (!runtimeHandle) {
        const char *error = dlerror();
        napi_throw_error(env, nullptr, error ? error : "Runtime dlopen failed after HSP preload");
        return nullptr;
    }
    napi_value exports;
    if (napi_load_module_with_info(env, "libharmonios.so", "fun.oboard.hamintosh/harmonios", &exports) != napi_ok) {
        napi_throw_error(env, nullptr, "Runtime N-API exports could not be loaded"); return nullptr;
    }
    OH_LOG_Print(LOG_APP, LOG_INFO, 0x484d, "HarmoniosLoad", "Loaded signed HSP cache globally before runtime");
    return exports;
}

napi_value Probe(napi_env env, napi_callback_info)
{
    // Keep this module independent of the cache ELF so dlerror survives a
    // dependency load failure in the actual runtime module.
    dlerror();
    static void *handle = nullptr;
    if (!handle) handle = dlopen("libharmonios.so", RTLD_NOW | RTLD_LOCAL);
    const char *message = handle ? "Runtime loaded; native exports unavailable" : dlerror();
    napi_value result;
    napi_create_string_utf8(env, message ? message : "Runtime load failed without dlerror",
        NAPI_AUTO_LENGTH, &result);
    return result;
}

napi_value Init(napi_env env, napi_value exports)
{
    napi_property_descriptor properties[] = {
        {"probeRuntimeLoad", nullptr, Probe, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"loadRuntime", nullptr, Load, nullptr, nullptr, nullptr, napi_default, nullptr}
    };
    napi_define_properties(env, exports, 2, properties);
    return exports;
}

napi_module module = {
    .nm_version = 1, .nm_flags = 0, .nm_filename = nullptr,
    .nm_register_func = Init, .nm_modname = "hm_load_probe", .nm_priv = nullptr, .reserved = {0}
};
}

extern "C" __attribute__((constructor)) void RegisterLoadProbe()
{
    napi_module_register(&module);
}
