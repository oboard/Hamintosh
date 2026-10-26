#include "napi/native_api.h"
#include <dlfcn.h>

namespace {
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
    napi_property_descriptor property = {
        "probeRuntimeLoad", nullptr, Probe, nullptr, nullptr, nullptr, napi_default, nullptr
    };
    napi_define_properties(env, exports, 1, &property);
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
