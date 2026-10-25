#include "napi/native_api.h"
#include "harmonios.h"
#include "execution_probe.h"
#include "harmony_surface.h"
#include <hilog/log.h>
#include <memory>
#include <string>
#include <fstream>
#include <vector>
#ifdef HM_HAS_AOT_TARGET
#include "packed_target.h"
#endif

namespace {
struct DiagnosticsWork {
    napi_async_work work = nullptr;
    napi_deferred deferred = nullptr;
    std::string directory, executable, sysroot, report;
    HmProbeResult raw, macho, packaged;
    HmProbeResult target;
    HmProbeResult darwin;
    HmProbeResult pac;
    HmProbeResult bootStack;
    HmProbeResult rebase;
    HmProbeResult dyld;
};

napi_value Text(napi_env env, const std::string &text)
{
    napi_value value;
    napi_create_string_utf8(env, text.c_str(), text.size(), &value);
    return value;
}

void SetText(napi_env env, napi_value object, const char *name, const std::string &text)
{
    napi_set_named_property(env, object, name, Text(env, text));
}

void SetInt(napi_env env, napi_value object, const char *name, int number)
{
    napi_value value;
    napi_create_int32(env, number, &value);
    napi_set_named_property(env, object, name, value);
}

void SetBool(napi_env env, napi_value object, const char *name, bool state)
{
    napi_value value;
    napi_get_boolean(env, state, &value);
    napi_set_named_property(env, object, name, value);
}

napi_value ProbeObject(napi_env env, const HmProbeResult &probe)
{
    napi_value value;
    napi_create_object(env, &value);
    SetText(env, value, "mode", probe.mode);
    SetText(env, value, "status", probe.status);
    SetText(env, value, "detail", probe.detail);
    SetInt(env, value, "value", probe.value);
    SetInt(env, value, "errno", probe.error);
    SetInt(env, value, "signal", probe.signal);
    SetInt(env, value, "traps", probe.traps);
    SetText(env, value, "faultPc", std::to_string(probe.faultPc));
    SetText(env, value, "faultAddress", std::to_string(probe.faultAddress));
    SetText(env, value, "syscall", std::to_string(probe.syscall));
    SetText(env, value, "requestPath", probe.requestPath);
    SetText(env, value, "message", probe.message);
    SetText(env, value, "unsupportedCalls", probe.unsupportedCalls);
    SetBool(env, value, "selfRebaseWitness", probe.selfRebaseWitness);
    SetBool(env, value, "dyldEntered", probe.dyldEntered);
    SetBool(env, value, "appExecuted", probe.appExecuted);
    return value;
}

napi_value RuntimeVerificationObject(napi_env env, const DiagnosticsWork &state)
{
    napi_value value;
    napi_create_object(env, &value);
    const bool attempted = state.target.status == "mapped-awaiting-dyld" || !state.dyld.status.empty();
    const bool verified = state.dyld.dyldEntered;
    SetBool(env, value, "runtimeExecutionAttempted", attempted);
    SetBool(env, value, "dyldEntered", verified);
    SetBool(env, value, "runtimeExecutionVerified", verified);
    SetBool(env, value, "appExecuted", state.dyld.appExecuted);
    SetText(env, value, "targetImageStatus", state.target.status);
    SetText(env, value, "runtimeStatus", state.dyld.status);
    SetInt(env, value, "traps", state.dyld.traps);
    SetInt(env, value, "signal", state.dyld.signal);
    SetText(env, value, "faultPc", std::to_string(state.dyld.faultPc));
    SetText(env, value, "faultAddress", std::to_string(state.dyld.faultAddress));
    return value;
}

void Execute(napi_env, void *data)
{
    auto *state = static_cast<DiagnosticsWork *>(data);
    state->packaged = hm_packaged_execution_probe();
    state->darwin = hm_darwin_execution_probe();
    state->pac = hm_pac_execution_probe();
    if (state->pac.status == "passed") state->rebase = hm_authenticated_rebase_probe();
    else state->rebase.status = "requires-pac-support";
    state->raw = hm_run_probe(state->directory + "/execution_probe.bin", false);
    state->macho = hm_run_probe(state->directory + "/return42.macho", true);
    state->target.mode = "mach-o-aot-image";
#ifdef HM_HAS_AOT_TARGET
    state->bootStack = hm_boot_stack_execution_probe(hm_target_image);
    std::ifstream input(state->executable, std::ios::binary | std::ios::ate);
    if (input && input.tellg() > 0 && input.tellg() <= 512 * 1024 * 1024) {
        std::vector<uint8_t> original(static_cast<size_t>(input.tellg()));
        input.seekg(0);
        uint64_t entry = 0;
        if (input.read(reinterpret_cast<char *>(original.data()), original.size())) {
            const int code = hm_validate_aot_image(original.data(), original.size(), hm_target_image, HM_TARGET_SPAN, &entry);
            state->target.status = code == 0 ? "mapped-awaiting-dyld" : "layout-mismatch";
            if (code == 0 && state->pac.status == "passed") {
                state->dyld = hm_start_cached_dyld(hm_target_image, state->executable, state->sysroot);
            }
            state->target.error = code;
            state->target.detail = "Original Mach-O segments are packaged in signed ELF at their original relative VM offsets. iOS entry has not been called.";
        }
    }
    if (state->target.status.empty()) state->target.status = "invalid-input";
#else
    state->target.status = "not-packaged-for-this-architecture";
    state->bootStack.status = "not-packaged-for-this-architecture";
#endif
    char *report = hm_inspect_json(state->executable.c_str(), state->sysroot.c_str());
    state->report = report ? report : "{\"status\":\"runtime-error\",\"appExecuted\":false}";
    hm_string_free(report);
    OH_LOG_Print(LOG_APP, LOG_INFO, 0x484d, "Harmonios", "Gate0 raw=%{public}s macho=%{public}s elf=%{public}s",
        state->raw.status.c_str(), state->macho.status.c_str(), state->packaged.status.c_str());
    OH_LOG_Print(LOG_APP, LOG_INFO, 0x484d, "Harmonios", "Target AOT image=%{public}s", state->target.status.c_str());
    OH_LOG_Print(LOG_APP, LOG_INFO, 0x484d, "Harmonios", "Darwin bridge=%{public}s traps=%{public}d",
        state->darwin.status.c_str(), state->darwin.traps);
    OH_LOG_Print(LOG_APP, LOG_INFO, 0x484d, "Harmonios", "ARM64e PAC=%{public}s signal=%{public}d",
        state->pac.status.c_str(), state->pac.signal);
    OH_LOG_Print(LOG_APP, LOG_INFO, 0x484d, "Harmonios", "Darwin initial stack=%{public}s", state->bootStack.status.c_str());
    OH_LOG_Print(LOG_APP, LOG_INFO, 0x484d, "Harmonios", "Authenticated chained rebase=%{public}s", state->rebase.status.c_str());
    OH_LOG_Print(LOG_APP, LOG_INFO, 0x484d, "Harmonios", "Apple dyld=%{public}s %{public}s", state->dyld.status.c_str(), state->dyld.detail.c_str());
}

void Complete(napi_env env, napi_status status, void *data)
{
    std::unique_ptr<DiagnosticsWork> state(static_cast<DiagnosticsWork *>(data));
    if (status != napi_ok) {
        napi_value error;
        napi_create_error(env, nullptr, Text(env, "Native diagnostics failed"), &error);
        napi_reject_deferred(env, state->deferred, error);
    } else {
        napi_value result;
        napi_create_object(env, &result);
        SetText(env, result, "runtime", hm_runtime_greeting());
        SetText(env, result, "compatReport", state->report);
        napi_set_named_property(env, result, "rawProbe", ProbeObject(env, state->raw));
        napi_set_named_property(env, result, "machoProbe", ProbeObject(env, state->macho));
        napi_set_named_property(env, result, "packagedProbe", ProbeObject(env, state->packaged));
        napi_set_named_property(env, result, "targetImage", ProbeObject(env, state->target));
        napi_set_named_property(env, result, "darwinProbe", ProbeObject(env, state->darwin));
        napi_set_named_property(env, result, "pacProbe", ProbeObject(env, state->pac));
        napi_set_named_property(env, result, "bootStackProbe", ProbeObject(env, state->bootStack));
        napi_set_named_property(env, result, "rebaseProbe", ProbeObject(env, state->rebase));
        napi_set_named_property(env, result, "dyldBootstrap", ProbeObject(env, state->dyld));
        napi_set_named_property(env, result, "runtimeVerification", RuntimeVerificationObject(env, *state));
        napi_resolve_deferred(env, state->deferred, result);
    }
    napi_delete_async_work(env, state->work);
}

bool ReadString(napi_env env, napi_value arg, std::string &out)
{
    size_t length = 0;
    if (napi_get_value_string_utf8(env, arg, nullptr, 0, &length) != napi_ok || length > 8192) return false;
    out.resize(length + 1);
    if (napi_get_value_string_utf8(env, arg, out.data(), out.size(), &length) != napi_ok) return false;
    out.resize(length);
    return out.find('\0') == std::string::npos;
}

napi_value RenderSurfaceObject(napi_env env, const HmRenderSurfaceResult &result)
{
    napi_value value;
    napi_create_object(env, &value);
    SetText(env, value, "status", result.status);
    napi_value success;
    napi_get_boolean(env, result.success, &success);
    napi_set_named_property(env, value, "success", success);
    napi_value attached;
    napi_get_boolean(env, hm_harmony_surface_is_attached(), &attached);
    napi_set_named_property(env, value, "attached", attached);
    return value;
}

napi_value AttachRenderSurface(napi_env env, napi_callback_info info)
{
    size_t argc = 3;
    napi_value args[3] {};
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    std::string surfaceId;
    uint32_t width = 0, height = 0;
    if (argc != 3 || !ReadString(env, args[0], surfaceId) ||
        napi_get_value_uint32(env, args[1], &width) != napi_ok ||
        napi_get_value_uint32(env, args[2], &height) != napi_ok) {
        napi_throw_type_error(env, nullptr, "Expected surface id, width and height");
        return nullptr;
    }
    return RenderSurfaceObject(env, hm_harmony_surface_attach(surfaceId.c_str(), width, height));
}

napi_value DetachRenderSurface(napi_env env, napi_callback_info)
{
    hm_harmony_surface_detach();
    return RenderSurfaceObject(env, {true, "surface-detached"});
}

napi_value RenderSurfaceStatus(napi_env env, napi_callback_info)
{
    const bool attached = hm_harmony_surface_is_attached();
    return RenderSurfaceObject(env, {attached, attached ? "surface-attached" : "surface-not-attached"});
}

napi_value RunDiagnostics(napi_env env, napi_callback_info info)
{
    size_t argc = 3;
    napi_value args[3] {};
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    auto state = std::make_unique<DiagnosticsWork>();
    if (argc != 3 || !ReadString(env, args[0], state->directory) ||
        !ReadString(env, args[1], state->executable) || !ReadString(env, args[2], state->sysroot)) {
        napi_throw_type_error(env, nullptr, "Expected probe directory, executable path and sysroot path");
        return nullptr;
    }
    napi_value promise;
    if (napi_create_promise(env, &state->deferred, &promise) != napi_ok) return nullptr;
    napi_status status = napi_create_async_work(env, nullptr, Text(env, "Harmonios diagnostics"),
        Execute, Complete, state.get(), &state->work);
    if (status == napi_ok) status = napi_queue_async_work(env, state->work);
    if (status != napi_ok) {
        napi_value error;
        napi_create_error(env, nullptr, Text(env, "Cannot queue native diagnostics"), &error);
        napi_reject_deferred(env, state->deferred, error);
        if (state->work) napi_delete_async_work(env, state->work);
        return promise;
    }
    state.release();
    return promise;
}

napi_value Init(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        {"runDiagnostics", nullptr, RunDiagnostics, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"attachRenderSurface", nullptr, AttachRenderSurface, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"detachRenderSurface", nullptr, DetachRenderSurface, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"getRenderSurfaceStatus", nullptr, RenderSurfaceStatus, nullptr, nullptr, nullptr, napi_default, nullptr}
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
    return exports;
}
}

static napi_module module = {
    .nm_version = 1, .nm_flags = 0, .nm_filename = nullptr,
    .nm_register_func = Init, .nm_modname = "harmonios", .nm_priv = nullptr, .reserved = {0}
};
extern "C" __attribute__((constructor)) void RegisterHarmoniosModule()
{
    napi_module_register(&module);
}
