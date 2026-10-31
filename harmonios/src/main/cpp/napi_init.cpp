#include "napi/native_api.h"
#include "harmonios.h"
#include "execution_probe.h"
#include "harmony_surface.h"
#include "frame_diagnostics.h"
#include <hilog/log.h>
#include <memory>
#include <string>
#include <fstream>
#include <vector>
#include <mutex>
#include <cerrno>
#include <cstring>
#include <cmath>
#include <sstream>
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/mman.h>
#ifdef HM_HAS_AOT_TARGET
#include "packed_target.h"
#endif

extern "C" int32_t hm_metal_probe_render_json(char *output, size_t outputLen);

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

void SetCount(napi_env env, napi_value object, const char *name, uint64_t number)
{
    napi_value value;
    napi_create_double(env, static_cast<double>(number), &value);
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
    SetCount(env, value, "traps", probe.traps);
    SetCount(env, value, "trapFallbackCount", probe.trapFallbackCount);
    SetCount(env, value, "swiftVwtAddressBridges", probe.swiftVwtAddressBridges);
    SetCount(env, value, "directCallCount", probe.directCallCount);
    SetText(env, value, "cacheBase", std::to_string(probe.cacheBase));
    napi_value scene;
    napi_create_object(env, &scene);
    SetInt(env, scene, "stage", probe.sceneStage);
    SetInt(env, scene, "signal", probe.sceneSignal);
    SetBool(env, scene, "faulted", probe.sceneFaulted);
    SetText(env, scene, "faultPc", std::to_string(probe.sceneFaultPc));
    SetText(env, scene, "window", std::to_string(probe.sceneWindow));
    SetText(env, scene, "rootViewController", std::to_string(probe.sceneRootController));
    SetText(env, scene, "rootView", std::to_string(probe.sceneRootView));
    napi_set_named_property(env, value, "scene", scene);
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
    SetCount(env, value, "traps", state.dyld.traps);
    SetCount(env, value, "trapFallbackCount", state.dyld.trapFallbackCount);
    SetCount(env, value, "directCallCount", state.dyld.directCallCount);
    SetInt(env, value, "signal", state.dyld.signal);
    SetText(env, value, "faultPc", std::to_string(state.dyld.faultPc));
    SetText(env, value, "faultAddress", std::to_string(state.dyld.faultAddress));
    return value;
}

void Execute(napi_env, void *data)
{
    static std::mutex diagnosticsMutex;
    std::lock_guard<std::mutex> lock(diagnosticsMutex);
    auto *state = static_cast<DiagnosticsWork *>(data);
    hm_clear_ca_renderer_last_report();
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
            auto *mapped = const_cast<uint8_t *>(hm_target_image);
            bool writable = true;
            // dyld can make __DATA_CONST read-only after binding. Restore only
            // original writable segments, never signed executable pages.
            for (const auto &segment : HM_TARGET_SEGMENTS) {
                if (!(segment.protection & PROT_WRITE)) continue;
                if ((segment.protection & PROT_EXEC) || mprotect(mapped + segment.offset,
                    segment.size, segment.protection)) {
                    writable = false;
                    state->target.error = errno;
                    state->target.status = "app-data-reset-protection-failed";
                    break;
                }
            }
            const int reset = writable ? hm_reset_app_data(original.data(), original.size(), mapped, HM_TARGET_SPAN) : -1;
            OH_LOG_Print(LOG_APP, reset != 0 ? LOG_ERROR : LOG_INFO, 0x484d, "Harmonios",
                "AppDataReset: executable=%{public}s bytes=%{public}zu span=%{public}llu reset=%{public}d",
                state->executable.c_str(), original.size(), static_cast<unsigned long long>(HM_TARGET_SPAN), reset);
            auto expectedImage = original;
            bool transformsValid = original.size() >= 8;
            uint64_t previousPc = 0;
            for (size_t i = 0; transformsValid && i < HM_TARGET_SWIFT_VWT_ADDRESS_SITE_COUNT; ++i) {
                const auto &site = HM_TARGET_SWIFT_VWT_ADDRESS_SITES[i];
                if (site.pc <= previousPc || site.pc < 4 || site.pc > HM_TARGET_SPAN - 4 ||
                    site.fileOffset < 4 || site.fileOffset > original.size() - 4) {
                    transformsValid = false; break;
                }
                uint32_t words[2] {};
                std::memcpy(words, original.data() + site.fileOffset - 4, sizeof(words));
                const auto table = site.metadataLoad & 31;
                const auto metadata = (site.metadataLoad >> 5) & 31;
                if (words[0] != site.metadataLoad || words[1] != site.operation ||
                    (site.metadataLoad & 0xffe00c00U) != 0xf8400000U ||
                    ((site.metadataLoad >> 12) & 0x1ff) != 0x1f8 ||
                    (site.operation & 0xffc00000U) != 0x91000000U ||
                    ((site.operation >> 10) & 0xfff) != 64 ||
                    ((site.operation >> 5) & 31) != table || table == 31 || metadata == 31 ||
                    metadata == table || (site.operation & 31) == 31) {
                    transformsValid = false; break;
                }
                const uint32_t replacement = HM_TARGET_SWIFT_VWT_ADDRESS_BRK;
                std::memcpy(expectedImage.data() + site.fileOffset, &replacement, sizeof(replacement));
                previousPc = site.pc;
            }
            // Validate every mapped byte, including each approved AOT bridge.
            // No executable page is changed at runtime.
            const int code = reset == 0 && transformsValid ? hm_validate_aot_image(expectedImage.data(), expectedImage.size(),
                hm_target_image, HM_TARGET_SPAN, &entry) : reset != 0 ? reset : -5;
            if (writable) {
                state->target.status = reset != 0 ? "app-data-reset-failed" :
                    code == 0 ? "mapped-awaiting-dyld" : "layout-mismatch";
                if (code == 0 && state->pac.status == "passed") {
                    state->dyld = hm_start_cached_dyld(hm_target_image, state->executable, state->sysroot);
                }
                state->target.error = code;
                state->target.detail = "Mach-O segments and audited Swift ABI bridges are packaged in signed ELF at original relative VM offsets; all bytes were validated.";
            }
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
    OH_LOG_Print(LOG_APP, LOG_INFO, 0x484d, "Harmonios", "Darwin bridge=%{public}s traps=%{public}llu",
        state->darwin.status.c_str(), static_cast<unsigned long long>(state->darwin.traps));
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
        std::vector<char> caRendererReport(16384, 0);
        const int caRendererStatus = hm_ca_renderer_last_report(caRendererReport.data(), caRendererReport.size());
        SetText(env, result, "caRendererProbe", caRendererStatus == 0 ? caRendererReport.data() :
            "{\"success\":false,\"stage\":\"report\",\"error\":\"CARenderer report unavailable or too large\"}");
        SetText(env, result, "frameDiagnostics", hm_frame_diagnostics_to_json());
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
    auto result = hm_harmony_surface_attach(surfaceId.c_str(), width, height);
    return RenderSurfaceObject(env, result);
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

napi_value PresentTestPattern(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value args[1] {};
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    uint32_t patternId = 0;
    if (argc >= 1 && args[0] != nullptr) {
        napi_get_value_uint32(env, args[0], &patternId);
    }
    return RenderSurfaceObject(env, hm_harmony_surface_present_test_pattern(patternId));
}

napi_value GetFrameDiagnostics(napi_env env, napi_callback_info)
{
    return Text(env, hm_frame_diagnostics_to_json());
}

napi_value ResetFrameDiagnostics(napi_env env, napi_callback_info)
{
    hm_frame_diagnostics_reset();
    return Text(env, "reset");
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

napi_value SetGuestSafeArea(napi_env env, napi_callback_info info)
{
    size_t argc = 4;
    napi_value args[4] {};
    double insets[4] {};
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    if (argc != 4) { napi_throw_type_error(env, nullptr, "Expected four safe-area insets"); return nullptr; }
    for (size_t i = 0; i < 4; ++i) {
        if (napi_get_value_double(env, args[i], &insets[i]) != napi_ok ||
            !std::isfinite(insets[i]) || insets[i] < 0) {
            napi_throw_type_error(env, nullptr, "Safe-area insets must be nonnegative numbers");
            return nullptr;
        }
    }
    hm_set_guest_safe_area(insets[0], insets[1], insets[2], insets[3]);
    napi_value result; napi_get_undefined(env, &result); return result;
}

napi_value DispatchTouchEvent(napi_env env, napi_callback_info info)
{
    size_t argc = 3;
    napi_value args[3] {};
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    if (argc < 3) return nullptr;
    int32_t type = 0;
    double x = 0.0, y = 0.0;
    napi_get_value_int32(env, args[0], &type);
    napi_get_value_double(env, args[1], &x);
    napi_get_value_double(env, args[2], &y);

    const bool handled = hm_dispatch_guest_touch(type, x, y);
    napi_value result;
    napi_get_boolean(env, handled, &result);
    return result;
}

napi_value CancelDiagnostics(napi_env env, napi_callback_info)
{
    hm_cancel_execution_probe();
    napi_value result;
    napi_get_undefined(env, &result);
    return result;
}

napi_value VulkanPreflight(napi_env env, napi_callback_info)
{
    using GetProc = void *(*)(void *, const char *);
    using CreateInstance = int32_t (*)(const void *, const void *, void **);
    using EnumDevices = int32_t (*)(void *, uint32_t *, void **);
    using EnumDeviceExt = int32_t (*)(void *, const char *, uint32_t *, void *);
    using DestroyInstance = void (*)(void *, const void *);
    struct Extension { char name[256]; uint32_t spec; };
    struct AppInfo { uint32_t type; const void *next; const char *name; uint32_t appVersion; const char *engine; uint32_t engineVersion; uint32_t apiVersion; };
    struct InstanceInfo { uint32_t type; const void *next; uint32_t flags; const AppInfo *app; const char *const *layers; uint32_t layerCount; const char *const *extensions; uint32_t extensionCount; };
    std::ostringstream result;
    void *library = dlopen("libvulkan.so", RTLD_NOW);
    if (!library) {
        result << "{\"error\":\"" << dlerror() << "\"}";
        return Text(env, result.str());
    }
    auto get = reinterpret_cast<GetProc>(dlsym(library, "vkGetInstanceProcAddr"));
    if (!get) return Text(env, "{\"error\":\"vkGetInstanceProcAddr missing\"}");
    AppInfo app {1, nullptr, "hm-preflight", 1, "hm", 1, 1u << 22};
    InstanceInfo info {2, nullptr, 0, &app, nullptr, 0, nullptr, 0};
    auto create = reinterpret_cast<CreateInstance>(get(nullptr, "vkCreateInstance"));
    void *instance = nullptr;
    if (!create || create(&info, nullptr, &instance) != 0 || !instance) return Text(env, "{\"error\":\"vkCreateInstance failed\"}");
    auto enumDevices = reinterpret_cast<EnumDevices>(get(instance, "vkEnumeratePhysicalDevices"));
    uint32_t deviceCount = 0;
    if (enumDevices) enumDevices(instance, &deviceCount, nullptr);
    std::vector<void *> devices(deviceCount);
    if (deviceCount) enumDevices(instance, &deviceCount, devices.data());
    auto enumDeviceExt = reinterpret_cast<EnumDeviceExt>(get(instance, "vkEnumerateDeviceExtensionProperties"));
    bool timeline = false;
    for (void *device : devices) {
        uint32_t count = 0;
        if (enumDeviceExt) enumDeviceExt(device, nullptr, &count, nullptr);
        std::vector<Extension> extensions(count);
        if (count && enumDeviceExt) enumDeviceExt(device, nullptr, &count, extensions.data());
        for (const auto &extension : extensions) {
            if (!std::strcmp(extension.name, "VK_KHR_timeline_semaphore")) timeline = true;
        }
    }
    auto destroy = reinterpret_cast<DestroyInstance>(get(instance, "vkDestroyInstance"));
    if (destroy) destroy(instance, nullptr);
    result << "{\"physicalDevices\":" << deviceCount << ",\"timelineSemaphore\":" << (timeline ? "true" : "false") << "}";
    return Text(env, result.str());
}

napi_value MetalRenderProbe(napi_env env, napi_callback_info)
{
    mkdir("/data/storage/el2/base/cache", 0700);
    setenv("XDG_CACHE_HOME", "/data/storage/el2/base/cache", 1);
    std::vector<char> output(4096, 0);
    hm_metal_probe_render_json(output.data(), output.size());
    return Text(env, output.data());
}

napi_value CaRendererProbe(napi_env env, napi_callback_info)
{
    std::vector<char> output(16384, 0);
    hm_safe_ca_renderer_probe(output.data(), output.size());
    return Text(env, output.data());
}

napi_value Init(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        {"runDiagnostics", nullptr, RunDiagnostics, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"attachRenderSurface", nullptr, AttachRenderSurface, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"detachRenderSurface", nullptr, DetachRenderSurface, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"getRenderSurfaceStatus", nullptr, RenderSurfaceStatus, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"presentTestPattern", nullptr, PresentTestPattern, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"getFrameDiagnostics", nullptr, GetFrameDiagnostics, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"resetFrameDiagnostics", nullptr, ResetFrameDiagnostics, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"setGuestSafeArea", nullptr, SetGuestSafeArea, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"dispatchTouchEvent", nullptr, DispatchTouchEvent, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"cancelDiagnostics", nullptr, CancelDiagnostics, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"vulkanPreflight", nullptr, VulkanPreflight, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"metalRenderProbe", nullptr, MetalRenderProbe, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"caRendererProbe", nullptr, CaRendererProbe, nullptr, nullptr, nullptr, napi_default, nullptr}
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
    // ArkTS imports HarmonyOS native modules through the default binding.
    // Export the same object there so both native-module conventions work.
    napi_set_named_property(env, exports, "default", exports);
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
