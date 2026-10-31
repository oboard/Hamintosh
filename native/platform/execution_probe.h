#pragma once
#include <string>
#include <cstdint>

struct HmProbeResult {
    std::string mode;
    std::string status;
    std::string detail;
    int value = -1;
    int error = 0;
    int signal = 0;
    uint64_t traps = 0;
    uint64_t trapFallbackCount = 0;
    uint64_t directCallCount = 0;
    uint64_t swiftVwtAddressBridges = 0;
    uint64_t faultPc = 0;
    uint64_t faultAddress = 0;
    uint64_t cacheBase = 0;
    uint64_t sceneFaultPc = 0, sceneWindow = 0, sceneRootController = 0, sceneRootView = 0;
    uint32_t sceneStage = 0;
    int sceneSignal = 0;
    bool sceneFaulted = false;
    int64_t syscall = 0;
    bool selfRebaseWitness = false;
    bool dyldEntered = false;
    // Set only after observing execution in the original App image, never by
    // static AOT validation or by entering Apple dyld.
    bool appExecuted = false;
    std::string requestPath;
    std::string message;
    std::string unsupportedCalls;
};

HmProbeResult hm_run_probe(const std::string &path, bool macho);
HmProbeResult hm_packaged_execution_probe();
HmProbeResult hm_darwin_execution_probe();
HmProbeResult hm_pac_execution_probe();
HmProbeResult hm_boot_stack_execution_probe(const void *appHeader);
HmProbeResult hm_authenticated_rebase_probe();
HmProbeResult hm_start_cached_dyld(const void *appHeader, const std::string &executable, const std::string &sysroot);
extern "C" int HmProbeUiScene();
extern "C" int hm_safe_probe_ui_scene();
extern "C" void hm_set_guest_safe_area(double top, double left, double bottom, double right);
extern "C" bool hm_dispatch_guest_touch(int32_t type, double x, double y);
extern "C" void hm_cancel_execution_probe();
uint64_t HmGuestObjcRuntimeSymbol(const char *name);
extern "C" int hm_safe_ca_renderer_probe(char *json, size_t len);
extern "C" int hm_safe_ca_renderer_probe_scene1(char *json, size_t len);
extern "C" int hm_safe_ca_renderer_probe_scene2(char *json, size_t len);
extern "C" int hm_safe_ca_renderer_probe_scene3(char *json, size_t len);
extern "C" int hm_ca_renderer_last_report(char *json, size_t len);
extern "C" void hm_clear_ca_renderer_last_report();
