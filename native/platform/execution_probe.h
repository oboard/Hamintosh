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
    uint64_t faultPc = 0;
    uint64_t faultAddress = 0;
    int64_t syscall = 0;
    bool selfRebaseWitness = false;
    bool dyldEntered = false;
    // Set only at the future handoff to the original App image, never by
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
