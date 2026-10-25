#include "execution_probe.h"
#include "hamintosh.h"
#include "cache_image.h"
#include "guest_files.h"
#include <sstream>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <mutex>
#include <setjmp.h>
#include <signal.h>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>
#include <ucontext.h>
#include <time.h>
#if defined(__aarch64__)
#include "darwin_probes.h"
#include "packed_bootstrap.h"
extern "C" int hm_enter_guest_stack(void *entry, void *stack, const void *header);
extern "C" int hm_enter_apple_dyld(void *entry, void *stack);
extern "C" int hm_boot_stack_probe_entry();
extern "C" uint64_t hm_pac_sign_pointer(uint64_t pointer, uint64_t modifier, uint32_t key);
#endif

namespace {
std::mutex probeMutex;
thread_local sigjmp_buf *activeProbe = nullptr;
thread_local volatile sig_atomic_t caughtSignal = 0;
constexpr int signals[] = {SIGSEGV, SIGBUS, SIGILL, SIGTRAP};
constexpr size_t signalCount = sizeof(signals) / sizeof(signals[0]);
struct sigaction previousActions[signalCount];
thread_local HmProcess *activeProcess = nullptr;
thread_local uintptr_t guestBegin = 0;
thread_local uintptr_t guestEnd = 0;
thread_local uintptr_t bootstrapBegin = 0, bootstrapEnd = 0;
thread_local volatile sig_atomic_t trapCount = 0;
thread_local bool stopUnknownSyscall = false;
thread_local bool unsupportedDarwinCall = false;
thread_local uint64_t faultPc = 0, faultAddress = 0;
thread_local int64_t lastSyscall = 0;
thread_local uint64_t faultArguments[8] = {};
thread_local const HmCacheImage *activeGuest = nullptr;
thread_local char requestedPath[1024] = {};
struct UnsupportedCall { int64_t number; uint64_t arguments[8]; uint64_t result; bool delivered; };
thread_local UnsupportedCall unsupportedCalls[16] {};
thread_local size_t unsupportedCount = 0;
thread_local bool trapLimitHit = false;
thread_local uint64_t portOptions[3] {};
thread_local bool capturedPortOptions = false;
thread_local uint8_t machRequest[256] {};
thread_local size_t machRequestSize = 0;

bool DispatchDarwinTrap(int number, void *context)
{
#if defined(__aarch64__)
    if (number != SIGTRAP || !activeProbe || !activeProcess || !context) return false;
    auto &state = static_cast<ucontext_t *>(context)->uc_mcontext;
    const auto pc = static_cast<uintptr_t>(state.pc);
    const bool inCache = pc >= guestBegin && pc <= guestEnd - 4;
    const bool inBootstrap = bootstrapBegin && pc >= bootstrapBegin && pc <= bootstrapEnd - 4;
    if (!inCache && !inBootstrap) return false;
    if (stopUnknownSyscall && trapCount >= 8192) { trapLimitHit = true; return false; }
    const auto instruction = *reinterpret_cast<const uint32_t *>(pc);
    if ((instruction & 0xfffffc1fU) == 0xd4294000U) {
        const auto reg = (instruction >> 5) & 31;
        if (reg != 31) state.regs[reg] = hm_process_tsd_base(activeProcess);
        state.pc += 4;
        ++trapCount;
        return true;
    }
    if (instruction != 0xd42909a0) return false;
    HmDarwinTrap frame {};
    frame.number = static_cast<int64_t>(state.regs[16]);
    lastSyscall = frame.number;
    for (size_t i = 0; i < 8; ++i) frame.arguments[i] = state.regs[i];
    frame.nzcv = state.pstate;
    // Rust dispatch is allocation-free; configured native callbacks perform
    // bounded host operations without replacing the host's thread state.
    const int dispatched = hm_darwin_dispatch(activeProcess, &frame);
    if (dispatched < 0) return false;
    if (stopUnknownSyscall && dispatched != 0) {
        if (unsupportedCount < 16) {
            auto &call = unsupportedCalls[unsupportedCount++];
            call.number = frame.number;
            for (size_t i = 0; i < 8; ++i) call.arguments[i] = frame.arguments[i];
            call.result = frame.result[0];
            call.delivered = static_cast<int32_t>(frame.number) >= 0 && static_cast<int32_t>(frame.number) != 521;
        }
        // Unsupported BSD operations return real Darwin ENOSYS/carry so Apple
        // code can take its own optional-feature fallback. Mach interfaces need
        // their individual return conventions and remain explicit stop points.
        // A requested abort is always terminal for this guest attempt.
        if (static_cast<int32_t>(frame.number) < 0 || static_cast<int32_t>(frame.number) == 521) {
            unsupportedDarwinCall = true; return false;
        }
    }
    state.regs[0] = frame.result[0];
    state.regs[1] = frame.result[1];
    state.pstate = frame.nzcv;
    state.pc += 4;
    ++trapCount;
    return true;
#else
    return false;
#endif
}

void ProbeSignal(int number, siginfo_t *info, void *context)
{
    if (DispatchDarwinTrap(number, context)) return;
    if (activeProbe) {
        caughtSignal = number;
#if defined(__aarch64__)
        if (context) {
            const auto &state = static_cast<ucontext_t *>(context)->uc_mcontext;
            faultPc = state.pc;
            lastSyscall = static_cast<int64_t>(state.regs[16]);
            for (size_t i = 0; i < 8; ++i) faultArguments[i] = state.regs[i];
            if (activeGuest && unsupportedDarwinCall) {
                if (static_cast<int32_t>(lastSyscall) == -47) {
                    const auto size = state.regs[2] >> 32;
                    if (size >= 24 && size <= sizeof(machRequest) &&
                        !hm_guest_copy_in(activeGuest, state.regs[0], machRequest, size))
                        machRequestSize = size;
                }
                if (static_cast<int32_t>(lastSyscall) == -24)
                    capturedPortOptions = !hm_guest_copy_in(activeGuest, state.regs[1],
                        reinterpret_cast<uint8_t *>(portOptions), sizeof(portOptions));
                uint64_t path = static_cast<int32_t>(lastSyscall) == 5 ? state.regs[0] : 0;
                if (static_cast<int32_t>(lastSyscall) == 463) path = state.regs[1];
                if (static_cast<int32_t>(lastSyscall) == 521) path = state.regs[4];
                size_t limit = sizeof(requestedPath) - 1;
                uint32_t mib[2] {};
                if (static_cast<int32_t>(lastSyscall) == 202 && state.regs[1] == 2 &&
                    !hm_guest_copy_in(activeGuest, state.regs[0], reinterpret_cast<uint8_t *>(mib), sizeof(mib)) &&
                    mib[0] == 0 && mib[1] == 3) {
                    path = state.regs[4];
                    if (state.regs[5] < limit) limit = state.regs[5];
                }
                for (size_t i = 0; path && i < limit; ++i) {
                    if (hm_guest_copy_in(activeGuest, path + i,
                        reinterpret_cast<uint8_t *>(requestedPath + i), 1)) {
                        requestedPath[0] = 0; break;
                    }
                    if (!requestedPath[i]) break;
                }
            }
        }
        faultAddress = info ? reinterpret_cast<uintptr_t>(info->si_addr) : 0;
#endif
        siglongjmp(*activeProbe, 1);
    }
    for (size_t i = 0; i < signalCount; ++i) {
        if (signals[i] != number) continue;
        const auto &previous = previousActions[i];
        if (previous.sa_handler == SIG_IGN) return;
        if (previous.sa_handler == SIG_DFL) {
            sigaction(number, &previous, nullptr);
            raise(number);
        } else if (previous.sa_flags & SA_SIGINFO) {
            previous.sa_sigaction(number, info, context);
        } else {
            previous.sa_handler(number);
        }
        return;
    }
}

bool Execute(void *entry, HmProbeResult &result, int expected = 42,
    HmProcess *process = nullptr, size_t codeSize = 0,
    void *guestStack = nullptr, const void *appHeader = nullptr,
    const HmCacheImage *cache = nullptr)
{
    std::lock_guard<std::mutex> lock(probeMutex);
    struct sigaction action {};
    action.sa_sigaction = ProbeSignal;
    action.sa_flags = SA_SIGINFO;
    sigemptyset(&action.sa_mask);
    size_t installed = 0;
    for (; installed < signalCount; ++installed) {
        if (sigaction(signals[installed], &action, &previousActions[installed]) != 0) break;
    }
    if (installed != signalCount) {
        result.error = errno;
        result.status = "signal-guard-failed";
        while (installed > 0) { --installed; sigaction(signals[installed], &previousActions[installed], nullptr); }
        return false;
    }
    sigjmp_buf jump;
    caughtSignal = 0;
    trapCount = 0;
    faultPc = faultAddress = 0;
    lastSyscall = 0;
    stopUnknownSyscall = cache != nullptr;
    unsupportedDarwinCall = false;
    unsupportedCount = 0;
    trapLimitHit = false;
    capturedPortOptions = false;
    machRequestSize = 0;
    activeGuest = cache;
    std::memset(requestedPath, 0, sizeof(requestedPath));
    activeProcess = process;
    guestBegin = reinterpret_cast<uintptr_t>(entry);
    guestEnd = guestBegin + codeSize;
    bootstrapBegin = bootstrapEnd = 0;
    if (cache) {
        guestBegin = reinterpret_cast<uintptr_t>(cache->base); guestEnd = guestBegin + cache->span;
        bootstrapBegin = reinterpret_cast<uintptr_t>(cache->bootstrapBase);
        bootstrapEnd = bootstrapBegin + cache->bootstrapSpan;
    }
    if (sigsetjmp(jump, 1) == 0) {
        activeProbe = &jump;
        // The App's entry is never called directly: original Apple dyld owns linking.
        int value;
#if defined(__aarch64__)
        value = cache ? hm_enter_apple_dyld(entry, guestStack) :
            guestStack ? hm_enter_guest_stack(entry, guestStack, appHeader) : reinterpret_cast<int (*)()>(entry)();
#else
        value = reinterpret_cast<int (*)()>(entry)();
#endif
        activeProbe = nullptr;
        result.value = value;
        result.status = value == expected ? "passed" : "wrong-result";
    } else {
        activeProbe = nullptr;
        result.signal = caughtSignal;
        result.status = "execution-fault";
    }
    result.traps = trapCount;
    result.faultPc = faultPc;
    result.faultAddress = faultAddress;
    result.syscall = lastSyscall;
    result.requestPath = requestedPath;
    if (static_cast<int32_t>(lastSyscall) == 521) { result.message = requestedPath; result.requestPath.clear(); }
    if (capturedPortOptions) {
        std::ostringstream options;
        options << "mach_port_construct options: flags=0x" << std::hex << uint32_t(portOptions[0])
            << ", qlimit=" << std::dec << (portOptions[0] >> 32)
            << ", reserved=0x" << std::hex << portOptions[1] << ",0x" << portOptions[2];
        result.message = options.str();
    }
    if (machRequestSize) {
        static constexpr char hex[] = "0123456789abcdef";
        result.message = "mach_msg2 request: ";
        for (size_t i = 0; i < machRequestSize; ++i) {
            result.message += hex[machRequest[i] >> 4];
            result.message += hex[machRequest[i] & 15];
        }
    }
    activeGuest = nullptr;
    if (unsupportedCount) {
        std::ostringstream trace;
        trace << '[';
        for (size_t i = 0; i < unsupportedCount; ++i) {
            if (i) trace << ',';
            const auto &call = unsupportedCalls[i];
            trace << "{\"number\":" << call.number << ",\"result\":" << call.result
                << ",\"delivered\":" << (call.delivered ? "true" : "false") << ",\"arguments\":[";
            for (size_t n = 0; n < 8; ++n) { if (n) trace << ','; trace << call.arguments[n]; }
            trace << "]}";
        }
        trace << ']';
        result.unsupportedCalls = trace.str();
    }
    stopUnknownSyscall = false;
    activeProcess = nullptr;
    guestBegin = guestEnd = 0;
    bootstrapBegin = bootstrapEnd = 0;
    for (size_t i = 0; i < signalCount; ++i) sigaction(signals[i], &previousActions[i], nullptr);
    return result.status == "passed";
}
}

HmProbeResult hm_start_cached_dyld(const void *appHeader, const std::string &executable, const std::string &sysroot)
{
    HmProbeResult result;
    result.mode = "apple-dyld-bootstrap";
#if defined(__aarch64__)
    static std::mutex cacheMutex;
    std::lock_guard<std::mutex> lock(cacheMutex);
    auto cache = hm_prepare_cache_image();
    if (!cache.error.empty()) { result.status = cache.error; return result; }
    if (!cache.bootstrapBase) { result.status = "requires-standalone-dyld"; return result; }
    cache.sysroot = sysroot.c_str();
    const auto dynamicData = hm_prepare_cache_dynamic_data(cache);
    if (!dynamicData.empty()) { result.status = dynamicData; return result; }
    const auto commpage = hm_prepare_commpage();
    if (!commpage.empty()) { result.status = commpage; return result; }
    constexpr size_t stackSize = 1024 * 1024, guardSize = 0x4000;
    auto *allocation = static_cast<uint8_t *>(mmap(nullptr, stackSize + 2 * guardSize, PROT_NONE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    if (allocation == MAP_FAILED) { result.status = "dyld-stack-allocation-failed"; result.error = errno; return result; }
    auto *stack = allocation + guardSize;
    cache.stack = stack;
    cache.stackSize = stackSize;
    cache.executable = executable.c_str();
    cache.sysroot = sysroot.c_str();
    uint64_t sp = 0;
    if (mprotect(stack, stackSize, PROT_READ | PROT_WRITE) ||
        hm_build_boot_stack(stack, stackSize, reinterpret_cast<uintptr_t>(appHeader), executable.c_str(), &sp)) {
        result.status = "dyld-stack-setup-failed";
        result.error = errno;
    } else {
        auto *process = hm_process_create(getpid(), getppid(), gettid());
        if (!process) result.status = "process-create-failed";
        else {
            hm_process_set_vm_protect(process, hm_cache_vm_protect, &cache);
            hm_process_set_getentropy(process, hm_guest_getentropy);
            hm_process_set_memory(process, hm_guest_copy_in, hm_guest_copy_out, reinterpret_cast<uintptr_t>(cache.base));
            hm_process_set_clock(process, hm_guest_clock);
            hm_process_set_vm_map(process, hm_guest_vm_map);
            hm_process_set_vm_deallocate(process, hm_guest_vm_deallocate);
            hm_process_set_files(process, hm_guest_open, hm_guest_close, hm_guest_duplicate);
            hm_process_set_resolve_file_id(process, hm_guest_resolve_file_id);
            Execute(cache.entry, result, 0, process, 0, reinterpret_cast<void *>(sp), appHeader, &cache);
            result.selfRebaseWitness = hm_bootstrap_rebase_witness(cache);
            hm_process_destroy(process);
            result.status = trapLimitHit ? "dyld-trap-limit" :
                result.signal == SIGTRAP && static_cast<int32_t>(result.syscall) == 521 ? "dyld-aborted" :
                result.signal == SIGTRAP && unsupportedDarwinCall ? "dyld-needs-darwin-call" :
                result.signal ? "dyld-execution-fault" : "dyld-returned-unexpectedly";
        }
    }
    std::ostringstream detail;
    const bool inBootstrap = cache.bootstrapBase && result.faultPc >= reinterpret_cast<uintptr_t>(cache.bootstrapBase) &&
        result.faultPc - reinterpret_cast<uintptr_t>(cache.bootstrapBase) < cache.bootstrapSpan;
    detail << "iOS 27 " << (cache.bootstrapBase ? "standalone" : "cached") << " dyld; " << cache.rebases
        << " cache rebases. PC " << (inBootstrap ? "bootstrap" : "cache") << "+0x"
        << std::hex << (result.faultPc ? result.faultPc - reinterpret_cast<uintptr_t>(inBootstrap ? cache.bootstrapBase : cache.base) : 0)
        << ", fault address 0x" << result.faultAddress << std::dec << ", x16=" << result.syscall
        << ". Args" << std::hex;
    for (auto argument : faultArguments) detail << " 0x" << argument;
    detail << ". App startup is incomplete.";
    result.detail = detail.str();
    munmap(allocation, stackSize + 2 * guardSize);
#else
    result.status = "unsupported-architecture";
#endif
    return result;
}

HmProbeResult hm_darwin_execution_probe()
{
    HmProbeResult result;
    result.mode = "darwin-arm64-syscall-bridge";
#if defined(__aarch64__)
    HmProcess *process = hm_process_create(getpid(), getppid(), gettid());
    if (!process) { result.status = "process-create-failed"; return result; }
    struct Fixture { const uint8_t *image; size_t codeSize; int expected; };
    const Fixture fixtures[] = {
        {hm_darwin_getpid_image, HM_DARWIN_GETPID_CODE_SIZE, getpid()},
        {hm_darwin_unix_error_image, HM_DARWIN_UNIX_ERROR_CODE_SIZE, 78},
        {hm_darwin_mach_self_image, HM_DARWIN_MACH_SELF_CODE_SIZE, 0x103},
        {hm_darwin_mach_error_image, HM_DARWIN_MACH_ERROR_CODE_SIZE, 46},
    };
    int traps = 0;
    for (const auto &fixture : fixtures) {
        const bool passed = Execute(const_cast<uint8_t *>(fixture.image) + 0x1000,
            result, fixture.expected, process, fixture.codeSize);
        traps += result.traps;
        if (!passed) break;
    }
    result.traps = traps;
    if (result.status == "passed" && traps != 4) result.status = "trap-count-mismatch";
    hm_process_destroy(process);
    result.detail = "Darwin getpid, BSD ENOSYS/carry, Mach task identity and unsupported Mach return crossed the signed AOT trap boundary. This is not App startup.";
#else
    result.status = "unsupported-architecture";
#endif
    return result;
}

#if defined(__aarch64__)
extern "C" const uint8_t hm_packaged_probe_image[4104];
extern "C" int hm_pac_probe_entry();
#endif

HmProbeResult hm_pac_execution_probe()
{
    HmProbeResult result;
    result.mode = "arm64e-hardware-pac";
#if defined(__aarch64__)
    Execute(reinterpret_cast<void *>(hm_pac_probe_entry), result);
    result.detail = "PACIBSP/AUTIBSP and PACIA/BLRAA used this HAP process's keys. Apple cache pointers still require rebasing and signing with these keys.";
#else
    result.status = "unsupported-architecture";
#endif
    return result;
}

#if defined(__aarch64__)
static uint64_t SignChainedPointer(uint64_t value, uint64_t storage,
    uint16_t diversity, uint8_t key, uint8_t addressDiversity)
{
    const uint64_t modifier = addressDiversity ?
        ((storage & 0x0000ffffffffffffULL) | (static_cast<uint64_t>(diversity) << 48)) : diversity;
    return hm_pac_sign_pointer(value, modifier, key);
}
#endif

HmProbeResult hm_authenticated_rebase_probe()
{
    HmProbeResult result;
    result.mode = "arm64e-bootstrap-chained-rebase";
#if defined(__aarch64__)
    // This image is isolated test state; serialize the whole mutation/call/reset cycle.
    static std::mutex rebaseMutex;
    std::lock_guard<std::mutex> lock(rebaseMutex);
    auto *mapped = const_cast<uint8_t *>(hm_bootstrap_image);
    uint64_t rebased = 0;
    int status = hm_reset_bootstrap_data(hm_bootstrap_original, HM_BOOTSTRAP_ORIGINAL_SIZE,
        mapped, HM_BOOTSTRAP_SPAN);
    if (status == 0) status = hm_apply_bootstrap_rebases(hm_bootstrap_original,
        HM_BOOTSTRAP_ORIGINAL_SIZE, mapped, HM_BOOTSTRAP_SPAN, SignChainedPointer, &rebased);
    if (status == 0 && rebased == 1) {
        Execute(mapped + HM_BOOTSTRAP_ENTRY_OFFSET, result);
    } else {
        result.status = "bootstrap-relocation-failed"; result.error = status;
    }
    hm_reset_bootstrap_data(hm_bootstrap_original, HM_BOOTSTRAP_ORIGINAL_SIZE, mapped, HM_BOOTSTRAP_SPAN);
    result.detail = "A self-contained MH_DYLINKER rebase was relocated and signed using its actual slot address/key/diversity, then called through BLRAA. No Apple dyld or App entry was called.";
#else
    result.status = "unsupported-architecture";
#endif
    return result;
}

HmProbeResult hm_boot_stack_execution_probe(const void *appHeader)
{
    HmProbeResult result;
    result.mode = "darwin-initial-stack";
#if defined(__aarch64__)
    const size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    const size_t stackSize = 1024 * 1024;
    void *mapping = mmap(nullptr, stackSize + 2 * page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) { result.status = "stack-allocation-failed"; result.error = errno; return result; }
    auto *stack = static_cast<uint8_t *>(mapping) + page;
    if (mprotect(stack, stackSize, PROT_READ | PROT_WRITE) != 0) {
        result.status = "stack-protection-failed"; result.error = errno;
    } else {
        uint64_t pointer = 0;
        const int status = hm_build_boot_stack(stack, stackSize, reinterpret_cast<uint64_t>(appHeader),
            "/apps/SwiftUIHelloWorld.app/SwiftUIHelloWorld", &pointer);
        if (status == 0) {
            Execute(reinterpret_cast<void *>(hm_boot_stack_probe_entry), result, 42, nullptr, 0,
                reinterpret_cast<void *>(pointer), appHeader);
        } else { result.status = "stack-build-failed"; result.error = status; }
    }
    munmap(mapping, stackSize + 2 * page);
    result.detail = "Entered an isolated RW guest stack with the target Mach-O header, argc/argv, envp and Apple executable_path arguments. Apple dyld has not been called.";
#else
    result.status = "unsupported-architecture";
#endif
    return result;
}

HmProbeResult hm_packaged_execution_probe()
{
    HmProbeResult result;
    result.mode = "mach-o-aot-elf";
#if defined(__aarch64__)
    HmProbePlan plan {};
    if (hm_probe_plan(hm_packaged_probe_image, sizeof(hm_packaged_probe_image), &plan) != 0) {
        result.status = "invalid-fixture";
        return result;
    }
    Execute(const_cast<uint8_t *>(hm_packaged_probe_image) + plan.entry_offset, result);
    result.detail = "Executed original Mach-O __TEXT bytes embedded unchanged in a HAP-signed ELF. This is the standalone probe, not SwiftUI.";
#else
    result.status = "unsupported-architecture";
    result.detail = "An ARM64 physical device is required.";
#endif
    return result;
}

HmProbeResult hm_run_probe(const std::string &path, bool macho)
{
    HmProbeResult result;
    result.mode = macho ? "mach-o-file-rx" : "raw-file-rx";
#if !defined(__aarch64__)
    result.status = "unsupported-architecture";
    result.detail = "An ARM64 physical device is required.";
    return result;
#else
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input || input.tellg() < 0 || input.tellg() > 1024 * 1024) {
        result.status = "invalid-fixture";
        result.detail = "Missing or oversized probe fixture.";
        return result;
    }
    std::vector<uint8_t> bytes(static_cast<size_t>(input.tellg()));
    input.seekg(0);
    if (!input.read(reinterpret_cast<char *>(bytes.data()), bytes.size())) {
        result.status = "invalid-fixture";
        return result;
    }
    HmProbePlan plan {};
    if (macho) {
        const int status = hm_probe_plan(bytes.data(), bytes.size(), &plan);
        if (status != 0) {
            result.status = "invalid-fixture";
            result.detail = "Rust rejected the Mach-O probe: " + std::to_string(status);
            return result;
        }
    } else {
        const std::vector<uint8_t> expected {0x40, 0x05, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6};
        if (bytes != expected) { result.status = "invalid-fixture"; return result; }
    }
    const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        result.status = "open-failed"; result.error = errno; result.detail = strerror(errno);
        return result;
    }
    void *mapping = mmap(nullptr, bytes.size(), PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
    result.error = mapping == MAP_FAILED ? errno : 0;
    close(fd);
    if (mapping == MAP_FAILED) {
        result.status = "mapping-denied";
        result.detail = strerror(result.error);
        return result;
    }
    auto *entry = static_cast<char *>(mapping) + plan.slice_offset + plan.entry_offset;
    __builtin___clear_cache(entry, entry + 8);
    Execute(entry, result);
    munmap(mapping, bytes.size());
    result.detail = result.status == "passed" ? "Executed mov w0,#42; ret from a file-backed RX mapping." :
        "RX mapping succeeded but entering the audited ARM64 fixture failed.";
    return result;
#endif
}
