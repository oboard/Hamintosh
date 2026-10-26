#include "execution_probe.h"
#include "harmonios.h"
#include "cache_image.h"
#include "code_signature.h"
#include "guest_files.h"
#include "objc_aot.h"
#include <window_manager/oh_display_manager.h>
#include <dlfcn.h>
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
#include <sys/auxv.h>
#include <asm/hwcap.h>
#endif
#if defined(__aarch64__)
#include "darwin_probes.h"
#include "packed_bootstrap.h"
#ifdef HM_HAS_AOT_TARGET
#include "packed_target.h"
#endif
extern "C" int hm_enter_guest_stack(void *entry, void *stack, const void *header);
extern "C" void hm_enter_workqueue_thread(void *entry, void *stack, void *pthread, uint64_t mach_port, uint64_t unused, void *workloop_id, uint64_t upcall_flags, uint64_t nevents);
extern "C" int hm_enter_apple_dyld(void *entry, void *stack);
extern "C" int hm_boot_stack_probe_entry();
extern "C" uint64_t hm_pac_sign_pointer(uint64_t pointer, uint64_t modifier, uint32_t key);
extern "C" uint64_t hm_pac_strip_instruction(uint64_t pointer);
extern "C" uint64_t hm_pac_strip_data(uint64_t pointer);
extern "C" uint64_t hm_pac_auth_function(uint64_t pointer);
#endif

namespace {
void ConfigureHostDisplay(HmProcess *process)
{
    // This API is present in the SDK but not in every device system image.
    // Keep it optional so a missing display service cannot prevent the native
    // compatibility module itself from loading.
    void *library = dlopen("libnative_display_manager.so", RTLD_NOW | RTLD_LOCAL);
    if (!library) return;
    using GetInt = NativeDisplayManager_ErrorCode (*)(int32_t *);
    using GetFloat = NativeDisplayManager_ErrorCode (*)(float *);
    auto getWidth = reinterpret_cast<GetInt>(dlsym(library, "OH_NativeDisplayManager_GetDefaultDisplayWidth"));
    auto getHeight = reinterpret_cast<GetInt>(dlsym(library, "OH_NativeDisplayManager_GetDefaultDisplayHeight"));
    auto getScale = reinterpret_cast<GetFloat>(
        dlsym(library, "OH_NativeDisplayManager_GetDefaultDisplayVirtualPixelRatio"));
    int32_t width = 0, height = 0;
    float scale = 0.0f;
    if (getWidth && getHeight && getScale &&
        getWidth(&width) == DISPLAY_MANAGER_OK && getHeight(&height) == DISPLAY_MANAGER_OK &&
        getScale(&scale) == DISPLAY_MANAGER_OK && width > 0 && height > 0 && scale > 0.0f) {
        hm_process_set_display(process, static_cast<uint32_t>(width),
            static_cast<uint32_t>(height), scale, scale);
    }
    dlclose(library);
}

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
constexpr sig_atomic_t TrapLimit = 262144;
thread_local bool stopUnknownSyscall = false;
thread_local bool unsupportedDarwinCall = false;
thread_local uint64_t faultPc = 0, faultAddress = 0, faultLr = 0;
thread_local uint64_t faultSp = 0;
thread_local uint8_t faultStackBytes[32] = {};
thread_local bool capturedFaultStack = false;
thread_local uint8_t faultPcBytes[16] = {};
thread_local bool capturedFaultPc = false;
thread_local int64_t lastSyscall = 0;
thread_local int64_t dispatchingCall = 0;
thread_local uint64_t dispatchingArguments[8] = {};
thread_local int64_t dispatchFaultCall = 0;
thread_local uint64_t dispatchFaultArguments[8] = {};
thread_local char dispatchFaultPath[256] = {};
thread_local uint64_t faultArguments[8] = {};
thread_local uint64_t faultFrames[32] = {};
thread_local size_t faultFrameCount = 0;
thread_local uint64_t faultRegisters[12] = {};
thread_local bool appCodeExecuted = false;
struct TrapRecord {
    uint64_t sequence;
    int64_t number;
    uintptr_t pc;
    uintptr_t caller;
    uint64_t arguments[8];
    uint64_t indirect;
    uint64_t result[2];
    bool dispatched;
};
struct ThreadCallAudit {
    int64_t number = 0;
    uint64_t opcode = 0, count = 0, arguments[8] {}, result = 0;
};
thread_local ThreadCallAudit threadCalls[16] {};
thread_local size_t threadCallCount = 0;
thread_local uint8_t threadRegistration[128] {};
thread_local size_t threadRegistrationSize = 0;
struct KeventCallAudit {
    uint64_t workloop = 0;
    uint64_t syscallFlags = 0;
    uint64_t words[9] {};
    bool scene = false;
};
thread_local KeventCallAudit keventCalls[64] {};
thread_local size_t keventCallCount = 0;
thread_local size_t keventCallDropped = 0;

struct UiSnapshot {
    uint64_t valueWitnessStored = 0;
    uint64_t valueWitnessExpected = 0;
    uint32_t valueWitnessAdaptations = 0;
    uint32_t localConformanceAdaptations = 0;
    bool inspected = false;
    int signal = 0;
    uint64_t faultPc = 0;
    uint64_t faultAddress = 0;
    uint64_t faultLr = 0;
    uint64_t faultArguments[8] {};
    uint64_t faultFrames[16] {};
    size_t faultFrameCount = 0;
    int traps = 0;
    int64_t lastSyscall = 0;
    TrapRecord trace[32] {};
    size_t traceCount = 0, traceNext = 0;
    char console[2048] {};
    char abortReason[512] {};
    size_t consoleSize = 0;
    bool faulted = false;
    uint64_t application = 0;
    uint64_t windows = 0;
    uint64_t windowCount = 0;
    uint64_t window = 0;
    uint64_t windowScene = 0;
    uint64_t rootViewController = 0;
    uint64_t rootView = 0;
    uint64_t layer = 0;
    uint64_t sublayers = 0;
    uint64_t sublayerCount = 0;
    uint32_t stage = 0;
    uint32_t applicationSelectorMask = 0;
    uint32_t delegateSelectorMask = 0;
    uint64_t delegate = 0;
    uint64_t sceneSession = 0;
    uint64_t sceneConfiguration = 0;
    uint64_t sceneSpecification = 0;
    uint64_t fbsScene = 0;
    uint64_t connectionOptions = 0;
    uint64_t uiScene = 0;
    uint64_t sceneDelegate = 0;
    bool sceneContextRequired = false;
    bool sceneRequested = false;
    bool attempted = false;
};
thread_local UiSnapshot uiSnapshot;
thread_local bool inspectingUiSnapshot = false;
thread_local uint64_t faultVolatile[11] = {};
thread_local uint8_t faultX17Bytes[32] = {};
thread_local bool capturedX17 = false;
thread_local bool capturedDiagnosticRegisters = false;
thread_local uint64_t diagnosticRegisters[32] {};
thread_local char faultString[192] = {};
thread_local char faultFormat[192] = {};
thread_local const HmCacheImage *activeGuest = nullptr;
thread_local const uint8_t *activeApp = nullptr;
thread_local char requestedPath[1024] = {};
struct UnsupportedCall { int64_t number; uint64_t arguments[8]; uint64_t result; bool delivered; uint64_t count; char path[512]; };
thread_local UnsupportedCall unsupportedCalls[16] {};
thread_local size_t unsupportedCount = 0;
thread_local bool trapLimitHit = false;
thread_local uint64_t portOptions[3] {};
thread_local bool capturedPortOptions = false;
thread_local uint8_t machRequest[1064] {};
thread_local size_t machRequestSize = 0;
// Keep the payload off the signal stack. CoreFoundation's current XPC request
// is 1960 bytes; retain one bounded complete message rather than a stale header
// from an earlier small check-in.
thread_local uint8_t machSendRequest[4096] {};
thread_local size_t machSendRequestSize = 0;
thread_local uint8_t machSendVectors[48] {};
thread_local bool capturedSendVectors = false;
thread_local char guestConsole[8192] {};
thread_local size_t guestConsoleSize = 0;

extern "C" void hm_guest_console(const void *, uint32_t fd, const uint8_t *bytes, size_t size)
{
    auto *output = inspectingUiSnapshot ? uiSnapshot.console : guestConsole;
    const size_t capacity = inspectingUiSnapshot ? sizeof(uiSnapshot.console) : sizeof(guestConsole);
    auto &used = inspectingUiSnapshot ? uiSnapshot.consoleSize : guestConsoleSize;
    if (!bytes || !size || used >= capacity - 1) return;
    const char prefix[] = "[guest stderr] ";
    if (fd == 2 && used + sizeof(prefix) < capacity) {
        std::memcpy(output + used, prefix, sizeof(prefix) - 1);
        used += sizeof(prefix) - 1;
    }
    for (size_t i = 0; i < size && used < capacity - 1; ++i) {
        const char ch = static_cast<char>(bytes[i]);
        output[used++] = ch >= 32 || ch == '\n' || ch == '\t' ? ch : '?';
    }
}
constexpr size_t trapTraceCapacity = 256;
thread_local TrapRecord trapTrace[trapTraceCapacity] {};
thread_local size_t trapTraceCount = 0;
thread_local size_t trapTraceNext = 0;

void RecordTrap(uintptr_t pc, uintptr_t caller, const HmDarwinTrap &frame, bool dispatched,
    uint64_t indirect = 0)
{
    // Keep both traces independent, including the ring cursor and budget.
    auto *records = inspectingUiSnapshot ? uiSnapshot.trace : trapTrace;
    const size_t capacity = inspectingUiSnapshot ? std::size(uiSnapshot.trace) : trapTraceCapacity;
    auto &count = inspectingUiSnapshot ? uiSnapshot.traceCount : trapTraceCount;
    auto &next = inspectingUiSnapshot ? uiSnapshot.traceNext : trapTraceNext;
    const size_t slot = count < capacity ? count++ : next;
    records[slot] = {static_cast<uint64_t>(trapCount + 1), frame.number, pc, caller, {},
        indirect, {frame.result[0], frame.result[1]}, dispatched};
    std::copy(std::begin(frame.arguments), std::end(frame.arguments), std::begin(records[slot].arguments));
    if (count == capacity) next = (slot + 1) % capacity;
}

bool InAppCode(uintptr_t address)
{
#if defined(__aarch64__) && defined(HM_HAS_AOT_TARGET)
    const auto base = reinterpret_cast<uintptr_t>(activeApp);
    return base && address >= base && address - base < HM_TARGET_SPAN;
#else
    return false;
#endif
}

bool DispatchDarwinTrap(int number, void *context)
{
#if defined(__aarch64__)
    if (number != SIGTRAP || !activeProbe || !activeProcess || !context) return false;
    auto &state = static_cast<ucontext_t *>(context)->uc_mcontext;
    const auto pc = static_cast<uintptr_t>(state.pc);
    if (InAppCode(pc)) appCodeExecuted = true;
    const bool inCache = pc >= guestBegin && pc <= guestEnd - 4;
    const bool inBootstrap = bootstrapBegin && pc >= bootstrapBegin && pc <= bootstrapEnd - 4;
    if (!inCache && !inBootstrap) return false;
    if (stopUnknownSyscall && trapCount >= TrapLimit) {
        if (!inspectingUiSnapshot) trapLimitHit = true;
        return false;
    }
    const auto instruction = *reinterpret_cast<const uint32_t *>(pc);
    if ((instruction & 0xffe0001fU) == 0xd4400000U) {
        // Audited diagnostic HLT inserted by pack_cache. Record all argument
        // registers and stop without pretending to skip the original call.
        HmDarwinTrap record {};
        record.number = -2000;
        for (size_t i = 0; i < 8; ++i) record.arguments[i] = state.regs[i];
        if (!inspectingUiSnapshot) {
            for (size_t i = 0; i < std::size(diagnosticRegisters); ++i)
                diagnosticRegisters[i] = state.regs[i];
            capturedDiagnosticRegisters = true;
        }
        RecordTrap(pc, state.regs[30], record, false);
        ++trapCount;
        return false;
    }
    if ((instruction & 0xfffffc1fU) == 0xd4294000U) {
        const auto reg = (instruction >> 5) & 31;
        if (reg != 31) state.regs[reg] = hm_process_tsd_base(activeProcess);
        HmDarwinTrap record {};
        record.number = -1000;
        record.arguments[0] = instruction;
        record.result[0] = state.regs[reg];
        RecordTrap(pc, state.regs[30], record, true);
        state.pc = hm_process_resume_pc(activeProcess, state.pc + 4);
        ++trapCount;
        return true;
    }
    if (instruction != 0xd42909a0) return false;
    HmDarwinTrap frame {};
    frame.number = static_cast<int64_t>(state.regs[16]);
    if (inspectingUiSnapshot) uiSnapshot.lastSyscall = frame.number;
    else lastSyscall = frame.number;
    for (size_t i = 0; i < 8; ++i) frame.arguments[i] = state.regs[i];
    uint64_t indirect = 0;
    if ((frame.number == -15 || frame.number == -10) && activeGuest) {
        hm_guest_copy_in(activeGuest, frame.arguments[1],
            reinterpret_cast<uint8_t *>(&indirect), sizeof(indirect));
    }
    if (!inspectingUiSnapshot && frame.number == -47 && activeGuest && (frame.arguments[1] & 1)) {
        machSendRequestSize = 0;
        capturedSendVectors = false;
        uint64_t sendSize = frame.arguments[2] >> 32;
        uint64_t sendAddress = frame.arguments[0];
        if (frame.arguments[1] & (1ULL << 32)) {
            uint8_t vectors[48] {};
            if (sendSize == 2 && !hm_guest_copy_in(activeGuest, frame.arguments[0],
                    vectors, sizeof(vectors))) {
                std::memcpy(machSendVectors, vectors, sizeof(vectors));
                capturedSendVectors = true;
                std::memcpy(&sendAddress, vectors, sizeof(sendAddress));
                std::memcpy(&sendSize, vectors + 16, sizeof(uint32_t));
            } else {
                sendSize = 0;
            }
        }
        if (sendSize >= 24 && sendSize <= sizeof(machSendRequest) &&
            !hm_guest_copy_in(activeGuest, sendAddress, machSendRequest, sendSize))
            machSendRequestSize = sendSize;
    }
    frame.nzcv = state.pstate;
    // Rust dispatch is allocation-free; configured native callbacks perform
    // bounded host operations without replacing the host's thread state.
    dispatchingCall = frame.number;
    std::copy(std::begin(frame.arguments), std::end(frame.arguments), dispatchingArguments);
    // Read change lists before dispatch: ERROR_EVENTS may reuse the same
    // buffer for receipts and overwrite the original request.
    if ((frame.number == 374 || frame.number == 375) && activeGuest &&
        frame.arguments[2] <= 64) {
        for (size_t i = 0; i < frame.arguments[2]; ++i) {
            if (keventCallCount == std::size(keventCalls)) {
                ++keventCallDropped;
                continue;
            }
            KeventCallAudit record;
            record.workloop = frame.number == 375 ? frame.arguments[0] : 0;
            record.syscallFlags = frame.arguments[7];
            record.scene = inspectingUiSnapshot;
            if (!hm_guest_copy_in(activeGuest, frame.arguments[1] + i * 72,
                    reinterpret_cast<uint8_t *>(record.words), sizeof(record.words))) {
                keventCalls[keventCallCount++] = record;
            }
        }
    }
    const int dispatched = hm_darwin_dispatch(activeProcess, &frame);
    dispatchingCall = 0;
    if (frame.number == 360 || frame.number == 361 || frame.number == 366 ||
        frame.number == 367 || frame.number == 368) {
        const auto opcode = frame.number == 368 ? frame.arguments[0] : 0;
        size_t slot = 0;
        while (slot < threadCallCount && (threadCalls[slot].number != frame.number ||
                threadCalls[slot].opcode != opcode)) ++slot;
        if (slot == threadCallCount && threadCallCount < std::size(threadCalls)) ++threadCallCount;
        if (slot < std::size(threadCalls)) {
            auto &record = threadCalls[slot];
            record.number = frame.number; record.opcode = opcode; ++record.count;
            std::copy(std::begin(frame.arguments), std::end(frame.arguments), record.arguments);
            record.result = frame.result[0];
        }
        if (frame.number == 366 && activeGuest) {
            const size_t size = std::min<size_t>(frame.arguments[4], sizeof(threadRegistration));
            if (size && !hm_guest_copy_in(activeGuest, frame.arguments[3], threadRegistration, size))
                threadRegistrationSize = size;
        }
    }
    if (dispatched < 0) return false;
    RecordTrap(pc, state.regs[30], frame, dispatched == 0, indirect);
    if (stopUnknownSyscall && dispatched != 0) {
        if (!inspectingUiSnapshot) {
            size_t slot = 0;
            while (slot < unsupportedCount && unsupportedCalls[slot].number != frame.number) ++slot;
            if (slot == unsupportedCount) {
                slot = unsupportedCount < std::size(unsupportedCalls) ? unsupportedCount++ : unsupportedCount - 1;
                unsupportedCalls[slot] = {};
            }
            auto &call = unsupportedCalls[slot];
            call.number = frame.number;
            ++call.count;
            for (size_t i = 0; i < 8; ++i) call.arguments[i] = frame.arguments[i];
            call.result = frame.result[0];
            call.delivered = static_cast<int32_t>(frame.number) >= 0 && static_cast<int32_t>(frame.number) != 521;
            // Preserve bounded pathname evidence for missing file operations;
            // raw guest addresses are unavailable after this attempt ends.
            if (activeGuest && (frame.number == 33 || frame.number == 220 ||
                    frame.number == 340 || frame.number == 398)) {
                std::memset(call.path, 0, sizeof(call.path));
                for (size_t n = 0; n + 1 < sizeof(call.path); ++n) {
                    if (hm_guest_copy_in(activeGuest, frame.arguments[0] + n,
                            reinterpret_cast<uint8_t *>(call.path + n), 1)) {
                        call.path[n] = 0;
                        break;
                    }
                    if (!call.path[n]) break;
                }
            }
        }
        // Unsupported BSD operations return real Darwin ENOSYS/carry so Apple
        // code can take its own optional-feature fallback. Mach interfaces need
        // their individual return conventions and remain explicit stop points.
        // A requested abort is always terminal for this guest attempt.
        if (static_cast<int32_t>(frame.number) < 0 || static_cast<int32_t>(frame.number) == 521) {
            if (!inspectingUiSnapshot) unsupportedDarwinCall = true;
            return false;
        }
    }
    state.regs[0] = frame.result[0];
    state.regs[1] = frame.result[1];
    state.pstate = frame.nzcv;
    state.pc = hm_process_resume_pc(activeProcess, state.pc + 4);
    ++trapCount;
    return true;
#else
    return false;
#endif
}

bool AdaptUnsignedObjcPointer(int number, void *context)
{
#if defined(__aarch64__) && defined(HM_HAS_AOT_TARGET)
    if (number != SIGILL || !context || !activeProbe || activeApp != hm_target_image || !activeGuest) return false;
    auto &state = static_cast<ucontext_t *>(context)->uc_mcontext;
    if (InAppCode(state.pc)) appCodeExecuted = true;
    if (state.pc < guestBegin || state.pc > guestEnd - 4) return false;
    const auto instruction = *reinterpret_cast<const uint32_t *>(state.pc);
    const auto operation = instruction & ~0x3ffU;
    constexpr uint32_t autib = 0xdac11400U;
    constexpr uint32_t autda = 0xdac11800U;
    if (operation != autib && operation != autda) return false;
    const auto valueReg = instruction & 31, modifierReg = (instruction >> 5) & 31;
    if (valueReg == 31 || modifierReg == 31) return false;
    const auto base = reinterpret_cast<uintptr_t>(activeApp);
    if (operation == autib) {
        // libunwind stores a procedure pointer and its address discriminator
        // as adjacent 64-bit values in the guest exception frame. The original
        // ARM64 App writes that pointer without a PAC; ARM64e libunwind then
        // reads it here and authenticates it with the IB key. Adapt only a
        // live guest stack slot whose stored value is the pointer being
        // authenticated, and only for an audited App/cache code address.
        const auto value = state.regs[valueReg];
        const auto modifier = state.regs[modifierReg];
        const auto stackBase = reinterpret_cast<uintptr_t>(activeGuest->stack);
        const auto stackEnd = stackBase + activeGuest->stackSize;
        const bool valueInCache = value >= guestBegin && value < guestEnd;
        const bool valueInApp = value >= base && value - base < HM_TARGET_SPAN;
        if ((modifier & 7) != 0 || !stackBase || modifier < stackBase + 8 ||
            modifier > stackEnd || (value & 3) != 0 || (!valueInCache && !valueInApp)) {
            return false;
        }
        uint64_t current = 0;
        if (hm_guest_copy_in(activeGuest, modifier - 8,
                reinterpret_cast<uint8_t *>(&current), sizeof(current)) || current != value) {
            return false;
        }
        const auto signedValue = hm_pac_sign_pointer(value, modifier, 1);
        state.regs[valueReg] = signedValue;
        HmDarwinTrap trace {};
        trace.number = -1006;
        trace.arguments[0] = modifier - 8;
        trace.arguments[1] = value;
        trace.arguments[2] = modifier;
        trace.result[0] = signedValue;
        RecordTrap(state.pc, state.regs[30], trace, true);
        ++trapCount;
        return true;
    }
    // ARM64 associated-conformance tail thunks pass an unsigned opaque
    // descriptor to the ARM64e SwiftCore entry. Both the descriptor and the
    // thunk come from the immutable App bytes audited by the packager. Limit
    // conversion to the observed SwiftCore caller and its original AUTDA;
    // never authenticate an arbitrary stack/cache pointer on the App's behalf.
    if (state.pc == guestBegin + 0x1d72454 &&
        state.regs[modifierReg] == 0xbdd1 &&
        state.regs[30] == guestBegin + 0x1d3a5b0 &&
        std::memcmp(activeGuest->base + 88, HM_TARGET_OBJC_CACHE_UUID, 16) == 0) {
        for (size_t i = 0; i < HM_TARGET_SWIFT_OPAQUE_COUNT; ++i) {
            const auto &record = HM_TARGET_SWIFT_OPAQUE[i];
            if (state.regs[valueReg] != base + record.offset || state.regs[9] != base + record.accessor) continue;
            uint64_t header;
            std::memcpy(&header, reinterpret_cast<const void *>(base + record.offset), sizeof(header));
            if (header != record.header) continue;
            const auto signedValue = hm_pac_sign_pointer(base + record.offset, 0xbdd1, 2);
            state.regs[valueReg] = signedValue;
            HmDarwinTrap trace {};
            trace.number = -1004;
            trace.arguments[0] = base + record.offset;
            trace.arguments[1] = base + record.accessor;
            trace.arguments[2] = record.header;
            trace.result[0] = signedValue;
            RecordTrap(state.pc, state.regs[30], trace, true);
            ++trapCount;
            return true;
        }
    }
    for (size_t i = 0; i < HM_TARGET_OBJC_POINTER_COUNT; ++i) {
        const auto &record = HM_TARGET_OBJC_POINTERS[i];
        if (record.cacheTarget && std::memcmp(activeGuest->base + 88, HM_TARGET_OBJC_CACHE_UUID, 16)) continue;
        const auto slot = base + record.slot;
        const auto expected = (record.cacheTarget ? reinterpret_cast<uintptr_t>(activeGuest->base) : base) + record.target;
        const auto modifier = (slot & 0x0000ffffffffffffULL) | (record.diversity << 48);
        uint64_t current; std::memcpy(&current, reinterpret_cast<const void *>(slot), 8);
        if (current != expected || state.regs[valueReg] != expected || state.regs[modifierReg] != modifier) continue;
        // The original ARM64 App contains an unsigned rebase or class bind.
        // Adapt exactly its audited field to the ARM64e runtime contract;
        // retain AUTDA itself and retry it with a correctly signed pointer.
        const auto signedValue = hm_pac_sign_pointer(expected, modifier, 2);
        std::memcpy(reinterpret_cast<void *>(slot), &signedValue, 8);
        state.regs[valueReg] = signedValue;
        HmDarwinTrap recordTrace {};
        recordTrace.number = -1001;
        recordTrace.arguments[0] = slot;
        recordTrace.arguments[1] = expected;
        recordTrace.result[0] = signedValue;
        RecordTrap(state.pc, state.regs[30], recordTrace, true);
        ++trapCount;
        return true;
    }
    // An ARM64 Swift app calls an ARM64e Swift runtime with unsigned
    // conformance descriptors. Apple's runtime authenticates this one
    // argument at swift_getWitnessTable. Bind the adaptation to that exact
    // cache instruction, diversity, and the audited target image bounds.
    constexpr uint64_t swiftWitnessAuthOffset = 0x1cb76b0;
    constexpr uint64_t swiftWitnessDiversity = 0xc6eb;
    const auto value = state.regs[valueReg];
    if (state.pc == guestBegin + swiftWitnessAuthOffset &&
        state.regs[modifierReg] == swiftWitnessDiversity &&
        std::memcmp(activeGuest->base + 88, HM_TARGET_OBJC_CACHE_UUID, 16) == 0) {
        for (size_t i = 0; i < HM_TARGET_SWIFT_WITNESS_COUNT; ++i) {
            const auto &record = HM_TARGET_SWIFT_WITNESSES[i];
            if (state.regs[30] != base + record.caller || value != guestBegin + record.target) continue;
            uint64_t current;
            std::memcpy(&current, reinterpret_cast<const void *>(base + record.slot), sizeof(current));
            if (current != value) continue;
            const auto signedValue = hm_pac_sign_pointer(value, swiftWitnessDiversity, 2);
            state.regs[valueReg] = signedValue;
            HmDarwinTrap trace {};
            trace.number = -1005;
            trace.arguments[0] = base + record.slot;
            trace.arguments[1] = value;
            trace.arguments[2] = base + record.caller;
            trace.result[0] = signedValue;
            RecordTrap(state.pc, state.regs[30], trace, true);
            ++trapCount;
            return true;
        }
    }
    if (state.pc == guestBegin + swiftWitnessAuthOffset &&
        state.regs[modifierReg] == swiftWitnessDiversity && InAppCode(state.regs[30]) &&
        std::memcmp(activeGuest->base + 88, HM_TARGET_OBJC_CACHE_UUID, 16) == 0) {
        // __swift5_proto uses 32-bit relative references: a valid conformance
        // may be aligned to four bytes. Whitelist its immutable descriptor
        // instead of rejecting it for not being pointer-aligned.
        for (size_t i = 0; i < HM_TARGET_SWIFT_LOCAL_CONFORMANCE_COUNT; ++i) {
            const auto &record = HM_TARGET_SWIFT_LOCAL_CONFORMANCES[i];
            if (value != base + record.offset) continue;
            uint64_t header[2];
            std::memcpy(header, activeApp + record.offset, sizeof(header));
            if (header[0] != record.first || header[1] != record.second) return false;
            const auto signedValue = hm_pac_sign_pointer(value, swiftWitnessDiversity, 2);
            state.regs[valueReg] = signedValue;
            HmDarwinTrap recordTrace {};
            recordTrace.number = -1002;
            if (inspectingUiSnapshot) ++uiSnapshot.localConformanceAdaptations;
            recordTrace.arguments[0] = value;
            recordTrace.arguments[1] = signedValue;
            recordTrace.result[0] = swiftWitnessDiversity;
            RecordTrap(state.pc, state.regs[30], recordTrace, true);
            ++trapCount;
            return true;
        }
    }
    // Swift metadata is bound into the ARM64 App's data/GOT slots as
    // unsigned pointers. The ARM64e runtime then authenticates those slots
    // with a slot-derived modifier and a metadata-class diversity. Sign only
    // a live App data slot whose current value is the pointer being
    // authenticated; every target remains bounded to the App or guest cache.
    const auto modifier = state.regs[modifierReg];
    const auto cacheValue = state.regs[valueReg];
    const auto slot = modifier & 0x0000ffffffffffffULL;
    const bool valueInCache = cacheValue >= guestBegin && cacheValue < guestEnd;
    const bool valueInApp = cacheValue >= base && cacheValue - base < HM_TARGET_SPAN;
    if ((slot & 7) == 0 && slot >= base + 0x8000 && slot < base + 0x10000 &&
        (valueInCache || valueInApp)) {
        uint64_t current; std::memcpy(&current, reinterpret_cast<const void *>(slot), 8);
        if (current == cacheValue) {
            const auto signedValue = hm_pac_sign_pointer(cacheValue, modifier, 2);
            // Keep the data slot and all other registers in their original
            // ARM64 representation. Later AUTDA instructions at the same slot
            // will hit this audit again and receive their own ephemeral value.
            state.regs[valueReg] = signedValue;
            HmDarwinTrap recordTrace {};
            recordTrace.number = -1003;
            recordTrace.arguments[0] = slot;
            recordTrace.arguments[1] = cacheValue;
            recordTrace.arguments[2] = modifier;
            recordTrace.result[0] = signedValue;
            recordTrace.result[1] = modifier;
            RecordTrap(state.pc, state.regs[30], recordTrace, true);
            ++trapCount;
            return true;
        }
    }
#endif
    return false;
}

bool AdaptSignedSwiftValueWitness(int number, siginfo_t *info, void *context)
{
#if defined(__aarch64__) && defined(HM_HAS_AOT_TARGET)
    if (number != SIGSEGV || !info || !context || !activeProbe || !activeGuest ||
        activeApp != hm_target_image) return false;
    auto &state = static_cast<ucontext_t *>(context)->uc_mcontext;
    const auto base = reinterpret_cast<uintptr_t>(activeApp);
    if (!InAppCode(state.pc) ||
        std::memcmp(activeGuest->base + 88, HM_TARGET_OBJC_CACHE_UUID, 16)) return false;
    for (size_t i = 0; i < HM_TARGET_SWIFT_VALUE_WITNESS_LOAD_COUNT; ++i) {
        const auto &record = HM_TARGET_SWIFT_VALUE_WITNESS_LOADS[i];
        if (state.pc != base + record.pc) continue;
        // The packager bounded this pair to the immutable App __text. App
        // code is outside the cache/heap address space accepted by copy_in.
        if (record.pc < 4 || record.pc > HM_TARGET_SPAN - 4) return false;
        uint32_t instructions[2];
        std::memcpy(instructions, activeApp + record.pc - 4, sizeof(instructions));
        if (instructions[0] != record.metadataLoad || instructions[1] != record.layoutLoad) return false;
        const auto tableRegister = record.metadataLoad & 31;
        const auto metadataRegister = (record.metadataLoad >> 5) & 31;
        const auto metadata = state.regs[metadataRegister];
        if ((metadata & 7) || metadata < 8) return false;
        uint64_t stored = 0;
        const auto slot = metadata - 8;
        if (hm_guest_copy_in(activeGuest, slot, reinterpret_cast<uint8_t *>(&stored), 8) ||
            stored != state.regs[tableRegister]) return false;
        const auto raw = hm_pac_strip_data(stored);
        const auto field = ((record.layoutLoad >> 10) & 0xfff) * 8;
        if (raw == stored || (raw & 7) ||
            reinterpret_cast<uintptr_t>(info->si_addr) != stored + field) return false;
        // Validate the original DA signature. Never modify Apple metadata or
        // turn an invalid pointer into an accepted one by simply stripping it.
        const auto modifier = (slot & 0x0000ffffffffffffULL) | (uint64_t(0x2e3f) << 48);
        const auto expected = hm_pac_sign_pointer(raw, modifier, 2);
        if (inspectingUiSnapshot) {
            uiSnapshot.valueWitnessStored = stored;
            uiSnapshot.valueWitnessExpected = expected;
        }
        if (expected != stored) return false;
        uint8_t layout[88];
        if (hm_guest_copy_in(activeGuest, raw, layout, sizeof(layout))) return false;
        state.regs[tableRegister] = raw;
        if (inspectingUiSnapshot) ++uiSnapshot.valueWitnessAdaptations;
        HmDarwinTrap trace {};
        trace.number = -1007;
        trace.arguments[0] = slot;
        trace.arguments[1] = stored;
        trace.arguments[2] = modifier;
        trace.result[0] = raw;
        RecordTrap(state.pc, state.regs[30], trace, true);
        ++trapCount;
        return true;
    }
#endif
    return false;
}

void ProbeSignal(int number, siginfo_t *info, void *context)
{
    if ((number == SIGBUS || number == SIGSEGV) && activeProbe && activeGuest && info) {
        const auto savedErrno = errno;
        const bool loaded = hm_cache_data_fault(activeGuest, reinterpret_cast<uintptr_t>(info->si_addr));
        errno = savedErrno;
        if (loaded) return;
    }
    if (AdaptSignedSwiftValueWitness(number, info, context)) return;
    if (AdaptUnsignedObjcPointer(number, context)) return;
    if (DispatchDarwinTrap(number, context)) return;
    if (activeProbe) {
        if (inspectingUiSnapshot) {
            uiSnapshot.signal = number;
            uiSnapshot.faultAddress = info ? reinterpret_cast<uintptr_t>(info->si_addr) : 0;
#if defined(__aarch64__)
            if (context) {
                const auto &state = static_cast<ucontext_t *>(context)->uc_mcontext;
                uiSnapshot.faultPc = state.pc;
                uiSnapshot.faultLr = state.regs[30];
                if (static_cast<int32_t>(state.regs[16]) == 521 && activeGuest) {
                    for (size_t i = 0; i + 1 < sizeof(uiSnapshot.abortReason); ++i) {
                        char byte = 0;
                        if (hm_guest_copy_in(activeGuest, state.regs[4] + i,
                                reinterpret_cast<uint8_t *>(&byte), 1) || !byte) break;
                        uiSnapshot.abortReason[i] = byte >= 32 && byte < 127 ? byte : '?';
                    }
                }
                for (size_t i = 0; i < 8; ++i) uiSnapshot.faultArguments[i] = state.regs[i];
                uint64_t frame = state.regs[29];
                while (uiSnapshot.faultFrameCount < std::size(uiSnapshot.faultFrames)) {
                    uint64_t record[2];
                    if ((frame & 15) || !activeGuest || hm_guest_copy_in(activeGuest, frame,
                            reinterpret_cast<uint8_t *>(record), sizeof(record))) break;
                    const auto next = hm_pac_strip_data(record[0]);
                    uiSnapshot.faultFrames[uiSnapshot.faultFrameCount++] =
                        hm_pac_strip_instruction(record[1]);
                    if (next <= frame) break;
                    frame = next;
                }
            }
#endif
            siglongjmp(*activeProbe, 1);
        }
        caughtSignal = number;
#if defined(__aarch64__)
        if (context) {
            const auto &state = static_cast<ucontext_t *>(context)->uc_mcontext;
            dispatchFaultCall = dispatchingCall;
            for (size_t i = 0; i < 8; ++i) dispatchFaultArguments[i] = dispatchingArguments[i];
            std::memset(dispatchFaultPath, 0, sizeof(dispatchFaultPath));
            if (dispatchFaultCall && activeGuest && dispatchingArguments[0]) {
                for (size_t i = 0; i + 1 < sizeof(dispatchFaultPath); ++i) {
                    char byte = 0;
                    if (hm_guest_copy_in(activeGuest, dispatchingArguments[0] + i,
                        reinterpret_cast<uint8_t *>(&byte), 1) || !byte) break;
                    dispatchFaultPath[i] = byte >= 32 && byte < 127 ? byte : '?';
                }
            }
            faultPc = state.pc;
            faultLr = state.regs[30];
            faultSp = state.sp;
            capturedFaultStack = activeGuest && !hm_guest_copy_in(activeGuest, faultSp,
                faultStackBytes, sizeof(faultStackBytes));
            capturedFaultPc = activeGuest && !hm_guest_copy_in(activeGuest, faultPc,
                faultPcBytes, sizeof(faultPcBytes));
            lastSyscall = static_cast<int64_t>(state.regs[16]);
            for (size_t i = 0; i < 8; ++i) faultArguments[i] = state.regs[i];
            for (size_t i = 0; i < std::size(faultRegisters); ++i) faultRegisters[i] = state.regs[19 + i];
            for (size_t i = 0; i < 11; ++i) faultVolatile[i] = state.regs[8 + i];
            capturedX17 = activeGuest && !hm_guest_copy_in(activeGuest, state.regs[17],
                faultX17Bytes, sizeof(faultX17Bytes));
            faultFrameCount = 0;
            std::memset(faultString, 0, sizeof(faultString));
            std::memset(faultFormat, 0, sizeof(faultFormat));
            if (activeGuest) {
                for (size_t i = 0; i + 1 < sizeof(faultString); ++i) {
                    char byte = 0;
                    if (hm_guest_copy_in(activeGuest, state.regs[20] + i,
                        reinterpret_cast<uint8_t *>(&byte), 1)) break;
                    if (!byte) break;
                    faultString[i] = byte >= 32 && byte < 127 ? byte : '?';
                }
                for (size_t i = 0; i + 1 < sizeof(faultFormat); ++i) {
                    char byte = 0;
                    if (hm_guest_copy_in(activeGuest, state.regs[2] + i,
                        reinterpret_cast<uint8_t *>(&byte), 1)) break;
                    if (!byte) break;
                    faultFormat[i] = byte >= 32 && byte < 127 ? byte : '?';
                }
                uint64_t frame = state.regs[29];
                for (size_t i = 0; i < sizeof(faultFrames) / sizeof(faultFrames[0]); ++i) {
                    uint64_t record[2];
                    if (frame & 15 || hm_guest_copy_in(activeGuest, frame,
                        reinterpret_cast<uint8_t *>(record), sizeof(record))) break;
                    constexpr uint64_t pointerMask = 0x0000ffffffffffffULL;
                    const uint64_t returnAddress = record[1] & pointerMask;
                    const uint64_t nextFrame = record[0] & pointerMask;
                    if (!returnAddress) break;
                    if (InAppCode(returnAddress)) appCodeExecuted = true;
                    faultFrames[faultFrameCount++] = returnAddress;
                    if (nextFrame <= frame) break;
                    frame = nextFrame;
                }
            }
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

// Experimental scene bring-up after the original App run has stopped. This
// may invoke lifecycle callbacks; it never establishes a rendered-frame claim.
extern "C" int HmProbeUiScene()
{
#if defined(__aarch64__) && defined(HM_HAS_AOT_TARGET)
    using GetClass = void *(*)(const char *);
    using RegisterSelector = void *(*)(const char *);
    using GetObjectClass = void *(*)(void *);
    using GetMethodImplementation = void *(*)(void *, void *);
    using UnaryMethod = void *(*)(void *, void *);
    using CountMethod = unsigned long (*)(void *, void *);

    const auto base = guestBegin;
    if (!activeGuest || std::memcmp(activeGuest->base + 88, HM_TARGET_OBJC_CACHE_UUID, 16)) return 0;
    const auto getClass = reinterpret_cast<GetClass>(base + 0x4203dc);
    const auto getObjectClass = reinterpret_cast<GetObjectClass>(base + 0x40b680);
    const auto registerSelector = reinterpret_cast<RegisterSelector>(base + 0x40e70c);
    auto selector = [&](const char *name) -> void * {
        // Clang declares SEL's cross-language ABI with the "strip" policy
        // (__ptrauth_objc_sel_abi); IMP function pointers authenticate below.
        return reinterpret_cast<void *>(hm_pac_strip_data(
            reinterpret_cast<uint64_t>(registerSelector(name))));
    };
    const auto getImplementation =
        reinterpret_cast<GetMethodImplementation>(base + 0x40fc44);
    auto lookup = [&](void *object, const char *name) -> void * {
        const auto methodSelector = selector(name);
        const auto implementation = getImplementation(getObjectClass(object), methodSelector);
        if (!implementation) return nullptr;
        return reinterpret_cast<void *>(hm_pac_auth_function(
            reinterpret_cast<uint64_t>(implementation)));
    };
    auto callObject = [&](void *receiver, const char *name) -> void * {
        const auto methodSelector = selector(name);
        const auto implementation = lookup(receiver, name);
        if (!implementation) return nullptr;
        return reinterpret_cast<UnaryMethod>(implementation)(receiver, methodSelector);
    };
    auto callObjects = [&](void *receiver, const char *name, void *a0 = nullptr,
            void *a1 = nullptr, void *a2 = nullptr, void *a3 = nullptr, void *a4 = nullptr) -> void * {
        if (!receiver) return nullptr;
        const auto methodSelector = selector(name);
        const auto implementation = lookup(receiver, name);
        if (!implementation) return nullptr;
        using ObjectMethod = void *(*)(void *, void *, void *, void *, void *, void *, void *);
        return reinterpret_cast<ObjectMethod>(implementation)(receiver, methodSelector, a0, a1, a2, a3, a4);
    };
    auto callCount = [&](void *receiver, const char *name) -> unsigned long {
        const auto methodSelector = selector(name);
        const auto implementation = lookup(receiver, name);
        if (!implementation) return 0;
        return reinterpret_cast<CountMethod>(implementation)(receiver, methodSelector);
    };

    const bool attempted = uiSnapshot.attempted;
    uiSnapshot = {};
    uiSnapshot.attempted = attempted;
    uiSnapshot.stage = 1;
    auto *applicationClass = getClass("UIApplication");
    if (!applicationClass) return 0;
    uiSnapshot.stage = 2;
    const auto sharedSelector = selector("sharedApplication");
    uiSnapshot.stage = 3;
    const auto sharedImplementation = getImplementation(
        getObjectClass(applicationClass), sharedSelector);
    if (!sharedImplementation) return 0;
    uiSnapshot.stage = 4;
    auto *application = reinterpret_cast<UnaryMethod>(
        hm_pac_auth_function(reinterpret_cast<uint64_t>(sharedImplementation)))(
        applicationClass, sharedSelector);
    uiSnapshot.application = reinterpret_cast<uint64_t>(application);
    if (!application) return 0;
    using RespondsToSelector = bool (*)(void *, void *);
    const auto respondsToSelector =
        reinterpret_cast<RespondsToSelector>(base + 0x40ed80);
    const char *const applicationSelectors[] = {
        "_createSceneForSession:",
        "_createSceneForSession:withTransitionContext:",
        "_requestSceneSessionActivation:userActivity:options:errorHandler:",
        "requestSceneSessionActivation:userActivity:options:errorHandler:",
        "_sceneForSession:",
        "_supportsSceneLifecycle",
        "_isSceneLifecycleSupported",
    };
    const auto applicationClassObject = getObjectClass(application);
    for (uint32_t index = 0; index < 7; ++index) {
        if (respondsToSelector(applicationClassObject,
                selector(applicationSelectors[index]))) {
            uiSnapshot.applicationSelectorMask |= 1U << index;
        }
    }
    void *delegate = callObject(application, "delegate");
    uiSnapshot.delegate = reinterpret_cast<uint64_t>(delegate);
    if (delegate) {
        const auto delegateClass = getObjectClass(delegate);
        const char *const delegateSelectors[] = {
            "scene:willConnectToSession:options:",
            "application:configurationForConnectingSceneSession:options:",
            "_scene:willConnectToSession:options:",
        };
        for (uint32_t index = 0; index < 3; ++index) {
            if (respondsToSelector(delegateClass, selector(delegateSelectors[index]))) {
                uiSnapshot.delegateSelectorMask |= 1U << index;
            }
        }
    }
    uiSnapshot.stage = 5;
    void *windows = callObject(application, "windows");
    uiSnapshot.stage = 6;
    uiSnapshot.windows = reinterpret_cast<uint64_t>(windows);
    if (!windows) return 0;
    uiSnapshot.windowCount = callCount(windows, "count");
    uiSnapshot.inspected = true;
    if (uiSnapshot.windowCount == 0) {
        using RequestSceneSession = void (*)(void *, void *, void *, void *, void *, void *);
        const char *requestName = "requestSceneSessionActivation:userActivity:options:errorHandler:";
        const auto requestSelector = selector(requestName);
        const auto requestImplementation = lookup(application, requestName);
        if (requestImplementation) {
            uiSnapshot.stage = 10;
            reinterpret_cast<RequestSceneSession>(requestImplementation)(
                application, requestSelector, nullptr, nullptr, nullptr, nullptr);
            uiSnapshot.sceneRequested = true;
            uint64_t defaultMode = 0;
            std::memcpy(&defaultMode, reinterpret_cast<const void *>(base + 0x604ec710),
                sizeof(defaultMode));
            // Audited cache slot 0x604ec710 is an unsigned chained pointer.
            using RunInMode = int32_t (*)(void *, double, uint8_t);
            const auto runInMode = reinterpret_cast<RunInMode>(base + 0x636624);
            if (defaultMode) runInMode(reinterpret_cast<void *>(defaultMode), 0.2, 1);
            void *sessionClass = getClass("UISceneSession");
            void *uuidClass = getClass("NSUUID");
            void *stringClass = getClass("NSString");
            if (sessionClass && uuidClass && stringClass) {
                void *uuidObject = callObject(uuidClass, "UUID");
                void *uuid = uuidObject ? callObject(uuidObject, "UUIDString") : nullptr;
                const auto stringWithUTF8 = selector("stringWithUTF8String:");
                const auto stringImplementation = lookup(stringClass, "stringWithUTF8String:");
                using StringWithUTF8 = void *(*)(void *, void *, const char *);
                void *configurationName = stringImplementation ?
                    reinterpret_cast<StringWithUTF8>(stringImplementation)(
                        stringClass, stringWithUTF8, "Default Configuration") : nullptr;
                uint64_t role = 0;
                std::memcpy(&role, reinterpret_cast<const void *>(base + 0x60609368),
                    sizeof(role));
                // Audited cache slot 0x60609368 is an unsigned chained pointer.
                void *sessionAllocation = callObject(sessionClass, "alloc");
                const char *initSessionName = "_initWithPersistentIdentifier:sessionRole:configurationName:";
                const auto initSessionSelector = selector(initSessionName);
                const auto initSessionImplementation = sessionAllocation ?
                    lookup(sessionAllocation, initSessionName) : nullptr;
                using InitSession = void *(*)(void *, void *, void *, void *, void *);
                void *session = (initSessionImplementation && uuid && role && configurationName) ?
                    reinterpret_cast<InitSession>(initSessionImplementation)(
                        sessionAllocation, initSessionSelector, uuid,
                        reinterpret_cast<void *>(role), configurationName) : nullptr;
                uiSnapshot.sceneSession = reinterpret_cast<uint64_t>(session);
                uiSnapshot.stage = 11;
                if (session && delegate) {
                    const char *configurationNameSelector =
                        "application:configurationForConnectingSceneSession:options:";
                    const auto configurationSelector = selector(configurationNameSelector);
                    const auto configurationImplementation =
                        lookup(delegate, configurationNameSelector);
                    using GetSceneConfiguration = void *(*)(void *, void *, void *, void *, void *);
                    void *configuration = configurationImplementation ?
                        reinterpret_cast<GetSceneConfiguration>(configurationImplementation)(
                            delegate, configurationSelector, application, session, nullptr) : nullptr;
                    uiSnapshot.sceneConfiguration = reinterpret_cast<uint64_t>(configuration);
                    if (configuration) {
                        const char *updateName = "_updateConfiguration:";
                        const auto updateSelector = selector(updateName);
                        const auto updateImplementation = lookup(session, updateName);
                        using UpdateConfiguration = void (*)(void *, void *, void *);
                        if (updateImplementation) {
                            reinterpret_cast<UpdateConfiguration>(updateImplementation)(
                                session, updateSelector, configuration);
                        }
                    }
                }
                uiSnapshot.stage = 12;
                // A real FBS scene supplies connection values, specification,
                // settings, and the UIKit context binder. A zero-initialized
                // UISceneConnectionOptions object violates those contracts.
                uiSnapshot.sceneContextRequired = true;
                if (session && uiSnapshot.sceneConfiguration) {
                    uiSnapshot.stage = 20;
                    void *specification = callObject(getClass("UIApplicationSceneSpecification"), "specification");
                    uiSnapshot.sceneSpecification = reinterpret_cast<uint64_t>(specification);
                    uiSnapshot.stage = 21;
                    void *fbsScene = specification ? callObjects(getClass("FBSScene"),
                        "pseudoSceneWithIdentifier:specification:", uuid, specification) : nullptr;
                    uiSnapshot.fbsScene = reinterpret_cast<uint64_t>(fbsScene);
                    if (fbsScene) {
                        uiSnapshot.stage = 22;
                        void *transitionClass = callObject(specification, "transitionContextClass");
                        void *transition = transitionClass ? callObject(transitionClass, "new") : nullptr;
                        void *actions = callObject(getClass("NSSet"), "set");
                        void *uiSceneClass = getClass("UIScene");
                        uiSnapshot.stage = 23;
                        void *options = callObjects(uiSceneClass,
                            "_connectionOptionsForScene:withSpecification:transitionContext:actions:sceneSession:",
                            fbsScene, specification, transition, actions, session);
                        uiSnapshot.connectionOptions = reinterpret_cast<uint64_t>(options);
                        if (options) {
                            uiSnapshot.stage = 24;
                            using CreateScene = void *(*)(void *, void *, void *, bool, void *, void *);
                            const char *createName = "_sceneForFBSScene:create:withSession:connectionOptions:";
                            const auto createSelector = selector(createName);
                            const auto createImplementation = lookup(uiSceneClass, createName);
                            void *scene = createImplementation ? reinterpret_cast<CreateScene>(createImplementation)(
                                uiSceneClass, createSelector, fbsScene, true, session, options) : nullptr;
                            uiSnapshot.uiScene = reinterpret_cast<uint64_t>(scene);
                            uiSnapshot.stage = 25;
                            if (scene) {
                                uiSnapshot.sceneContextRequired = false;
                                uiSnapshot.sceneDelegate = reinterpret_cast<uint64_t>(callObject(scene, "delegate"));
                                // The UIKit factory already runs connection handlers,
                                // _readySceneForConnection, and the delegate callback.
                                uiSnapshot.stage = 26;
                                callObject(scene, "_finishSceneConnection");
                                uiSnapshot.stage = 27;
                            }
                        }
                    }
                }
            }
            windows = callObject(application, "windows");
            uiSnapshot.windows = reinterpret_cast<uint64_t>(windows);
            uiSnapshot.windowCount = windows ? callCount(windows, "count") : 0;
        }
    }
    uiSnapshot.stage = 7;
    void *window = windows ? callObject(windows, "firstObject") : nullptr;
    uiSnapshot.window = reinterpret_cast<uint64_t>(window);
    if (!window) return 0;
    uiSnapshot.stage = 8;
    void *windowScene = callObject(window, "windowScene");
    void *rootViewController = callObject(window, "rootViewController");
    void *rootView = rootViewController ? callObject(rootViewController, "view") : nullptr;
    void *layer = callObject(window, "layer");
    void *sublayers = layer ? callObject(layer, "sublayers") : nullptr;
    uiSnapshot.windowScene = reinterpret_cast<uint64_t>(windowScene);
    uiSnapshot.rootViewController = reinterpret_cast<uint64_t>(rootViewController);
    uiSnapshot.rootView = reinterpret_cast<uint64_t>(rootView);
    uiSnapshot.layer = reinterpret_cast<uint64_t>(layer);
    uiSnapshot.sublayers = reinterpret_cast<uint64_t>(sublayers);
    uiSnapshot.sublayerCount = sublayers ? callCount(sublayers, "count") : 0;
    uiSnapshot.stage = 9;
    uiSnapshot.inspected = true;
    return 1;
#else
    return 0;
#endif
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
    faultPc = faultAddress = faultLr = 0;
    lastSyscall = 0;
    dispatchingCall = 0;
    dispatchFaultCall = 0;
    std::fill(std::begin(dispatchFaultArguments), std::end(dispatchFaultArguments), 0);
    std::memset(dispatchFaultPath, 0, sizeof(dispatchFaultPath));
    faultFrameCount = 0;
    capturedX17 = false;
    capturedDiagnosticRegisters = false;
    appCodeExecuted = false;
    uiSnapshot = {};
    inspectingUiSnapshot = false;
    threadCallCount = threadRegistrationSize = 0;
    keventCallCount = keventCallDropped = 0;
    std::fill(std::begin(keventCalls), std::end(keventCalls), KeventCallAudit {});
    std::fill(std::begin(threadCalls), std::end(threadCalls), ThreadCallAudit {});
    std::memset(threadRegistration, 0, sizeof(threadRegistration));
    std::memset(diagnosticRegisters, 0, sizeof(diagnosticRegisters));
    stopUnknownSyscall = cache != nullptr;
    unsupportedDarwinCall = false;
    unsupportedCount = 0;
    trapLimitHit = false;
    capturedPortOptions = false;
    machRequestSize = 0;
    machSendRequestSize = 0;
    capturedSendVectors = false;
    guestConsoleSize = 0;
    std::memset(guestConsole, 0, sizeof(guestConsole));
    trapTraceCount = trapTraceNext = 0;
    activeGuest = cache;
    activeApp = static_cast<const uint8_t *>(appHeader);
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
#if defined(__aarch64__) && defined(HM_HAS_AOT_TARGET)
        if (cache && appCodeExecuted) {
            const auto executionTraps = trapCount;
            trapCount = 0;
            inspectingUiSnapshot = true;
            uiSnapshot.attempted = true;
            uiSnapshot.stage = 100;
            sigjmp_buf uiJump;
            if (sigsetjmp(uiJump, 1) == 0) {
                activeProbe = &uiJump;
                hm_enter_guest_stack(reinterpret_cast<void *>(HmProbeUiScene),
                    cache->stack + cache->stackSize - 0x4000, nullptr);
                activeProbe = nullptr;
            } else {
                activeProbe = nullptr;
                uiSnapshot.faulted = true;
            }
            uiSnapshot.traps = trapCount;
            inspectingUiSnapshot = false;
            dispatchingCall = 0;
            trapCount = executionTraps;
        }
#endif
    }
    result.traps = trapCount;
    result.faultPc = faultPc;
    result.faultAddress = faultAddress;
    result.syscall = lastSyscall;
    result.appExecuted = appCodeExecuted;
    result.requestPath = requestedPath;
    if (static_cast<int32_t>(lastSyscall) == 521) { result.message = requestedPath; result.requestPath.clear(); }
    if (capturedPortOptions) {
        std::ostringstream options;
        options << "mach_port_construct options: flags=0x" << std::hex << uint32_t(portOptions[0])
            << ", qlimit=" << std::dec << (portOptions[0] >> 32)
            << ", reserved=0x" << std::hex << portOptions[1] << ",0x" << portOptions[2];
        result.message = options.str();
    }
    if (machSendRequestSize) {
        static constexpr char hex[] = "0123456789abcdef";
        result.message = "mach_msg2 send: ";
        for (size_t i = 0; i < machSendRequestSize; ++i) {
            result.message += hex[machSendRequest[i] >> 4];
            result.message += hex[machSendRequest[i] & 15];
        }
    }
    if (capturedSendVectors) {
        static constexpr char hex[] = "0123456789abcdef";
        if (!result.message.empty()) result.message += " ";
        result.message += "mach_msg2 vectors: ";
        for (auto byte : machSendVectors) {
            result.message += hex[byte >> 4];
            result.message += hex[byte & 15];
        }
    }
    if (machRequestSize) {
        static constexpr char hex[] = "0123456789abcdef";
        if (!result.message.empty()) result.message += " ";
        result.message += "mach_msg2 request: ";
        for (size_t i = 0; i < machRequestSize; ++i) {
            result.message += hex[machRequest[i] >> 4];
            result.message += hex[machRequest[i] & 15];
        }
    }
    if (guestConsoleSize) {
        result.message += result.message.empty() ? "" : " ";
        result.message += "guest console: ";
        result.message.append(guestConsole, guestConsoleSize);
    }
    if (trapTraceCount) {
        std::ostringstream trace;
        trace << (result.message.empty() ? "" : " ") << "recent traps:";
        const size_t first = trapTraceCount < trapTraceCapacity ? 0 : trapTraceNext;
        for (size_t i = 0; i < trapTraceCount; ++i) {
            const auto &record = trapTrace[(first + i) % trapTraceCapacity];
            trace << " [" << record.sequence << ':' << record.number << " pc=0x" << std::hex << record.pc
                << " lr=0x" << record.caller;
            for (size_t argument = 0; argument < std::size(record.arguments); ++argument)
                trace << " a" << std::dec << argument << "=0x" << std::hex << record.arguments[argument];
            if (record.indirect) trace << " indirect=0x" << std::hex << record.indirect;
            trace << " r0=0x" << record.result[0]
                << " r1=0x" << record.result[1] << std::dec << " dispatched="
                << (record.dispatched ? 1 : 0) << ']';
        }
        result.message += trace.str();
    }
    if (uiSnapshot.attempted || uiSnapshot.inspected || uiSnapshot.faulted) {
        std::ostringstream ui;
        ui << (result.message.empty() ? "" : " ")
            << "ui snapshot: inspected=" << (uiSnapshot.inspected ? 1 : 0)
            << " app=0x" << std::hex << uiSnapshot.application
            << " windows=0x" << uiSnapshot.windows << " count=" << std::dec << uiSnapshot.windowCount
            << " window=0x" << std::hex << uiSnapshot.window
            << " scene=0x" << uiSnapshot.windowScene
            << " rootVC=0x" << uiSnapshot.rootViewController
            << " rootView=0x" << uiSnapshot.rootView
            << " layer=0x" << uiSnapshot.layer
            << " sublayers=0x" << uiSnapshot.sublayers
            << " sublayerCount=" << std::dec << uiSnapshot.sublayerCount
            << " delegate=0x" << std::hex << uiSnapshot.delegate
            << " appSelectors=0x" << uiSnapshot.applicationSelectorMask
            << " delegateSelectors=0x" << uiSnapshot.delegateSelectorMask
            << " sceneRequested=" << (uiSnapshot.sceneRequested ? 1 : 0)
            << " session=0x" << std::hex << uiSnapshot.sceneSession
            << " configuration=0x" << std::hex << uiSnapshot.sceneConfiguration
            << " sceneContextRequired=" << uiSnapshot.sceneContextRequired
            << " specification=0x" << std::hex << uiSnapshot.sceneSpecification
            << " fbsScene=0x" << uiSnapshot.fbsScene
            << " options=0x" << uiSnapshot.connectionOptions
            << " uiScene=0x" << uiSnapshot.uiScene
            << " sceneDelegate=0x" << uiSnapshot.sceneDelegate
            << " stage=" << std::dec << uiSnapshot.stage
            << " attempted=" << (uiSnapshot.attempted ? 1 : 0)
            << " faulted=" << (uiSnapshot.faulted ? 1 : 0)
            << " inspectionTraps=" << uiSnapshot.traps
            << " inspectionSyscall=" << uiSnapshot.lastSyscall
            << " inspectionSignal=" << uiSnapshot.signal
            << " inspectionPC=0x" << std::hex << uiSnapshot.faultPc
            << " inspectionAddress=0x" << uiSnapshot.faultAddress
            << " inspectionLR=0x" << uiSnapshot.faultLr
            << " valueWitnessStored=0x" << uiSnapshot.valueWitnessStored
            << " valueWitnessExpected=0x" << uiSnapshot.valueWitnessExpected
            << " valueWitnessAdaptations=" << std::dec << uiSnapshot.valueWitnessAdaptations
            << " localConformanceAdaptations=" << uiSnapshot.localConformanceAdaptations << std::hex;
        if (uiSnapshot.faulted) {
            ui << " inspectionArgs";
            for (auto argument : uiSnapshot.faultArguments) ui << " 0x" << argument;
            ui << " inspectionFrames";
            for (size_t i = 0; i < uiSnapshot.faultFrameCount; ++i)
                ui << " 0x" << uiSnapshot.faultFrames[i];
        }
        if (uiSnapshot.abortReason[0]) ui << " inspectionAbortReason " << uiSnapshot.abortReason;
        if (uiSnapshot.consoleSize) {
            ui << " inspectionConsole ";
            ui.write(uiSnapshot.console, uiSnapshot.consoleSize);
        }
        if (uiSnapshot.traceCount) {
            ui << " inspectionRecentTraps";
            const auto capacity = std::size(uiSnapshot.trace);
            const auto first = uiSnapshot.traceCount < capacity ? 0 : uiSnapshot.traceNext;
            for (size_t i = 0; i < uiSnapshot.traceCount; ++i) {
                const auto &record = uiSnapshot.trace[(first + i) % capacity];
                ui << " [" << std::dec << record.sequence << ':' << record.number
                    << " pc=0x" << std::hex << record.pc << " lr=0x" << record.caller;
                for (size_t n = 0; n < std::size(record.arguments); ++n)
                    ui << " a" << std::dec << n << "=0x" << std::hex << record.arguments[n];
                ui << " r0=0x" << record.result[0] << " dispatched=" << record.dispatched << ']';
            }
        }
        result.message += ui.str();
    }
    if (keventCallCount || keventCallDropped) {
        std::ostringstream events;
        events << " guest kevent changes dropped=" << keventCallDropped;
        for (size_t i = 0; i < keventCallCount; ++i) {
            const auto &call = keventCalls[i];
            events << " [scene=" << call.scene << " wl=0x" << std::hex << call.workloop
                << " flags=0x" << call.syscallFlags << " words=";
            for (auto word : call.words) events << " 0x" << word;
            events << ']';
        }
        result.message += events.str();
    }
    if (threadCallCount) {
        std::ostringstream threads;
        threads << " guest thread calls";
        for (size_t i = 0; i < threadCallCount; ++i) {
            const auto &call = threadCalls[i];
            threads << " [" << std::dec << call.number << " count=" << call.count;
            for (auto argument : call.arguments) threads << " 0x" << std::hex << argument;
            threads << " result=0x" << call.result << ']';
        }
        threads << " registrationBytes=";
        constexpr char hex[] = "0123456789abcdef";
        for (size_t i = 0; i < threadRegistrationSize; ++i)
            threads << hex[threadRegistration[i] >> 4] << hex[threadRegistration[i] & 15];
        result.message += threads.str();
    }
    if (faultFrameCount) {
        std::ostringstream frames;
        frames << (result.message.empty() ? "" : " ") << "return frames:";
        for (size_t i = 0; i < faultFrameCount; ++i)
            frames << " [0x" << std::hex << faultFrames[i] << ']';
        result.message += frames.str();
    }
    activeGuest = nullptr;
    activeApp = nullptr;
    if (unsupportedCount) {
        std::ostringstream trace;
        trace << '[';
        for (size_t i = 0; i < unsupportedCount; ++i) {
            if (i) trace << ',';
            const auto &call = unsupportedCalls[i];
            trace << "{\"number\":" << call.number << ",\"result\":" << call.result
                << ",\"count\":" << call.count
                << ",\"delivered\":" << (call.delivered ? "true" : "false") << ",\"arguments\":[";
            for (size_t n = 0; n < 8; ++n) { if (n) trace << ','; trace << call.arguments[n]; }
            trace << ']';
            if (call.path[0]) {
                trace << ",\"path\":\"";
                for (const char *p = call.path; *p; ++p) {
                    if (*p == '"' || *p == '\\') trace << '\\';
                    trace << (static_cast<unsigned char>(*p) < 32 ? '?' : *p);
                }
                trace << '"';
            }
            trace << '}';
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
    const auto cacheData = hm_prepare_cache_data(cache);
    if (!cacheData.empty()) { result.status = cacheData; return result; }
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
    const auto signature = hm_prepare_code_signature(cache);
    if (!signature.empty()) { munmap(allocation, stackSize + 2 * guardSize); result.status = signature; return result; }
    uint64_t sp = 0;
    if (mprotect(stack, stackSize, PROT_READ | PROT_WRITE) ||
        hm_build_boot_stack(stack, stackSize, reinterpret_cast<uintptr_t>(appHeader), executable.c_str(), &sp)) {
        result.status = "dyld-stack-setup-failed";
        result.error = errno;
    } else {
        auto *process = hm_process_create(getpid(), getppid(), gettid());
        if (!process) result.status = "process-create-failed";
        else {
            hm_process_set_executable(process, executable.c_str(), executable.size());
            ConfigureHostDisplay(process);
            hm_process_set_vm_protect(process, hm_cache_vm_protect, &cache);
            hm_process_set_getentropy(process, hm_guest_getentropy);
            hm_process_set_memory(process, hm_guest_copy_in, hm_guest_copy_out, reinterpret_cast<uintptr_t>(cache.base));
            hm_process_set_clock(process, hm_guest_clock);
            hm_process_set_console(process, hm_guest_console);
            hm_process_set_vm_map(process, hm_guest_vm_map);
            hm_process_set_vm_remap(process, hm_objc_aot_remap);
            hm_process_set_map_file(process, hm_guest_map_file);
            hm_process_set_aot_map_file(process, hm_objc_aot_map_file);
            hm_process_set_fcntl(process, hm_objc_aot_fcntl);
            hm_process_set_vm_deallocate(process, hm_guest_vm_deallocate);
            hm_process_set_files(process, hm_guest_open, hm_guest_close, hm_guest_duplicate);
            hm_process_set_file_stat(process, hm_guest_file_stat);
            hm_process_set_file_io(process, hm_guest_file_read, hm_guest_file_seek);
            hm_process_set_directory_reader(process, hm_guest_read_directory);
            hm_process_set_code_signature(process, hm_guest_code_signature_blob);
            hm_process_set_resolve_file_id(process, hm_guest_resolve_file_id);
            // Native evidence: control actually reached Apple dyld's entry.
            // App handoff remains a separate fact and must set appExecuted
            // at the real App entry call.
            result.dyldEntered = true;
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
        << ", fault address 0x" << result.faultAddress << ", lr=0x" << faultLr << std::dec << ", x16=" << result.syscall
        << ". Args" << std::hex;
    for (auto argument : faultArguments) detail << " 0x" << argument;
    detail << ". x19..x30";
    for (auto value : faultRegisters) detail << " 0x" << value;
    if (dispatchFaultCall) {
        detail << ". faultDuringDispatch=" << dispatchFaultCall << " args";
        for (auto value : dispatchFaultArguments) detail << " 0x" << std::hex << value;
        if (dispatchFaultPath[0]) detail << ", dispatchPath=\"" << dispatchFaultPath << '"';
        detail << std::dec;
    }
    detail << ". x8..x18";
    for (auto value : faultVolatile) detail << " 0x" << value;
    detail << ". sp=0x" << faultSp;
    if (capturedFaultStack) {
        static constexpr char stackHex[] = "0123456789abcdef";
        detail << " stack@sp=";
        for (auto byte : faultStackBytes) {
            detail << stackHex[byte >> 4] << stackHex[byte & 15];
        }
    }
    if (capturedFaultPc) {
        static constexpr char pcHex[] = "0123456789abcdef";
        detail << " bytes@pc=";
        for (auto byte : faultPcBytes) {
            detail << pcHex[byte >> 4] << pcHex[byte & 15];
        }
    }
    detail << ". app header=0x" << reinterpret_cast<uintptr_t>(appHeader)
        << ", guest stack=0x" << reinterpret_cast<uintptr_t>(cache.stack) << "+0x" << cache.stackSize;
    if (capturedX17) {
        constexpr char hex[] = "0123456789abcdef";
        detail << ". bytes@x17=";
        for (auto byte : faultX17Bytes) detail << hex[byte >> 4] << hex[byte & 15];
    }
    if (faultString[0]) detail << ", x20 string \"" << faultString << '\"';
    if (faultFormat[0]) detail << ", x2 string \"" << faultFormat << '\"';
    if (capturedDiagnosticRegisters) {
        detail << ". diagnostic registers";
        for (size_t i = 0; i < std::size(diagnosticRegisters); ++i)
            detail << " x" << std::dec << i << "=0x" << std::hex << diagnosticRegisters[i];
    }
    detail << ". lazyDataPages=" << std::dec << hm_cache_data_pages();
    if (hm_cache_data_error()[0]) detail << ", dataPager=" << hm_cache_data_error();
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
    const unsigned long hwcap = getauxval(AT_HWCAP);
    std::ostringstream hardware;
    hardware << "AT_HWCAP=0x" << std::hex << hwcap;
#ifdef HWCAP_PACA
    hardware << "; PACA: " << ((hwcap & HWCAP_PACA) ? "yes" : "no");
#endif
#ifdef HWCAP_PACG
    hardware << "; PACG: " << ((hwcap & HWCAP_PACG) ? "yes" : "no");
#endif
    hardware << ". PACIBSP/AUTIBSP and PACIA/BLRAA used this HAP process's keys. Apple cache pointers still require rebasing and signing with these keys.";
    result.detail = hardware.str();
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
