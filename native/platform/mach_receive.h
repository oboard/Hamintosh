#pragma once
#include <cstdint>

// Receiving a real message is not an idle boundary: its caller still owns the
// reply and libdispatch's synchronous wait context has not been unwound yet.
inline bool hm_is_idle_mach_receive(int64_t syscall, uint64_t options,
    uint64_t sendSize, uint64_t legacyReceiveName, uint64_t receiveBits, uint64_t result)
{
    constexpr uint64_t machReceiveTimeout = 0x100;
    constexpr uint64_t machReceiveTimedOut = 0x10004003;
    if ((options & 3) != 2 || result != machReceiveTimedOut) return false;
    if (syscall == -47 && (receiveBits >> 32) != 0) {
        if (options & (1ULL << 32)) {
            // CoreFoundation receives message + auxiliary vectors. The high
            // size word is their count, not a scalar send-message size.
            return sendSize == (2ULL << 32);
        }
        return sendSize == 0 && (options & machReceiveTimeout);
    }
    return syscall == -31 && legacyReceiveName != 0 && sendSize == 0 &&
        (options & machReceiveTimeout);
}
