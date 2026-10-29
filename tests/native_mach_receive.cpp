#include "mach_receive.h"
#include <cassert>
#include <iostream>

int main()
{
    constexpr uint64_t port = 0x2f03ULL << 32;
    assert(hm_is_idle_mach_receive(-47, 0x404000102, 0, 0, port, 0x10004003));
    assert(!hm_is_idle_mach_receive(-47, 0x40700420e, 0, 0, port, 0));
    assert(!hm_is_idle_mach_receive(-47, 0x40700020e, 0, 0, port, 0x10004003));
    assert(!hm_is_idle_mach_receive(-47, 0x103, 24ULL << 32, 0, port, 0x10004003));
    assert(!hm_is_idle_mach_receive(-47, 0x102, 0, 0, 0, 0x10004003));
    assert(!hm_is_idle_mach_receive(-47, 0x102, 0, 0, port, 0x10004002));
    assert(hm_is_idle_mach_receive(-47, 0x507000806, 2ULL << 32, 0, port, 0x10004003));
    assert(!hm_is_idle_mach_receive(-47, 0x507000806, 2ULL << 32, 0, port, 0));
    assert(!hm_is_idle_mach_receive(-47, 0x507000806, 1ULL << 32, 0, port, 0x10004003));
    assert(hm_is_idle_mach_receive(-31, 0x102, 0, 0x2f03, 0, 0x10004003));
    std::cout << "Mach receive: real RPC replies excluded from scene idle delivery\n";
}
