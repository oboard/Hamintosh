#include "objc_aot.h"
#include "objc_trampolines.h"
#include <array>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

extern "C" {
alignas(0x4000) extern const uint8_t hm_objc_image[0x14000] = {};
alignas(0x4000) uint8_t hm_objc_pool_0[0x10000] {};
alignas(0x4000) uint8_t hm_objc_pool_1[0x10000] {};
}
using Memory = std::array<uint8_t, 128>;
extern "C" uint32_t hm_guest_copy_in(const void *context, uint64_t address, uint8_t *out, size_t size)
{
    const auto &bytes = *static_cast<const Memory *>(context);
    if (size > bytes.size() || address > bytes.size() - size) return 14;
    std::memcpy(out, bytes.data()+address, size);
    return 0;
}
extern "C" uint32_t hm_guest_copy_out(const void *context, uint64_t address, const uint8_t *input, size_t size)
{
    auto &bytes = *const_cast<Memory *>(static_cast<const Memory *>(context));
    if (size > bytes.size() || address > bytes.size() - size) return 14;
    std::memcpy(bytes.data()+address, input, size);
    return 0;
}
int main()
{
    char path[] = "/tmp/harmonios-aot-test-XXXXXX";
    const int fd = mkstemp(path);
    assert(fd >= 0);
    unlink(path);
    assert(write(fd, hm_objc_image, HM_OBJC_FILESIZE) == HM_OBJC_FILESIZE);
    Memory memory {};
    uint64_t signature[] = {0, HM_OBJC_SIGNATUREOFFSET, HM_OBJC_SIGNATURESIZE};
    std::memcpy(memory.data()+8, signature, sizeof(signature));
    hm_objc_aot_reset();
    assert(hm_objc_aot_fcntl(&memory, -1, 97, 8) == 45);
    assert(hm_objc_aot_fcntl(&memory, fd, 97, 120) == 14);
    assert(hm_objc_aot_fcntl(&memory, fd, 97, 8) == 0);
    uint64_t end; std::memcpy(&end, memory.data()+8, 8);
    assert(end == HM_OBJC_CODEEND);
    uint64_t address = 0;
    assert(hm_objc_aot_reserve(&address, 1, 0, 1, 3) == -1);
    assert(hm_objc_aot_reserve(&address, HM_OBJC_SPAN, 0x3fff, 0x3c000001, 3) == 0);
    assert(address == reinterpret_cast<uintptr_t>(hm_objc_image));
    assert(!hm_objc_aot_access(address, 0xc000, 1));
    uint64_t wrong = address+0x4000;
    assert(hm_objc_aot_map_file(nullptr, &wrong, 0xc000, 5, 0x12, fd, 0) == 22);
    assert(hm_objc_aot_map_file(nullptr, &address, 0xc000, 7, 0x12, fd, 0) == 2);
    assert(hm_objc_aot_map_file(nullptr, &address, 0xc000, 5, 0x12, fd, 0) == 0);
    assert(hm_objc_aot_access(address, 0xc000, 5));
    assert(!hm_objc_aot_access(address, 0xc000, 2));
    const uint8_t corrupt = 1;
    assert(pwrite(fd, &corrupt, 1, 0) == 1);
    assert(hm_objc_aot_map_file(nullptr, &address, 0xc000, 5, 0x12, fd, 0) == 45);
    assert(hm_objc_aot_fcntl(&memory, fd, 98, 0) == 45);
    uint64_t pool[3] {};
    for (size_t i = 0; i < 2; ++i) {
        assert(hm_objc_aot_reserve(&pool[i], 0x10000, 0, 0x29000001, 3) == 0);
        assert(hm_objc_aot_access(pool[i], 0x4000, 3));
        assert(!hm_objc_aot_access(pool[i]+0x4000, 0xc000, 4));
    }
    assert(hm_objc_aot_reserve(&pool[2], 0x10000, 0, 0x29000001, 3) == 3);
    uint64_t target = pool[0]+0x4000;
    uint32_t current = 0, maximum = 0;
    assert(hm_objc_aot_remap(nullptr, &target, 0xc000, 0, 0x4000, address+0x4000,
                           1, &current, &maximum, 0) == 46);
    assert(hm_objc_aot_remap(nullptr, &target, 0xc000, 0, 0x4000, address,
                           1, &current, &maximum, 0) == 0);
    assert(current == 5 && maximum == 5 && hm_objc_aot_access(target, 0xc000, 5));
    assert(!hm_objc_aot_access(target, 0xc000, 2));
    assert(hm_objc_aot_protect(address, 0x4000, 3) == 2);
    assert(hm_objc_aot_deallocate(address, 0x4000) == 4);
    assert(hm_objc_aot_deallocate(address, HM_OBJC_SPAN) == 0);
    hm_objc_pool_0[0] = 7;
    hm_objc_aot_reset();
    assert(!hm_objc_aot_access(pool[0], 1, 1) && hm_objc_pool_0[0] == 0);
    close(fd);
    puts("ObjC AOT: exact file identity, immutable RX, pool bounds and reset passed");
}
