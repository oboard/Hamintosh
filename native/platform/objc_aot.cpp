#include "objc_aot.h"
#include "cache_image.h"
#include <algorithm>
#include <array>
#include <cstring>
#include <sys/stat.h>
#include <unistd.h>
#ifdef HM_HAS_OBJC_AOT
#include "objc_trampolines.h"
namespace {
constexpr size_t Page = 0x4000;
bool pendingImage = false, imageReserved = false;
std::array<uint8_t, HM_OBJC_SPAN / Page> imagePermissions {};
std::array<bool, HM_OBJC_POOL_COUNT> poolsReserved {};
std::array<std::array<uint8_t, 4>, HM_OBJC_POOL_COUNT> poolPermissions {};

bool Contains(uint64_t base, uint64_t length, uint64_t address, uint64_t size)
{
    return address >= base && size <= length && address - base <= length - size;
}

bool MatchesFile(int fd)
{
    struct stat info {};
    if (fd < 0 || fstat(fd, &info) || !S_ISREG(info.st_mode) ||
        uint64_t(info.st_size) != HM_OBJC_FILESIZE) return false;
    // Compare every source byte, including the CodeDirectory, with bytes in
    // this HAP's immutable signed ELF. No arbitrary file gains RX permission.
    uint8_t bytes[4096];
    for (size_t at = 0; at < HM_OBJC_FILESIZE;) {
        const auto size = std::min(sizeof(bytes), size_t(HM_OBJC_FILESIZE - at));
        const auto count = pread(fd, bytes, size, static_cast<off_t>(at));
        if (count != static_cast<ssize_t>(size) || std::memcmp(bytes, hm_objc_source + at, size)) return false;
        at += size;
    }
    return true;
}

struct View { uint64_t base, size; uint8_t *permissions; bool image; };
View Find(uint64_t address, uint64_t size)
{
    const auto base = reinterpret_cast<uintptr_t>(hm_objc_image);
    if (imageReserved && Contains(base, HM_OBJC_SPAN, address, size))
        return {base, HM_OBJC_SPAN, imagePermissions.data(), true};
    for (size_t i = 0; i < HM_OBJC_POOL_COUNT; ++i) {
        const auto pool = reinterpret_cast<uintptr_t>(HM_OBJC_POOLS[i]);
        if (poolsReserved[i] && Contains(pool, 4 * Page, address, size))
            return {pool, 4 * Page, poolPermissions[i].data(), false};
    }
    return {};
}
}
#endif

void hm_objc_aot_reset()
{
#ifdef HM_HAS_OBJC_AOT
    pendingImage = imageReserved = false;
    imagePermissions.fill(0);
    poolsReserved.fill(false);
    for (size_t i = 0; i < HM_OBJC_POOL_COUNT; ++i) {
        poolPermissions[i].fill(0);
        std::memset(HM_OBJC_POOLS[i], 0, Page);
    }
#endif
}

int32_t hm_objc_aot_reserve(uint64_t *address, uint64_t size, uint64_t mask,
    uint32_t flags, uint32_t protection)
{
#ifdef HM_HAS_OBJC_AOT
    if (!address || (flags & 0x00ffffffU) != 1 || mask > Page - 1 || protection & ~3U) return -1;
    const auto tag = flags >> 24;
    if (pendingImage && !imageReserved && size == HM_OBJC_SPAN && (tag == 60 || tag == 0)) {
        *address = reinterpret_cast<uintptr_t>(hm_objc_image);
        imageReserved = true;
        pendingImage = false;
        imagePermissions.fill(0);
        return 0;
    }
    // Apple's block IMP allocator reserves data + the entire TEXT segment.
    if (imageReserved && size == Page + HM_OBJC_TEXTSIZE && tag == 41 && protection == 3) {
        for (size_t i = 0; i < HM_OBJC_POOL_COUNT; ++i) {
            if (poolsReserved[i]) continue;
            poolsReserved[i] = true;
            poolPermissions[i].fill(0);
            poolPermissions[i][0] = 3;
            std::memset(HM_OBJC_POOLS[i], 0, Page);
            *address = reinterpret_cast<uintptr_t>(HM_OBJC_POOLS[i]);
            return 0;
        }
        return 3; // KERN_NO_SPACE: finite pre-signed code pool exhausted.
    }
#endif
    return -1;
}

bool hm_objc_aot_access(uint64_t address, size_t size, uint32_t protection)
{
#ifdef HM_HAS_OBJC_AOT
    const auto view = Find(address, size);
    if (!view.permissions) return false;
    if (!size) return true;
    const auto first = (address - view.base) / Page;
    const auto last = (address - view.base + size - 1) / Page;
    for (size_t i = first; i <= last; ++i)
        if ((view.permissions[i] & protection) != protection) return false;
    return true;
#else
    return false;
#endif
}

int32_t hm_objc_aot_protect(uint64_t address, uint64_t size, uint32_t protection)
{
#ifdef HM_HAS_OBJC_AOT
    const auto view = Find(address, size);
    if (!view.permissions) return -1;
    if (address % Page || size % Page || protection & ~7U) return 4;
    const auto first = (address - view.base) / Page;
    for (size_t i = first; i < first + size / Page; ++i) {
        const uint32_t maximum = view.image ? (i < 3 ? 5 : 1) : (i == 0 ? 3 : 5);
        if (protection & ~maximum) return 2;
    }
    std::fill_n(view.permissions + first, size / Page, protection);
    return 0;
#else
    return -1;
#endif
}

int32_t hm_objc_aot_deallocate(uint64_t address, uint64_t size)
{
#ifdef HM_HAS_OBJC_AOT
    const auto view = Find(address, size);
    if (!view.permissions) return -1;
    if (address != view.base || size != view.size) return 4;
    if (view.image) { imageReserved = false; imagePermissions.fill(0); }
    else {
        for (size_t i = 0; i < HM_OBJC_POOL_COUNT; ++i) if (address == reinterpret_cast<uintptr_t>(HM_OBJC_POOLS[i])) {
            poolsReserved[i] = false;
            poolPermissions[i].fill(0);
            std::memset(HM_OBJC_POOLS[i], 0, Page);
        }
    }
    // Borrowed signed ELF pages remain owned by the host dynamic linker.
    return 0;
#else
    return -1;
#endif
}

extern "C" uint32_t hm_objc_aot_fcntl(const void *context, int32_t descriptor,
    uint32_t command, uint64_t argument)
{
#ifdef HM_HAS_OBJC_AOT
    if (command != 97 && command != 98) return 78;
    if (!MatchesFile(descriptor)) return 45;
    if (command == 98) return 0; // The exact signed HAP image satisfies local library validation.
    uint64_t signature[3];
    if (hm_guest_copy_in(context, argument, reinterpret_cast<uint8_t *>(signature), sizeof(signature))) return 14;
    if (signature[0] || signature[1] != HM_OBJC_SIGNATUREOFFSET || signature[2] != HM_OBJC_SIGNATURESIZE) return 22;
    const uint64_t end = HM_OBJC_CODEEND;
    if (hm_guest_copy_out(context, argument, reinterpret_cast<const uint8_t *>(&end), sizeof(end))) return 14;
    pendingImage = true;
    return 0;
#else
    return 78;
#endif
}

extern "C" uint32_t hm_objc_aot_map_file(const void *, uint64_t *address,
    uint64_t size, uint32_t protection, uint32_t flags, int32_t descriptor, uint64_t offset)
{
#ifdef HM_HAS_OBJC_AOT
    if (!address || !imageReserved || !MatchesFile(descriptor)) return 45;
    if (flags != 0x12 && flags != 0x40012) return 45; // PRIVATE | FIXED [| UNIX03]
    const auto base = reinterpret_cast<uintptr_t>(hm_objc_image);
    if (!size || offset % Page || size % Page || offset > HM_OBJC_SPAN || size > HM_OBJC_SPAN - offset ||
        *address != base + offset) return 22;
    const auto result = hm_objc_aot_protect(*address, size, protection);
    return result < 0 ? 45 : static_cast<uint32_t>(result);
#else
    return 45;
#endif
}

extern "C" uint32_t hm_objc_aot_remap(const void *, uint64_t *address,
    uint64_t size, uint64_t mask, uint32_t flags, uint64_t source, uint32_t copy,
    uint32_t *current, uint32_t *maximum, uint32_t inheritance)
{
#ifdef HM_HAS_OBJC_AOT
    if (!address || !current || !maximum || mask || flags != 0x4000 || copy != 1 || inheritance != 0) return 4;
    if (!imageReserved || source != reinterpret_cast<uintptr_t>(hm_objc_image) || size != HM_OBJC_TEXTSIZE) return 46;
    for (size_t i = 0; i < HM_OBJC_POOL_COUNT; ++i) {
        if (!poolsReserved[i] || *address != reinterpret_cast<uintptr_t>(HM_OBJC_POOLS[i] + Page)) continue;
        // The copied instruction pages were already embedded and signed at
        // build time. Only the data page is mutable; no RX mapping or code
        // copying happens at runtime.
        if (std::memcmp(HM_OBJC_POOLS[i] + Page, hm_objc_image, HM_OBJC_TEXTSIZE)) return 2;
        std::fill(poolPermissions[i].begin()+1, poolPermissions[i].end(), 5);
        *current = *maximum = 5;
        return 0;
    }
    return 1;
#else
    return 46;
#endif
}
