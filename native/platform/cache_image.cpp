#include "cache_image.h"
#include "harmintosh.h"
#include "data_pager.h"
#ifdef HM_HAS_BOOT_DYLD
#include "packed_dyld.h"
#endif
#include <cstring>
#include <algorithm>
#include <vector>
#include <cerrno>
#include <sys/mman.h>
#include <unistd.h>
#include <time.h>
#include <array>
#include <sys/stat.h>
#if defined(__aarch64__) && defined(HM_HAS_IOS_CACHE)
extern "C" const uint8_t hm_ios_cache_base[];
extern "C" const uint8_t hm_ios_cache_descriptor[];
extern "C" const uint8_t hm_ios_cache_descriptor_end[];
extern "C" const uint8_t hm_ios_cache_data[];
extern "C" const uint8_t hm_ios_cache_data_end[];
extern "C" uint64_t hm_pac_sign_pointer(uint64_t, uint64_t, uint32_t);
namespace {
uint64_t Quad(const uint8_t *p) { uint64_t n; std::memcpy(&n, p, 8); return n; }
struct Range {
    uint64_t start, size, protection;
    const uint8_t *original = nullptr;
    std::vector<uint8_t> pageProtection;
};
std::vector<Range> ranges;
std::vector<Range> bootstrapRanges;
HmDataPager dataPager;
constexpr char cachePath[] = "/System/Cryptexes/OS/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e";
struct Anonymous {
    uint8_t *base = nullptr;
    uint64_t size = 0;
    // One GiB per region with a Darwin 16 KiB granule. Metadata is fixed
    // storage so the synchronous trap path never calls the host allocator.
    std::array<uint8_t, 65536> permissions {};
};
std::array<Anonymous, 64> anonymousRegions;
struct MappingView {
    uint8_t *pages = nullptr;
    uint64_t protection = 0, offset = 0;
};
MappingView FindMapping(const HmCacheImage *cache, uint64_t address, uint64_t size) {
    if (!cache || address > UINT64_MAX - size) return {};
    struct Part { const uint8_t *base; std::vector<Range> *regions; };
    const Part parts[] = {{cache->base, &ranges}, {cache->bootstrapBase, &bootstrapRanges}};
    for (const auto &part : parts) {
        if (!part.base || address < reinterpret_cast<uintptr_t>(part.base)) continue;
        const auto offset = address - reinterpret_cast<uintptr_t>(part.base);
        for (auto &r : *part.regions) {
            if (offset >= r.start && size <= r.size && offset - r.start <= r.size - size)
                return {r.pageProtection.data(), r.protection, offset - r.start};
        }
    }
    for (auto &r : anonymousRegions) {
        if (!r.base) continue;
        const auto base = reinterpret_cast<uintptr_t>(r.base);
        if (address >= base && size <= r.size && address - base <= r.size - size)
            return {r.permissions.data(), 3, address - base};
    }
    return {};
}
bool Contains(uint64_t offset, uint64_t size, uint64_t protection) {
    auto found = std::upper_bound(ranges.begin(), ranges.end(), offset,
        [](uint64_t value, const Range &range) { return value < range.start; });
    if (found == ranges.begin()) return false;
    const auto &r = *--found;
    return size <= r.size && offset - r.start <= r.size - size &&
        (r.protection & protection) == protection;
}
bool CanAccess(const HmCacheImage *cache, uint64_t address, uint64_t size, uint8_t protection) {
    if (!cache || address > UINT64_MAX - size) return false;
    if (dataPager.Contains(address, size)) return dataPager.Access(address, size, protection);
    const auto stack = reinterpret_cast<uintptr_t>(cache->stack);
    if (address >= stack && size <= cache->stackSize && address - stack <= cache->stackSize - size) return (protection & ~3U) == 0;
    const auto view = FindMapping(cache, address, size);
    if (!view.pages) return false;
    if (!size) return true;
    const size_t first = view.offset / 0x4000, last = (view.offset + size - 1) / 0x4000;
    for (size_t i = first; i <= last; ++i) if ((view.pages[i] & protection) != protection) return false;
    return true;
}
}
#endif
HmCacheImage hm_prepare_cache_image()
{
    HmCacheImage image;
#if defined(__aarch64__) && defined(HM_HAS_IOS_CACHE)
    dataPager.Reset();
    for (auto &r : anonymousRegions) if (r.base) {
        munmap(r.base, r.size);
        r.base = nullptr;
        r.size = 0;
    }
    const auto *meta = hm_ios_cache_descriptor;
    const size_t bytes = reinterpret_cast<uintptr_t>(hm_ios_cache_descriptor_end) - reinterpret_cast<uintptr_t>(meta);
    if (bytes < 64 || std::memcmp(meta, "HMCACHE1", 8) || (Quad(meta + 8) != 2 && Quad(meta + 8) != 3)) {
        image.error = "invalid-cache-descriptor"; return image;
    }
    const auto span = Quad(meta + 24), header = Quad(meta + 32), entry = Quad(meta + 40);
    image.dataPackRequired = Quad(meta + 8) == 3;
    const auto count = Quad(meta + 48), rebases = Quad(meta + 56);
    if (count > 16384 || rebases > 100000000 || bytes != 64 + count * 32 + rebases * 24 ||
        span == 0 || span > (1ULL << 36) || header >= span || entry >= span) {
        image.error = "invalid-cache-layout"; return image;
    }
    auto *base = const_cast<uint8_t *>(hm_ios_cache_base);
    if (reinterpret_cast<uintptr_t>(base) > UINTPTR_MAX - span) {
        image.error = "cache-address-overflow"; return image;
    }
    if (ranges.empty()) {
        std::vector<Range> validated;
        const auto dataSize = reinterpret_cast<uintptr_t>(hm_ios_cache_data_end) - reinterpret_cast<uintptr_t>(hm_ios_cache_data);
        for (size_t i = 0; i < count; ++i) {
            const auto *p = meta + 64 + i * 32;
            Range r {Quad(p), Quad(p + 8), Quad(p + 16), {}, {}};
            const auto source = Quad(p + 24);
            if (r.start >= span || r.size > span - r.start || !r.size || r.start % 0x4000 || r.size % 0x4000 ||
                r.protection & ~7ULL || (r.protection & 6) == 6 ||
                (i && validated.back().start + validated.back().size > r.start)) {
                image.error = "invalid-cache-page-range"; return image;
            }
            if (r.protection & 4) {
                if (source != UINT64_MAX) { image.error = "executable-cache-data-blob"; return image; }
            } else {
                if (source > dataSize || r.size > dataSize - source) { image.error = "invalid-cache-data-blob"; return image; }
                r.original = hm_ios_cache_data + source;
            }
            r.pageProtection.assign((r.size + 0x3fff) / 0x4000, r.protection);
            validated.push_back(std::move(r));
        }
        ranges = std::move(validated);
    }
    // OHOS musl initially maps an ELF's whole load span as a readable file
    // view. It overlays PT_LOADs but leaves their gaps readable. Revoke those
    // aliases before any guest access so deferred data really faults into its
    // original source page, rather than reading unrelated packed code bytes.
    uint64_t gap = 0;
    for (const auto &r : ranges) {
        if (r.start > gap && mprotect(base + gap, r.start - gap, PROT_NONE)) {
            image.error = "cache-gap-protection-failed"; return image;
        }
        gap = r.start + r.size;
    }
    if (gap < span && mprotect(base + gap, span - gap, PROT_NONE)) {
        image.error = "cache-gap-protection-failed"; return image;
    }
    if (!Contains(header, 32, 1) || !Contains(entry, 4, 4) || Quad(base + header) != 0x0100000cfeedfacfULL) {
        image.error = "invalid-cache-dyld-header"; return image;
    }
    const auto *records = meta + 64 + count * 32;
    for (size_t i = 0; i < rebases; ++i) {
        const auto *p = records + i * 24;
        if (!Contains(Quad(p), 8, 2) || Quad(p + 8) >= span || p[18] > 3 || p[19] > 3 || p[21] || p[22] || p[23]) {
            image.error = "invalid-cache-rebase-record"; return image;
        }
    }
    for (auto &r : ranges) {
        if (r.original) {
            if (mmap(base + r.start, r.size, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == MAP_FAILED) {
                image.error = "cache-data-reset-protection-failed"; return image;
            }
            std::memcpy(base + r.start, r.original, r.size);
        }
        if (mprotect(base + r.start, r.size, r.protection)) {
            image.error = "cache-data-final-protection-failed"; return image;
        }
        std::fill(r.pageProtection.begin(), r.pageProtection.end(), r.protection);
    }
    for (size_t i = 0; i < rebases; ++i) {
        const auto *p = records + i * 24;
        const auto storage = reinterpret_cast<uintptr_t>(base) + Quad(p);
        uint64_t value = reinterpret_cast<uintptr_t>(base) + Quad(p + 8);
        uint16_t diversity; std::memcpy(&diversity, p + 16, 2);
        if (p[19] & 1) {
            const uint64_t modifier = (p[19] & 2) ? ((storage & 0x0000ffffffffffffULL) | (uint64_t(diversity) << 48)) : diversity;
            value = hm_pac_sign_pointer(value, modifier, p[18]);
        } else value |= uint64_t(p[20]) << 56;
        std::memcpy(reinterpret_cast<void *>(storage), &value, 8);
    }
    image.base = base; image.span = span; image.entry = base + entry; image.rebases = rebases;
#ifdef HM_HAS_BOOT_DYLD
    image.bootstrapBase = const_cast<uint8_t *>(hm_dyld_image);
    image.bootstrapSpan = HM_DYLD_SPAN;
    if (bootstrapRanges.empty()) {
        for (const auto &s : HM_DYLD_SEGMENTS) {
            Range r {s.offset, s.size, s.protection, {}, {}};
            r.pageProtection.assign((r.size + 0x3fff) / 0x4000, r.protection);
            bootstrapRanges.push_back(std::move(r));
        }
    }
    for (auto &r : bootstrapRanges) if (r.protection & 2) {
        if (mprotect(image.bootstrapBase + r.start, r.size, r.protection)) {
            image.error = "bootstrap-data-reset-protection-failed"; return image;
        }
        std::fill(r.pageProtection.begin(), r.pageProtection.end(), r.protection);
    }
    if (hm_reset_bootstrap_data(hm_dyld_original, HM_DYLD_ORIGINAL_SIZE, image.bootstrapBase, image.bootstrapSpan)) {
        image.error = "bootstrap-data-reset-failed"; return image;
    }
    uint64_t bootEntry = 0;
    if (hm_validate_aot_image(hm_dyld_original, HM_DYLD_ORIGINAL_SIZE, image.bootstrapBase,
        image.bootstrapSpan, &bootEntry) || bootEntry != HM_DYLD_ENTRY_OFFSET) {
        image.error = "bootstrap-aot-byte-validation-failed"; return image;
    }
    // The standalone Apple dyld, rather than our cache relocator, performs
    // its own bootstrap chained fixups before initializing libc/process info.
    image.entry = image.bootstrapBase + HM_DYLD_ENTRY_OFFSET;
#endif
#else
    image.error = "ios-cache-not-packaged";
#endif
    return image;
}

std::string hm_prepare_cache_data(HmCacheImage &image)
{
#if defined(__aarch64__) && defined(HM_HAS_IOS_CACHE)
    const std::string path = std::string(image.sysroot) + "/cache-data.pack";
    if (!dataPager.Open(path.c_str(), image.base, image.span, image.base + 88, hm_pac_sign_pointer, Quad(image.base + 224))) {
        return !image.dataPackRequired && std::strcmp(dataPager.Error(), "cache-data-not-staged") == 0 ? "" : dataPager.Error();
    }
    for (const auto &range : ranges)
        dataPager.MarkLoaded(range.start, range.size, range.protection);
#endif
    return {};
}

bool hm_cache_data_fault(const HmCacheImage *image, uint64_t address)
{
#if defined(__aarch64__) && defined(HM_HAS_IOS_CACHE)
    return image && dataPager.Fault(address);
#else
    return false;
#endif
}

uint64_t hm_cache_data_pages()
{
#if defined(__aarch64__) && defined(HM_HAS_IOS_CACHE)
    return dataPager.Pages();
#else
    return 0;
#endif
}

const char *hm_cache_data_error()
{
#if defined(__aarch64__) && defined(HM_HAS_IOS_CACHE)
    return dataPager.Error();
#else
    return "";
#endif
}

bool hm_bootstrap_rebase_witness(const HmCacheImage &image)
{
#if defined(__aarch64__) && defined(HM_HAS_IOS_CACHE) && defined(HM_HAS_BOOT_DYLD)
    const auto address = reinterpret_cast<uintptr_t>(image.bootstrapBase) + HM_DYLD_WITNESS_LOCATION;
    const auto view = FindMapping(&image, address, 8);
    if (!view.pages || !(view.pages[view.offset / 0x4000] & 1)) return false;
    return Quad(reinterpret_cast<const uint8_t *>(address)) ==
        reinterpret_cast<uintptr_t>(image.bootstrapBase) + HM_DYLD_WITNESS_TARGET;
#else
    return false;
#endif
}

std::string hm_prepare_cache_dynamic_data(HmCacheImage &image)
{
#if defined(__aarch64__) && defined(HM_HAS_IOS_CACHE)
    // Apple SharedCacheRuntime creates this kernel-owned page separately from
    // the cache files. Match the v4 layout used by this bootstrap dyld, with
    // real backing-file IDs and no processor-specific function variants enabled.
    if (!image.base || !image.sysroot || !Contains(0, 512, 1)) return "cache-dynamic-header-missing";
    const auto offset = Quad(image.base + 496), size = Quad(image.base + 504);
    if (size != 0x4000 || offset % 0x4000 || offset > image.span || size > image.span - offset)
        return "cache-dynamic-layout-invalid";
    for (const auto &r : ranges) if (offset < r.start + r.size && r.start < offset + size && r.start != offset)
        return "cache-dynamic-overlaps-file-pages";
    struct stat info {};
    const std::string physicalPath = std::string(image.sysroot) + cachePath;
    if (lstat(physicalPath.c_str(), &info) || !S_ISREG(info.st_mode)) return "cache-backing-file-missing";
    image.cacheFileDevice = static_cast<uint32_t>(info.st_dev);
    image.cacheFileInode = info.st_ino;
    if (!image.cacheFileDevice || !static_cast<uint32_t>(image.cacheFileInode)) return "cache-file-id-unrepresentable";
    auto *page = static_cast<uint8_t *>(mmap(image.base + offset, size, PROT_READ | PROT_WRITE,
        MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    if (page == MAP_FAILED) return "cache-dynamic-map-failed";
    std::memcpy(page, "dyld_data    v4", 15);
    std::memcpy(page + 16, &image.cacheFileDevice, 8);
    std::memcpy(page + 24, &image.cacheFileInode, 8);
    const uint32_t pathOffset = 112, pathSize = sizeof(cachePath);
    std::memcpy(page + 36, &pathOffset, 4);
    std::memcpy(page + 92, &pathSize, 4);
    std::memcpy(page + pathOffset, cachePath, pathSize);
    // Roots bitmaps remain invalid until a real overlay scan is implemented.
    if (mprotect(page, size, PROT_READ)) return "cache-dynamic-protect-failed";
    const auto existing = std::find_if(ranges.begin(), ranges.end(), [offset](const Range &r) { return r.start == offset; });
    if (existing == ranges.end()) {
        const auto position = std::lower_bound(ranges.begin(), ranges.end(), offset,
            [](const Range &range, uint64_t value) { return range.start < value; });
        ranges.insert(position, {offset, size, 1, {}, {1}});
    }
    return {};
#else
    return "ios-cache-not-packaged";
#endif
}

extern "C" uint32_t hm_guest_resolve_file_id(const void *context, uint64_t device,
    uint64_t inode, uint8_t *path, size_t *size)
{
#if defined(__aarch64__) && defined(HM_HAS_IOS_CACHE)
    const auto *image = static_cast<const HmCacheImage *>(context);
    if (!image || !path || !size) return 14;
    if (device != image->cacheFileDevice || inode != image->cacheFileInode) return 2;
    if (*size < sizeof(cachePath)) return 34;
    std::memcpy(path, cachePath, sizeof(cachePath));
    *size = sizeof(cachePath);
    return 0;
#else
    return 78;
#endif
}

extern "C" uint32_t hm_cache_vm_protect(const void *context, uint64_t address,
    uint64_t size, uint32_t setMaximum, uint32_t protection)
{
#if defined(__aarch64__) && defined(HM_HAS_IOS_CACHE)
    const auto *cache = static_cast<const HmCacheImage *>(context);
    if (!cache || setMaximum) return 46; // KERN_NOT_SUPPORTED
    if (protection & ~0x17U || (protection & 6) == 6 || address % 0x4000 || size % 0x4000) return 4;
    if (!size) return 0;
    if (dataPager.Contains(address, size)) return dataPager.Protect(address, size, protection & 7);
    const auto view = FindMapping(cache, address, size);
    if (!view.pages) return 1; // KERN_INVALID_ADDRESS
    if ((view.protection & (protection & 7)) != (protection & 7)) return 2;
    // VM_PROT_COPY asks for a private copy; ELF data mappings already use COW.
    if (mprotect(reinterpret_cast<void *>(address), size, protection & 7)) return 2;
    const size_t first = view.offset / 0x4000;
    for (size_t i = first; i < first + size / 0x4000; ++i) view.pages[i] = protection & 7;
    return 0;
#else
    return 46;
#endif
}

extern "C" uint32_t hm_guest_getentropy(const void *context, uint64_t address, uint64_t size)
{
#if defined(__aarch64__) && defined(HM_HAS_IOS_CACHE)
    const auto *cache = static_cast<const HmCacheImage *>(context);
    if (size > 256) return 5; // Darwin EIO
    if (!size) return 0;
    if (!cache) return 14; // Darwin EFAULT
    if (!CanAccess(cache, address, size, 2)) return 14;
    if (getentropy(reinterpret_cast<void *>(address), size)) return errno == EFAULT ? 14 : 5;
    return 0;
#else
    return 78;
#endif
}

extern "C" uint32_t hm_guest_copy_out(const void *context, uint64_t address, const uint8_t *bytes, size_t size)
{
#if defined(__aarch64__) && defined(HM_HAS_IOS_CACHE)
    if (!CanAccess(static_cast<const HmCacheImage *>(context), address, size, 2)) return 14;
    if (size) std::memcpy(reinterpret_cast<void *>(address), bytes, size);
    return 0;
#else
    return 78;
#endif
}

extern "C" uint32_t hm_guest_copy_in(const void *context, uint64_t address, uint8_t *bytes, size_t size)
{
#if defined(__aarch64__) && defined(HM_HAS_IOS_CACHE)
    if (!CanAccess(static_cast<const HmCacheImage *>(context), address, size, 1)) return 14;
    if (size) std::memcpy(bytes, reinterpret_cast<const void *>(address), size);
    return 0;
#else
    return 78;
#endif
}

std::string hm_prepare_commpage()
{
#if defined(__aarch64__)
    // XNU arm/cpu_capabilities.h defines a mutable and a read-only commpage.
    // Keep optional CPU/time fast paths disabled until their host counterparts
    // are implemented; Darwin's own fallback calls then reach our trap boundary.
    static bool ready = false;
    if (ready) return {};
    constexpr uintptr_t addresses[] = {0xfffffc000ULL, 0xfffff4000ULL};
    std::vector<void *> allocations;
    for (auto address : addresses) {
        auto *requested = reinterpret_cast<void *>(address);
        auto *page = static_cast<uint8_t *>(mmap(requested, 0x4000, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
        if (page == MAP_FAILED || page != requested) {
            if (page != MAP_FAILED) munmap(page, 0x4000);
            for (auto *allocation : allocations) munmap(allocation, 0x4000);
            return "darwin-commpage-address-unavailable";
        }
        allocations.push_back(page);
        std::memcpy(page, "commpage 64-bit", 14);
        uint16_t version = 3; std::memcpy(page + 0x1e, &version, 2);
        // Emulate Darwin's 16 KiB guest VM granule, independently of host pages.
        page[0x24] = page[0x25] = page[0x37] = 14;
        const auto cpus = static_cast<uint8_t>(std::min<long>(255, std::max<long>(1, sysconf(_SC_NPROCESSORS_ONLN))));
        page[0x22] = page[0x34] = page[0x35] = page[0x36] = cpus;
    }
    for (auto *page : allocations) if (mprotect(page, 0x4000, PROT_READ)) {
        for (auto *allocation : allocations) munmap(allocation, 0x4000);
        return "darwin-commpage-protection-failed";
    }
    ready = true;
#endif
    return {};
}

extern "C" uint32_t hm_guest_clock(const void *, uint32_t mode, uint64_t *value)
{
    if (!value || mode > 2) return 4;
    clockid_t clock = CLOCK_MONOTONIC;
    if (mode == 2) clock = CLOCK_REALTIME;
    if (mode == 1) {
#ifdef CLOCK_BOOTTIME
        clock = CLOCK_BOOTTIME;
#else
        return 46;
#endif
    }
    timespec now {};
    if (clock_gettime(clock, &now)) return 5;
    // Guest timebase is nanoseconds; mach_timebase_info must use numerator and
    // denominator 1 when that interface is added.
    *value = uint64_t(now.tv_sec) * 1000000000ULL + now.tv_nsec;
    return 0;
}

extern "C" uint32_t hm_guest_vm_map(const void *context, uint64_t *addressPointer,
    uint64_t size, uint64_t mask, uint32_t flags, uint32_t protection)
{
#if defined(__aarch64__) && defined(HM_HAS_IOS_CACHE)
    const auto *cache = static_cast<const HmCacheImage *>(context);
    if (!addressPointer) return 4;
    if (protection & ~3U) return 2; // Executable pages must come from signed AOT mappings.
    if (!size || size > (1ULL << 30) || mask > (1ULL << 30) - 1 || (mask & (mask + 1))) return 4;
    const uint64_t rounded = (size + 0x3fff) & ~0x3fffULL;
    const auto userFlags = flags & 0x00ffffffU;
    if (userFlags == 0x4000) {
        const uint64_t address = *addressPointer;
        if (!address || address % 0x4000 || address > UINT64_MAX - rounded) return 4;
        const uint64_t end = address + rounded;
        bool contained = false;
        for (const auto &r : anonymousRegions) {
            if (!r.base) continue;
            const auto base = reinterpret_cast<uintptr_t>(r.base);
            if (address >= base && end <= base + r.size) {
                contained = true;
                break;
            }
        }
        if (!contained) return 1;
        if (hm_guest_vm_deallocate(context, address, rounded)) return 1;
        auto *mapped = static_cast<uint8_t *>(mmap(reinterpret_cast<void *>(address), rounded,
            protection, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0));
        if (mapped == MAP_FAILED || reinterpret_cast<uintptr_t>(mapped) != address) return 3;
        Anonymous *slot = nullptr;
        for (auto &r : anonymousRegions) if (!r.base) { slot = &r; break; }
        if (!slot) {
            munmap(mapped, rounded);
            return 3;
        }
        slot->size = rounded;
        std::fill_n(slot->permissions.begin(), rounded / 0x4000, protection);
        slot->base = mapped;
        return 0;
    }
    if (userFlags != 1) return 46; // Only VM_FLAGS_ANYWHERE plus the user tag.
    Anonymous *slot = nullptr;
    for (auto &r : anonymousRegions) if (!r.base) { slot = &r; break; }
    if (!slot) return 3;
    const uint64_t alignment = std::max<uint64_t>(0x4000, mask + 1);
    uint64_t hint = 0;
    hint = *addressPointer;
    const uint64_t allocationSize = rounded + alignment;
    auto *raw = static_cast<uint8_t *>(mmap(reinterpret_cast<void *>(hint), allocationSize,
        protection, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    if (raw == MAP_FAILED) return 3;
    const auto rawAddress = reinterpret_cast<uintptr_t>(raw);
    const uint64_t aligned = (rawAddress + alignment - 1) & ~(alignment - 1);
    const uint64_t prefix = aligned - rawAddress;
    const uint64_t suffix = allocationSize - prefix - rounded;
    if (prefix) munmap(raw, prefix);
    if (suffix) munmap(reinterpret_cast<void *>(aligned + rounded), suffix);
    slot->size = rounded;
    std::fill_n(slot->permissions.begin(), rounded / 0x4000, protection);
    slot->base = reinterpret_cast<uint8_t *>(aligned);
    *addressPointer = aligned;
    return 0;
#else
    return 46;
#endif
}

extern "C" uint32_t hm_guest_map_file(const void *context, uint64_t *address,
    uint64_t size, uint32_t protection, int32_t descriptor, uint64_t offset)
{
#if defined(__aarch64__) && defined(HM_HAS_IOS_CACHE)
    if (!context || !address || descriptor < 0) return 22;
    if (!size || size > (1ULL << 30) || offset > UINT64_MAX - size || offset % 0x4000) return 22;
    if (protection & ~3U) return 45; // Signed AOT images own executable mappings.
    const uint64_t rounded = (size + 0x3fff) & ~0x3fffULL;
    Anonymous *slot = nullptr;
    for (auto &r : anonymousRegions) if (!r.base) { slot = &r; break; }
    if (!slot) return 12;
    const uint64_t hint = *address & ~0x3fffULL;
    void *mapped = mmap(reinterpret_cast<void *>(hint), rounded, protection,
        MAP_PRIVATE, descriptor, static_cast<off_t>(offset));
    if (mapped == MAP_FAILED) {
        switch (errno) {
            case ENOENT: return 2;
            case EBADF: return 9;
            case ENOMEM: return 12;
            case EACCES: return 13;
            case EINVAL: return 22;
            case EOVERFLOW: return 84;
            default: return 5;
        }
    }
    slot->base = static_cast<uint8_t *>(mapped);
    slot->size = rounded;
    std::fill_n(slot->permissions.begin(), rounded / 0x4000, protection);
    *address = reinterpret_cast<uintptr_t>(mapped);
    return 0;
#else
    return 46;
#endif
}
extern "C" uint32_t hm_guest_vm_deallocate(const void *, uint64_t address, uint64_t size)
{
#if defined(__aarch64__) && defined(HM_HAS_IOS_CACHE)
    if (!size) return 0;
    if (address % 0x4000 || size > UINT64_MAX - 0x3fff) return 4;
    const auto rounded = (size + 0x3fff) & ~0x3fffULL;
    if (address > UINT64_MAX - rounded) return 4;
    const auto end = address + rounded;
    for (size_t index = 0; index < anonymousRegions.size(); ++index) {
        auto &region = anonymousRegions[index];
        if (!region.base) continue;
        const auto regionStart = reinterpret_cast<uintptr_t>(region.base);
        if (address < regionStart || end > regionStart + region.size) continue;
        const auto prefix = address - regionStart;
        const auto suffix = regionStart + region.size - end;
        const auto startPage = prefix / 0x4000;
        const auto pageCount = rounded / 0x4000;
        Anonymous *suffixRegion = nullptr;
        size_t suffixIndex = anonymousRegions.size();
        if (prefix && suffix) {
            for (size_t candidate = 0; candidate < anonymousRegions.size(); ++candidate) {
                if (!anonymousRegions[candidate].base) {
                    suffixRegion = &anonymousRegions[candidate];
                    suffixIndex = candidate;
                    break;
                }
            }
            if (!suffixRegion) return 3;
        }
        if (munmap(reinterpret_cast<void *>(address), rounded)) return 1;
        if (!prefix && !suffix) {
            region.base = nullptr;
            region.size = 0;
            region.permissions.fill(0);
        } else if (!prefix) {
            std::move(region.permissions.begin() + pageCount,
                region.permissions.begin() + pageCount + suffix / 0x4000,
                region.permissions.begin());
            std::fill(region.permissions.begin() + suffix / 0x4000, region.permissions.end(), 0);
            region.base = reinterpret_cast<uint8_t *>(end);
            region.size = suffix;
        } else if (!suffix) {
            region.size = prefix;
            std::fill(region.permissions.begin() + prefix / 0x4000, region.permissions.end(), 0);
        } else {
            const auto suffixPages = suffix / 0x4000;
            std::copy(region.permissions.begin() + startPage + pageCount,
                region.permissions.begin() + startPage + pageCount + suffixPages,
                suffixRegion->permissions.begin());
            std::fill(suffixRegion->permissions.begin() + suffixPages,
                suffixRegion->permissions.end(), 0);
            suffixRegion->base = reinterpret_cast<uint8_t *>(end);
            suffixRegion->size = suffix;
            region.size = prefix;
            std::fill(region.permissions.begin() + prefix / 0x4000,
                region.permissions.end(), 0);
        }
        return 0;
    }
    return 1;
#else
    return 46;
#endif
}
