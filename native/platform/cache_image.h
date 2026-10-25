#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
struct HmCacheImage {
    uint8_t *base = nullptr;
    size_t span = 0;
    void *entry = nullptr;
    uint8_t *bootstrapBase = nullptr;
    size_t bootstrapSpan = 0;
    uint8_t *stack = nullptr;
    size_t stackSize = 0;
    const char *executable = nullptr;
    const char *sysroot = nullptr;
    uint64_t rebases = 0;
    uint64_t cacheFileDevice = 0, cacheFileInode = 0;
    std::string error;
};
// Caller serializes preparation and execution. Each launch restores data before
// signing cache pointers with this host process's PAC keys.
HmCacheImage hm_prepare_cache_image();
std::string hm_prepare_cache_dynamic_data(HmCacheImage &image);
extern "C" uint32_t hm_guest_resolve_file_id(const void *context, uint64_t device,
    uint64_t inode, uint8_t *path, size_t *size);
bool hm_bootstrap_rebase_witness(const HmCacheImage &image);
std::string hm_prepare_commpage();
extern "C" uint32_t hm_cache_vm_protect(const void *context, uint64_t address,
    uint64_t size, uint32_t setMaximum, uint32_t protection);
extern "C" uint32_t hm_guest_getentropy(const void *context, uint64_t address, uint64_t size);
extern "C" uint32_t hm_guest_copy_out(const void *context, uint64_t address, const uint8_t *bytes, size_t size);
extern "C" uint32_t hm_guest_copy_in(const void *context, uint64_t address, uint8_t *bytes, size_t size);
extern "C" uint32_t hm_guest_clock(const void *context, uint32_t continuous, uint64_t *value);
extern "C" uint32_t hm_guest_vm_map(const void *context, uint64_t addressPointer,
    uint64_t size, uint64_t mask, uint32_t flags, uint32_t protection);
extern "C" uint32_t hm_guest_vm_deallocate(const void *context, uint64_t address, uint64_t size);
