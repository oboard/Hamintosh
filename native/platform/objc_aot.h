#pragma once
#include <cstddef>
#include <cstdint>

void hm_objc_aot_reset();
int32_t hm_objc_aot_reserve(uint64_t *address, uint64_t size, uint64_t mask,
    uint32_t flags, uint32_t protection);
bool hm_objc_aot_access(uint64_t address, size_t size, uint32_t protection);
// -1 means the address/file does not belong to this signed AOT image.
int32_t hm_objc_aot_protect(uint64_t address, uint64_t size, uint32_t protection);
int32_t hm_objc_aot_deallocate(uint64_t address, uint64_t size);
extern "C" uint32_t hm_objc_aot_fcntl(const void *context, int32_t descriptor,
    uint32_t command, uint64_t argument);
extern "C" uint32_t hm_objc_aot_map_file(const void *context, uint64_t *address,
    uint64_t size, uint32_t protection, uint32_t flags, int32_t descriptor, uint64_t offset);

extern "C" uint32_t hm_objc_aot_remap(const void *context, uint64_t *address,
    uint64_t size, uint64_t mask, uint32_t flags, uint64_t source, uint32_t copy,
    uint32_t *current, uint32_t *maximum, uint32_t inheritance);
