#pragma once
#include <cstdint>
#include <cstddef>
extern "C" uint32_t hm_guest_open(const void *context, int32_t parent, const uint8_t *path, size_t length,
    uint32_t flags, uint32_t mode, int32_t *descriptor);
extern "C" uint32_t hm_guest_close(const void *context, int32_t descriptor);
extern "C" uint32_t hm_guest_duplicate(const void *context, int32_t descriptor, int32_t *output);
extern "C" uint32_t hm_guest_file_stat(const void *context, int32_t parent,
    const uint8_t *path, size_t length, uint32_t flags, uint8_t *output, size_t outputSize);
