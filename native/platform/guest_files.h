#pragma once
#include <cstdint>
#include <cstddef>
extern "C" uint32_t hm_guest_open(const void *context, int32_t parent, const uint8_t *path, size_t length,
    uint32_t flags, uint32_t mode, int32_t *descriptor);
extern "C" uint32_t hm_guest_close(const void *context, int32_t descriptor);
extern "C" uint32_t hm_guest_duplicate(const void *context, int32_t descriptor, int32_t *output);
extern "C" uint32_t hm_guest_file_stat(const void *context, int32_t parent,
    const uint8_t *path, size_t length, uint32_t flags, uint8_t *output, size_t outputSize);
extern "C" uint32_t hm_guest_code_signature_blob(const void *context, uint32_t type,
    uint64_t output, uint64_t outputSize);
extern "C" uint32_t hm_guest_file_read(const void *context, int32_t descriptor,
    uint8_t *output, size_t size, int64_t offset, size_t *count);
extern "C" uint32_t hm_guest_file_seek(const void *context, int32_t descriptor,
    int64_t offset, uint32_t whence, int64_t *position);
