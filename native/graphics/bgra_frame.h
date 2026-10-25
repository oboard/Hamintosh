#pragma once

#include <cstddef>
#include <cstdint>

// Copies one tightly packed BGRA frame into an OHOS buffer that may have a
// larger stride. This function has no platform dependency so its bounds and
// row-copy behavior can be tested on the build host.
bool hm_copy_bgra_frame(uint8_t *destination, size_t destination_size,
    uint32_t destination_stride, const uint8_t *source, size_t source_size,
    uint32_t width, uint32_t height, uint32_t source_stride);
