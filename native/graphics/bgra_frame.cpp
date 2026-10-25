#include "bgra_frame.h"

#include <cstring>
#include <limits>

bool hm_copy_bgra_frame(uint8_t *destination, size_t destination_size,
    uint32_t destination_stride, const uint8_t *source, size_t source_size,
    uint32_t width, uint32_t height, uint32_t source_stride)
{
    if (!destination || !source || width == 0 || height == 0 || width > 8192 || height > 8192)
        return false;
    if (width > std::numeric_limits<uint32_t>::max() / 4) return false;
    const uint32_t row_size = width * 4;
    if (source_stride < row_size || destination_stride < row_size) return false;
    const uint64_t source_required = static_cast<uint64_t>(source_stride) * (height - 1) + row_size;
    const uint64_t destination_required = static_cast<uint64_t>(destination_stride) * (height - 1) + row_size;
    if (source_required > source_size || destination_required > destination_size) return false;
    for (uint32_t row = 0; row < height; ++row)
        std::memcpy(destination + static_cast<size_t>(row) * destination_stride,
            source + static_cast<size_t>(row) * source_stride, row_size);
    return true;
}
