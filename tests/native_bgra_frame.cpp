#include "bgra_frame.h"

#include <cassert>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <vector>

int main()
{
    constexpr uint32_t width = 2, height = 2, sourceStride = 8, destinationStride = 12;
    const std::vector<uint8_t> source {
        1, 2, 3, 4, 5, 6, 7, 8,
        9, 10, 11, 12, 13, 14, 15, 16,
    };
    std::vector<uint8_t> destination(destinationStride * height, 0xaa);
    assert(hm_copy_bgra_frame(destination.data(), destination.size(), destinationStride,
        source.data(), source.size(), width, height, sourceStride));
    const uint8_t expected[] {
        1, 2, 3, 4, 5, 6, 7, 8, 0xaa, 0xaa, 0xaa, 0xaa,
        9, 10, 11, 12, 13, 14, 15, 16, 0xaa, 0xaa, 0xaa, 0xaa,
    };
    assert(std::memcmp(destination.data(), expected, sizeof(expected)) == 0);
    assert(!hm_copy_bgra_frame(destination.data(), destination.size(), width * 4 - 1,
        source.data(), source.size(), width, height, sourceStride));
    assert(!hm_copy_bgra_frame(destination.data(), 19, destinationStride,
        source.data(), source.size(), width, height, sourceStride));
    assert(!hm_copy_bgra_frame(destination.data(), destination.size(), destinationStride,
        source.data(), source.size() - 1, width, height, sourceStride));
    assert(!hm_copy_bgra_frame(destination.data(), destination.size(), destinationStride,
        source.data(), source.size(), width, height, width * 4 - 1));
    std::cout << "BGRA frame: stride, bounds and row copies passed\n";
}
