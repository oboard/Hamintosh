#include "frame_diagnostics.h"

#include <cassert>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <vector>

int main()
{
    // Test 1: Reset and verify initial state
    hm_frame_diagnostics_reset();
    assert(hm_frame_diagnostics_total_count() == 0);
    assert(hm_frame_diagnostics_snapshot().empty());

    // Test 2: FNV-1a hash correctness and determinism
    const uint8_t sample1[] = {0x01, 0x02, 0x03, 0x04};
    const uint8_t sample2[] = {0x01, 0x02, 0x03, 0x04};
    const uint8_t sample3[] = {0x01, 0x02, 0x03, 0x05};
    uint64_t hash1 = hm_frame_fnv1a_64(sample1, sizeof(sample1));
    uint64_t hash2 = hm_frame_fnv1a_64(sample2, sizeof(sample2));
    uint64_t hash3 = hm_frame_fnv1a_64(sample3, sizeof(sample3));
    assert(hash1 != 0);
    assert(hash1 == hash2);
    assert(hash1 != hash3);

    // Test 3: Record test pixels
    hm_frame_diagnostics_record(HM_FRAME_SOURCE_TEST_PIXELS, 100, 200, 400, 512, 12, sample1, sizeof(sample1));
    assert(hm_frame_diagnostics_total_count() == 1);
    auto snapshot = hm_frame_diagnostics_snapshot(10);
    assert(snapshot.size() == 1);
    assert(snapshot[0].sequenceNumber == 1);
    assert(snapshot[0].source == HM_FRAME_SOURCE_TEST_PIXELS);
    assert(snapshot[0].width == 100);
    assert(snapshot[0].height == 200);
    assert(snapshot[0].sourceStride == 400);
    assert(snapshot[0].bufferStride == 512);
    assert(snapshot[0].pixelFormat == 12);
    assert(snapshot[0].contentHash == hash1);

    // Test 4: Record Apple transaction frame
    hm_frame_diagnostics_record(HM_FRAME_SOURCE_APPLE_TRANSACTION, 540, 960, 2160, 2176, 12, sample3, sizeof(sample3));
    assert(hm_frame_diagnostics_total_count() == 2);
    snapshot = hm_frame_diagnostics_snapshot(10);
    assert(snapshot.size() == 2);
    assert(snapshot[1].sequenceNumber == 2);
    assert(snapshot[1].source == HM_FRAME_SOURCE_APPLE_TRANSACTION);
    assert(snapshot[1].width == 540);
    assert(snapshot[1].height == 960);
    assert(snapshot[1].contentHash == hash3);

    // Test 5: JSON serialization
    std::string json = hm_frame_diagnostics_to_json();
    assert(json.find("\"totalFrames\":2") != std::string::npos);
    assert(json.find("\"source\":\"test-pixels\"") != std::string::npos);
    assert(json.find("\"source\":\"apple-transaction\"") != std::string::npos);
    assert(json.find("\"width\":540") != std::string::npos);

    // Test 6: Reset clears records
    hm_frame_diagnostics_reset();
    assert(hm_frame_diagnostics_total_count() == 0);
    assert(hm_frame_diagnostics_snapshot().empty());

    // Transparent and padded data must not turn an empty guest layer into
    // evidence of visible App content.
    const uint8_t padded[] = {
        0, 0, 0, 255, 255, 255, 255, 0, 255, 255, 255, 255,
        1, 2, 3, 255, 0, 0, 0, 0, 255, 255, 255, 255
    };
    hm_frame_diagnostics_record(HM_FRAME_SOURCE_GUEST_LAYER_SNAPSHOT, 2, 2, 12, 12,
        20, padded, sizeof(padded));
    snapshot = hm_frame_diagnostics_snapshot();
    assert(snapshot[0].nonBlackPixels == 1);
    assert(snapshot[0].nonTransparentPixels == 2);
    assert(hm_frame_diagnostics_to_json().find("guest-layer-snapshot") != std::string::npos);
    hm_frame_diagnostics_reset();

    std::cout << "Frame diagnostics: recording, provenance, hashing and JSON passed\n";
    return 0;
}
