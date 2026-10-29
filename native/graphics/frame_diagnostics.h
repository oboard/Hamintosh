#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#ifdef __cplusplus
extern "C" {
#endif

// Source category of a presented frame.
typedef enum {
    HM_FRAME_SOURCE_UNKNOWN = 0,
    HM_FRAME_SOURCE_TEST_PIXELS = 1,
    HM_FRAME_SOURCE_APPLE_TRANSACTION = 2,
    HM_FRAME_SOURCE_GUEST_LAYER_SNAPSHOT = 3
} HmFrameSource;

#ifdef __cplusplus
}
#endif

struct HmFrameDiagnosticRecord {
    uint64_t sequenceNumber;
    HmFrameSource source;
    uint32_t width;
    uint32_t height;
    uint32_t sourceStride;
    uint32_t bufferStride;
    uint32_t pixelFormat;
    uint64_t contentHash;
    uint64_t timestampNs;
    uint64_t nonBlackPixels;
    uint64_t nonTransparentPixels;
};

#ifdef __cplusplus
extern "C" {
#endif

// Records a newly presented frame into the diagnostic ring buffer.
void hm_frame_diagnostics_record(HmFrameSource source, uint32_t width,
    uint32_t height, uint32_t source_stride, uint32_t buffer_stride,
    uint32_t pixel_format, const uint8_t *pixels, size_t size);

// Resets all frame diagnostic records (e.g. at cold start or test boundary).
void hm_frame_diagnostics_reset(void);

// Returns the total number of frames recorded since process start or last reset.
uint64_t hm_frame_diagnostics_total_count(void);

// Computes 64-bit FNV-1a hash of a byte buffer.
uint64_t hm_frame_fnv1a_64(const uint8_t *data, size_t size);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
// Returns the last N frame records (up to max_count).
std::vector<HmFrameDiagnosticRecord> hm_frame_diagnostics_snapshot(size_t max_count = 32);

// Formats the records as JSON string.
std::string hm_frame_diagnostics_to_json(size_t max_count = 32);
#endif
