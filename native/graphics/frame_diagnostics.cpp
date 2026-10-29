#include "frame_diagnostics.h"

#include <chrono>
#include <deque>
#include <iomanip>
#include <mutex>
#include <sstream>

namespace {
std::mutex diagnosticsMutex;
std::deque<HmFrameDiagnosticRecord> recentRecords;
uint64_t totalFrameCount = 0;
constexpr size_t MAX_RING_BUFFER = 64;

const char *SourceToString(HmFrameSource source)
{
    switch (source) {
    case HM_FRAME_SOURCE_TEST_PIXELS:
        return "test-pixels";
    case HM_FRAME_SOURCE_APPLE_TRANSACTION:
        return "apple-transaction";
    case HM_FRAME_SOURCE_GUEST_LAYER_SNAPSHOT:
        return "guest-layer-snapshot";
    default:
        return "unknown";
    }
}
}

extern "C" uint64_t hm_frame_fnv1a_64(const uint8_t *data, size_t size)
{
    constexpr uint64_t FNV_OFFSET_BASIS = 14695981039346656037ULL;
    constexpr uint64_t FNV_PRIME = 1099511628211ULL;

    uint64_t hash = FNV_OFFSET_BASIS;
    if (!data) return hash;
    for (size_t i = 0; i < size; ++i) {
        hash ^= static_cast<uint64_t>(data[i]);
        hash *= FNV_PRIME;
    }
    return hash;
}

extern "C" void hm_frame_diagnostics_record(HmFrameSource source, uint32_t width,
    uint32_t height, uint32_t source_stride, uint32_t buffer_stride,
    uint32_t pixel_format, const uint8_t *pixels, size_t size)
{
    const uint64_t hash = hm_frame_fnv1a_64(pixels, size);
    uint64_t nonBlack = 0, nonTransparent = 0;
    if (pixels && uint64_t(width) * 4 <= source_stride) {
        for (uint32_t y = 0; y < height; ++y) {
            const auto row = uint64_t(y) * source_stride;
            if (row > size || uint64_t(width) * 4 > size - row) break;
            for (uint32_t x = 0; x < width; ++x) {
                const auto *p = pixels + row + uint64_t(x) * 4;
                if (p[3]) ++nonTransparent;
                if (p[3] && (p[0] || p[1] || p[2])) ++nonBlack;
            }
        }
    }
    const auto now = std::chrono::steady_clock::now().time_since_epoch();
    const uint64_t timestampNs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(now).count());

    std::lock_guard<std::mutex> lock(diagnosticsMutex);
    ++totalFrameCount;
    HmFrameDiagnosticRecord record {
        totalFrameCount,
        source,
        width,
        height,
        source_stride,
        buffer_stride,
        pixel_format,
        hash,
        timestampNs,
        nonBlack,
        nonTransparent
    };

    recentRecords.push_back(record);
    while (recentRecords.size() > MAX_RING_BUFFER) {
        recentRecords.pop_front();
    }
}

extern "C" void hm_frame_diagnostics_reset(void)
{
    std::lock_guard<std::mutex> lock(diagnosticsMutex);
    recentRecords.clear();
    totalFrameCount = 0;
}

extern "C" uint64_t hm_frame_diagnostics_total_count(void)
{
    std::lock_guard<std::mutex> lock(diagnosticsMutex);
    return totalFrameCount;
}

std::vector<HmFrameDiagnosticRecord> hm_frame_diagnostics_snapshot(size_t max_count)
{
    std::lock_guard<std::mutex> lock(diagnosticsMutex);
    std::vector<HmFrameDiagnosticRecord> result;
    if (recentRecords.empty() || max_count == 0) return result;

    const size_t start = recentRecords.size() > max_count ?
        recentRecords.size() - max_count : 0;
    result.assign(recentRecords.begin() + start, recentRecords.end());
    return result;
}

std::string hm_frame_diagnostics_to_json(size_t max_count)
{
    const auto snapshot = hm_frame_diagnostics_snapshot(max_count);
    const uint64_t total = hm_frame_diagnostics_total_count();

    std::ostringstream ss;
    ss << "{\"totalFrames\":" << total << ",\"recentFrames\":[";
    for (size_t i = 0; i < snapshot.size(); ++i) {
        const auto &rec = snapshot[i];
        if (i > 0) ss << ",";
        ss << "{"
           << "\"sequenceNumber\":" << rec.sequenceNumber << ","
           << "\"source\":\"" << SourceToString(rec.source) << "\","
           << "\"width\":" << rec.width << ","
           << "\"height\":" << rec.height << ","
           << "\"sourceStride\":" << rec.sourceStride << ","
           << "\"bufferStride\":" << rec.bufferStride << ","
           << "\"pixelFormat\":" << rec.pixelFormat << ","
           << "\"contentHash\":\"0x" << std::hex << std::setfill('0') << std::setw(16) << rec.contentHash << std::dec << "\","
           << "\"timestampNs\":" << rec.timestampNs << ","
           << "\"nonBlackPixels\":" << rec.nonBlackPixels << ","
           << "\"nonTransparentPixels\":" << rec.nonTransparentPixels
           << "}";
    }
    ss << "]}";
    return ss.str();
}
