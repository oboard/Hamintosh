#include "harmony_surface.h"
#include "bgra_frame.h"
#include "frame_diagnostics.h"

#include <native_window/buffer_handle.h>
#include <native_buffer/buffer_common.h>
#include <native_buffer/native_buffer.h>
#include <native_window/external_window.h>

#include <cstring>
#include <limits>
#include <mutex>
#include <vector>
#include <sys/mman.h>
#include <unistd.h>

namespace {
std::mutex surfaceMutex;
OHNativeWindow *nativeWindow = nullptr;
uint32_t surfaceWidth = 0;
uint32_t surfaceHeight = 0;

HmRenderSurfaceResult PresentInternal(const uint8_t *pixels, size_t size,
    uint32_t width, uint32_t height, uint32_t stride, HmFrameSource source)
{
    if (!pixels || !width || !height || stride < width * 4)
        return {false, "invalid-frame"};

    std::lock_guard<std::mutex> lock(surfaceMutex);
    if (!nativeWindow) return {false, "surface-not-attached"};
    if (width != surfaceWidth || height != surfaceHeight) return {false, "frame-geometry-mismatch"};

    OHNativeWindowBuffer *buffer = nullptr;
    int fence = -1;
    if (OH_NativeWindow_NativeWindowRequestBuffer(nativeWindow, &buffer, &fence) != 0 || !buffer)
        return {false, "native-window-request-failed"};
    if (fence >= 0) close(fence);

    BufferHandle *handle = OH_NativeWindow_GetBufferHandleFromNative(buffer);
    if (!handle || handle->stride <= 0 || handle->size <= 0 ||
            static_cast<uint32_t>(handle->stride) < width * 4) {
        (void)OH_NativeWindow_NativeWindowAbortBuffer(nativeWindow, buffer);
        return {false, "native-window-invalid-buffer"};
    }

    uint8_t *mapped = static_cast<uint8_t *>(handle->virAddr);
    bool mappedHere = false;
    if (!mapped && handle->fd >= 0) {
        mapped = static_cast<uint8_t *>(mmap(nullptr, static_cast<size_t>(handle->size),
            PROT_READ | PROT_WRITE, MAP_SHARED, handle->fd, 0));
        if (mapped == MAP_FAILED) mapped = nullptr;
        else mappedHere = true;
    }
    if (!mapped || !hm_copy_bgra_frame(mapped, static_cast<size_t>(handle->size),
            static_cast<uint32_t>(handle->stride), pixels, size, width, height, stride)) {
        if (mappedHere) munmap(mapped, static_cast<size_t>(handle->size));
        (void)OH_NativeWindow_NativeWindowAbortBuffer(nativeWindow, buffer);
        return {false, "native-window-copy-failed"};
    }
    if (mappedHere) munmap(mapped, static_cast<size_t>(handle->size));

    Region region {nullptr, 0};
    if (OH_NativeWindow_NativeWindowFlushBuffer(nativeWindow, buffer, -1, region) != 0) {
        (void)OH_NativeWindow_NativeWindowAbortBuffer(nativeWindow, buffer);
        return {false, "native-window-flush-failed"};
    }

    // Record frame provenance diagnostics
    hm_frame_diagnostics_record(source, width, height, stride,
        static_cast<uint32_t>(handle->stride),
        static_cast<uint32_t>(handle->format),
        pixels, size);

    return {true, "frame-presented"};
}
}

bool hm_harmony_surface_is_attached()
{
    std::lock_guard<std::mutex> lock(surfaceMutex);
    return nativeWindow != nullptr;
}

HmRenderSurfaceResult hm_harmony_surface_attach(const char *surface_id,
    uint32_t width, uint32_t height)
{
    if (!surface_id || !*surface_id || !width || !height || width > 8192 || height > 8192)
        return {false, "invalid-surface-geometry"};
    uint64_t parsed = 0;
    for (const char *digit = surface_id; *digit; ++digit) {
        if (*digit < '0' || *digit > '9') return {false, "invalid-surface-id"};
        const uint64_t value = static_cast<uint64_t>(*digit - '0');
        if (parsed > (std::numeric_limits<uint64_t>::max() - value) / 10)
            return {false, "invalid-surface-id"};
        parsed = parsed * 10 + value;
    }
    if (parsed == 0) return {false, "invalid-surface-id"};

    OHNativeWindow *window = nullptr;
    if (OH_NativeWindow_CreateNativeWindowFromSurfaceId(parsed, &window) != 0 || !window)
        return {false, "native-window-create-failed"};
    if (OH_NativeWindow_NativeWindowHandleOpt(window, SET_BUFFER_GEOMETRY,
            static_cast<int32_t>(width), static_cast<int32_t>(height)) != 0) {
        OH_NativeWindow_DestroyNativeWindow(window);
        return {false, "native-window-geometry-failed"};
    }
    if (OH_NativeWindow_NativeWindowHandleOpt(window, SET_FORMAT,
            static_cast<int32_t>(NATIVEBUFFER_PIXEL_FMT_BGRA_8888)) != 0) {
        OH_NativeWindow_DestroyNativeWindow(window);
        return {false, "native-window-format-failed"};
    }
    const uint64_t usage = NATIVEBUFFER_USAGE_CPU_READ | NATIVEBUFFER_USAGE_CPU_WRITE |
        NATIVEBUFFER_USAGE_MEM_DMA | NATIVEBUFFER_USAGE_HW_RENDER | NATIVEBUFFER_USAGE_HW_TEXTURE;
    (void)OH_NativeWindow_NativeWindowHandleOpt(window, SET_USAGE, usage);
    (void)OH_NativeWindow_NativeWindowHandleOpt(window, SET_SWAP_INTERVAL, 1);
    (void)OH_NativeWindow_NativeWindowHandleOpt(window, SET_TIMEOUT, 250);

    std::lock_guard<std::mutex> lock(surfaceMutex);
    if (nativeWindow) {
        OH_NativeWindow_CleanCache(nativeWindow);
        OH_NativeWindow_DestroyNativeWindow(nativeWindow);
    }
    nativeWindow = window;
    surfaceWidth = width;
    surfaceHeight = height;
    return {true, "surface-attached"};
}

void hm_harmony_surface_detach()
{
    OHNativeWindow *window = nullptr;
    {
        std::lock_guard<std::mutex> lock(surfaceMutex);
        window = nativeWindow;
        nativeWindow = nullptr;
        surfaceWidth = 0;
        surfaceHeight = 0;
    }
    if (window) {
        OH_NativeWindow_CleanCache(window);
        OH_NativeWindow_DestroyNativeWindow(window);
    }
}

void *hm_harmony_surface_retain_native_window()
{
    std::lock_guard<std::mutex> lock(surfaceMutex);
    if (!nativeWindow || OH_NativeWindow_NativeObjectReference(nativeWindow) != 0) return nullptr;
    return nativeWindow;
}

void hm_harmony_surface_release_native_window(void *window)
{
    if (window) (void)OH_NativeWindow_NativeObjectUnreference(window);
}

HmRenderSurfaceResult hm_harmony_surface_present_bgra(const uint8_t *pixels,
    size_t size, uint32_t width, uint32_t height, uint32_t stride)
{
    return PresentInternal(pixels, size, width, height, stride, HM_FRAME_SOURCE_APPLE_TRANSACTION);
}

HmRenderSurfaceResult hm_harmony_surface_present_test_pattern(uint32_t pattern_id)
{
    uint32_t width = 0;
    uint32_t height = 0;
    {
        std::lock_guard<std::mutex> lock(surfaceMutex);
        if (!nativeWindow) return {false, "surface-not-attached"};
        width = surfaceWidth;
        height = surfaceHeight;
    }
    if (!width || !height) return {false, "invalid-surface-geometry"};

    const uint32_t stride = width * 4;
    const size_t total_bytes = static_cast<size_t>(stride) * height;
    std::vector<uint8_t> test_pixels(total_bytes);

    for (uint32_t y = 0; y < height; ++y) {
        uint8_t *row = test_pixels.data() + static_cast<size_t>(y) * stride;
        for (uint32_t x = 0; x < width; ++x) {
            uint8_t *pixel = row + x * 4;
            if (pattern_id == 1) {
                // Color gradient
                pixel[0] = static_cast<uint8_t>((x * 255) / width);         // B
                pixel[1] = static_cast<uint8_t>((y * 255) / height);        // G
                pixel[2] = static_cast<uint8_t>(((x + y) * 255) / (width + height)); // R
                pixel[3] = 255;                                            // A
            } else if (pattern_id == 2) {
                // Checkerboard (32x32 tiles)
                const bool tile = ((x / 32) ^ (y / 32)) & 1;
                const uint8_t c = tile ? 240 : 30;
                pixel[0] = c;
                pixel[1] = c;
                pixel[2] = c;
                pixel[3] = 255;
            } else {
                // Solid cyan-ish test color
                pixel[0] = 0xeb; // B
                pixel[1] = 0x8a; // G
                pixel[2] = 0x12; // R
                pixel[3] = 0xff; // A
            }
        }
    }

    return PresentInternal(test_pixels.data(), test_pixels.size(), width, height, stride,
        HM_FRAME_SOURCE_TEST_PIXELS);
}
