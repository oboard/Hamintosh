#pragma once

#include <cstddef>
#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

struct HmRenderSurfaceResult {
    bool success;
    const char *status;
};

// Attaches an ArkUI XComponent surface. The surface id is the decimal string
// returned by XComponentController.getXComponentSurfaceId().
HmRenderSurfaceResult hm_harmony_surface_attach(const char *surface_id,
    uint32_t width, uint32_t height);
void hm_harmony_surface_detach();

// Copies a tightly packed BGRA frame into the current OHNativeWindow and
// presents it. This is the M1 CoreAnimation/IOSurface software-output entry.
HmRenderSurfaceResult hm_harmony_surface_present_bgra(const uint8_t *pixels,
    size_t size, uint32_t width, uint32_t height, uint32_t stride);

// Presents a synthetic/test BGRA frame to verify the host display pipeline
// independently of Apple guest rendering.
HmRenderSurfaceResult hm_harmony_surface_present_test_pattern(uint32_t pattern_id);

// Retains the underlying OHNativeWindow for a Vulkan or Metal compatibility
// swapchain. The caller must release the result with
// hm_harmony_surface_release_native_window().
void *hm_harmony_surface_retain_native_window();
void hm_harmony_surface_release_native_window(void *window);

bool hm_harmony_surface_is_attached();

#ifdef __cplusplus
}
#endif
