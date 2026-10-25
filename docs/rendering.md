# Graphics handoff

## Implemented M1 boundary

`XComponent(SURFACE)` now provides a real ArkUI surface to the native library.
`XComponentController.getXComponentSurfaceId()` is passed through N-API, and
`OH_NativeWindow_CreateNativeWindowFromSurfaceId()` creates the process-local
`OHNativeWindow` used for presentation.

The native graphics boundary is:

```text
ArkUI XComponent
  -> OHNativeWindow
  -> hm_harmony_surface_present_bgra(...)
  -> OH_NativeWindow buffer queue
```

`hm_harmony_surface_present_bgra` accepts a tightly packed BGRA frame or a
stride-padded source, copies it into the requested buffer, and flushes the
buffer. It rejects geometry mismatches, short buffers, invalid strides, and
calls made before surface attachment. The app does not generate a placeholder
frame: nothing is presented until the Apple CoreAnimation/IOSurface bridge
supplies real pixels.

The BGRA row copy is platform independent and covered by
`tests/native_bgra_frame.cpp` and `tests/test_renderer.py`.

## CoreAnimation hook still required

The missing upstream hook is the point where Apple's UIKit/CoreAnimation
commits a drawable. A software path can forward its CPU-visible BGRA/IOSurface
contents to `hm_harmony_surface_present_bgra`. A GPU-only drawable must expose
its IOSurface-backed Metal texture instead; copying it through the CPU would
be a fallback with lower performance.

## Metal path

`metal2vulkan` is required for the final GPU architecture, but it is not a
prerequisite for every first M1 frame. Static SwiftUI text can use the CPU BGRA
path if UIKit/CoreAnimation produces a CPU-readable surface. It becomes
mandatory when the App's rendering requires GPU-only CoreAnimation or Metal
resources.

No `metal2vulkan`, MoltenVK, or equivalent translator is currently vendored in
this repository; only the architecture document references it. The native
surface boundary now exposes a retained `OHNativeWindow`:

```text
hm_harmony_surface_retain_native_window()
  -> vkCreateSurfaceOHOS(VK_OHOS_surface)
  -> Vulkan swapchain and queue
  -> metal2vulkan command/resource translation
  <- Apple Metal command buffers and textures
```

The translator must cover the operations reached by SwiftUI rather than a toy
triangle: `MTLDevice`, `MTLCommandQueue`, command buffers/encoders, textures,
IOSurfaces and external memory, render targets, samplers, buffers, and pipeline
creation. The retained window is the stable host swapchain handoff; ownership
is released with `hm_harmony_surface_release_native_window()`.

## Device evidence

A HarmonyOS ARM64 run reached `NativeWindow connected; waiting for a
CoreAnimation frame` with the XComponent surface visible. The same run still
reported `appExecuted=false`, so this confirms the host display boundary and
does not claim that SwiftUI rendered. No frame was synthesized or presented.
