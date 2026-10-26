# Host Presentation and Acceptance Preparation (Track 4)

## Overview

Track 4 prepares the HarmonyOS host presentation pipeline and acceptance tooling for the first SwiftUI frame on ARM64. It audits the existing display path (`native/graphics/`, `napi_init.cpp`, `Index.ets`), adds frame diagnostics to record frame provenance and content hashes, and introduces repeat run acceptance verification (`tools/repeat_run_acceptance.py`).

---

## 1. Host Display Path Audit & Fixes

### 1.1 Buffer Handle Usage Flags
- **Problem**: When creating `OHNativeWindow` via `OH_NativeWindow_CreateNativeWindowFromSurfaceId()`, buffer usage was left unconfigured (`0`). While `SET_BUFFER_GEOMETRY` and `SET_FORMAT` (BGRA_8888) were requested, omitting CPU read/write and GPU render usage flags (`SET_USAGE`) caused some graphics driver implementations to allocate buffers backed solely by non-CPU-mappable hardware regions, leading to failure or `virAddr == nullptr` requiring fallback `mmap`.
- **Fix**: Configured explicit `SET_USAGE` in `hm_harmony_surface_attach`:
  ```cpp
  const uint64_t usage = NATIVEBUFFER_USAGE_CPU_READ | NATIVEBUFFER_USAGE_CPU_WRITE |
      NATIVEBUFFER_USAGE_MEM_DMA | NATIVEBUFFER_USAGE_HW_RENDER | NATIVEBUFFER_USAGE_HW_TEXTURE;
  (void)OH_NativeWindow_NativeWindowHandleOpt(window, SET_USAGE, usage);
  ```

### 1.2 NativeWindow Cache Cleaning & Stale Frame Elimination
- **Problem**: During rapid relaunch, page re-entry, or re-attaching the XComponent surface (`onDestroy` -> `onLoad`), older buffer queues could retain unflushed buffers or cached handles from a prior session, presenting stale frames across runs.
- **Fix**: Called `OH_NativeWindow_CleanCache(window)` upon detaching or re-attaching an existing window in `harmony_surface.cpp` before destruction.

### 1.3 BGRA Stride and Bounds Validation
- **Audit**: `hm_copy_bgra_frame` correctly verifies `row_size = width * 4`, `source_stride >= row_size`, `destination_stride >= row_size`, and strict bounds `(height - 1) * stride + row_size <= buffer_size`. It performs row-by-row `memcpy`, preventing buffer overrun when the hardware buffer stride exceeds `width * 4`.

### 1.4 NativeWindow Buffer Lifecycle & Fence Discipline
- **Audit**:
  - `OH_NativeWindow_NativeWindowRequestBuffer` returns an acquired buffer and fence.
  - Acquired `fenceFd >= 0` is closed immediately before CPU write operations.
  - If buffer validation, mapping, or row copy fails, `OH_NativeWindow_NativeWindowAbortBuffer` is invoked to return the buffer cleanly to the queue without flushing bad pixels.
  - Flush completes with `OH_NativeWindow_NativeWindowFlushBuffer(nativeWindow, buffer, -1, region)` with default full-dirty region.

---

## 2. Frame Provenance Diagnostics

To strictly separate synthetic test frames from genuine Apple UIKit / CoreAnimation transactions and prevent false positive claims of a "first frame", frame provenance diagnostics have been added in `native/graphics/frame_diagnostics.h` and `native/graphics/frame_diagnostics.cpp`.

### 2.1 Recorded Metadata Per Presented Frame
Every frame presented through `hm_harmony_surface_present_bgra` or `hm_harmony_surface_present_test_pattern` records:
- `sequenceNumber`: Monotonically increasing 1-based counter per process run.
- `source`:
  - `test-pixels` (`HM_FRAME_SOURCE_TEST_PIXELS`): Synthetic test pattern generated host-side.
  - `apple-transaction` (`HM_FRAME_SOURCE_APPLE_TRANSACTION`): Real frame from Apple CoreAnimation / IOSurface transaction.
- `width`, `height`: Rendered dimensions.
- `sourceStride`, `bufferStride`: Stride of input vs NativeWindow buffer.
- `pixelFormat`: Hardware pixel format (e.g. `NATIVEBUFFER_PIXEL_FMT_BGRA_8888`).
- `contentHash`: 64-bit FNV-1a hash of the pixel payload.
- `timestampNs`: Nanosecond timestamp from `std::chrono::steady_clock`.

### 2.2 Integration Seams
- **Host Library**: `native/graphics/frame_diagnostics.cpp` maintains an in-memory thread-safe ring buffer of recent frames.
- **N-API**:
  - `runDiagnostics` now embeds `"frameDiagnostics"` in `compatReport`.
  - `presentTestPattern(patternId)` allows explicit host presentation testing.
  - `getFrameDiagnostics()` and `resetFrameDiagnostics()` expose frame records.
- **Index.ets**: Included in `compat-report.json` and chunked via `hilog` (`HarmoniosReport`).

---

## 3. Acceptance Script: `tools/repeat_run_acceptance.py`

### 3.1 Purpose
Runs cold-start repeat iterations (default: 3) against a connected HarmonyOS device using `tools/run_device.py`. It guarantees repeatability and checks:
1. Cold-start independence: each run forces app termination (`aa force-stop`), clears logs, and launches cleanly.
2. Complete reporting: validates `device-compat-report.json` and `harmonios-latest.jpeg` exist for every run.
3. Fresh frame verification: verifies that the first presented frame in each run starts at sequence 1, confirming no stale process or window reuse across runs.
4. Screenshot integrity: checks that screenshots have valid file sizes and captures.

### 3.2 Usage
```bash
# Run 3 consecutive cold-start checks on the default device
python3 tools/repeat_run_acceptance.py --runs 3

# Target a specific device serial and custom output directory
python3 tools/repeat_run_acceptance.py --runs 5 --device <serial> --output artifacts/acceptance-test
```

### 3.3 Acceptance Output
Generates per-run folders (`run-01/`, `run-02/`, ...) and a consolidated summary file `acceptance-summary.json` documenting execution timings, exit codes, trap counts, and provenance validation.
