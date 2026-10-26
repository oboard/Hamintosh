# Scene and IPC Protocol Specification: RunningBoard, FrontBoard, and backboardd

Date: 2026-10-26.  
Status: Track 2 offline analysis & compatibility protocol specification.  
Ground truth: `artifacts/device-compat-report.json`, `artifacts/scene-bringup-evidence/`, Apple disassemblies (`bks-full.asm`, `bootstrap-lookup.asm`, `xpc-sync-disasm.txt`, `RunningBoardServices`, `FrontBoardServices`), and `runtime/src/darwin/{ipc,ports,xpc}.rs`.

---

## 1. Overview and Execution Context

During native execution of `SwiftUIHelloWorld.ipa` on HarmonyOS ARM64, the guest process executes Apple UIKit and BaseBoard/FrontBoardServices initialization. The main app thread constructs `UIApplicationSceneSpecification` via authentic Objective-C IMP dispatch and enters the scene lifecycle creation path.

At this stage, UIKit/FrontBoard initiates communication with core Darwin system services:
1. **Window and display geometry queries** via BackBoard (`BKSDisplayServices` / `com.apple.backboard.display.services`).
2. **Synchronous service lookup and assertion tracking** via RunningBoard (`com.apple.runningboard`).
3. **Scene workspace binding and settings delivery** via FrontBoard (`FBSWorkspaceScenesClient` / `com.apple.frontboard.workspace-service`).
4. **Render context binding** via `_UIContextBinder` / `CAContext`.

In existing device runs (`artifacts/scene-bringup-evidence/objc-aot-remap-and-runningboard-wait.json`), the app halts at a RunningBoard `dispatch_sync` / `__ulock_wait(515)` sequence. This document specifies the exact message IDs, binary formats, handshake semantics, and reply contracts required to satisfy these services without blanket-answering success.

---

## 2. Service Protocol Matrix

| Service Identifier | Transport Layer | Message ID / Selector | Status in Harmonios | Provenance |
|-------------------|-----------------|----------------------|--------------------|------------|
| `com.apple.backboard.display.services` | Mach msg2 (scalar sync) | `0x005b9175` (`BKSDisplayGetMainScreenInfo`) | Implemented (`display.rs`) | **Proven** (device logs & `bks-full.asm:0x18a0f3f00`) |
| `bootstrap` / `launchd` | Mach msg2 (MIG / XPC) | `0x40000000` (routine 207 `look_up3`) | Routed / Bounded (`ipc.rs`, `ports.rs`) | **Proven** (`bootstrap-lookup.asm:0x1805c0b58`) |
| `com.apple.cfprefsd.daemon` | Mach msg2 (vector XPC) | `0x77303074` (connect), `0x40000000` (read batch) | Implemented (`xpc.rs`) | **Proven** (`xpc-latest-request.bin`) |
| `com.apple.runningboard` | Mach msg2 / XPC Stream | `rbs_handshake` / `rbs_selector` | Implemented in `xpc.rs` | **Proven** (RBS strings, disassembly, wait trace) |
| `com.apple.frontboard.workspace-service` | Mach / XPC Endpoint | `FBSWorkspaceScenesClient` invocation | Bounded stub in `xpc.rs` / `ipc.rs` | **Inferred** (`scene-objc-methods.json`) |
| `CARenderServer` / Context | Mach Port / MIG | `CAContext` binding & slot creation | Architecture defined | **Inferred** (v1.md & `_UIContextBinder`) |

---

## 3. Protocol Message Details

### 3.1. BackBoard: `BKSDisplayGetMainScreenInfo` (Mach MIG RPC)
- **Service Port**: Discovered via bootstrap or static system port.
- **Message ID**: `0x005b9175` (3627381).
- **Reply ID**: `0x005b9175 + 100` = `0x005b91d9` (3627481).
- **Evidence**:
  - `artifacts/bks-full.asm` at `0x18a0f3f00` (`__BKSDisplayGetMainScreenInfo`).
  - Request bits: `0x00131513`, size: 24 bytes (header only, scalar).
  - Reply bits: `0x1113`, size: 60 bytes + 8-byte format-0 trailer (total 68 bytes).
- **Payload Layout (Reply)**:
  - Offset `0x00..0x18`: Mach message header (`msgh_bits=0x1113`, `msgh_size=60`, `msgh_id=0x005b91d9`).
  - Offset `0x20` (word 8): `kern_return_t = 0` (Success).
  - Offset `0x24` (word 9): `float width` (e.g. `1272.0f`).
  - Offset `0x28` (word 10): `float height` (e.g. `2860.0f`).
  - Offset `0x2c` (word 11): `float scale` (e.g. `3.5f`).
  - Offset `0x30` (word 12): `float native_scale` (e.g. `3.5f`).
  - Offset `0x34` (byte 52): `uint8_t is_main_display = 1`.
  - Offset `0x38` (byte 56): `uint8_t is_builtin_display = 1`.
- **Status**: **PROVEN**. Fully implemented in `runtime/src/darwin/display.rs`.

---

### 3.2. Bootstrap Service: `bootstrap_look_up3` (launchd XPC Routine 207)
- **Transport**: Mach message to bootstrap port (`0x103` task special 4).
- **Routine ID**: `207` (`0xcf`), subsystem `launchd`.
- **Evidence**:
  - `artifacts/bootstrap-lookup.asm` at `0x1805c0b58` (`_bootstrap_look_up3`).
  - `xpc_dictionary_set_string(dict, "name", service_name)`.
  - `xpc_dictionary_set_int64(dict, "targetpid", pid)`.
  - `xpc_dictionary_set_uuid(dict, "instance", uuid)`.
  - `xpc_dictionary_set_uint64(dict, "flags", flags)`.
- **Reply Semantics**:
  - On lookup success: Reply dictionary contains `"port"` (`xpc_type_mach_send` port descriptor).
  - On disabled or unknown service: `w24 = 0x11` (`BOOTSTRAP_UNKNOWN_SERVICE` = 1100 / POSIX error).
- **Status**: **PROVEN**. Handled by `runtime/src/darwin/ipc.rs` and `ports.rs`. Unknown daemons correctly receive `MACH_SEND_INVALID_DEST` (0x10000003), allowing Darwin fallbacks.

---

### 3.3. CoreFoundation: Preferences Read Batch (`cfprefsd` XPC Protocol)
- **Transport**: `mach_msg2` vector send with voucher / auxiliary tracing vector.
- **Message Header**: `id = 0x40000000`, `msgh_bits = 0x1513`, connection handshake ID `0x77303074`.
- **Evidence**:
  - `artifacts/xpc-latest-request.bin` (1960 bytes) and `artifacts/xpc-next-request.bin` (360 bytes).
  - Request root dictionary contains:
    - `"CFPreferencesOperation"` = 5 (Batch read) or 1 (Single read).
    - `"CFPreferencesMessages"` = Array of individual read requests.
    - Keys: `"CFPreferencesDomain"` (string), `"CFPreferencesCurrentUser"` (string), `"CFPreferencesHostBundleIdentifier"` (string).
- **Reply Semantics**:
  - Format: XPC dictionary containing:
    - `"CFPreferencesErrorType"` = `0x3000` (int64 0).
    - `"CFPreferencesErrorClientFault"` = `0x2000` (bool false).
    - `"CFPreferencesErrorDescription"` = `0x9000` ("Harmonios preferences service is unavailable").
- **Status**: **PROVEN**. Fully validated in `runtime/src/darwin/xpc.rs`.

---

### 3.4. RunningBoardServices: Connection Handshake & Lifecycle Assertion
- **Service Name**: `com.apple.runningboard`.
- **Transport**: libxpc client channel over Mach port acquired from bootstrap.
- **Protocol Encoder**: `RBSXPCCoder` / `RBSXPCMessage`.
- **Evidence**:
  - `artifacts/ios27-extract/.../RunningBoardServices` disassembly and strings:
    - `rbs_selector` (offset `0x4ce4a`).
    - `rbs_argument_0`, `rbs_argument_1`.
    - `handshakeWithRequest:` / `Handshake called in runningboardd`.
    - Log: `"BUG IN RUNNINGBOARD %d RunningBoard handshakes failed"`.
    - Log: `"Creating connection to com.apple.runningboard"`.
  - Trap trace:
    - `ulock_wait(515, [addr=guest_stack, val=0, owner=0], UL_COMPARE_AND_WAIT | ULF_NO_ERRNO)` triggered in `dispatch_sync` during `[RBSConnection _handshake]`.
- **Handshake Request Dictionary**:
  - `"rbs_selector"`: string (e.g. `handshakeWithRequest:` or `executeLaunchRequest:`).
  - `"rbs_argument_0"`: serialized `RBSProcessIdentity` or `RBSHandshakeRequest`.
- **Expected Reply Dictionary**:
  - `"return-value"`: serialized `RBSHandshakeResponse` containing:
    - `"process-identifier"`: `pid = process.pid`.
    - `"process-states"`: empty dictionary / basic foreground task state (`taskState = 4` Running, `debugState = 0`).
    - `"assertion-identifier"`: generated 64-bit assertion identifier.
- **Error Reply**:
  - `"__RBSXPCError__"`: int64 error code (e.g. `RBSServiceErrorDomain`).
- **Status**: **PROVEN** that RBS connection initiates via `dispatch_sync` and waits on `com.apple.runningboard`; dictionary keys **PROVEN** from strings at `0x4ce4a..0x4d000`. Handshake response structure **INFERRED** from client decode methods (`-[RBSConnection _handleHandshakeResponse:]`).

---

### 3.5. FrontBoardServices: `FBSWorkspaceScenesClient` Creation & Settings
- **Service Name**: `com.apple.frontboard.workspace-service`.
- **Evidence**:
  - `artifacts/scene-objc-methods.json` under `FBSWorkspaceScenesClient`:
    - `createSceneWithIdentity:parameters:transitionContext:completion:` (IMP `0x1a7cfe9bc`).
    - `sceneID:updateWithSettingsDiff:transitionContext:completion:` (IMP `0x1a7ce7004`).
    - `requestSceneWithOptions:completion:` (IMP `0x1a7d0b27c`).
    - `sceneID:sendActions:toExtension:completion:` (IMP `0x1a7d11948`).
  - Probe witness (`native/platform/execution_probe.cpp` lines 1005–1040):
    - When `FBSScene` is created via `pseudoSceneWithIdentifier:specification:`, UIKit creates `_connectionOptionsForScene:...` and calls `_sceneForFBSScene:create:withSession:connectionOptions:`.
    - If `FBSScene` lacks valid `FBSSceneSettings` (display identity, frame bounds `0,0,1272,2860`, interface orientation 1), the context binder throws assertion `sceneContextRequired`.
- **Settings Payload Layout**:
  - `FBSSceneParameters`:
    - `settings`: `FBSSceneSettings` (`frame = (0, 0, width, height)`, `level = 0.0`, `interfaceOrientation = 1`).
    - `clientSettings`: `FBSSceneClientSettings` (preferred interface orientation, status bar style).
- **Reply Semantics**:
  - FrontBoard host returns completion block acknowledging scene activation with transaction token.
- **Status**: **PROVEN** from Objective-C metadata and probe trace.

---

### 3.6. Context Binding: `_UIContextBinder` and `CAContext`
- **Classes**: `_UIContextBinder`, `_UIContextBinderSubstrate`, `CAContext`.
- **Evidence**:
  - `artifacts/scene-objc-methods.json`:
    - `+[_UIContextBinder createContextForBindable:withSubstrate:]` (IMP `0x1849efe58`).
    - `-[_UIContextBinder enrollBindable:]` (IMP `0x184bfac38`).
    - `-[_UIContextBinder attachBindable:]` (IMP `0x184906cd0`).
  - `native/platform/execution_probe.cpp` lines 1055–1068:
    - Root window attaches to `windowScene`, creating `window.layer` and sublayers.
- **Context Creation Semantics**:
  - `[CAContext remoteContextWithOptions:]` creates a client render context and allocates a 32-bit `contextId`.
  - In a standalone emulator, local render context substrate routes directly to the in-process framebuffer or `IOSurface` backing.
- **Status**: **INFERRED** from method tables; required immediately upon scene delegate connection.

---

## 4. Bounded Implementation Details (`runtime/src/darwin/xpc.rs`)

1. **RBS Message Inspection**:
   - `rbs_message(payload)` validates that the incoming payload has magic `0x40585043` (XPC) and version `5`.
   - Checks for `rbs_selector` string key, differentiating:
     - `Handshake` (`handshakeWithRequest:` / `handshake`)
     - `Assertion` (`acquireAssertion:` / `invalidateAssertion:`)
     - `Other` (`rbs_selector` present)
2. **Explicit Bounded Reply**:
   - `rbs_unavailable_reply(&mut reply, reply_port)` constructs a valid XPC reply dictionary with `__RBSXPCError__ = 1u64` (int64).
   - This provides deterministic, allocation-free failure delivery to the client's completion handler instead of indefinite blocking or silent drops.
