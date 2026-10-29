# Unified Harmonios toolchain

`tools/converter/src/main.rs` is the entry point for the Rust `harmonios` CLI.
`src/toolkit/` implements the host tools. CMake invokes the same CLI with Cargo;
there is no Python subprocess in the native build or device-run path.

```sh
cargo install --path tools/converter --locked
harmonios prepare-ipa '/path/to/App.ipa'
harmonios run-device --no-clean --output artifacts/my-run
```

`harmonios install App.ipa` prepares the selected IPA, rebuilds and signs the
HAP with that actual target, installs the HAP/HSP, and collects a device run.
`--no-launch` stops after installation. Merely copying another executable into
the sandbox cannot change the code already embedded in the signed HAP.
`convert` produces audited AOT source artifacts; those sources still require
compilation and HAP signing before execution.

## Commands

| Command | Replaces the former tool |
| --- | --- |
| `prepare-ipa IPA` | `prepare_ipa.py` |
| `pack-macho IMAGE OUTPUT [--role target\|bootstrap\|dyld]` | `pack_macho.py` |
| `pack-probe IMAGE ASSEMBLY` | `pack_probe.py` |
| `pack-darwin-probe OUTPUT` | `pack_darwin_probe.py` |
| `make-bootstrap-fixture OUTPUT --clang CLANG --objcopy OBJCOPY` | `make_bootstrap_fixture.py` |
| `prepare-bootstrap DYLD CACHE OUTPUT` | `prepare_bootstrap.py` |
| `pack-objc-trampolines IMAGE OUTPUT [--pools 8]` | `pack_objc_trampolines.py` |
| `pack-objc-trampolines IMAGE --verify-elf ELF` | Trampoline ELF byte/permission verification |
| `pack-cache CACHE OUTPUT --pages CONFIG [--clang CLANG] [--full]` | `pack_cache.py` |
| `pack-cache-data CACHE OUTPUT` | `pack_cache_data.py` |
| `audit-libsystem-shim CACHE PACKAGE_JSON OUTPUT` | `audit_libsystem_shim.py` |
| `build` / `sign` | Signed HSP and HAP build via Hvigor |
| `run-device [--device ID] [--output DIRECTORY]` | `run_device.py`, including cache HSP reuse |
| `collect-device [--device ID] [--output DIRECTORY]` | `collect_device.py` |
| `repeat-run-acceptance [--runs 3]` | `repeat_run_acceptance.py` |
| `analyze-device-fault REPORT` | `analyze_device_fault.py` |
| `analyze-workqueue-report REPORT` | `analyze_workqueue_report.py` |
| `stage-sysroot SOURCE [--output OUTPUT]` | `stage_sysroot.py` |
| `stage-system-resources SOURCE PATH... [--output OUTPUT]` | `stage_system_resources.py` |
| `fetch-zip-member URL MEMBER OUTPUT [--workers 16]` | Both ZIP range download tools |
| `extract-sysroot ARCHIVE OUTPUT --ipsw IPSW --pem-db DB` | `extract_sysroot.py` |
| `extract-bootstrap ARCHIVE OUTPUT --ipsw IPSW --cache CACHE` | `extract_bootstrap.py` |
| `cache-info CACHE` | Direct use of the runtime cache parser |
| `dump-backboard-headers CACHE OUTPUT --ipsw IPSW` | Dump actual BackBoard interfaces with cache provenance |
| `cache-read CACHE VM_ADDRESS SIZE OUTPUT` | Bounded reads for cache disassembly |
| `cache-address CACHE ADDRESS [--runtime-base BASE]` | Resolve a preferred or runtime address to its image, section and nearest function start |
| `cache-objc-class CACHE CLASSREF_VM_ADDRESS` | Follow cache rebases to identify an Objective-C class reference |
| `render-probe` | `render_probe.py` |

`fetch-zip-member-aria2` is an alias using the same Rust parallel range downloader;
`--connections` aliases `--workers`. The downloader uses curl for HTTP transport,
validates Content-Range and ETag, checkpoints completed blocks after syncing data,
and verifies the expanded size and CRC32 before publishing a member. It handles
stored and deflated ZIP64 members. Extraction requires a completed verified download.

Device runs support `--skip-build`, `--skip-install`, `--no-launch`, `--clean`,
`--no-clean`, `--force-cache-hsp`, `--repack-cache`, `--no-repack-cache`,
`--repack-cache-data`, `--no-stage-cache-data`, `--bundle`, `--ability`, and
`--timeout`. `--clean` is explicit; normal runs use incremental builds.
An advisory workspace lock serializes Rust device runs. Incomplete runs preserve
logs, process observations, and a screenshot when available.
`--no-compress-transfer` disables HDC compression for transport diagnostics.
Large files sent to `/data/local/tmp` use 64 MiB streams, device-side assembly
and a full SHA-256 check before publishing the completed transfer.

The former Python files remain as regression references for the existing Python
tests and historical command records. They are not called by the Rust CLI or
CMake. Production use should invoke `harmonios`; no new behavior is added to the
Python copies.

## Conversion-time ABI plan

`pack-macho` generates `abi-plan.json` alongside the assembly, linker script and
C++ header. App data offsets come from actual Mach-O segments and chained fixups.
Protocol, nominal-type, conformance and requirement imports are resolved through
bounded export tries and declared reexports. Local nominal descriptors must be
listed by `__swift5_types`, reside in immutable metadata, and match their saved
headers. No fixed data interval from a previous App authorizes a new pointer.

The converter records SwiftCore's original AUTDA/check sequences and binds them
to the selected cache UUID. The native bridge validates those instructions, the
exact slot and target, the metadata category's discriminator, and local headers
before signing a temporary register and retrying Apple's original AUTDA. App GOT
slots retain the representation produced by dyld. This remains a bounded ABI
bridge rather than a complete ARM64-to-ARM64e compiler.

For App code that loads a value-witness pointer and immediately forms its layout
address (`metadata[-1] + 64`), conversion audits the exact instruction pair and
replaces the ADD with a declared bridge trap in the signed ELF. The bridge
authenticates the pointer against its metadata slot before adding the offset.
The loader compares the full mapped code against an expected shadow image;
the source IPA and runtime executable pages are never rewritten.

The metadata relationships follow Swift's
[ABI metadata definitions](https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h)
and [relative-pointer layout](https://github.com/swiftlang/swift/blob/main/include/swift/Basic/RelativePointer.h).

## Verification on 2026-10-28

- Rebuilt cache: 287 ranges, 655,589,376 selected bytes and 3,509 patch records.
  Every range's offset, size, permission and packed SHA-256 matches the existing
  package. The linked ELF passes load-permission, span, header-table and byte checks.
  Its full SHA-256 is
  `71703b07272cd29691a4cde11c149eab8a50b703995d9a2fd26686debba2be82`.
- Rebuilt data pack: 2,329,690,112 bytes, 3,428 mappings, SHA-256
  `25f72fcd350990fed1d224aba58c50503a4175fb9a78cc120277ef9892537149`;
  byte identity matches the existing package's SHA-256.
- Rust tests cover slot bounds beyond the old App layout, invalid metadata binds,
  export trie errors, RX mapping boundaries, report chunks, and a real local
  HTTP-range/deflate/CRC download round trip.
- The new Gallery IPA has entered its App code and UIKit's idle receive loop on
  device. The `challenge-demo-rust-live-context` run recorded 710,887 traps, two
  converted layout-address bridges, and a diagnostic timeout with signal zero.
  It produced zero guest frames; scene connection and real rendering still
  require further runtime work.

Local evidence is in `artifacts/rust-cache-validation/`,
`artifacts/rust-data-validation/`, and `artifacts/challenge-demo-rust-*/`.

## Real rendering and input work, 2026-10-28

Use `harmonios run-device --ability HarmoniosSpecifiedAbility --output DIR` for
the full-screen guest surface. AppRunner guards against duplicate launches on
surface reconstruction. Both runtime windows request foreground keep-screen-on;
the CLI validates ability launch success and bounds each HDC command.

`CALayer.renderInContext:` output now has `guest-layer-snapshot` provenance,
separate from an Apple transaction. Frame records count visible non-black and
non-transparent pixels, excluding row padding. The former one-frame black result
is not a Gallery rendering success: `artifacts/gallery-render-fullscreen/` has
zero visible pixels and no root view controller.

The IPC path now delivers a combined send/receive reply during that same trap,
instead of leaving it queued for a later wait on the reused thread port. The
captured notification-center bootstrap request verifies exactly one copyout and
no residual reply. Bootstrap replies use a proper complex Mach body, received
send-right descriptor, requested audit trailer, bootstrap sender identity and
the recipient PID/exec-count fields checked by the original libxpc. Recipient
identity matches TASK_AUDIT_TOKEN. Ordinary local replies retain their own sender
identity. Scalar untimed receives release the guest execution gate while waiting
for a reply, and shutdown interrupts the wait with balanced gate hooks.

Scene delivery excludes successful RPC receives and admits the observed empty
message/auxiliary vector receive at the CoreFoundation loop. A scene fault ends
the guest attempt and preserves the actual signal, stage, registers and bounded
stack evidence; it no longer continues to submit an empty window.

`artifacts/gallery-render-blocking-reply/device-compat-report.json` has passed the
previous libdispatch reply-port/receive-timeout failures and reached a new
BackBoardServices assertion at cache offset `0xa1030d8`, stage 24. Disassembly
identifies `BKSHIDEventDeliveryManager.m:170`: its
`clientConnectionForServiceWithName:` lookup for `BKHIDEventDeliveryManager`
returns nil. The next implementation step is a real local HID delivery connection
and scene context. Real Gallery pixels and touch responses remain unverified.

Checks are recorded in `artifacts/gallery-ipc-runtime-tests.log`,
`artifacts/gallery-ipc-runtime-clippy.log` and `artifacts/rust-toolchain-tests.log`.
Native tests cover frame transparency/padding and RPC-versus-idle receive routing.

For device logs, pass the cache base from the same process to `cache-address` as `--runtime-base`. Function starts are boundaries, not symbol names; an address outside any image has no image field. `cache-objc-class` accepts a preferred cache address of a class-reference slot and reads version-5 slide chains; it is intended for cache class references with read-only class metadata.
