# libsystem_kernel boundary

Harmonios currently enforces a syscall trap boundary, not a complete replacement
of the Apple `libsystem_kernel.dylib` image.

```text
Apple Framework
  -> Apple libSystem / libsystem_kernel wrapper bytes
  -> Darwin svc #0x80 replaced with a Harmonios trap
  -> hm_darwin_dispatch
  -> Darwin compatibility callbacks
  -> OHOS libc or Harmony services
```

The selected executable pages never contain an untranslated Darwin
`svc #0x80` or `TPIDRRO_EL0` read. This prevents the Darwin syscall number from
reaching the Harmony/Linux kernel ABI. Unknown calls stop at the compatibility
report instead of being passed through.

The Apple wrapper image still executes before the trap. Therefore this layer is
described as `svc-trap-boundary`; it is not `fullLibsystemKernelReplacement`.
The remaining hard problem is binding the selected libsystem_kernel exports to
Harmonios-owned entry points so that Apple wrapper code no longer executes.

## Build gate

`tools/run_device.py` runs:

```text
tools/audit_libsystem_shim.py
```

after AOT cache packaging and before the HAP build. The gate re-reads every
selected executable source range and its final packed page. It fails if:

- the source and patch manifest disagree;
- a packed page still contains `svc #0x80` or `TPIDRRO_EL0`;
- the expected Harmonios trap markers are missing; or
- an executable piece is absent or has a different size.

The audit writes `artifacts/ios27-aot/libsystem-shim.json`. It records the source,
patched, packed-remaining and trap-marker counts, plus the complete export
inventory and a hash for the selected `libsystem_kernel.dylib` export names.
The manifest also states explicitly whether the full image replacement exists.

## Current evidence

The audited iOS 27 package reports:

```text
replacementLevel: svc-trap-boundary
directHostSyscallABI: false
fullLibsystemKernelReplacement: false
```

The exact count and export list are emitted into `libsystem-shim.json` for each
package so stale documentation is not used as proof.

## Next implementation

Replace imports and/or export entry points for the symbols actually reached by
the App. The first candidates are the Mach RPC/trap exports used by dyld,
libdispatch and libxpc. Each replacement needs the original XNU signature,
guest-memory validation, Mach return conventions and a native/DarwinServer
implementation. A symbol is counted as replaced only when the Apple wrapper
entry is no longer part of the executed path and a test proves the Harmonios
entry returned the correct ABI result.
