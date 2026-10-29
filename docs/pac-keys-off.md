# iOS 27 keys-off conversion

The device pipeline defaults to `--pac strip`. `pacstrip.rs` derives the
same-size instruction rewrites from Bergamota, with one necessary difference:
OpenHarmony devices support hardware PAuth, so HINT encodings such as
PACIBSP/AUTIBSP must also become NOPs. Leaving a signing prologue beside a
RETAB converted to RET produces a signed branch destination.

The cache exports `hm_ios_cache_pac_mode`. Its eager relocator and lazy data
pager use that mode to leave authenticated fixup destinations unsigned. Guest
callbacks and worker entry pointers use the same policy; the isolated hardware
PAC and authenticated-rebase probes continue to use the host hardware keys.
The Darwin initial stack advertises `ptrauth_disabled=1`, following dyld's
`keysOff` and XNU's `PTRAUTH_DISABLED_FLAG` conventions.

Independent dyld and ObjC trampoline conversion use the packaged cache's mode.
Their standalone Mach-O passes exclude LC_DATA_IN_CODE ranges. Trampolines
retain a separate immutable original image for validating source files, while
the HAP contains the transformed executable image and prebuilt clones. The
ELF verifier checks each clone against the deterministic transformation.

Cache instructions are rewritten only inside code sections discovered from the
actual Mach-O headers and shared-cache branch islands. LDRAA/LDRAB recognition
uses the existing image whitelist because shared caches omit LC_DATA_IN_CODE.
The audit recomputes the expected transformation from the original cache and
compares every selected executable byte, including unchanged instructions.
It rejects both missing rewrites and undeclared mutations. PAC class counts
replace millions of redundant JSON patch objects; syscall and explicit patch
records remain separately audited.

`pacTransformVersion` invalidates older packages when the pass changes. The
runner stages the current cache library into the HSP module and verifies that
the signed HSP's cache SHA-256 matches that library before installation.

## Actual BackBoard interfaces

```sh
cargo run --manifest-path tools/converter/Cargo.toml -- \
  dump-backboard-headers \
  artifacts/ios27-system/cache/dyld_shared_cache_arm64e \
  artifacts/ios27-headers-verified --ipsw artifacts/tools/ipsw
```

This exports BackBoardServices, BackBoardHIDEventFoundation and BaseBoard from
the selected DSC using blacktop/ipsw. If firmware omits its optional local
symbols companion, only an inspection copy of the primary header has its
symbolFileUUID cleared. All mapped runtime metadata and subcache bytes remain
the originals. `provenance.json` records both primary-header hashes, cache UUID,
OS version and the ipsw build used for the dump.

The verified input is iOS 27.0 / 24A437, cache UUID
`55c72a0a0bfa3cd1b18ca83ff3411ac3`. The server protocol exposes
`submitRuleChanges:`; the Apple server has
`initWithDeliveryManagerProvider:ruleChangeAuthority:` and
`initWithIncomingServiceConnectionHandler:ruleChangeAuthority:`. Its initializer
requires non-null provider/handler and authority. Instantiating it with nil
arguments would exercise an assertion rather than establish service support.

## Validation boundary

Local evidence: `artifacts/pac-v2-all-tests.log`,
`artifacts/pac-v2-clippy.log`, `artifacts/ios27-aot/libsystem-shim.json`,
`artifacts/ios27-headers-verified/provenance.json` and the signed build logs in
`artifacts/swiftui-pac-v2-run/`.

These checks establish conversion and build properties. They do not establish
BackBoard activation, a non-null SwiftUI root controller, visible guest pixels,
touch delivery or a complete VSync/runloop cycle. Those require device evidence.
