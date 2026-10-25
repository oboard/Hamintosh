use crate::macho;
use serde_json::{Value, json};
use std::{
    collections::HashSet,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

const SHARED_CACHE_PATH: &str =
    "/System/Cryptexes/OS/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e";

pub fn inspect(executable: &Path, sysroot: &Path) -> Value {
    let bytes = match fs::metadata(executable).and_then(|m| {
        if m.len() > 512 * 1024 * 1024 {
            Err(std::io::Error::other(
                "executable exceeds 512 MiB inspection limit",
            ))
        } else {
            fs::read(executable)
        }
    }) {
        Ok(v) => v,
        Err(e) => {
            return json!({"status":"invalid-input", "appExecuted":false, "error":e.to_string()});
        }
    };
    let image = match macho::parse(&bytes) {
        Ok(v) => v,
        Err(e) => return json!({"status":"invalid-mach-o", "appExecuted":false, "error":e}),
    };
    let cache_path = root_path(sysroot, SHARED_CACHE_PATH);
    let cache_attempted = cache_path.is_some();
    let (cache_images, cache_error) = match &cache_path {
        Some(path) => match crate::cache::image_paths(path) {
            Ok(paths) => (paths, None),
            Err(error) => (vec![], Some(error)),
        },
        None => (vec![], None),
    };
    let cache_inventory: HashSet<&str> = cache_images.iter().map(String::as_str).collect();
    let cache_error_is_none = cache_error.is_none();
    let mut missing_standalone = vec![];
    let mut missing_weak_standalone = vec![];
    let mut resolved_required = vec![];
    let mut resolved_weak = vec![];
    let mut unresolved_required = vec![];
    let mut unresolved_weak = vec![];
    let mut bundle_dependencies = vec![];
    let mut pac_images = vec![];
    let mut available = vec![];
    let mut dyld_layout = Value::Null;
    if let Some(dyld) = &image.interpreter {
        if !root_file(sysroot, dyld) {
            missing_standalone.push(dyld.clone());
            if cache_inventory.contains(dyld.as_str()) {
                resolved_required.push(dyld.clone());
            } else if cache_attempted && cache_error.is_none() {
                unresolved_required.push(dyld.clone());
            }
        } else {
            available.push(dyld.clone());
            if let Some(path) = root_path(sysroot, dyld) {
                if let Ok(bytes) = fs::read(&path) {
                    dyld_layout = match macho::parse(&bytes) {
                        Ok(info) => json!({"entryCommand":info.entry_command,
                            "entryFileOffset":info.entry_file_offset, "mappedVmSpan":info.mapped_vm_span,
                            "requiresOriginalCacheLayout":info.mapped_vm_span > 512 * 1024 * 1024,
                            "cpuSubtype":info.cpu_subtype}),
                        Err(error) => json!({"error":error}),
                    };
                }
            }
        }
    }
    for dep in &image.dependencies {
        if dep.path.starts_with('@') {
            bundle_dependencies.push(dep.path.clone());
        } else if !root_file(sysroot, &dep.path) {
            if dep.weak {
                missing_weak_standalone.push(dep.path.clone());
                if cache_inventory.contains(dep.path.as_str()) {
                    resolved_weak.push(dep.path.clone());
                } else if cache_attempted && cache_error.is_none() {
                    unresolved_weak.push(dep.path.clone());
                }
            } else {
                missing_standalone.push(dep.path.clone());
                if cache_inventory.contains(dep.path.as_str()) {
                    resolved_required.push(dep.path.clone());
                } else if cache_attempted && cache_error.is_none() {
                    unresolved_required.push(dep.path.clone());
                }
            }
        } else {
            available.push(dep.path.clone());
        }
    }
    for guest in &available {
        if let Some(path) = root_path(sysroot, guest) {
            let mut header = [0u8; 32];
            if fs::File::open(path)
                .and_then(|mut f| f.read_exact(&mut header))
                .is_ok()
                && header[..4] == [0xcf, 0xfa, 0xed, 0xfe]
            {
                let subtype = u32::from_le_bytes(header[8..12].try_into().unwrap()) & 0x00ff_ffff;
                if matches!(subtype, 2 | 12) {
                    pac_images.push(guest.clone());
                }
            }
        }
    }
    let mut blockers = vec![];
    let fixup_summary = match macho::fixups::parse(&bytes, &image) {
        Ok(plan) => json!({
            "imports":plan.imports.len(), "locations":plan.fixups.len(),
            "rebases":plan.fixups.iter().filter(|f| matches!(f.target, macho::fixups::Target::Rebase { .. })).count(),
            "binds":plan.fixups.iter().filter(|f| matches!(f.target, macho::fixups::Target::Bind { .. })).count(),
            "authenticated":plan.fixups.iter().filter(|f| f.authentication.is_some()).count(),
            "pointerFormats":plan.pointer_formats,
        }),
        Err(error) => {
            blockers.push("invalid-or-unsupported-chained-fixups");
            json!({"error":error})
        }
    };
    if image.encrypted {
        blockers.push("encrypted-executable");
    }
    if image.platform != Some(2) {
        blockers.push("not-ios-device-platform");
    }
    if !cache_attempted {
        blockers.push("shared-cache-inventory-missing");
    } else if cache_error.is_some() {
        blockers.push("shared-cache-inventory-invalid");
    }
    if !unresolved_required.is_empty() {
        blockers.push("shared-cache-unresolved-required-images");
    }
    if !bundle_dependencies.is_empty() {
        blockers.push("bundle-dependency-resolution-not-attempted");
    }
    if dyld_layout["requiresOriginalCacheLayout"] == true {
        blockers.push("dyld-extracted-cache-layout-requires-original-cache");
    }
    // This inspector does not observe the native cache mapping, hardware PAC
    // probes, dyld execution or Darwin dispatch. Keep their runtime state unknown
    // instead of reporting these already-progressing components as unimplemented.
    blockers.push("runtime-execution-not-verified-by-static-inspection");
    json!({
        "schemaVersion":1, "status":"blocked", "stage":"preflight", "appExecuted":false,
        "runtime":"Hello from Rust", "executable":executable, "sysroot":sysroot,
        "bundleInfo":{
            "path":executable.parent(),
            "hasInfoPlist":executable.parent().is_some_and(|p| p.join("Info.plist").is_file()),
            "hasPkgInfo":executable.parent().is_some_and(|p| p.join("PkgInfo").is_file()),
        },
        "image":image, "missingFiles":unresolved_required, "missingWeakImages":unresolved_weak,
        "missingStandaloneImages":missing_standalone, "missingWeakStandaloneImages":missing_weak_standalone,
        "availableSharedCacheImages":resolved_required, "availableWeakSharedCacheImages":resolved_weak,
        "unresolvedRequiredImages":unresolved_required, "unresolvedWeakImages":unresolved_weak,
        "cacheResolutionAttempted":cache_attempted,
        "cacheInventoryPath":cache_path,
        "cacheInventoryImageCount":cache_images.len(),
        "cacheResolutionError":cache_error,
        "sharedCacheResolution":{
            "attempted":cache_attempted,
            "inventoryAvailable":cache_attempted && cache_error_is_none,
            "inventoryImages":cache_images.len(),
            "resolvedRequiredImages":resolved_required,
            "resolvedWeakImages":resolved_weak,
            "unresolvedRequiredImages":unresolved_required,
            "unresolvedWeakImages":unresolved_weak,
        },
        "dependencyAvailability":if cache_attempted && cache_error_is_none {"standalone-and-shared-cache-inspected"} else {"shared-cache-inventory-unavailable"},
        "availableSysrootFiles":available, "pacImages":pac_images,
        "dyldLayout":dyld_layout,
        "fixupSummary":fixup_summary,
        "unresolvedBundleImages":bundle_dependencies,
        "requiredImports":image.undefined_symbols,
        "missingSymbols":[], "missingMachServices":[], "unsupportedSyscalls":[],
        "symbolResolutionAttempted":false, "loadedImages":0, "blockers":blockers,
        "nextStep":"Inspect unresolvedRequiredImages first; shared-cache-resolved paths are available runtime images even without standalone dylibs. Then inspect dyldBootstrap and its unsupportedCalls for the current execution blocker."
    })
}

fn root_file(root: &Path, guest: &str) -> bool {
    root_path(root, guest).is_some()
}

fn root_path(root: &Path, guest: &str) -> Option<PathBuf> {
    // No guest traversal or symlink escape into the host filesystem.
    if !guest.starts_with('/') || guest.split('/').any(|c| c == "..") {
        return None;
    }
    let (Ok(root), Ok(path)) = (
        root.canonicalize(),
        root.join(guest.trim_start_matches('/')).canonicalize(),
    ) else {
        return None;
    };
    (path.starts_with(root) && path.is_file()).then_some(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let root = std::env::temp_dir().join(format!(
                "harmintosh-report-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(root.join("sysroot")).unwrap();
            Self(root)
        }
        fn inspect(&self) -> Value {
            inspect(&self.0.join("executable"), &self.0.join("sysroot"))
        }
        fn cache_inventory(&self, images: &[&str]) {
            let table = 460usize;
            let strings = table + images.len() * 32;
            let mut bytes = vec![0u8; strings];
            bytes[..14].copy_from_slice(b"dyld_v1 arm64e");
            bytes[448..452].copy_from_slice(&(table as u32).to_le_bytes());
            bytes[452..456].copy_from_slice(&(images.len() as u32).to_le_bytes());
            for (index, path) in images.iter().enumerate() {
                let entry = table + index * 32;
                let offset = bytes.len();
                bytes[entry + 24..entry + 28].copy_from_slice(&(offset as u32).to_le_bytes());
                bytes.extend_from_slice(path.as_bytes());
                bytes.push(0);
            }
            let path = self
                .0
                .join("sysroot")
                .join(SHARED_CACHE_PATH.trim_start_matches('/'));
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, bytes).unwrap();
        }
        fn executable(&self) {
            let mut bytes = include_bytes!("../../tests/fixtures/return42.macho").to_vec();
            let mut at = 128;
            let mut commands = 2u32;
            for (command, path) in [
                (0xcu32, "/usr/lib/libSystem.B.dylib"),
                (0x80000018, "/usr/lib/swift/libOptional.dylib"),
                (0xc, "@rpath/Local.framework/Local"),
            ] {
                let size = (24 + path.len() + 1 + 7) & !7;
                bytes[at..at + 4].copy_from_slice(&command.to_le_bytes());
                bytes[at + 4..at + 8].copy_from_slice(&(size as u32).to_le_bytes());
                bytes[at + 8..at + 12].copy_from_slice(&24u32.to_le_bytes());
                bytes[at + 24..at + 24 + path.len()].copy_from_slice(path.as_bytes());
                at += size;
                commands += 1;
            }
            bytes[16..20].copy_from_slice(&commands.to_le_bytes());
            bytes[20..24].copy_from_slice(&((at - 32) as u32).to_le_bytes());
            fs::write(self.0.join("executable"), bytes).unwrap();
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn absent_standalone_files_do_not_claim_absent_cached_libraries() {
        let fixture = Fixture::new();
        fixture.executable();
        let report = fixture.inspect();
        assert_eq!(report["missingFiles"], json!([]));
        assert_eq!(report["missingWeakImages"], json!([]));
        assert_eq!(
            report["missingStandaloneImages"],
            json!(["/usr/lib/libSystem.B.dylib"])
        );
        assert_eq!(
            report["missingWeakStandaloneImages"],
            json!(["/usr/lib/swift/libOptional.dylib"])
        );
        assert_eq!(report["cacheResolutionAttempted"], false);
        assert_eq!(report["symbolResolutionAttempted"], false);
        assert_eq!(report["loadedImages"], 0);
        assert_eq!(report["appExecuted"], false);
        assert_eq!(
            report["unresolvedBundleImages"],
            json!(["@rpath/Local.framework/Local"])
        );
        let blockers = report["blockers"].as_array().unwrap();
        assert!(
            !blockers
                .iter()
                .any(|v| v.as_str().is_some_and(|s| s.ends_with("not-implemented")))
        );
        assert!(
            report["nextStep"]
                .as_str()
                .unwrap()
                .contains("dyldBootstrap")
        );
    }

    #[test]
    fn packaged_shared_cache_inventory_resolves_required_and_weak_dependencies() {
        let fixture = Fixture::new();
        fixture.executable();
        fixture.cache_inventory(&["/usr/lib/libSystem.B.dylib"]);
        let report = fixture.inspect();
        assert_eq!(report["cacheResolutionAttempted"], true);
        assert_eq!(report["cacheInventoryImageCount"], 1);
        assert_eq!(
            report["availableSharedCacheImages"],
            json!(["/usr/lib/libSystem.B.dylib"])
        );
        assert_eq!(
            report["missingStandaloneImages"],
            json!(["/usr/lib/libSystem.B.dylib"])
        );
        assert_eq!(report["missingFiles"], json!([]));
        assert_eq!(
            report["unresolvedWeakImages"],
            json!(["/usr/lib/swift/libOptional.dylib"])
        );
        assert_eq!(
            report["dependencyAvailability"],
            "standalone-and-shared-cache-inspected"
        );
        let blockers = report["blockers"].as_array().unwrap();
        assert!(!blockers.iter().any(|value| {
            matches!(
                value.as_str(),
                Some("shared-cache-resolution-not-attempted")
                    | Some("shared-cache-unresolved-required-images")
            )
        }));
    }

    #[test]
    fn existing_standalone_image_is_available_but_execution_remains_unverified() {
        let fixture = Fixture::new();
        fixture.executable();
        let path = fixture.0.join("sysroot/usr/lib/libSystem.B.dylib");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, include_bytes!("../../tests/fixtures/return42.macho")).unwrap();
        let report = fixture.inspect();
        assert_eq!(report["missingStandaloneImages"], json!([]));
        assert_eq!(
            report["availableSysrootFiles"],
            json!(["/usr/lib/libSystem.B.dylib"])
        );
        assert_eq!(report["cacheResolutionAttempted"], false);
        assert_eq!(report["status"], "blocked");
        assert_eq!(report["appExecuted"], false);
    }
}
