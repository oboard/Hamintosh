use crate::macho;
use serde_json::{json, Value};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};

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
            return json!({"status":"invalid-input", "appExecuted":false, "error":e.to_string()})
        }
    };
    let image = match macho::parse(&bytes) {
        Ok(v) => v,
        Err(e) => return json!({"status":"invalid-mach-o", "appExecuted":false, "error":e}),
    };
    let mut missing = vec![];
    let mut weak_missing = vec![];
    let mut bundle_dependencies = vec![];
    let mut pac_images = vec![];
    let mut available = vec![];
    let mut dyld_layout = Value::Null;
    if let Some(dyld) = &image.interpreter {
        if !root_file(sysroot, dyld) {
            missing.push(dyld.clone());
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
                weak_missing.push(dep.path.clone());
            } else {
                missing.push(dep.path.clone());
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
    if !missing.is_empty() {
        blockers.push("missing-ios-sysroot-images");
    }
    if !bundle_dependencies.is_empty() {
        blockers.push("bundle-dependency-resolution-not-implemented");
    }
    if dyld_layout["requiresOriginalCacheLayout"] == true {
        blockers.push("dyld-extracted-cache-layout-requires-original-cache");
    }
    if matches!(image.cpu_subtype & 0x00ff_ffff, 2 | 12) || !pac_images.is_empty() {
        blockers.push("arm64e-pac-compatibility-not-implemented");
    }
    // Presence of files alone never implies that a SwiftUI app can execute.
    blockers.extend([
        "apple-dyld-bootstrap-not-implemented",
        "darwin-mach-compatibility-not-implemented",
        "coreanimation-surface-bridge-not-implemented",
    ]);
    json!({
        "schemaVersion":1, "status":"blocked", "stage":"preflight", "appExecuted":false,
        "runtime":"Hello from Rust", "executable":executable, "sysroot":sysroot,
        "bundleInfo":{
            "path":executable.parent(),
            "hasInfoPlist":executable.parent().is_some_and(|p| p.join("Info.plist").is_file()),
            "hasPkgInfo":executable.parent().is_some_and(|p| p.join("PkgInfo").is_file()),
        },
        "image":image, "missingFiles":missing, "missingWeakImages":weak_missing,
        "availableSysrootFiles":available, "pacImages":pac_images,
        "dyldLayout":dyld_layout,
        "fixupSummary":fixup_summary,
        "unresolvedBundleImages":bundle_dependencies,
        "requiredImports":image.undefined_symbols,
        "missingSymbols":[], "missingMachServices":[], "unsupportedSyscalls":[],
        "symbolResolutionAttempted":false, "loadedImages":0, "blockers":blockers,
        "nextStep":"Use the target device Gate 0 result to choose direct or AOT packaging; implement Apple dyld bootstrap, ARM64e/PAC compatibility and Darwin/Mach adapters before entering the App."
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
