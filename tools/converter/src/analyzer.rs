use std::path::Path;
use super::ir::{Architecture, DependencyInfo, ExportInfo, FixupInfo, ImportInfo, IosImage, SegmentInfo};
use super::unpacker::ExtractedApp;
use harmonios_runtime::macho;

pub fn analyze_app<P: AsRef<Path>>(app: &ExtractedApp, source_path: P) -> Result<IosImage, String> {
    let parsed = macho::parse(&app.executable_bytes)
        .map_err(|e| format!("Mach-O parser error: {e:?}"))?;

    let arch = match parsed.architecture {
        "arm64" => {
            if parsed.cpu_subtype & 0x00ff_ffff == 2 {
                Architecture::Arm64e
            } else {
                Architecture::Arm64
            }
        }
        "arm64e" => Architecture::Arm64e,
        _ => Architecture::Other(parsed.cpu_subtype),
    };

    let segments = parsed
        .segments
        .into_iter()
        .map(|s| SegmentInfo {
            name: s.name,
            vm_address: s.vm_address,
            vm_size: s.vm_size,
            file_offset: s.file_offset,
            file_size: s.file_size,
            protection: s.protection,
        })
        .collect();

    let dependencies = parsed
        .dependencies
        .into_iter()
        .map(|d| DependencyInfo {
            path: d.path,
            current_version: 0,
            compatibility_version: 0,
            weak: d.weak,
        })
        .collect();

    let fixups_count = if parsed.chained_fixups { 1 } else { 0 };

    Ok(IosImage {
        path: source_path.as_ref().to_path_buf(),
        bundle_id: app.bundle_id.clone(),
        bundle_name: app.bundle_name.clone(),
        executable: app.executable_name.clone(),
        arch,
        minimum_os: app.minimum_os.clone(),
        sdk: app.sdk.clone(),
        segments,
        dependencies,
        fixups: FixupInfo {
            count: fixups_count,
            chained_format: if parsed.chained_fixups { "chained_fixups".to_string() } else { "classic".to_string() },
        },
        exports: ExportInfo {
            count: 0,
            names: Vec::new(),
        },
        imports: ImportInfo {
            count: 0,
            symbols: Vec::new(),
        },
    })
}
