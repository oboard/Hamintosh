use crate::ir::IosImage;
use crate::manifest::TargetManifest;
use crate::unpacker::{BundleExtractionResult, ExtractedApp};
use std::path::{Path, PathBuf};

pub fn generate_aot_artifacts<P: AsRef<Path>>(
    image: &IosImage,
    app: &ExtractedApp,
    bundle_result: &BundleExtractionResult,
    source_ipa: Option<&Path>,
    app_dir: P,
) -> Result<PathBuf, String> {
    let out = app_dir.as_ref();
    std::fs::create_dir_all(out).map_err(|e| format!("Failed to create output dir: {e}"))?;

    // 1. Write executable binary
    let exec_path = out.join("executable");
    std::fs::write(&exec_path, &app.executable_bytes)
        .map_err(|e| format!("Failed to write executable: {e}"))?;

    // Also write <out>/<executable_name> so dyld or bundle lookup can find it by name
    let named_exec_path = out.join(&app.executable_name);
    if named_exec_path != exec_path && !named_exec_path.exists() {
        let _ = std::fs::write(&named_exec_path, &app.executable_bytes);
    }

    // 2. Select and copy/normalize icon.png
    let mut resolved_icon = None;
    if let Some(ref icon_name) = app.icon_filename {
        let candidate = out.join(icon_name);
        let target_icon = out.join("icon.png");
        if candidate.exists() {
            if candidate != target_icon {
                let _ = std::fs::copy(&candidate, &target_icon);
            }
            crate::unpacker::normalize_png_if_cgbi(&target_icon);
            resolved_icon = Some("icon.png".to_string());
        }
    }
    if resolved_icon.is_none() {
        let target_icon = out.join("icon.png");
        if target_icon.exists() {
            resolved_icon = Some("icon.png".to_string());
        }
    }

    // 3. Write manifest.json matching Harmonios Index.ets
    let manifest = TargetManifest {
        name: app.bundle_name.clone(),
        bundle_id: app.bundle_id.clone(),
        executable: app.executable_name.clone(),
        minimum_os: app.minimum_os.clone(),
        sdk: Some(app.sdk.clone()),
        sha256: Some(app.executable_sha256.clone()),
        version: Some(app.version.clone()),
        size: Some(bundle_result.formatted_size.clone()),
        icon: resolved_icon,
        bundle_directory: format!("{}.app", app.bundle_name),
        bundle_files: bundle_result.bundle_files.clone(),
        source_ipa: source_ipa.map(|p| p.to_string_lossy().to_string()),
    };

    let manifest_path = out.join("manifest.json");
    let manifest_json = serde_json::to_string_pretty(&manifest)
        .map_err(|e| format!("Failed to serialize manifest: {e}"))?;
    std::fs::write(&manifest_path, manifest_json)
        .map_err(|e| format!("Failed to write manifest.json: {e}"))?;

    // 4. Write aot_info.json (full image analysis for runtime inspection)
    let aot_info_path = out.join("aot_info.json");
    let aot_info_json = serde_json::to_string_pretty(image)
        .map_err(|e| format!("Failed to serialize aot_info: {e}"))?;
    std::fs::write(&aot_info_path, aot_info_json)
        .map_err(|e| format!("Failed to write aot_info.json: {e}"))?;

    // 5. Generate packed_target.S, packed_target.h, packed_target.ld
    crate::toolkit::pack_target(&exec_path, out)?;

    Ok(out.to_path_buf())
}
