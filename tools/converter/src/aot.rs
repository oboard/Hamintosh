use std::path::Path;
use super::ir::IosImage;
use super::unpacker::ExtractedApp;

pub fn generate_aot_artifacts<P: AsRef<Path>>(
    image: &IosImage,
    app: &ExtractedApp,
    out_dir: P,
) -> Result<(), String> {
    let out = out_dir.as_ref();
    std::fs::create_dir_all(out).map_err(|e| format!("Failed to create output dir: {e}"))?;

    // 1. Write executable binary
    let exec_path = out.join("executable");
    std::fs::write(&exec_path, &app.executable_bytes)
        .map_err(|e| format!("Failed to write executable: {e}"))?;

    // 2. Write manifest.json
    let manifest_path = out.join("manifest.json");
    let manifest_json = serde_json::to_string_pretty(image)
        .map_err(|e| format!("Failed to serialize manifest: {e}"))?;
    std::fs::write(&manifest_path, manifest_json)
        .map_err(|e| format!("Failed to write manifest: {e}"))?;

    // 3. Copy icon if present
    if let Some(ref icon_name) = image.icon {
        let bundle_icon = out.join("bundle").join(icon_name);
        if bundle_icon.exists() {
            let target_icon = out.join(icon_name);
            if bundle_icon != target_icon {
                if let Some(parent) = target_icon.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                std::fs::copy(&bundle_icon, &target_icon)
                    .map_err(|e| format!("Failed to copy icon: {e}"))?;
            }
            let icon_png = out.join("icon.png");
            if bundle_icon != icon_png && !icon_png.exists() {
                let _ = std::fs::copy(&bundle_icon, icon_png);
            }
        }
    }

    println!("Generated AOT artifacts at {:?}", out);
    println!("Bundle ID: {}", image.bundle_id);
    println!("Executable: {}", image.executable);
    if let Some(ref icon) = image.icon {
        println!("Icon: {}", icon);
    }
    println!("Segments: {}", image.segments.len());
    println!("Dependencies: {}", image.dependencies.len());

    Ok(())
}
