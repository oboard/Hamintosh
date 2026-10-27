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

    println!("Generated AOT artifacts at {:?}", out);
    println!("Bundle ID: {}", image.bundle_id);
    println!("Executable: {}", image.executable);
    println!("Segments: {}", image.segments.len());
    println!("Dependencies: {}", image.dependencies.len());

    Ok(())
}
