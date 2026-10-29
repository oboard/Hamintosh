use std::fs::File;
use std::io::Read;
use std::path::Path;
use zip::ZipArchive;

use crate::sha256::sha256_hex;

pub struct ExtractedApp {
    pub bundle_id: String,
    pub bundle_name: String,
    pub executable_name: String,
    pub minimum_os: String,
    pub version: String,
    pub sdk: String,
    pub executable_bytes: Vec<u8>,
    pub executable_sha256: String,
    pub icon_filename: Option<String>,
    pub app_dir_name: String,
}

pub fn unpack_ipa<P: AsRef<Path>>(ipa_path: P) -> Result<ExtractedApp, String> {
    let file = File::open(ipa_path.as_ref()).map_err(|e| format!("Failed to open IPA: {e}"))?;
    let mut archive = ZipArchive::new(file).map_err(|e| format!("Invalid ZIP archive: {e}"))?;

    // Find Info.plist
    let mut info_plist_entry = None;
    let mut app_dir_name = String::new();
    for i in 0..archive.len() {
        let file = archive.by_index(i).map_err(|e| format!("Zip error: {e}"))?;
        let name = file.name().to_string();
        if name.starts_with("Payload/") && name.ends_with(".app/Info.plist") {
            let parts: Vec<&str> = name.split('/').collect();
            if parts.len() == 3 {
                app_dir_name = parts[1].to_string();
                info_plist_entry = Some(i);
                break;
            }
        }
    }

    let info_idx = info_plist_entry
        .ok_or_else(|| "Could not find Payload/*.app/Info.plist in IPA".to_string())?;
    let mut info_bytes = Vec::new();
    {
        let mut f = archive
            .by_index(info_idx)
            .map_err(|e| format!("Zip entry error: {e}"))?;
        f.read_to_end(&mut info_bytes)
            .map_err(|e| format!("Failed to read Info.plist: {e}"))?;
    }

    let plist_val: plist::Value = plist::Value::from_reader(std::io::Cursor::new(&info_bytes))
        .map_err(|e| format!("Failed to parse Info.plist: {e}"))?;

    let dict = plist_val
        .as_dictionary()
        .ok_or_else(|| "Info.plist root is not a dictionary".to_string())?;

    let bundle_id = dict
        .get("CFBundleIdentifier")
        .and_then(|v| v.as_string())
        .unwrap_or("unknown.bundle")
        .to_string();

    let bundle_name = dict
        .get("CFBundleDisplayName")
        .or_else(|| dict.get("CFBundleName"))
        .and_then(|v| v.as_string())
        .unwrap_or(&bundle_id)
        .to_string();

    let executable_name = dict
        .get("CFBundleExecutable")
        .and_then(|v| v.as_string())
        .ok_or_else(|| "Missing CFBundleExecutable in Info.plist".to_string())?
        .to_string();

    let minimum_os = dict
        .get("MinimumOSVersion")
        .and_then(|v| v.as_string())
        .unwrap_or("15.0")
        .to_string();

    let version = dict
        .get("CFBundleShortVersionString")
        .or_else(|| dict.get("CFBundleVersion"))
        .and_then(|v| v.as_string())
        .unwrap_or("1.0")
        .to_string();

    let sdk = dict
        .get("DTSDKName")
        .and_then(|v| v.as_string())
        .unwrap_or("iphoneos")
        .to_string();

    // Collect candidate icon names
    let mut candidate_icons = Vec::new();
    if let Some(icons) = dict.get("CFBundleIcons").and_then(|v| v.as_dictionary()) {
        if let Some(primary) = icons
            .get("CFBundlePrimaryIcon")
            .and_then(|v| v.as_dictionary())
        {
            if let Some(files) = primary.get("CFBundleIconFiles").and_then(|v| v.as_array()) {
                for f in files {
                    if let Some(s) = f.as_string() {
                        candidate_icons.push(s.to_string());
                    }
                }
            }
        }
    }
    if let Some(files) = dict.get("CFBundleIconFiles").and_then(|v| v.as_array()) {
        for f in files {
            if let Some(s) = f.as_string() {
                candidate_icons.push(s.to_string());
            }
        }
    }
    if let Some(f) = dict.get("CFBundleIconFile").and_then(|v| v.as_string()) {
        candidate_icons.push(f.to_string());
    }

    // Search all PNG icons in archive
    let mut icon_matches: Vec<(String, u64)> = Vec::new();
    let prefix = format!("Payload/{}/", app_dir_name);
    for i in 0..archive.len() {
        if let Ok(file) = archive.by_index(i) {
            let name = file.name().to_string();
            if name.starts_with(&prefix) && name.ends_with(".png") && !name.contains("__MACOSX") {
                let filename = name[prefix.len()..].to_string();
                let is_candidate = candidate_icons.iter().any(|c| filename.starts_with(c))
                    || filename.contains("AppIcon")
                    || filename.to_lowercase().contains("icon");
                if is_candidate {
                    icon_matches.push((filename, file.size()));
                }
            }
        }
    }

    // Sort icons: prefer 60x60@2x / 60x60@3x or larger files for crisp UI
    icon_matches.sort_by(|a, b| {
        let score = |s: &str, sz: u64| -> u64 {
            let mut sc = sz;
            if s.contains("60x60@3x") || s.contains("180") {
                sc += 1_000_000;
            } else if s.contains("60x60@2x") || s.contains("120") {
                sc += 500_000;
            } else if s.contains("AppIcon") {
                sc += 100_000;
            }
            sc
        };
        score(&b.0, b.1).cmp(&score(&a.0, a.1))
    });

    let icon_filename = icon_matches.first().map(|(name, _)| name.clone());

    // Read the main executable binary
    let exec_path = format!("Payload/{}/{}", app_dir_name, executable_name);
    let mut exec_entry = archive
        .by_name(&exec_path)
        .map_err(|e| format!("Could not find executable '{exec_path}' in IPA: {e}"))?;

    let mut executable_bytes = Vec::new();
    exec_entry
        .read_to_end(&mut executable_bytes)
        .map_err(|e| format!("Failed to read executable bytes: {e}"))?;

    let executable_sha256 = sha256_hex(&executable_bytes);

    Ok(ExtractedApp {
        bundle_id,
        bundle_name,
        executable_name,
        minimum_os,
        version,
        sdk,
        executable_bytes,
        executable_sha256,
        icon_filename,
        app_dir_name,
    })
}

pub fn normalize_png_if_cgbi(path: &Path) {
    if let Ok(mut f) = File::open(path) {
        let mut header = [0u8; 16];
        if f.read_exact(&mut header).is_ok() && &header[12..16] == b"CgBI" {
            drop(f);
            let _ = std::process::Command::new("sips")
                .args(["-s", "format", "png"])
                .arg(path)
                .arg("--out")
                .arg(path)
                .output();
        }
    }
}

pub struct BundleExtractionResult {
    #[allow(dead_code)]
    pub total_size_bytes: u64,
    pub formatted_size: String,
    pub bundle_files: Vec<String>,
}

pub fn extract_bundle_to_dir<P: AsRef<Path>, Q: AsRef<Path>>(
    ipa_path: P,
    out_dir: Q,
) -> Result<BundleExtractionResult, String> {
    let file = File::open(ipa_path.as_ref()).map_err(|e| format!("Failed to open IPA: {e}"))?;
    let mut archive = ZipArchive::new(file).map_err(|e| format!("Invalid ZIP archive: {e}"))?;

    let out = out_dir.as_ref();
    std::fs::create_dir_all(out).map_err(|e| format!("Failed to create output directory: {e}"))?;

    let mut total_size_bytes = 0u64;
    let mut bundle_files = Vec::new();

    for i in 0..archive.len() {
        let mut file = archive.by_index(i).map_err(|e| format!("Zip error: {e}"))?;
        let name = file.name().to_string();
        if !name.starts_with("Payload/") {
            continue;
        }
        let parts: Vec<&str> = name.split('/').collect();
        if parts.len() < 2 || !parts[1].ends_with(".app") {
            continue;
        }
        let rel_path = parts[2..].join("/");
        if rel_path.is_empty() {
            continue;
        }
        let target_path = out.join(&rel_path);
        if file.is_dir() {
            std::fs::create_dir_all(&target_path)
                .map_err(|e| format!("Failed to create directory: {e}"))?;
        } else {
            if let Some(parent) = target_path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("Failed to create parent directory: {e}"))?;
            }
            let mut outfile = File::create(&target_path)
                .map_err(|e| format!("Failed to create file {:?}: {e}", target_path))?;
            let written = std::io::copy(&mut file, &mut outfile)
                .map_err(|e| format!("Failed to extract file: {e}"))?;
            drop(outfile);

            total_size_bytes += written;
            bundle_files.push(rel_path.clone());

            if target_path.extension().is_some_and(|ext| ext == "png") {
                normalize_png_if_cgbi(&target_path);
            }
        }
    }

    bundle_files.sort();

    let formatted_size = if total_size_bytes < 1024 * 1024 {
        format!("{} KB", total_size_bytes / 1024)
    } else {
        format!("{:.1} MB", total_size_bytes as f64 / (1024.0 * 1024.0))
    };

    Ok(BundleExtractionResult {
        total_size_bytes,
        formatted_size,
        bundle_files,
    })
}
