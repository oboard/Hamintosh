//! Dump the interfaces of the actual device cache, including stripped caches
//! whose optional local-symbol companion was not shipped in the firmware.
use super::{cache, hash, read, run, write, write_json, Result};
use serde_json::json;
use std::{path::Path, process::Command};

pub fn dump(primary: &Path, output: &Path, ipsw: &Path) -> Result<()> {
    let source = cache::load(primary)?;
    std::fs::create_dir_all(output).map_err(|e| e.to_string())?;
    let output = output.canonicalize().map_err(|e| e.to_string())?;
    let view = output.join("cache-view");
    std::fs::create_dir_all(&view).map_err(|e| e.to_string())?;
    let mut header = read(primary)?;
    let original_hash = hash(&header);
    let mut symbols = primary.as_os_str().to_os_string();
    symbols.push(".symbols");
    let omit_symbols = !Path::new(&symbols).is_file();
    if omit_symbols {
        // dyld_cache_header::symbolFileUUID at byte 400. This is an
        // unmapped local-symbol companion, not Objective-C runtime metadata.
        // Change only the inspection copy; guest inputs remain untouched.
        header.get_mut(400..416).ok_or("short cache header")?.fill(0);
    }
    let inspected = view.join(primary.file_name().ok_or("cache filename")?);
    write(&inspected, &header)?;
    #[cfg(unix)]
    for path in source.files.iter().skip(1).map(|file| file.path.as_path())
        .chain((!omit_symbols).then_some(Path::new(&symbols))) {
        let target = view.join(path.file_name().ok_or("cache filename")?);
        if target.symlink_metadata().is_err() {
            std::os::unix::fs::symlink(path.canonicalize().map_err(|e| e.to_string())?, target)
                .map_err(|e| e.to_string())?;
        }
    }
    let version = run(Command::new(ipsw).arg("version"))?;
    let frameworks = ["BackBoardServices", "BackBoardHIDEventFoundation", "BaseBoard", "BoardServices"];
    for framework in frameworks {
        let log = run(Command::new(ipsw).arg("class-dump").arg(&inspected)
            .arg(framework).arg("--headers").arg("--output").arg(output.join(framework)))?;
        write(&output.join(format!("{framework}.log")), log)?;
    }
    write_json(&output.join("provenance.json"), &json!({
        "primaryUUID": source.files[0].uuid, "primarySha256": original_hash,
        "inspectionSha256": hash(&header), "omittedLocalSymbols": omit_symbols,
        "osVersion": source.os_version, "platform": source.platform,
        "source": primary.canonicalize().map_err(|e| e.to_string())?,
        "ipsw": version.trim(), "frameworks": frameworks,
    }))
}
