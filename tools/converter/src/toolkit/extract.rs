use super::{
    cache, download, hash, json, macho, objc, read, run, staging, write, write_json, Result,
};
use serde_json::{json as j, Value};
use std::{
    path::{Path, PathBuf},
    process::Command,
};
struct Mounts(Vec<PathBuf>);
impl Drop for Mounts {
    fn drop(&mut self) {
        for p in self.0.iter().rev() {
            let _ = Command::new("hdiutil").arg("detach").arg(p).output();
        }
    }
}
fn mount(dmg: &Path, record: &Path) -> Result<Mounts> {
    let b = Command::new("hdiutil")
        .args(["attach", "-readonly", "-nobrowse", "-plist"])
        .arg(dmg)
        .output()
        .map_err(|e| e.to_string())?;
    if !b.status.success() {
        return Err(String::from_utf8_lossy(&b.stderr).into_owned());
    }
    write(record, &b.stdout)?;
    let plist =
        plist::Value::from_reader(std::io::Cursor::new(&b.stdout)).map_err(|e| e.to_string())?;
    let mounts = plist
        .as_dictionary()
        .and_then(|p| p.get("system-entities"))
        .and_then(plist::Value::as_array)
        .ok_or("missing mount entities")?
        .iter()
        .filter_map(|v| {
            v.as_dictionary()
                .and_then(|d| d.get("mount-point"))
                .and_then(plist::Value::as_string)
                .map(PathBuf::from)
        })
        .collect::<Vec<_>>();
    if mounts.is_empty() {
        return Err("image mounted without readable filesystem".into());
    }
    Ok(Mounts(mounts))
}
fn copy(source: &Path, dest: &Path) -> Result<()> {
    std::fs::create_dir_all(dest.parent().ok_or("missing output parent")?)
        .map_err(|e| e.to_string())?;
    let p = dest.with_extension("partial");
    std::fs::copy(source, &p).map_err(|e| e.to_string())?;
    std::fs::rename(p, dest).map_err(|e| e.to_string())
}
fn verified(archive: &Path) -> Result<Value> {
    let name = archive
        .file_name()
        .ok_or("archive filename")?
        .to_string_lossy();
    let source = json(&archive.with_file_name(format!("{name}.source.json")))?;
    download::verify_download(archive, &source)?;
    Ok(source)
}
pub fn sysroot(archive: &Path, out: &Path, ipsw: &Path, pem: &Path) -> Result<()> {
    std::fs::create_dir_all(out).map_err(|e| e.to_string())?;
    let status = out.join("extraction-status.json");
    let source = verified(archive)?;
    write_json(
        &status,
        &j!({"stage":"decrypting-systemos","runtimeComplete":false,"source":source}),
    )?;
    let decrypted = out.join("system-image");
    std::fs::create_dir_all(&decrypted).map_err(|e| e.to_string())?;
    let name = archive.file_name().ok_or("archive name")?.to_string_lossy();
    let dmg = decrypted.join(name.strip_suffix(".aea").unwrap_or(&name));
    if !dmg.is_file() {
        let logs = run(Command::new(ipsw)
            .args(["fw", "aea", "--pem-db"])
            .arg(pem)
            .arg("--output")
            .arg(&decrypted)
            .arg(archive))?;
        write(&out.join("decryption.log"), logs)?
    }
    if !dmg.is_file() {
        return Err("decrypted image missing".into());
    }
    let mounts = mount(&dmg, &out.join("mount.plist"))?;
    let mut candidates = vec![];
    for m in &mounts.0 {
        for relative in [
            "System/Library/Caches/com.apple.dyld",
            "System/Library/dyld",
        ] {
            let d = m.join(relative);
            if !d.is_dir() {
                continue;
            }
            for entry in std::fs::read_dir(d).map_err(|e| e.to_string())? {
                let p = entry.map_err(|e| e.to_string())?.path();
                if p.file_name().is_some_and(|n| {
                    n == "dyld_shared_cache_arm64e" || n == "dyld_shared_cache_arm64e_x1"
                }) {
                    candidates.push(p)
                }
            }
        }
    }
    let preferred = candidates
        .iter()
        .filter(|p| {
            p.file_name()
                .is_some_and(|n| n == "dyld_shared_cache_arm64e")
        })
        .cloned()
        .collect::<Vec<_>>();
    if preferred.len() == 1 {
        candidates = preferred
    }
    if candidates.len() != 1 {
        return Err("expected one primary iOS ARM64e cache".into());
    }
    let c = cache::load(&candidates[0])?;
    if c.platform != 2 || c.os_version >> 16 < 27 {
        return Err("expected iOS 27+ cache".into());
    }
    let destination = out.join("cache");
    for f in &c.files {
        copy(
            &f.path,
            &destination.join(f.path.file_name().ok_or("cache filename")?),
        )?
    }
    let primary = destination.join(candidates[0].file_name().unwrap());
    let copied = cache::load(&primary)?;
    write_json(&out.join("cache-layout.json"), &copied)?;
    for rel in ["usr/lib/dyld", "usr/lib/libobjc-trampolines.dylib"] {
        for m in &mounts.0 {
            let path = m.join(rel);
            if path.is_file() && !path.is_symlink() {
                if rel.ends_with("libobjc-trampolines.dylib") {
                    let identity = objc::inspect(&read(&path)?)?;
                    write_json(&out.join(format!("{rel}.json")), &identity)?
                }
                copy(&path, &out.join(rel))?;
                break;
            }
        }
    }
    write_json(
        &status,
        &j!({"stage":"cache-imported","runtimeComplete":false,"source":source,"primary":primary,"files":copied.files.len(),"images":copied.images.len()}),
    )
}
pub fn bootstrap(archive: &Path, out: &Path, ipsw: &Path, primary: &Path) -> Result<()> {
    let source = verified(archive)?;
    std::fs::create_dir_all(out).map_err(|e| e.to_string())?;
    let payload = out.join("bootstrap-ramdisk.dmg");
    run(Command::new(ipsw)
        .args(["img4", "im4p", "extract", "--output"])
        .arg(&payload)
        .arg(archive))?;
    let mounts = mount(&payload, &out.join("ramdisk-mount.plist"))?;
    let candidates = mounts
        .0
        .iter()
        .map(|p| p.join("usr/lib/dyld"))
        .filter(|p| p.is_file() && !p.is_symlink())
        .collect::<Vec<_>>();
    if candidates.len() != 1 {
        return Err("expected one regular /usr/lib/dyld".into());
    }
    let b = read(&candidates[0])?;
    let id = macho::uuid(&b)?;
    let c = cache::load(primary)?;
    if id != macho::uuid(&cache::vm(&c, c.dyld_header_address, 65536)?)? {
        return Err("ramdisk dyld UUID does not match cache".into());
    }
    write(&out.join("bootstrap/dyld"), &b)?;
    let record = j!({"stage":"standalone-dyld-imported","runtimeComplete":false,"source":source,"uuid":id,"size":b.len(),"sha256":hash(&b),"cachePrimaryUUID":c.files[0].uuid});
    write_json(&out.join("bootstrap/source.json"), &record)?;
    staging::sysroot(
        out,
        &super::root().join("harmonios/src/main/resources/rawfile/sysroot"),
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(&record).map_err(|e| e.to_string())?
    );
    Ok(())
}
