use super::{cache, hash, json, objc, read, root, write_json, Result};
use serde_json::{json as j, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path, PathBuf},
};
fn relative(p: &Path) -> bool {
    !p.as_os_str().is_empty() && !p.components().any(|c| !matches!(c, Component::Normal(_)))
}
fn copy(from: &Path, to: &Path) -> Result<()> {
    if let Some(p) = to.parent() {
        std::fs::create_dir_all(p).map_err(|e| e.to_string())?;
    }
    std::fs::copy(from, to).map_err(|e| format!("{}: {e}", from.display()))?;
    Ok(())
}
pub fn sysroot(source: &Path, out: &Path) -> Result<()> {
    let metadata = json(&source.join("bootstrap/source.json"))?;
    let dyld = source.join("bootstrap/dyld");
    if hash(&read(&dyld)?) != metadata["sha256"].as_str().ok_or("missing dyld hash")? {
        return Err("standalone dyld differs from verified extraction".into());
    }
    copy(&dyld, &out.join("usr/lib/dyld"))?;
    let mut files = vec!["usr/lib/dyld".to_string()];
    let version = source.join("SystemVersion.plist");
    let fallback = root().join("runtime/sysroot/SystemVersion.plist");
    let version = if version.is_file() { version } else { fallback };
    if version.is_file() {
        let rel = "System/Library/CoreServices/SystemVersion.plist";
        copy(&version, &out.join(rel))?;
        files.push(rel.into())
    }
    let trampoline = source.join("usr/lib/libobjc-trampolines.dylib");
    let mut images = vec![];
    if trampoline.is_file() {
        let mut id = objc::inspect(&read(&trampoline)?)?;
        id["path"] = j!("/usr/lib/libobjc-trampolines.dylib");
        images.push(id);
        copy(&trampoline, &out.join("usr/lib/libobjc-trampolines.dylib"))?;
        files.push("usr/lib/libobjc-trampolines.dylib".into())
    }
    let layout = json(&source.join("cache-layout.json"))?;
    let primary = &layout["files"][0];
    if primary["uuid"] != metadata["cachePrimaryUUID"] {
        return Err("cache UUID mismatch".into());
    }
    let original = Path::new(primary["path"].as_str().ok_or("missing primary path")?);
    let local = source
        .join("cache")
        .join(original.file_name().ok_or("primary filename")?);
    let rel = "System/Cryptexes/OS/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e";
    copy(
        if local.is_file() { &local } else { original },
        &out.join(rel),
    )?;
    files.push(rel.into());
    write_json(
        &out.join("manifest.json"),
        &j!({"files":files,"aotImages":images,"dyldUUID":metadata["uuid"],"dyldSHA256":metadata["sha256"]}),
    )
}
fn walk(base: &Path, path: &Path, found: &mut Vec<PathBuf>) -> Result<()> {
    let m = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if m.file_type().is_symlink()
        || !path
            .canonicalize()
            .map_err(|e| e.to_string())?
            .starts_with(base)
    {
        return Err(format!(
            "resource escapes source or is symbolic: {}",
            path.display()
        ));
    }
    if m.is_file() {
        found.push(path.to_path_buf())
    } else if m.is_dir() {
        for e in std::fs::read_dir(path).map_err(|e| e.to_string())? {
            walk(base, &e.map_err(|e| e.to_string())?.path(), found)?
        }
    }
    Ok(())
}
pub fn resources(source: &Path, out: &Path, paths: &[String]) -> Result<Value> {
    let source = source.canonicalize().map_err(|e| e.to_string())?;
    let version =
        plist::Value::from_file(source.join("System/Library/CoreServices/SystemVersion.plist"))
            .map_err(|e| e.to_string())?;
    let dict = version.as_dictionary().ok_or("invalid SystemVersion")?;
    if dict.get("ProductName").and_then(plist::Value::as_string) != Some("iPhone OS")
        || dict
            .get("ProductVersion")
            .and_then(plist::Value::as_string)
            .and_then(|s| s.split('.').next())
            != Some("27")
    {
        return Err("expected iOS 27 resource source".into());
    }
    let mut manifest = json(&out.join("manifest.json"))?;
    let mut candidates = vec![];
    for p in paths {
        let p = Path::new(p);
        if !relative(p) {
            return Err("resource path must stay within source".into());
        }
        walk(&source, &source.join(p), &mut candidates)?
    }
    candidates.sort();
    let mut files = BTreeMap::new();
    for p in &candidates {
        let b = read(p)?;
        if b.len() >= 4
            && matches!(
                cache::u32le(&b, 0)?,
                0xfeedfacf
                    | 0xcffaedfe
                    | 0xfeedface
                    | 0xcefaedfe
                    | 0xbebafeca
                    | 0xcafebabe
                    | 0xbfbafeca
                    | 0xcafebabf
                    | 0x464c457f
            )
        {
            return Err(format!(
                "executable resources require signed AOT: {}",
                p.display()
            ));
        }
        let rel = p
            .strip_prefix(&source)
            .map_err(|e| e.to_string())?
            .to_string_lossy()
            .into_owned();
        files.insert(rel, j!({"bytes":b.len(),"sha256":hash(&b)}));
    }
    for p in &candidates {
        copy(
            p,
            &out.join(p.strip_prefix(&source).map_err(|e| e.to_string())?),
        )?
    }
    let mut names = manifest["files"]
        .as_array()
        .ok_or("missing manifest files")?
        .iter()
        .filter_map(Value::as_str)
        .map(String::from)
        .collect::<BTreeSet<_>>();
    names.extend(files.keys().cloned());
    manifest["files"] = j!(names);
    if manifest.get("resourceSources").is_none() {
        manifest["resourceSources"] = j!([])
    }
    manifest["resourceSources"]
        .as_array_mut()
        .ok_or("invalid resource sources")?
        .push(j!({"root":source,"systemVersion":version,"files":files}));
    write_json(&out.join("manifest.json"), &manifest)?;
    Ok(j!(files))
}
