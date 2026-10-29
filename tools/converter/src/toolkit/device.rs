use super::{cache, json, option, pacstrip, read, root, run, write, write_json, Result};
use serde_json::{json as j, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
fn file_hash(p: &Path) -> Result<String> {
    file_hash_prefix(p, u64::MAX)
}
fn file_hash_prefix(p: &Path, limit: u64) -> Result<String> {
    let mut f = File::open(p).map_err(|e| e.to_string())?.take(limit);
    let mut h = Sha256::new();
    let mut b = vec![0; 8 * 1024 * 1024];
    loop {
        let n = f.read(&mut b).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        h.update(&b[..n])
    }
    Ok(format!("{:x}", h.finalize()))
}
fn number(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64().ok_or_else(|| format!("missing number: {k}"))
}
fn string<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str().ok_or_else(|| format!("missing string: {k}"))
}
fn expected_pac_word(word: u32, offset: u64, code: &[(u64, u64, bool)]) -> Option<u32> {
    if !pacstrip::may_contain_pac(word) { return None; }
    match pacstrip::rewrite_word(word) {
        (Some(after), Some(class)) if code
            .get(code.partition_point(|&(low, _, _)| low <= offset).wrapping_sub(1))
            .is_some_and(|&(_, high, ldra)| offset.checked_add(4).is_some_and(|end| end <= high)
                && (ldra || !matches!(class, "LDRAA" | "LDRAB"))) => Some(after),
        _ => None,
    }
}
pub fn audit(primary: &Path, package: &Path, out: &Path) -> Result<Value> {
    let config = json(&root().join("tools/cache-demand-overrides.json"))?;
    let mut custom = BTreeMap::new();
    for item in config["instructionPatches"]
        .as_array()
        .into_iter()
        .flatten()
    {
        let parse = |k: &str| -> Result<u64> {
            u64::from_str_radix(string(item, k)?.trim_start_matches("0x"), 16)
                .map_err(|e| e.to_string())
        };
        custom.insert(
            parse("offset")?,
            (parse("expected")? as u32, parse("replacement")? as u32),
        );
    }
    let p = json(package)?;
    let strip_pac = p["pacMode"] == "strip";
    let mut pac_code = Vec::new();
    if strip_pac {
        let source = cache::load(primary)?;
        if p["primaryUUID"] != source.files[0].uuid {
            return Err("PAC audit cache UUID mismatch".into());
        }
        for path in p["instructionAuditImages"].as_array().into_iter().flatten() {
            let path = path.as_str().ok_or("invalid PAC audit image")?;
            let image = source.images.iter().find(|i| i.path == path)
                .ok_or("PAC audit image missing from source cache")?;
            let ldra = pacstrip::ldra_whitelisted(path);
            for section in cache::image(&source, image.address)?.sections {
                if section.flags & 0x80000400 != 0 {
                    pac_code.push((section.address - source.preferred_base,
                        section.address - source.preferred_base + section.size, ldra));
                }
            }
        }
        for section in cache::image(&source, source.dyld_header_address)?.sections {
            if section.flags & 0x80000400 != 0 {
                pac_code.push((section.address - source.preferred_base,
                    section.address - source.preferred_base + section.size, false));
            }
        }
        // The cache builder's branch islands are executable code too.
        if p["cacheTextStubs"] == true {
            for file in &source.files {
                for mapping in &file.mappings {
                    if mapping.flags & 8 != 0 {
                        let skip = if mapping.file_offset == 0 { 16384 } else { 0 };
                        pac_code.push((mapping.address - source.preferred_base + skip,
                            mapping.address - source.preferred_base + mapping.size, false));
                    }
                }
            }
        }
        pac_code.sort_unstable();
        pac_code.dedup();
    }
    let ranges = p["ranges"].as_array().ok_or("missing selected ranges")?;
    let patches = p["syscallPatches"]
        .as_array()
        .ok_or("missing syscall patches")?;
    let mut patch_map = BTreeMap::new();
    for item in patches {
        let off = number(item, "offset")?;
        if patch_map.insert(off, item).is_some() {
            return Err("duplicate syscall patch offset".into());
        }
    }
    let (mut svcs, mut tls, mut pac, mut count) = (0, 0, 0, 0);
    let mut visited = BTreeSet::new();
    for (i, r) in ranges.iter().enumerate() {
        if number(r, "protection")? & 4 == 0 {
            continue;
        }
        count += 1;
        let original = Path::new(string(r, "path")?);
        let source = if original.is_file() {
            original.to_path_buf()
        } else {
            primary
                .parent()
                .unwrap()
                .join(original.file_name().ok_or("cache path")?)
        };
        let mut f = File::open(source).map_err(|e| e.to_string())?;
        let n = number(r, "size")? as usize;
        if !n.is_multiple_of(4) {
            return Err("unaligned executable range".into());
        }
        f.seek(SeekFrom::Start(number(r, "fileOffset")?))
            .map_err(|e| e.to_string())?;
        let mut b = vec![0; n];
        f.read_exact(&mut b).map_err(|e| e.to_string())?;
        let packed = read(&out.join(format!("pages-{i:03}.bin")))?;
        if b.len() != packed.len() {
            return Err("packed executable length mismatch".into());
        }
        let low = number(r, "offset")?;
        for at in (0..n).step_by(4) {
            let w = cache::u32le(&b, at)?;
            let got = cache::u32le(&packed, at)?;
            let offset = low + at as u64;
            if patch_map.contains_key(&offset) {
                let expected = if let Some(&(before, after)) = custom.get(&offset) {
                    if w != before {
                        return Err(format!("instruction source mismatch at {offset:#x}"));
                    }
                    after
                } else if matches!(offset, 0x2eb28e60 | 0x2eb28eb0 | 0x2eb28edc) {
                    0xd65f03c0
                } else if w == 0xd4001001 {
                    svcs += 1;
                    0xd42909a0
                } else if w & !31 == 0xd53bd060 {
                    tls += 1;
                    0xd4294000 | ((w & 31) << 5)
                } else if pacstrip::may_contain_pac(w) {
                    match pacstrip::rewrite_word(w) {
                        (Some(replacement), Some(_)) => {
                            pac += 1;
                            replacement
                        }
                        _ => return Err(format!("unrecognized PAC patch at {offset:#x}")),
                    }
                } else {
                    return Err(format!("unauthorized patch record at {offset:#x}"));
                };
                if got != expected {
                    return Err(format!(
                        "mismatched Darwin patch at {offset:#x}: expected {expected:#010x}, got {got:#010x}"
                    ));
                }
                visited.insert(offset);
            } else {
                let replacement = if strip_pac { expected_pac_word(w, offset, &pac_code) } else { None };
                let expected = replacement.unwrap_or(w);
                if got != expected {
                    return Err(format!(
                        "unaudited code mutation at {offset:#x}: expected {expected:#010x}, packed {got:#010x}"
                    ));
                }
                if replacement.is_some() { pac += 1; }
            }
        }
    }
    if visited.len() != patch_map.len() {
        return Err("patch record outside selected executable ranges".into());
    }
    let v = j!({"schemaVersion":1,"status":"svc-boundary-verified-wrapper-still-executed","replacementLevel":"svc-trap-boundary","directHostSyscallABI":false,"fullLibsystemKernelReplacement":false,"boundary":{"selectedExecutableRanges":count,"source":{"svc80":svcs,"tpidrro":tls,"pac":pac},"patched":{"svc80":svcs,"tpidrro":tls,"pac":pac},"packedRemaining":{"svc80":0,"tpidrro":0,"pac":0},"issues":[]},"implementation":"Rust: every selected instruction byte checked against source"});
    write_json(&out.join("libsystem-shim.json"), &v)?;
    Ok(v)
}
struct Device<'a> {
    id: Option<&'a str>,
    bundle: &'a str,
    compress_transfer: bool,
}
fn bounded_command(command: &mut Command, timeout: Duration) -> Result<String> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    let mut stdout = child.stdout.take().ok_or("missing command stdout")?;
    let mut stderr = child.stderr.take().ok_or("missing command stderr")?;
    let out = std::thread::spawn(move || {
        let mut bytes = vec![];
        stdout.read_to_end(&mut bytes).map(|_| bytes)
    });
    let err = std::thread::spawn(move || {
        let mut bytes = vec![];
        stderr.read_to_end(&mut bytes).map(|_| bytes)
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            break Some(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let out = out
        .join()
        .map_err(|_| "stdout reader panicked")?
        .map_err(|e| e.to_string())?;
    let err = err
        .join()
        .map_err(|_| "stderr reader panicked")?
        .map_err(|e| e.to_string())?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out),
        String::from_utf8_lossy(&err)
    );
    match status {
        Some(status) if status.success() => Ok(text),
        Some(status) => Err(format!("{command:?}: {status}: {text}")),
        None => Err(format!(
            "{command:?}: timed out after {} seconds: {text}",
            timeout.as_secs()
        )),
    }
}
fn launch_result(text: String) -> Result<()> {
    if text.contains("start ability successfully") {
        Ok(())
    } else {
        Err(format!("ability launch failed: {text}"))
    }
}
impl Device<'_> {
    fn command(&self, args: &[&str]) -> Command {
        let mut c = Command::new("hdc");
        if let Some(id) = self.id {
            c.args(["-t", id]);
        }
        c.args(args);
        c
    }
    fn call(&self, args: &[&str]) -> Result<String> {
        let timeout = if args.starts_with(&["file", "send"]) {
            1800
        } else if args.starts_with(&["shell", "bm", "install"]) {
            180
        } else {
            30
        };
        bounded_command(&mut self.command(args), Duration::from_secs(timeout))
    }
    fn try_call(&self, args: &[&str]) -> String {
        self.call(args).unwrap_or_else(|e| e)
    }
    fn recv(&self, remote: &str, local: &Path) -> Result<String> {
        self.call(&[
            "file",
            "recv",
            "-b",
            self.bundle,
            remote,
            &local.to_string_lossy(),
        ])
    }
    fn send(&self, local: &Path, remote: &str, sandbox: bool) -> Result<()> {
        // Bound each HDC stream. Large HSPs can deadlock the TCP backend in
        // WriteUvTcpFd once its peer applies backpressure. Assemble byte-for-
        // byte on the device, verify SHA-256, then publish the completed file.
        const CHUNK: u64 = 64 * 1024 * 1024;
        let size = std::fs::metadata(local).map_err(|e| e.to_string())?.len();
        if !sandbox && size > CHUNK && remote.starts_with("/data/local/tmp/") {
            let mut input = File::open(local).map_err(|e| e.to_string())?;
            let scratch = std::env::temp_dir().join(format!("harmonios-transfer-{}.part", std::process::id()));
            struct Cleanup(PathBuf);
            impl Drop for Cleanup { fn drop(&mut self) { let _ = std::fs::remove_file(&self.0); } }
            let _cleanup = Cleanup(scratch.clone());
            let part = format!("{remote}.part");
            let assembled = format!("{remote}.assembling");
            let quote = |s: &str| format!("'{}'", s.replace('\'', "'\\''"));
            let previous = self.try_call(&["shell", "stat", "-c", "%s", &assembled]);
            let mut sent = previous.trim().parse::<u64>().ok()
                .filter(|n| *n <= size && (*n == size || *n % CHUNK == 0)).unwrap_or(0);
            if sent != 0 {
                let digest = self.try_call(&["shell", "sha256sum", &assembled]);
                if digest.split_whitespace().next() != Some(file_hash_prefix(local, sent)?.as_str()) {
                    sent = 0;
                } else {
                    input.seek(SeekFrom::Start(sent)).map_err(|e| e.to_string())?;
                    println!("==> resume verified transfer at {sent}/{size} bytes");
                }
            }
            while sent < size {
                let mut output = File::create(&scratch).map_err(|e| e.to_string())?;
                let copied = std::io::copy(&mut (&mut input).take(CHUNK), &mut output).map_err(|e| e.to_string())?;
                if copied == 0 { return Err("source shortened during HDC transfer".into()); }
                drop(output);
                self.send_one(&scratch, &part, false)?;
                self.call(&["shell", &format!("cat {} {} {}", quote(&part), if sent == 0 { ">" } else { ">>" }, quote(&assembled))])?;
                sent += copied;
                println!("==> transferred {sent}/{size} bytes");
            }
            let digest = self.call(&["shell", "sha256sum", &assembled])?;
            if digest.split_whitespace().next() != Some(file_hash(local)?.as_str()) {
                return Err("assembled device transfer SHA-256 mismatch".into());
            }
            self.call(&["shell", "mv", &assembled, remote])?;
            self.call(&["shell", "rm", "-f", &part])?;
            return Ok(());
        }
        self.send_one(local, remote, sandbox)
    }
    fn send_one(&self, local: &Path, remote: &str, sandbox: bool) -> Result<()> {
        let p = local.to_string_lossy();
        let mut a = if sandbox {
            vec!["file", "send", "-b", self.bundle]
        } else {
            vec!["file", "send"]
        };
        // HAP/ZIP are compressed application archives; HSP stores libhm_ioscache.so
        // uncompressed, so -z significantly speeds up the over-the-network transfer.
        if self.compress_transfer && !matches!(
            local.extension().and_then(|e| e.to_str()),
            Some("hap" | "zip")
        ) {
            a.push("-z");
        }
        a.extend([&p, remote]);
        let t = self.call(&a)?;
        if !t.contains("FileTransfer finish") {
            return Err(format!("file transfer incomplete: {t}"));
        }
        println!("{}", t.trim());
        Ok(())
    }
}
fn hsp_identity(path: &Path) -> Result<Value> {
    let mut z = zip::ZipArchive::new(File::open(path).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let mut names = vec![];
    for i in 0..z.len() {
        names.push(z.by_index(i).map_err(|e| e.to_string())?.name().to_owned())
    }
    names.sort();
    if names.windows(2).any(|n| n[0] == n[1]) {
        return Err("duplicate HSP member".into());
    }
    let mut h = Sha256::new();
    let mut cache_hash = None;
    let mut cache_bytes = 0;
    let mut b = vec![0; 8 * 1024 * 1024];
    for name in names {
        let mut f = z.by_name(&name).map_err(|e| e.to_string())?;
        h.update((name.len() as u32).to_le_bytes());
        h.update(name.as_bytes());
        h.update(f.size().to_le_bytes());
        let mut ch = Sha256::new();
        let is_cache = name == "libs/arm64-v8a/libhm_ioscache.so";
        loop {
            let n = f.read(&mut b).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            h.update(&b[..n]);
            if is_cache {
                ch.update(&b[..n])
            }
        }
        if is_cache {
            cache_hash = Some(format!("{:x}", ch.finalize()));
            cache_bytes = f.size()
        }
    }
    Ok(
        j!({"sha256":format!("{:x}",h.finalize()),"cacheSHA256":cache_hash.ok_or("HSP missing cache ELF")?,"cacheBytes":cache_bytes,"module":"ioscache","ready":true}),
    )
}
#[cfg(unix)]
fn file_identity(path: &Path) -> Result<Value> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(path).map_err(|e| e.to_string())?;
    Ok(j!([
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime() as i128 * 1_000_000_000 + m.mtime_nsec() as i128,
        m.ctime() as i128 * 1_000_000_000 + m.ctime_nsec() as i128
    ]))
}
#[cfg(not(unix))]
fn file_identity(_path: &Path) -> Result<Value> {
    Ok(Value::Null)
}
fn cached_hsp_identity(path: &Path) -> Result<Value> {
    let before = file_identity(path)?;
    let stamp = path.with_file_name(format!(
        "{}.identity.json",
        path.file_name().ok_or("HSP filename")?.to_string_lossy()
    ));
    if !before.is_null() {
        if let Ok(saved) = json(&stamp) {
            let payload = &saved["payload"];
            if saved["file"] == before
                && payload["ready"] == true
                && payload["module"] == "ioscache"
                && ["sha256", "cacheSHA256"].iter().all(|k| {
                    payload[k]
                        .as_str()
                        .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
                })
            {
                return Ok(payload.clone());
            }
        }
    }
    let identity = hsp_identity(path)?;
    if file_identity(path)? != before {
        return Err("cache HSP changed while hashing".into());
    }
    if !before.is_null() {
        write_json(&stamp, &j!({"file":before,"payload":identity}))?;
    }
    Ok(identity)
}
fn install(d: &Device, hap: &Path, out: &Path, force: bool) -> Result<()> {
    let hsp = root().join("ioscache/build/default/outputs/default/ioscache-default-signed.hsp");
    let mut z = zip::ZipArchive::new(File::open(hap).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    for i in 0..z.len() {
        if z.by_index(i)
            .map_err(|e| e.to_string())?
            .name()
            .ends_with("/libhm_ioscache.so")
        {
            return Err("entry HAP contains cache ELF".into());
        }
    }
    let started = Instant::now();
    let mut current = cached_hsp_identity(&hsp)?;
    current["bundle"] = j!(d.bundle);
    let stamp = "data/storage/el2/base/haps/harmonios/files/ioscache-installed.json";
    let prior = out.join("ioscache-device-stamp.json");
    if prior.exists() {
        std::fs::remove_file(&prior).map_err(|e| e.to_string())?
    }
    let got = d.recv(stamp, &prior).is_ok();
    let dump = d.try_call(&["shell", "bm", "dump", "-n", d.bundle]);
    let present = dump
        .find('{')
        .and_then(|p| serde_json::from_str::<Value>(&dump[p..]).ok())
        .is_some_and(|v| {
            v["moduleNames"]
                .as_array()
                .is_some_and(|v| v.iter().any(|v| v == "ioscache"))
        });
    let reuse = !force && present && got && json(&prior).ok().is_some_and(|p| p == current);
    let rh = "/data/local/tmp/harmonios-install.hap";
    let rs = "/data/local/tmp/harmonios-ioscache.hsp";
    if reuse {
        println!("==> reuse installed cache HSP")
    } else {
        d.send(&hsp, rs, false)?
    }
    let start = Instant::now();
    d.send(hap, rh, false)?;
    let sent = start.elapsed().as_secs_f64();
    let start = Instant::now();
    let mut args = vec!["shell", "bm", "install", "-r", "-p", rh];
    if !reuse {
        args.push(rs)
    }
    let t = d.call(&args)?;
    if !t.contains("install bundle successfully") {
        return Err(t);
    }
    let installed = start.elapsed().as_secs_f64();
    if !reuse {
        let local = out.join("ioscache-installed.json");
        write_json(&local, &current)?;
        d.send(&local, stamp, true)?
    }
    write_json(
        &out.join("iteration-timings.json"),
        &j!({"cacheHsp":if reuse{"reuse"}else{"transferred"},"hapTransferSeconds":sent,"bmInstallSeconds":installed,"installSeconds":started.elapsed().as_secs_f64(),"identity":current}),
    )?;
    println!(
        "==> install completed in {:.3}s",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}
fn stage_data(
    d: &Device,
    out: &Path,
    p: &Path,
    warm_up: bool,
    warm_up_timeout: Duration,
) -> Result<()> {
    let manifest = p.with_file_name(format!(
        "{}.json",
        p.file_name()
            .ok_or("cache data filename")?
            .to_string_lossy()
    ));
    let m = json(&manifest)?;
    let primary = root().join("artifacts/ios27-system/cache/dyld_shared_cache_arm64e");
    let cache_set = cache::load(&primary)?;
    if number(&m, "bytes")? != std::fs::metadata(p).map_err(|e| e.to_string())?.len()
        || m["primaryUUID"] != cache_set.files[0].uuid
    {
        return Err("cache data identity/size mismatch".into());
    }
    let remote = "data/storage/el2/base/haps/harmonios/files/sysroot/cache-data.pack";
    let stamp = out.join("cache-data-device.json");
    if stamp.exists() {
        std::fs::remove_file(&stamp).map_err(|e| e.to_string())?
    }
    if d.recv(&format!("{remote}.json"), &stamp).is_ok() {
        if let Ok(prior) = json(&stamp) {
            if ["sha256", "bytes", "primaryUUID"]
                .iter()
                .all(|k| prior[k] == m[k])
                && d.try_call(&["shell", "-b", d.bundle, "ls", remote])
                    .contains("cache-data.pack")
            {
                println!("==> reuse staged cache data");
                return Ok(());
            }
        }
    }
    if file_hash(p)? != string(&m, "sha256")? {
        return Err("cache data SHA256 mismatch".into());
    }
    if warm_up {
        d.call(&[
            "shell",
            "aa",
            "start",
            "-a",
            "HarmoniosAbility",
            "-b",
            d.bundle,
        ])?;
        let deadline = Instant::now() + warm_up_timeout;
        while !d
            .try_call(&[
                "shell",
                "-b",
                d.bundle,
                "ls",
                "data/storage/el2/base/haps/harmonios/files/sysroot/usr/lib/dyld",
            ])
            .contains("dyld")
        {
            if Instant::now() >= deadline {
                return Err("warm-up did not create the private sysroot".into());
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        d.call(&["shell", "aa", "force-stop", d.bundle])?;
    }
    d.send(p, remote, true)?;
    d.send(&manifest, &format!("{remote}.json"), true)
}
fn decode(records: &str) -> Option<Value> {
    let mut chunks = BTreeMap::new();
    for line in records.lines() {
        let Some((_, tail)) = line.split_once("HarmoniosReport:") else {
            continue;
        };
        let tail = tail.trim_start();
        let tail = if tail.starts_with('[') {
            tail.split_once(']')?.1.trim_start()
        } else {
            tail
        };
        let Some((n, text)) = tail.split_once(' ') else {
            continue;
        };
        let Ok(n) = n.parse::<usize>() else { continue };
        if n == 0 {
            chunks.clear()
        }
        chunks.insert(n, text);
    }
    let mut s = String::new();
    for (n, t) in chunks {
        if n != s.chars().count() {
            return None;
        }
        s.push_str(t)
    }
    serde_json::from_str(&s).ok()
}
fn screenshot(d: &Device, out: &Path) -> Result<()> {
    let remote = "/data/local/tmp/harmonios-latest.jpeg";
    d.call(&["shell", "snapshot_display", "-f", remote])?;
    d.call(&[
        "file",
        "recv",
        remote,
        &out.join("harmonios-latest.jpeg").to_string_lossy(),
    ])?;
    Ok(())
}
fn incomplete(d: &Device, out: &Path, records: &str) -> Result<()> {
    write(&out.join("report-device-incomplete.log"), records)?;
    let p = d.try_call(&["shell", "pidof", d.bundle]);
    write(&out.join("incomplete-process.log"), &p)?;
    for tag in ["runtime", "system"] {
        let args = if tag == "runtime" {
            vec!["shell", "hilog", "-x", "-T", "Harmonios"]
        } else {
            vec!["shell", "hilog", "-x"]
        };
        write(
            &out.join(format!("incomplete-{tag}.log")),
            d.try_call(&args),
        )?
    }
    let shot = screenshot(d, out);
    write_json(
        &out.join("incomplete-run.json"),
        &j!({"processObservedAlive":!p.trim().is_empty()&&p.split_whitespace().all(|s|s.parse::<u64>().is_ok()),"screenshotError":shot.err()}),
    )
}
pub fn execute(a: &[String], collect_only: bool) -> Result<()> {
    validate_arguments(a)?;
    let duration = |key: &str, default: &str| -> Result<Duration> {
        let n = option(a, key)
            .unwrap_or(default)
            .parse::<f64>()
            .map_err(|e| e.to_string())?;
        if !n.is_finite() || n <= 0.0 || n > 86400.0 {
            return Err(format!("invalid duration for {key}"));
        }
        Ok(Duration::from_secs_f64(n))
    };
    let timeout = duration("--timeout", "90")?;
    let interval = duration("--interval", "0.5")?;
    let warm_up_timeout = duration("--warm-up-timeout", "15")?;
    let r = root();
    let data_pack = option(a, "--cache-data-pack")
        .map(PathBuf::from)
        .unwrap_or_else(|| r.join("artifacts/ios27-data/cache-data.pack"));
    let output = option(a, "--output")
        .map(PathBuf::from)
        .unwrap_or_else(|| r.join("artifacts"));
    std::fs::create_dir_all(&output).map_err(|e| e.to_string())?;
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(r.join("artifacts/device-run.lock"))
        .map_err(|e| e.to_string())?;
    lock.try_lock()
        .map_err(|_| "another harmonios device run owns this workspace".to_string())?;
    let d = Device {
        id: option(a, "--device"),
        bundle: option(a, "--bundle").unwrap_or("fun.oboard.hamintosh"),
        compress_transfer: !a.iter().any(|arg| arg == "--no-compress-transfer"),
    };
    let hap = r.join("harmonios/build/default/outputs/default/harmonios-default-signed.hap");
    let contains = |s: &str| a.iter().any(|x| x == s);
    let pac_mode = match option(a, "--pac") {
        Some(value) => super::pacstrip::PacMode::parse(value)
            .ok_or_else(|| "--pac expects one of: strip, none".to_string())?,
        None => super::pacstrip::PacMode::Strip,
    };
    if !collect_only {
        if !contains("--skip-build") {
            let primary = r.join("artifacts/ios27-system/cache/dyld_shared_cache_arm64e");
            // Only incidental extras live in a JSON file (extra pages, ranges and
            // instruction patches). The image set itself is derived from the App's
            // own LC_LOAD_DYLIB closure plus the runtime services UIKit opens.
            let overrides = r.join("tools/cache-demand-overrides.json");
            let overrides = if overrides.is_file() { Some(overrides) } else { None };
            let cache_output = r.join("artifacts/ios27-aot");
            let library = cache_output.join("libhm_ioscache.so");
            let demand_path = cache_output.join("demand.json");
            let app_executable = r.join(
                "harmonios/src/main/resources/rawfile/target/executable",
            );
            let expected_mode = if pac_mode == pacstrip::PacMode::Strip { "strip" } else { "none" };
            let pac_stale = json(&cache_output.join("package.json"))
                .map(|manifest| manifest["pacMode"] != expected_mode
                    || manifest["pacTransformVersion"] != pacstrip::TRANSFORM_VERSION)
                .unwrap_or(true);
            if pac_stale && contains("--no-repack-cache") {
                return Err("packaged PAC transform is stale; rebuild without --no-repack-cache".into());
            }
            let stale = std::fs::metadata(&app_executable)
                .and_then(|m| m.modified())
                .ok()
                .zip(std::fs::metadata(&library).and_then(|m| m.modified()).ok())
                .is_some_and(|(a, b)| a > b);
            if contains("--repack-cache")
                || pac_stale
                || !library.is_file()
                || stale && !contains("--no-repack-cache")
            {
                println!("==> derive cache demand from App dependencies (Rust)");
                let demand = super::cache_pack::derive_demand(
                    &primary,
                    &app_executable,
                    overrides.as_deref(),
                )?;
                if !demand["missingDependencies"]
                    .as_array()
                    .is_some_and(|v| v.is_empty())
                {
                    println!(
                        "    cache does not carry: {}",
                        demand["missingDependencies"]
                    );
                }
                super::write_json(&demand_path, &demand)?;
                println!(
                    "==> repack signed cache inputs (Rust, pac={})",
                    if pac_mode == super::pacstrip::PacMode::Strip { "strip" } else { "none" }
                );
                super::cache_pack::pack(
                    &primary,
                    &cache_output,
                    Path::new("/Applications/DevEco-Studio.app/Contents/sdk/default/hms/native/BiSheng/bin/clang"),
                    Some(&demand_path),
                    false,
                    pac_mode,
                )?;
            }
            let data = &data_pack;
            if !data.is_file() || contains("--repack-cache-data") {
                println!("==> prepare non-executable cache data (Rust)");
                super::data_pack::pack(&primary, data)?;
            }
            if contains("--clean") {
                println!("==> hvigor clean");
                let logs = run(Command::new(
                    "/Applications/DevEco-Studio.app/Contents/tools/hvigor/bin/hvigorw",
                )
                .current_dir(&r)
                .args([
                    "clean",
                    "--mode",
                    "module",
                    "-p",
                    "product=default",
                    "-p",
                    "module=harmonios@default",
                    "--no-daemon",
                ]))?;
                write(&output.join("clean.log"), logs)?;
            }
            println!("==> audit Darwin syscall boundary (Rust)");
            audit(
                &r.join("artifacts/ios27-system/cache/dyld_shared_cache_arm64e"),
                &r.join("artifacts/ios27-aot/package.json"),
                &r.join("artifacts/ios27-aot"),
            )?;
            let source = r.join("artifacts/ios27-aot/libhm_ioscache.so");
            let target = r.join("ioscache/libs/arm64-v8a/libhm_ioscache.so");
            if !target.is_file() || file_hash(&source)? != file_hash(&target)? {
                std::fs::create_dir_all(target.parent().unwrap()).map_err(|e| e.to_string())?;
                std::fs::copy(&source, &target).map_err(|e| e.to_string())?;
            }
            for (task, module) in [("assembleHsp", "ioscache"), ("assembleHap", "harmonios")] {
                println!("==> hvigor {task}");
                let o = run(Command::new(
                    "/Applications/DevEco-Studio.app/Contents/tools/hvigor/bin/hvigorw",
                )
                .current_dir(&r)
                .args([
                    task,
                    "-p",
                    "buildMode=debug",
                    "--mode",
                    "module",
                    "-p",
                    "product=default",
                    "-p",
                    &format!("module={module}@default"),
                    "--no-daemon",
                ]))?;
                write(&output.join(format!("{task}.log")), o)?
            }
            let hsp = r.join("ioscache/build/default/outputs/default/ioscache-default-signed.hsp");
            // The identity stamp records the sha256 of the stripped cache ELF
            // inside the HSP, so compare it with the freshly stripped
            // intermediate rather than the pre-strip audited ELF.
            let packaged = r.join(
                "ioscache/build/default/intermediates/stripped_native_libs/default/arm64-v8a/libhm_ioscache.so",
            );
            let reference = if packaged.is_file() { &packaged } else { &source };
            if cached_hsp_identity(&hsp)?["cacheSHA256"] != file_hash(reference)? {
                return Err("signed HSP does not contain the current audited cache ELF".into());
            }
        }
        if contains("--build-only") {
            return Ok(());
        }
        if !contains("--skip-install") {
            install(&d, &hap, &output, contains("--force-cache-hsp"))?
        }
        if contains("--no-launch") {
            return Ok(());
        }
        d.try_call(&["shell", "power-shell", "wakeup"]);
        d.call(&["shell", "aa", "force-stop", d.bundle])?;
        if !contains("--no-stage-cache-data") {
            stage_data(
                &d,
                &output,
                &data_pack,
                !contains("--no-warm-up"),
                warm_up_timeout,
            )?
        }
        d.call(&["shell", "aa", "force-stop", d.bundle])?;
        d.call(&["shell", "hilog", "-r"])?;
    }
    let time = d
        .try_call(&["shell", "date", "+%s%3N"])
        .trim()
        .parse::<u64>()
        .unwrap_or_else(|_| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64
        });
    if !collect_only {
        let ability = option(a, "--ability").unwrap_or("HarmoniosAbility");
        let t = d.call(&["shell", "aa", "start", "-a", ability, "-b", d.bundle])?;
        launch_result(t)?;
    }
    let deadline = Instant::now() + timeout;
    let report = output.join("device-compat-report.json");
    let mut records = String::new();
    loop {
        let disk = output.join("device-report.partial.json");
        let mut found = None;
        if d.recv(
            "data/storage/el2/base/haps/harmonios/files/compat-report.json",
            &disk,
        )
        .is_ok()
        {
            if let Ok(v) = json(&disk) {
                if (collect_only || v["timestamp"].as_u64().is_some_and(|n| n >= time))
                    && v["dyldBootstrap"]["status"]
                        .as_str()
                        .is_some_and(|s| !s.is_empty())
                {
                    found = Some(v)
                }
            }
        }
        if found.is_none() {
            records = d.try_call(&["shell", "hilog", "-x", "-T", "HarmoniosReport"]);
            found = decode(&records)
                .filter(|v| collect_only || v["timestamp"].as_u64().is_some_and(|n| n >= time));
        }
        if let Some(v) = found {
            write_json(&report, &v)?;
            write(&output.join("report-device.log"), &records)?;
            screenshot(&d, &output)?;
            println!("{}",serde_json::to_string_pretty(&j!({"report":report,"status":v["dyldBootstrap"]["status"],"traps":v["dyldBootstrap"]["traps"],"signal":v["dyldBootstrap"]["signal"],"appExecuted":v["preflight"]["appExecuted"],"detail":v["dyldBootstrap"]["detail"],"frameDiagnostics":v["frameDiagnostics"]})).unwrap());
            return Ok(());
        }
        if Instant::now() >= deadline {
            incomplete(&d, &output, &records)?;
            return Err(format!(
                "diagnostic timeout; evidence: {}",
                output.display()
            ));
        }
        std::thread::sleep(interval);
    }
}

fn validate_arguments(args: &[String]) -> Result<()> {
    let mut i = 0;
    while i < args.len() {
        let key = args[i].as_str();
        if matches!(
            key,
            "--device"
                | "--bundle"
                | "--ability"
                | "--output"
                | "--timeout"
                | "--interval"
                | "--cache-data-pack"
                | "--warm-up-timeout"
                | "--pac"
        ) {
            let value = args
                .get(i + 1)
                .ok_or_else(|| format!("{key} requires a value"))?;
            if value.starts_with("--") {
                return Err(format!("{key} requires a value"));
            }
            i += 2;
        } else if matches!(
            key,
            "--skip-build"
                | "--skip-install"
                | "--no-launch"
                | "--build-only"
                | "--clean"
                | "--no-clean"
                | "--force-cache-hsp"
                | "--repack-cache"
                | "--no-repack-cache"
                | "--repack-cache-data"
                | "--no-stage-cache-data"
                | "--stage-cache-data"
                | "--warm-up"
                | "--no-warm-up"
                | "--compressed-install"
                | "--no-compress-transfer"
        ) {
            i += 1;
        } else {
            return Err(format!("unknown device option: {key}"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pac_audit_requires_complete_source_code_word_and_ldra_permission() {
        let code = [(0x100, 0x110, false), (0x200, 0x210, true)];
        assert_eq!(expected_pac_word(0xd65f0fff, 0x100, &code), Some(pacstrip::RET));
        assert_eq!(expected_pac_word(0xd65f0fff, 0xfc, &code), None);
        assert_eq!(expected_pac_word(0xd65f0fff, 0x110, &code), None);
        assert_eq!(expected_pac_word(0xd65f0fff, 0x10e, &code), None);
        // LDRAB-looking literals outside the whitelist remain byte identical.
        assert_eq!(expected_pac_word(0xf8200420, 0x100, &code), None);
        assert_eq!(expected_pac_word(0xf8200420, 0x200, &code), Some(0xf9400020));
        assert_eq!(expected_pac_word(0xd503201f, 0x100, &code), None);
        assert_eq!(expected_pac_word(0xd65f0fff, u64::MAX, &code), None);
    }
    #[test]
    fn launch_failure_is_not_an_execution_timeout() {
        assert!(launch_result("start ability successfully.".into()).is_ok());
        let message =
            "Error Code:10106102 The device screen is locked during the application launch";
        assert!(launch_result(message.into())
            .unwrap_err()
            .contains("10106102"));
        assert!(launch_result("".into()).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn stalled_device_command_is_terminated_and_failure_output_preserved() {
        let started = Instant::now();
        let error = bounded_command(
            Command::new("/bin/sleep").arg("2"),
            Duration::from_millis(50),
        )
        .unwrap_err();
        assert!(error.contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(1));
        let error = bounded_command(
            Command::new("/bin/sh").args(["-c", "printf launch-error >&2; exit 7"]),
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert!(error.contains("launch-error"));
        assert!(error.contains('7'));
    }
    #[test]
    fn hsp_identity_invalidates_after_same_size_rewrite() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!("harmonios-hsp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.hsp");
        let create = |bytes: &[u8]| {
            let mut zip = zip::ZipWriter::new(File::create(&path).unwrap());
            zip.start_file(
                "libs/arm64-v8a/libhm_ioscache.so",
                zip::write::FileOptions::default()
                    .compression_method(zip::CompressionMethod::Stored),
            )
            .unwrap();
            zip.write_all(bytes).unwrap();
            zip.finish().unwrap();
        };
        create(b"first");
        let original = std::fs::metadata(&path).unwrap();
        let first = cached_hsp_identity(&path).unwrap();
        assert_eq!(first, cached_hsp_identity(&path).unwrap());
        create(b"other");
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(original.modified().unwrap()))
            .unwrap();
        assert_eq!(original.len(), std::fs::metadata(&path).unwrap().len());
        assert_ne!(
            first["cacheSHA256"],
            cached_hsp_identity(&path).unwrap()["cacheSHA256"]
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn report_chunks_require_contiguous_offsets_and_reset_at_zero() {
        let logs = "HarmoniosReport: 0 {\"ok\":\nHarmoniosReport: 6 true}\n";
        assert_eq!(decode(logs), Some(j!({"ok":true})));
        assert!(decode("HarmoniosReport: 0 {\"ok\":\nHarmoniosReport: 7 true}").is_none());
        assert_eq!(
            decode("HarmoniosReport: 0 garbage\nHarmoniosReport: 0 {}"),
            Some(j!({}))
        );
    }
}
