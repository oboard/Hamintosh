use super::{
    cache::{u32le, u64le},
    json, write_json, Result,
};
use serde_json::{json as j, Value};
use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
    process::Command,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    },
    time::Duration,
};
static SERIAL: AtomicUsize = AtomicUsize::new(0);
fn fetch(url: &str, range: &str) -> Result<(Vec<u8>, String, String)> {
    let header = std::env::temp_dir().join(format!(
        "harmonios-http-{}-{}.headers",
        std::process::id(),
        SERIAL.fetch_add(1, Ordering::Relaxed)
    ));
    let result = Command::new("curl")
        .args([
            "--location",
            "--fail",
            "--silent",
            "--show-error",
            "--max-time",
            "90",
            "--range",
            range,
            "--dump-header",
        ])
        .arg(&header)
        .arg(url)
        .output()
        .map_err(|e| e.to_string())?;
    let text = std::fs::read_to_string(&header).map_err(|e| e.to_string())?;
    std::fs::remove_file(header).map_err(|e| e.to_string())?;
    if !result.status.success() {
        return Err(String::from_utf8_lossy(&result.stderr).into_owned());
    }
    let mut content = None;
    let mut etag = String::new();
    let mut status = 0;
    for l in text.lines() {
        if l.starts_with("HTTP/") {
            status = l
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            content = None;
            etag.clear()
        } else if let Some((k, v)) = l.split_once(':') {
            if k.eq_ignore_ascii_case("content-range") {
                content = Some(v.trim().to_string())
            }
            if k.eq_ignore_ascii_case("etag") {
                etag = v.trim().to_string()
            }
        }
    }
    if status != 206 {
        return Err("server did not honor HTTP range".into());
    }
    Ok((result.stdout, content.ok_or("missing Content-Range")?, etag))
}
fn range(url: &str, start: u64, end: u64, etag: Option<&str>) -> Result<Vec<u8>> {
    let (b, r, e) = fetch(url, &format!("{start}-{end}"))?;
    if !r.starts_with(&format!("bytes {start}-{end}/"))
        || b.len() as u64 != end - start + 1
        || etag.is_some_and(|t| !t.is_empty() && t != e)
    {
        return Err("HTTP range length/identity mismatch".into());
    }
    Ok(b)
}
fn half(b: &[u8], p: usize) -> Result<usize> {
    Ok(u16::from_le_bytes(
        b.get(p..p + 2)
            .ok_or("truncated ZIP u16")?
            .try_into()
            .unwrap(),
    ) as usize)
}
fn locate(url: &str, member: &str) -> Result<Value> {
    let (tail, r, etag) = fetch(url, "-131072")?;
    let bounds = r
        .strip_prefix("bytes ")
        .and_then(|s| s.split_once('/'))
        .ok_or("invalid suffix range response")?;
    let total = bounds.1.parse::<u64>().map_err(|e| e.to_string())?;
    let (start, end) = bounds.0.split_once('-').ok_or("invalid suffix bounds")?;
    let start = start.parse::<u64>().map_err(|e| e.to_string())?;
    let end = end.parse::<u64>().map_err(|e| e.to_string())?;
    if tail.len() > 131072 || tail.len() as u64 != end - start + 1 {
        return Err("invalid ZIP tail length".into());
    }
    let at = tail
        .windows(4)
        .rposition(|b| b == b"PK\x05\x06")
        .ok_or("ZIP end not found")?;
    let (mut size, mut offset) = (u32le(&tail, at + 12)? as u64, u32le(&tail, at + 16)? as u64);
    if offset == 0xffffffff || size == 0xffffffff {
        let p = at.checked_sub(20).ok_or("ZIP64 locator missing")?;
        if tail.get(p..p + 4) != Some(b"PK\x06\x07") {
            return Err("ZIP64 locator missing".into());
        }
        let o = u64le(&tail, p + 8)?;
        let b = range(url, o, o + 55, Some(&etag))?;
        if b.get(..4) != Some(b"PK\x06\x06") {
            return Err("invalid ZIP64 end".into());
        }
        size = u64le(&b, 40)?;
        offset = u64le(&b, 48)?;
    }
    if size == 0 || size > 32 * 1024 * 1024 || offset + size > total {
        return Err("ZIP directory outside metadata bounds".into());
    }
    let b = range(url, offset, offset + size - 1, Some(&etag))?;
    let mut p = 0;
    while b.get(p..p + 4) == Some(b"PK\x01\x02") {
        let flags = half(&b, p + 8)?;
        let method = half(&b, p + 10)?;
        let crc = u32le(&b, p + 16)?;
        let (mut compressed, mut length) = (u32le(&b, p + 20)? as u64, u32le(&b, p + 24)? as u64);
        let (n, x, comment) = (half(&b, p + 28)?, half(&b, p + 30)?, half(&b, p + 32)?);
        let mut local = u32le(&b, p + 42)? as u64;
        let end = p + 46 + n + x + comment;
        if end > b.len() {
            return Err("ZIP entry outside directory".into());
        }
        if &b[p + 46..p + 46 + n] == member.as_bytes() {
            let extra = &b[p + 46 + n..p + 46 + n + x];
            let mut e = 0;
            while e + 4 <= extra.len() {
                let k = half(extra, e)?;
                let count = half(extra, e + 2)?;
                if e + 4 + count > extra.len() {
                    return Err("ZIP64 extra bounds".into());
                }
                if k == 1 {
                    let mut q = e + 4;
                    for v in [&mut length, &mut compressed, &mut local] {
                        if *v == 0xffffffff {
                            if q + 8 > e + 4 + count {
                                return Err("ZIP64 extra truncated".into());
                            }
                            *v = u64le(extra, q)?;
                            q += 8;
                        }
                    }
                }
                e += 4 + count;
            }
            if flags & 1 != 0 || !matches!(method, 0 | 8) || method == 0 && compressed != length {
                return Err("unsupported encrypted/compression ZIP member".into());
            }
            let h = range(url, local, local + 29, Some(&etag))?;
            if h.get(..4) != Some(b"PK\x03\x04") {
                return Err("invalid local ZIP header".into());
            }
            let start = local + 30 + half(&h, 26)? as u64 + half(&h, 28)? as u64;
            if start.checked_add(compressed).is_none_or(|n| n > total) {
                return Err("ZIP member exceeds archive".into());
            }
            return Ok(
                j!({"url":url,"etag":etag,"member":member,"start":start,"size":length,"crc32":crc,"method":method,"compressedSize":compressed}),
            );
        }
        p = end;
    }
    Err(format!("ZIP member not found: {member}"))
}
pub fn download(url: &str, member: &str, out: &Path, workers: usize) -> Result<()> {
    if !(1..=32).contains(&workers) {
        return Err("workers must be between 1 and 32".into());
    }
    let source = locate(url, member)?;
    std::fs::create_dir_all(out.parent().ok_or("download output parent")?)
        .map_err(|e| e.to_string())?;
    let name = out
        .file_name()
        .ok_or("download filename")?
        .to_string_lossy();
    let partial = out.with_file_name(format!("{name}.partial"));
    let checkpoint = out.with_file_name(format!("{name}.progress.json"));
    let mut done = BTreeSet::new();
    if checkpoint.exists() && partial.exists() {
        let old = json(&checkpoint)?;
        if old["source"] != source {
            return Err("partial download belongs to different source".into());
        }
        done = serde_json::from_value(old["completed"].clone()).map_err(|e| e.to_string())?;
    }
    let size = source["compressedSize"]
        .as_u64()
        .ok_or("missing transfer size")?;
    let block = 4 * 1024 * 1024u64;
    let count = size.div_ceil(block) as usize;
    if done.iter().any(|&n| n >= count) {
        return Err("invalid completed chunk index".into());
    }
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&partial)
        .map_err(|e| e.to_string())?;
    file.set_len(size).map_err(|e| e.to_string())?;
    let jobs = (0..count).filter(|i| !done.contains(i)).collect::<Vec<_>>();
    let next = AtomicUsize::new(0);
    let done = Mutex::new(done);
    let error = Mutex::new(None);
    let file = Mutex::new(file);
    std::thread::scope(|scope| {
        for _ in 0..workers {
            let (source, jobs, next, done, error, file, checkpoint) =
                (&source, &jobs, &next, &done, &error, &file, &checkpoint);
            scope.spawn(move || loop {
                if error.lock().unwrap().is_some() {
                    return;
                }
                let j = next.fetch_add(1, Ordering::Relaxed);
                let Some(&i) = jobs.get(j) else { return };
                let at = i as u64 * block;
                let n = (size - at).min(block);
                let start = source["start"].as_u64().unwrap() + at;
                let mut received = None;
                for attempt in 0..4 {
                    match range(url, start, start + n - 1, source["etag"].as_str()) {
                        Ok(b) => {
                            received = Some(b);
                            break;
                        }
                        Err(e) => {
                            if attempt == 3 {
                                *error.lock().unwrap() = Some(e);
                                return;
                            }
                            std::thread::sleep(Duration::from_secs(1 << attempt));
                        }
                    }
                }
                let b = received.unwrap();
                let result = (|| -> Result<()> {
                    let mut f = file.lock().unwrap();
                    f.seek(SeekFrom::Start(at))
                        .and_then(|_| f.write_all(&b))
                        .and_then(|_| f.sync_data())
                        .map_err(|e| e.to_string())?;
                    drop(f);
                    let mut d = done.lock().unwrap();
                    d.insert(i);
                    let tmp = checkpoint.with_extension("json.partial");
                    write_json(&tmp, &j!({"source":source,"completed":*d}))?;
                    std::fs::rename(tmp, checkpoint).map_err(|e| e.to_string())?;
                    if d.len() % 16 == 0 || d.len() == count {
                        println!("download {}/{count} blocks", d.len());
                    }
                    Ok(())
                })();
                if let Err(e) = result {
                    *error.lock().unwrap() = Some(e);
                    return;
                }
            });
        }
    });
    if let Some(e) = error.into_inner().unwrap() {
        return Err(e);
    }
    let mut target = partial.clone();
    if source["method"] == 8 {
        target = out.with_file_name(format!("{name}.inflating"));
        let input = File::open(&partial).map_err(|e| e.to_string())?;
        let mut decoder = flate2::read::DeflateDecoder::new(input);
        let mut dest = File::create(&target).map_err(|e| e.to_string())?;
        let expected = source["size"].as_u64().unwrap();
        let n = std::io::copy(
            &mut std::io::Read::by_ref(&mut decoder).take(expected + 1),
            &mut dest,
        )
        .map_err(|e| e.to_string())?;
        if n != expected || decoder.total_in() != size {
            return Err("invalid ZIP deflate extent".into());
        }
    }
    verify_download(&target, &source)?;
    std::fs::rename(&target, out).map_err(|e| e.to_string())?;
    if target != partial {
        std::fs::remove_file(partial).map_err(|e| e.to_string())?
    }
    write_json(&out.with_file_name(format!("{name}.source.json")), &source)?;
    if checkpoint.exists() {
        std::fs::remove_file(checkpoint).map_err(|e| e.to_string())?
    }
    Ok(())
}
pub fn verify_download(path: &Path, source: &Value) -> Result<()> {
    let mut f = File::open(path).map_err(|e| e.to_string())?;
    if f.metadata().map_err(|e| e.to_string())?.len()
        != source["size"].as_u64().ok_or("download size missing")?
    {
        return Err("verified archive size mismatch".into());
    }
    let mut h = crc32fast::Hasher::new();
    let mut b = vec![0; 8 * 1024 * 1024];
    loop {
        let n = f.read(&mut b).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        h.update(&b[..n])
    }
    if Some(h.finalize() as u64) != source["crc32"].as_u64() {
        return Err("download CRC32 mismatch".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::TcpListener, time::Instant};
    #[test]
    fn range_download_checks_zip_deflate_identity_size_and_crc() {
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let payload = b"owned SwiftUI fixture bytes".repeat(8192);
        zip.start_file(
            "Payload/Test.app/Test",
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated),
        )
        .unwrap();
        zip.write_all(&payload).unwrap();
        let bytes = zip.finish().unwrap().into_inner();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut served = 0;
            while served < 4 && Instant::now() < deadline {
                let (mut s, _) = match listener.accept() {
                    Ok(s) => s,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    Err(e) => panic!("{e}"),
                };
                s.set_nonblocking(false).unwrap();
                s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                let mut request = Vec::new();
                loop {
                    let mut b = [0; 1];
                    s.read_exact(&mut b).unwrap();
                    request.push(b[0]);
                    if request.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let text = String::from_utf8(request).unwrap();
                let range = text
                    .lines()
                    .find_map(|s| {
                        s.split_once(':')
                            .filter(|(k, _)| k.eq_ignore_ascii_case("Range"))
                            .map(|(_, v)| v.trim().trim_start_matches("bytes="))
                    })
                    .unwrap();
                let (a, b) = range.split_once('-').unwrap();
                let (start, end) = if a.is_empty() {
                    (
                        bytes.len().saturating_sub(b.parse().unwrap()),
                        bytes.len() - 1,
                    )
                } else {
                    (a.parse::<usize>().unwrap(), b.parse::<usize>().unwrap())
                };
                let body = &bytes[start..=end];
                write!(s,"HTTP/1.1 206 Partial Content\r\nETag: \"fixture-v1\"\r\nContent-Range: bytes {start}-{end}/{}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",bytes.len(),body.len()).unwrap();
                s.write_all(body).unwrap();
                served += 1;
            }
            assert_eq!(served, 4);
        });
        let dir = std::env::temp_dir().join(format!(
            "harmonios-download-test-{}",
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("member");
        let result = download(
            &format!("http://{address}/fixture.zip"),
            "Payload/Test.app/Test",
            &out,
            2,
        );
        server.join().unwrap();
        result.unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), payload);
        let source = super::super::json(&dir.join("member.source.json")).unwrap();
        std::fs::write(&out, b"corrupt").unwrap();
        assert!(verify_download(&out, &source).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
