use super::{cache, write_json, Result};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};
const PAGE: u64 = 0x4000;
struct Map {
    path: std::path::PathBuf,
    address: u64,
    size: u64,
    file_offset: u64,
    max: u32,
    prot: u32,
    slide_offset: u64,
    slide_size: u64,
}
fn aligned(a: u64, n: u64) -> (u64, u64) {
    (a & !(PAGE - 1), (a + n + PAGE - 1) & !(PAGE - 1))
}
pub fn pack(primary: &Path, out: &Path) -> Result<serde_json::Value> {
    let c = cache::load(primary)?;
    let mut maps = vec![];
    let mut spans = BTreeSet::new();
    for f in &c.files {
        for m in &f.mappings {
            if m.max_protection & 4 == 0 {
                maps.push(Map {
                    path: f.path.clone(),
                    address: m.address,
                    size: m.size,
                    file_offset: m.file_offset,
                    max: m.max_protection,
                    prot: m.protection,
                    slide_offset: m.slide_info_offset,
                    slide_size: m.slide_info_size,
                })
            } else if m.file_offset == 0 {
                spans.insert((m.address, m.address + PAGE));
            }
        }
    }
    for i in &c.images {
        let b = cache::vm(&c, i.address, 32)?;
        spans.insert(aligned(i.address, 32 + cache::u32le(&b, 20)? as u64));
        for s in cache::image(&c, i.address)?.sections {
            if s.size > 0
                && s.flags & 0x80000400 == 0
                && cache::location(&c, s.address, s.size)?.1.max_protection & 4 != 0
            {
                spans.insert(aligned(s.address, s.size));
            }
        }
    }
    let mut metadata_maps: Vec<Map> = vec![];
    for (a, e) in spans {
        let (f, _, o) = cache::location(&c, a, e - a)?;
        if let Some(p) = metadata_maps.last_mut() {
            if p.path == f.path && a <= p.address + p.size && p.file_offset + a - p.address == o {
                p.size = (p.address + p.size).max(e) - p.address;
                continue;
            }
        }
        metadata_maps.push(Map {
            path: f.path.clone(),
            address: a,
            size: e - a,
            file_offset: o,
            max: 1,
            prot: 1,
            slide_offset: 0,
            slide_size: 0,
        })
    }
    let code_bytes: u64 = metadata_maps.iter().map(|m| m.size).sum();
    maps.extend(metadata_maps);
    maps.sort_by_key(|m| m.address);
    if maps.is_empty() || maps.len() > 16384 {
        return Err("invalid data mapping count".into());
    }
    let mut metadata = vec![0; maps.len() * 80];
    let mut records = vec![];
    for m in &maps {
        let offset = m
            .address
            .checked_sub(c.preferred_base)
            .ok_or("data offset below cache")?;
        if offset % PAGE != 0
            || m.size == 0
            || m.size % PAGE != 0
            || offset + m.size > c.region_size
            || m.max & !3 != 0
            || m.prot & !m.max != 0
        {
            return Err("invalid data mapping".into());
        }
        let (mut page, mut value, mut start, mut count) = (0, 0, 0, 0);
        if m.slide_size > 0 {
            let mut f = File::open(&m.path).map_err(|e| e.to_string())?;
            f.seek(SeekFrom::Start(m.slide_offset))
                .map_err(|e| e.to_string())?;
            if m.slide_size > 64 * 1024 * 1024 {
                return Err("slide table too large".into());
            }
            let mut b = vec![0; m.slide_size as usize];
            f.read_exact(&mut b).map_err(|e| e.to_string())?;
            page = cache::u32le(&b, 4)? as u64;
            count = cache::u32le(&b, 8)? as u64;
            value = cache::u64le(&b, 16)?;
            if cache::u32le(&b, 0)? != 5
                || !matches!(page, 4096 | PAGE)
                || count > m.size / page
                || 24 + count * 2 > b.len() as u64
            {
                return Err("invalid v5 data slide table".into());
            }
            start = 64 + metadata.len() as u64;
            metadata.extend(&b[24..24 + count as usize * 2])
        }
        let crc = 64 + metadata.len() as u64;
        metadata.resize(metadata.len() + m.size as usize / PAGE as usize * 4, 0);
        records.push([
            offset,
            m.size,
            0,
            m.max as u64 | ((m.prot as u64) << 8),
            page,
            value,
            start,
            count,
            crc,
            0,
        ]);
    }
    let ms = (64 + metadata.len() as u64 + PAGE - 1) & !(PAGE - 1);
    metadata.resize(ms as usize - 64, 0);
    let mut position = ms;
    for r in &mut records {
        r[2] = position;
        position += r[1]
    }
    std::fs::create_dir_all(out.parent().ok_or("data pack output parent")?)
        .map_err(|e| e.to_string())?;
    let temp = out.with_extension("pack.partial");
    let mut dest = File::create(&temp).map_err(|e| e.to_string())?;
    dest.seek(SeekFrom::Start(ms)).map_err(|e| e.to_string())?;
    let mut block = vec![0; 8 * 1024 * 1024];
    for (i, m) in maps.iter().enumerate() {
        let mut source = File::open(&m.path).map_err(|e| e.to_string())?;
        source
            .seek(SeekFrom::Start(m.file_offset))
            .map_err(|e| e.to_string())?;
        let mut at = 0;
        while at < m.size {
            let n = (m.size - at).min(block.len() as u64) as usize;
            source
                .read_exact(&mut block[..n])
                .map_err(|e| e.to_string())?;
            for (p, b) in block[..n].chunks(PAGE as usize).enumerate() {
                let slot = (records[i][8] - 64 + (at / PAGE + p as u64) * 4) as usize;
                metadata[slot..slot + 4].copy_from_slice(&crc32fast::hash(b).to_le_bytes());
            }
            dest.write_all(&block[..n]).map_err(|e| e.to_string())?;
            at += n as u64
        }
        for (j, w) in records[i].iter().enumerate() {
            metadata[i * 80 + j * 8..i * 80 + j * 8 + 8].copy_from_slice(&w.to_le_bytes())
        }
    }
    dest.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    let mut header = b"HMDATA01".to_vec();
    let uuid = &c.files[0].uuid;
    for i in (0..uuid.len()).step_by(2) {
        header.push(u8::from_str_radix(&uuid[i..i + 2], 16).map_err(|e| e.to_string())?)
    }
    for n in [c.preferred_base, c.region_size, maps.len() as u64, position] {
        header.extend(n.to_le_bytes())
    }
    header.extend((ms as u32).to_le_bytes());
    header.extend(crc32fast::hash(&metadata).to_le_bytes());
    dest.write_all(&header)
        .and_then(|_| dest.write_all(&metadata))
        .and_then(|_| dest.sync_all())
        .map_err(|e| e.to_string())?;
    if dest.metadata().map_err(|e| e.to_string())?.len() != position {
        return Err("cache data size mismatch".into());
    }
    drop(dest);
    std::fs::rename(temp, out).map_err(|e| e.to_string())?;
    let mut f = File::open(out).map_err(|e| e.to_string())?;
    let mut h = Sha256::new();
    loop {
        let n = f.read(&mut block).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        h.update(&block[..n])
    }
    let manifest = serde_json::json!({"primaryUUID":uuid,"sha256":format!("{:x}",h.finalize()),"bytes":position,"mappings":maps.len(),"dataBytes":position-ms,"executableBytes":0,"pageSize":PAGE,"codeMetadataBytes":code_bytes});
    let name = out.file_name().ok_or("data filename")?.to_string_lossy();
    write_json(&out.with_file_name(format!("{name}.json")), &manifest)?;
    Ok(manifest)
}
