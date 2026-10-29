use super::{cache, hash, json, pacstrip, run, write, write_json, Result};
use harmonios_runtime::cache::{slide, CacheSet};
use serde::{Deserialize, Serialize};
use serde_json::{json as j, Value};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt::Write as _,
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    process::Command,
};
const PAGE: u64 = 0x4000;
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Range {
    address: u64,
    offset: u64,
    size: u64,
    path: PathBuf,
    file_offset: u64,
    protection: u32,
    initial_protection: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_offset: Option<u64>,
    #[serde(default)]
    original_sha256: String,
    #[serde(default)]
    packed_sha256: String,
}
fn num(v: &Value) -> Result<u64> {
    if let Some(n) = v.as_u64() {
        Ok(n)
    } else {
        let s = v.as_str().ok_or("expected integer or hex string")?;
        if let Some(s) = s.strip_prefix("0x") {
            u64::from_str_radix(s, 16).map_err(|e| e.to_string())
        } else {
            s.parse::<u64>().map_err(|e| e.to_string())
        }
    }
}
fn round(a: u64) -> u64 {
    (a + PAGE - 1) & !(PAGE - 1)
}
fn merge(c: &CacheSet, spans: &[(u64, u64)], lazy: bool) -> Result<Vec<Range>> {
    let mut spans = spans.to_vec();
    spans.sort();
    let mut result: Vec<Range> = vec![];
    for (a, e) in spans {
        if e <= a || a % PAGE != 0 || e % PAGE != 0 {
            return Err("unaligned/empty cache selection".into());
        }
        let (f, m, o) = cache::location(c, a, e - a)?;
        let prot = m.max_protection;
        if prot & 6 == 6 {
            return Err("writable executable cache range".into());
        }
        if lazy && prot & 4 == 0 {
            continue;
        }
        if let Some(prev) = result.last_mut() {
            if a <= prev.address + prev.size {
                if prev.path == f.path
                    && prev.protection == prot
                    && prev.file_offset + a - prev.address == o
                {
                    prev.size = (prev.address + prev.size).max(e) - prev.address;
                    continue;
                } else if a < prev.address + prev.size {
                    return Err("conflicting cache ranges".into());
                }
            }
        }
        result.push(Range {
            address: a,
            offset: a - c.preferred_base,
            size: e - a,
            path: f.path.clone(),
            file_offset: o,
            protection: prot,
            initial_protection: m.protection,
            data_offset: None,
            original_sha256: String::new(),
            packed_sha256: String::new(),
        })
    }
    Ok(result)
}
fn coalesce(c: &CacheSet, mut ranges: Vec<Range>, maximum: usize) -> Result<Vec<Range>> {
    if ranges.len() <= maximum {
        return Ok(ranges);
    }
    let mut candidates = vec![];
    for (i, pair) in ranges.windows(2).enumerate() {
        let (l, r) = (&pair[0], &pair[1]);
        if l.protection != 5
            || r.protection != 5
            || r.address < l.address + l.size
            || l.path != r.path
            || l.file_offset + r.address - l.address != r.file_offset
        {
            continue;
        }
        if let Ok((f, m, o)) = cache::location(c, l.address, r.address + r.size - l.address) {
            if f.path == l.path && m.max_protection == 5 && o == l.file_offset {
                candidates.push((r.address - l.address - l.size, i))
            }
        }
    }
    let needed = ranges.len() - maximum;
    if candidates.len() < needed {
        return Err("cannot fit program headers within RX mappings".into());
    }
    candidates.sort();
    let joined = candidates[..needed]
        .iter()
        .map(|(_, i)| *i)
        .collect::<BTreeSet<_>>();
    let mut result: Vec<Range> = vec![];
    for (i, r) in ranges.drain(..).enumerate() {
        if i > 0 && joined.contains(&(i - 1)) {
            let p = result.last_mut().unwrap();
            p.size = r.address + r.size - p.address
        } else {
            result.push(r)
        }
    }
    Ok(result)
}
fn branch(pc: u64, w: u32) -> Option<u64> {
    if w & 0x7c000000 != 0x14000000 {
        return None;
    }
    let delta = (((w & 0x3ffffff) << 6) as i32 >> 6) as i64 * 4;
    pc.checked_add_signed(delta)
}
fn stubs(c: &CacheSet, instructions: &[(u64, u64)]) -> Result<Vec<(u64, u64)>> {
    let mut images = c.images.iter().collect::<Vec<_>>();
    images.sort_by_key(|i| i.address);
    let mut regions = vec![];
    for pair in images.windows(2) {
        if let Some(shard) = pair[0]
            .path
            .strip_prefix("/usr/lib/objc/libobjcMsgSend")
            .and_then(|s| s.strip_suffix(".dylib"))
        {
            if shard.bytes().all(|b| b.is_ascii_digit()) {
                regions.push((pair[0].address, pair[1].address));
            }
        }
    }
    let page = |a| -> Option<u64> {
        if regions.iter().any(|&(s, e)| s <= a && a < e) {
            let p = a & !(PAGE - 1);
            cache::location(c, p, PAGE).ok().map(|_| p)
        } else {
            None
        }
    };
    let mut pages = BTreeSet::new();
    let mut todo = instructions.to_vec();
    while let Some((a, n)) = todo.pop() {
        let b = cache::vm(c, a, n as usize)?;
        for (i, w) in b.chunks_exact(4).enumerate() {
            if let Some(p) =
                branch(a + i as u64 * 4, u32::from_le_bytes(w.try_into().unwrap())).and_then(page)
            {
                if pages.insert(p) {
                    todo.push((p, PAGE))
                }
            }
        }
    }
    Ok(pages.into_iter().map(|a| (a, a + PAGE)).collect())
}
fn selectors(c: &CacheSet) -> Result<Vec<(u64, u64)>> {
    let base = c.preferred_base;
    let h = cache::vm(c, base, 480)?;
    let opts = cache::u64le(&h, 464)?;
    let n = cache::u64le(&h, 472)?;
    if n < 48 {
        return Err("missing ObjC optimization header".into());
    }
    let b = cache::vm(c, base + opts, 48)?;
    if !(1..=4).contains(&cache::u32le(&b, 0)?) {
        return Err("unsupported ObjC optimization version".into());
    }
    let mut spans = vec![(base + opts, n)];
    let mut names: BTreeMap<u64, (u64, u64, u64)> = BTreeMap::new();
    for field in [24, 32, 40] {
        let o = cache::u64le(&b, field)?;
        if o == 0 {
            continue;
        }
        let table = base + o;
        let t = cache::vm(c, table, 20)?;
        let (cap, occ, shift, mask) = (
            cache::u32le(&t, 4)? as u64,
            cache::u32le(&t, 8)? as u64,
            cache::u32le(&t, 12)? as u64,
            cache::u32le(&t, 16)? as u64,
        );
        if cache::u32le(&t, 0)? != 0
            || cap == 0
            || cap > 1 << 24
            || !cap.is_power_of_two()
            || occ > cap
            || shift > 64
            || mask >= 1 << 24
            || mask & (mask + 1) != 0
        {
            return Err("invalid ObjC string hash table".into());
        }
        let start = 32 + 256 * 4 + mask + 1 + cap;
        let mut size = start + cap * 4;
        let offsets = cache::vm(c, table + start, (cap * 4) as usize)?;
        if field != 24 {
            let o = size + cap * 8;
            let count = cache::u32le(&cache::vm(c, table + o, 4)?, 0)? as u64;
            if count > 1 << 24 {
                return Err("invalid duplicate object count".into());
            }
            size = o + 4 + count * 8
        }
        cache::location(c, table, size)?;
        spans.push((table, size));
        for w in offsets.chunks_exact(4) {
            let rel = i32::from_le_bytes(w.try_into().unwrap());
            if rel == 0 {
                continue;
            }
            let a = table
                .checked_add_signed(rel as i64)
                .ok_or("selector offset overflow")?;
            let (_, m, _) = cache::location(c, a, 1)?;
            if m.protection & 1 == 0 || m.protection & 4 != 0 {
                return Err("selector name outside data".into());
            }
            names
                .entry(m.address)
                .and_modify(|v| {
                    v.0 = v.0.min(a);
                    v.1 = v.1.max(a)
                })
                .or_insert((a, a, m.address + m.size));
        }
    }
    for (field, size) in [(8, 24u64), (16, 8)] {
        let o = cache::u64le(&b, field)?;
        if o == 0 {
            continue;
        }
        let a = base + o;
        let h = cache::vm(c, a, 8)?;
        let count = cache::u32le(&h, 0)? as u64;
        if count > c.images.len() as u64 || cache::u32le(&h, 4)? as u64 != size {
            return Err("invalid ObjC header info".into());
        }
        let len = 8 + count * size;
        let data = cache::vm(c, a, len as usize)?;
        spans.push((a, len));
        if field == 8 {
            for i in 0..count {
                let slot = 8 + i * size + 8;
                let rel = cache::u64le(&data, slot as usize)? as i64;
                if rel != 0 {
                    let target = (a + slot)
                        .checked_add_signed(rel)
                        .ok_or("ObjC header info overflow")?;
                    cache::location(c, target, 8)?;
                    spans.push((target, 8));
                }
            }
        }
    }
    for (_, (first, last, end)) in names {
        let tail = cache::vm(c, last, (end - last).min(65536) as usize)?;
        let n = tail
            .iter()
            .position(|v| *v == 0)
            .ok_or("unterminated selector string")?;
        spans.push((first, last + n as u64 + 1 - first))
    }
    Ok(spans
        .into_iter()
        .map(|(a, n)| (a & !(PAGE - 1), round(a + n)))
        .collect())
}
fn deferred(s: &str) -> bool {
    matches!(s, "__LINKEDIT" | "__OBJC_RO" | "__OBJC_RW")
}
fn elf_verify(
    path: &Path,
    ranges: &[Range],
    start: u64,
    span: u64,
    blob: u64,
    max: Option<u64>,
) -> Result<()> {
    let mut f = File::open(path).map_err(|e| e.to_string())?;
    let mut h = [0; 64];
    f.read_exact(&mut h).map_err(|e| e.to_string())?;
    if &h[..6] != b"\x7fELF\x02\x01"
        || u16::from_le_bytes(h[16..18].try_into().unwrap()) != 3
        || u16::from_le_bytes(h[18..20].try_into().unwrap()) != 183
    {
        return Err("expected ARM64 ELF shared library".into());
    }
    let off = cache::u64le(&h, 32)?;
    let count = u16::from_le_bytes(h[56..58].try_into().unwrap()) as usize;
    if u16::from_le_bytes(h[54..56].try_into().unwrap()) != 56
        || !(1..=2048).contains(&count)
        || max.is_some_and(|m| off + count as u64 * 56 > m)
    {
        return Err("invalid/excessive program header table".into());
    }
    let mut table = vec![0; count * 56];
    f.seek(SeekFrom::Start(off))
        .and_then(|_| f.read_exact(&mut table))
        .map_err(|e| e.to_string())?;
    let mut loads = vec![];
    for b in table.chunks_exact(56) {
        if cache::u32le(b, 0)? != 1 {
            continue;
        }
        let flags = cache::u32le(b, 4)?;
        let (fo, va, fs, ms, align) = (
            cache::u64le(b, 8)?,
            cache::u64le(b, 16)?,
            cache::u64le(b, 32)?,
            cache::u64le(b, 40)?,
            cache::u64le(b, 48)?,
        );
        if flags & 3 == 3 || fs > ms || align == 0 || fo % align != va % align {
            return Err("invalid ELF load".into());
        }
        loads.push((flags, fo, va, fs, ms))
    }
    if loads.iter().map(|p| p.2 + p.4).max().unwrap_or(0) < start + span {
        return Err("ELF does not reserve cache span".into());
    }
    use sha2::{Digest, Sha256};
    let mut block = vec![0; 8 * 1024 * 1024];
    for r in ranges {
        let (prot, address) = if let Some(o) = r.data_offset {
            (4, blob + o)
        } else {
            (
                (if r.protection & 1 != 0 { 4 } else { 0 })
                    | (if r.protection & 2 != 0 { 2 } else { 0 })
                    | (if r.protection & 4 != 0 { 1 } else { 0 }),
                start + r.offset,
            )
        };
        let found = loads
            .iter()
            .filter(|p| {
                p.0 == prot
                    && p.2 <= address
                    && address + r.size <= p.2 + p.3
                    && (r.data_offset.is_some() || p.2 == address && p.3 == r.size && p.4 == r.size)
            })
            .collect::<Vec<_>>();
        if found.len() != 1 {
            return Err("linked cache mapping differs from plan".into());
        }
        let p = found[0];
        f.seek(SeekFrom::Start(p.1 + address - p.2))
            .map_err(|e| e.to_string())?;
        let mut h = Sha256::new();
        let mut left = r.size;
        while left > 0 {
            let n = left.min(block.len() as u64) as usize;
            f.read_exact(&mut block[..n]).map_err(|e| e.to_string())?;
            h.update(&block[..n]);
            left -= n as u64
        }
        if format!("{:x}", h.finalize()) != r.packed_sha256 {
            return Err("linked cache bytes changed".into());
        }
    }
    Ok(())
}
pub fn pack(
    primary: &Path,
    out: &Path,
    clang: &Path,
    config: Option<&Path>,
    full: bool,
    pac_mode: pacstrip::PacMode,
) -> Result<Value> {
    std::fs::create_dir_all(out).map_err(|e| e.to_string())?;
    let out = out.canonicalize().map_err(|e| e.to_string())?;
    let c = cache::load(primary)?;
    if c.platform != 2 || c.os_version < 27 << 16 {
        return Err("expected iOS 27+ device cache".into());
    }
    let demand = if let Some(p) = config {
        json(p)?
    } else {
        j!({})
    };
    if config.is_some() && demand["primaryUUID"] != c.files[0].uuid {
        return Err("cache demand UUID mismatch".into());
    }
    let yes = |k: &str| demand[k] == true;
    let lazy = yes("lazyData");
    let mut images = vec![];
    let mut spans = vec![];
    let mut code: Vec<(u64, u64, Option<String>)> = vec![];
    let mut allsegs = vec![];
    let mut queue = VecDeque::from([(c.dyld_header_address, 0usize)]);
    let mut selected = BTreeSet::new();
    let mut explicit = BTreeSet::new();
    let depth = if yes("dependencies") {
        usize::MAX
    } else {
        demand["dependencyDepth"].as_u64().unwrap_or(0) as usize
    };
    if depth != usize::MAX && depth > 64 {
        return Err("invalid dependency depth".into());
    }
    for p in demand["images"].as_array().into_iter().flatten() {
        let name = p.as_str().ok_or("invalid selected image")?;
        let image = c
            .images
            .iter()
            .find(|i| i.path == name)
            .ok_or_else(|| format!("missing selected image: {name}"))?;
        explicit.insert(name.to_owned());
        queue.push_back((image.address, 0));
    }
    while let Some((a, d)) = queue.pop_front() {
        if !selected.insert(a) {
            continue;
        }
        let meta = cache::image(&c, a)?;
        if a != c.dyld_header_address {
            let name = &c
                .images
                .iter()
                .find(|i| i.address == a)
                .ok_or("missing image header")?
                .path;
            images.push(j!({"path":name,"address":a,"closureDepth":d,"dependencies":meta.dependencies,"reexports":meta.reexports}));
            if d < depth {
                for dep in &meta.dependencies {
                    if let Some(i) = c.images.iter().find(|i| i.path == *dep) {
                        queue.push_back((i.address, d + 1))
                    }
                }
            }
            if yes("reexports") {
                for dep in &meta.reexports {
                    if let Some(i) = c.images.iter().find(|i| i.path == *dep) {
                        queue.push_back((i.address, d + 1))
                    }
                }
            }
        }
        if let Some((a, n)) = meta.exports {
            spans.push((a & !(PAGE - 1), round(a + n as u64)))
        }
        let image_path = c
            .images
            .iter()
            .find(|i| i.address == a)
            .map(|i| i.path.clone());
        for s in &meta.sections {
            if s.flags & 0x80000400 != 0 {
                code.push((s.address, s.size, image_path.clone()))
            }
        }
        allsegs.extend(meta.segments);
    }
    if full {
        for f in &c.files {
            for m in &f.mappings {
                spans.push((m.address, m.address + m.size))
            }
        }
    } else {
        for m in &c.files[0].mappings {
            spans.push((m.address, m.address + m.size))
        }
        for f in c.files.iter().skip(1) {
            for m in &f.mappings {
                if m.file_offset == 0 && m.size >= PAGE {
                    spans.push((m.address, m.address + PAGE))
                }
            }
        }
        for s in &allsegs {
            if !deferred(&s.name) {
                spans.push((s.address & !(PAGE - 1), round(s.address + s.size)))
            }
        }
    }
    if yes("stubs") {
        for f in &c.files {
            for m in &f.mappings {
                if m.flags & 8 != 0 {
                    spans.push((m.address, m.address + m.size));
                    let skip = if m.file_offset == 0 { PAGE } else { 0 };
                    if m.size > skip {
                        code.push((m.address + skip, m.size - skip, None))
                    }
                }
            }
        }
    }
    for p in demand["pages"].as_array().into_iter().flatten() {
        let p = num(p)?;
        if p % PAGE != 0 || p + PAGE > c.region_size {
            return Err("invalid demand page".into());
        }
        spans.push((c.preferred_base + p, c.preferred_base + p + PAGE));
    }
    for r in demand["ranges"].as_array().into_iter().flatten() {
        let (a, b) = (num(&r[0])?, num(&r[1])?);
        if a >= b || a % PAGE != 0 || b % PAGE != 0 || b > c.region_size {
            return Err("invalid demand range".into());
        }
        spans.push((c.preferred_base + a, c.preferred_base + b));
    }
    if yes("objcSelectors") {
        let plain_code: Vec<(u64, u64)> = code.iter().map(|&(a, n, _)| (a, n)).collect();
        spans.extend(stubs(&c, &plain_code)?);
        if !lazy {
            spans.extend(selectors(&c)?);
        }
    }
    if !lazy && (yes("headers") || yes("tlv")) {
        for i in &c.images {
            let meta = cache::image(&c, i.address)?;
            if yes("headers") {
                let n = cache::u32le(&cache::vm(&c, i.address, 32)?, 20)? as u64 + 32;
                spans.push((i.address & !(PAGE - 1), round(i.address + n)))
            }
            if yes("tlv") {
                for s in meta.sections {
                    if s.flags & 0xff == 0x13 && s.size > 0 {
                        if s.size % 24 != 0 || s.address % 8 != 0 {
                            return Err("invalid thread variable section".into());
                        }
                        spans.push((s.address & !(PAGE - 1), round(s.address + s.size)))
                    }
                }
            }
        }
    }
    let mut ranges = merge(&c, &spans, lazy)?;
    let limit = demand["maxProgramHeaderBytes"].as_u64();
    if let Some(n) = limit {
        if !(4096..=65536).contains(&n) {
            return Err("invalid ELF program-header limit".into());
        }
        ranges = coalesce(&c, ranges, ((n - 64) / 56 - 4) as usize)?;
    }
    let mut ordered = c.images.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|i| i.address);
    let mut audited = BTreeSet::new();
    for r in &ranges {
        if r.protection & 4 == 0 {
            continue;
        }
        let first = ordered
            .partition_point(|i| i.address <= r.address)
            .saturating_sub(1);
        let last = ordered.partition_point(|i| i.address < r.address + r.size);
        for i in &ordered[first..last] {
            if audited.insert(i.path.clone()) {
                let path = Some(i.path.clone());
                code.extend(
                    cache::image(&c, i.address)?
                        .sections
                        .into_iter()
                        .filter(|s| s.flags & 0x80000400 != 0)
                        .map(|s| (s.address, s.size, path.clone())),
                )
            }
        }
    }
    for f in &c.files {
        for m in &f.mappings {
            if m.flags & 8 != 0 {
                let skip = if m.file_offset == 0 { PAGE } else { 0 };
                if m.size > skip {
                    code.push((m.address + skip, m.size - skip, None))
                }
            }
        }
    }
    code.sort();
    code.dedup();
    let mut data_size = 0;
    for r in &mut ranges {
        if r.protection & 4 == 0 {
            r.data_offset = Some(data_size);
            data_size += r.size;
        }
    }
    let selected = ranges
        .iter()
        .map(|r| r.offset..r.offset + r.size)
        .collect::<Vec<_>>();
    let mut records = vec![];
    let (mut locations, mut authenticated, mut outside) = (0u64, 0u64, 0u64);
    for f in &c.files {
        for m in &f.mappings {
            let summary = slide::walk_selected(f, m, c.preferred_base, Some(&selected), |r| {
                if r.target_offset >= c.region_size {
                    return Err("relocation target outside cache".into());
                }
                outside += !selected.iter().any(|v| v.contains(&r.target_offset)) as u64;
                let mut b = [0; 24];
                b[..8].copy_from_slice(&r.location_offset.to_le_bytes());
                b[8..16].copy_from_slice(&r.target_offset.to_le_bytes());
                b[20] = r.high8;
                if let Some(a) = &r.authentication {
                    b[16..18].copy_from_slice(&a.diversity.to_le_bytes());
                    b[18] = a.key;
                    b[19] = 1 | ((a.address_diversity as u8) << 1);
                }
                records.extend(b);
                Ok(())
            })?;
            locations += summary.locations;
            authenticated += summary.authenticated;
        }
    }
    let summary =
        j!({"locations":locations,"authenticated":authenticated,"targetsOutsideSelection":outside});
    write(&out.join("fixups.bin"), &records)?;
    write_json(
        &out.join("ranges.json"),
        &selected
            .iter()
            .map(|r| [r.start, r.end])
            .collect::<Vec<_>>(),
    )?;
    let version = if lazy { 3u64 } else { 2 };
    let mut descriptor = vec![];
    for w in [
        u64::from_le_bytes(*b"HMCACHE1"),
        version,
        c.preferred_base,
        c.region_size,
        c.dyld_header_address - c.preferred_base,
        c.dyld_entry_address - c.preferred_base,
        ranges.len() as u64,
        locations,
    ] {
        descriptor.extend(w.to_le_bytes())
    }
    for r in &ranges {
        for w in [
            r.offset,
            r.size,
            r.protection as u64,
            r.data_offset.unwrap_or(u64::MAX),
        ] {
            descriptor.extend(w.to_le_bytes())
        }
    }
    descriptor.extend(records);
    let desc = out.join("descriptor.bin");
    write(&desc, &descriptor)?;
    let mut asm=format!(".section .rodata.hm_cache_descriptor,\"a\",%progbits\n.p2align 3\n.global hm_ios_cache_descriptor\nhm_ios_cache_descriptor:\n.incbin \"{}\"\n.global hm_ios_cache_descriptor_end\nhm_ios_cache_descriptor_end:\n.section .rodata.hm_cache_data,\"a\",%progbits\n.p2align 14\n.global hm_ios_cache_data\nhm_ios_cache_data:\n",desc.display());
    writeln!(asm, ".section .rodata.hm_cache_pac,\"a\",%progbits\n.p2align 3\n.global hm_ios_cache_pac_mode\nhm_ios_cache_pac_mode:\n.quad {}", u64::from(pac_mode == pacstrip::PacMode::Strip)).unwrap();
    let mut ph = String::from(
        "PHDRS { metadata PT_LOAD FLAGS(4) FILEHDR PHDRS; dynamic PT_DYNAMIC FLAGS(4);\n",
    );
    let mut layout=String::from(".hash : { *(.hash) } :metadata\n.gnu.hash : { *(.gnu.hash) } :metadata\n.dynsym : { *(.dynsym) } :metadata\n.dynstr : { *(.dynstr) } :metadata\n.dynamic : { *(.dynamic) } :metadata :dynamic\n.rodata : { *(.rodata*) } :metadata\n");
    let mut patches = vec![];
    let mut custom = BTreeMap::new();
    for item in demand["instructionPatches"]
        .as_array()
        .into_iter()
        .flatten()
    {
        let o = num(&item["offset"])?;
        let (e, r) = (num(&item["expected"])?, num(&item["replacement"])?);
        if o % 4 != 0
            || e > u32::MAX as u64
            || r > u32::MAX as u64
            || custom
                .insert(
                    c.preferred_base + o,
                    (e as u32, r as u32, item["reason"].clone()),
                )
                .is_some()
        {
            return Err("invalid/duplicate instruction patch".into());
        }
    }
    let mut used = BTreeSet::new();
    let mut pac_report = pacstrip::PacReport::default();
    let mut breaks = BTreeMap::new();
    for item in demand["breakpoints"].as_array().into_iter().flatten() {
        let o = num(&item["offset"])?;
        let im = if item.get("immediate").is_some() {
            num(&item["immediate"])?
        } else {
            0x484d
        };
        if o % 4 != 0 || im > 65535 {
            return Err("invalid breakpoint".into());
        }
        breaks.insert(c.preferred_base + o, im as u32);
    }
    for (i, r) in ranges.iter_mut().enumerate() {
        let mut b = cache::vm(&c, r.address, r.size as usize).or_else(|_| {
            let mut f = File::open(&r.path).map_err(|e| e.to_string())?;
            f.seek(SeekFrom::Start(r.file_offset))
                .map_err(|e| e.to_string())?;
            let mut b = vec![0; r.size as usize];
            f.read_exact(&mut b).map_err(|e| e.to_string())?;
            Ok::<_, String>(b)
        })?;
        r.original_sha256 = hash(&b);
        if r.protection & 4 != 0 {
            for &(a, n, ref image) in &code {
                let start = a.max(r.address);
                let end = (a + n).min(r.address + r.size);
                if end <= start {
                    continue;
                }
                let ldra_allowed = image
                    .as_deref()
                    .is_some_and(pacstrip::ldra_whitelisted);
                for at in (start..end).step_by(4) {
                    let p = (at - r.address) as usize;
                    let mut w = cache::u32le(&b, p)?;
                    let mut handled = false;
                    if let Some((expected, replace, reason)) = custom.get(&at) {
                        if w != *expected {
                            return Err(format!("instruction mismatch at {at:#x}"));
                        }
                        w = *replace;
                        b[p..p + 4].copy_from_slice(&w.to_le_bytes());
                        patches.push(j!({"offset":at-c.preferred_base,"original":format!("{expected:#010x}"),"replacement":format!("{replace:#010x}"),"reason":reason}));
                        used.insert(at);
                        handled = true;
                    }
                    if let Some(im) = breaks.get(&at) {
                        b[p..p + 4].copy_from_slice(&(0xd4400000 | im << 5).to_le_bytes());
                        patches.push(j!({"offset":at-c.preferred_base,"original":format!("{w:#010x}"),"replacement":format!("hlt #{im:#x}")}));
                        handled = true;
                    }
                    let replacement =
                        if matches!(at - c.preferred_base, 0x2eb28e60 | 0x2eb28eb0 | 0x2eb28edc) {
                            Some((0xd65f03c0, "dispatch-void-stub-brk".into()))
                        } else if w == 0xd4001001 {
                            Some((0xd42909a0, "svc #0x80".into()))
                        } else if w & !31 == 0xd53bd060 {
                            Some((
                                0xd4294000 | ((w & 31) << 5),
                                format!("mrs x{}, tpidrro_el0", w & 31),
                            ))
                        } else {
                            None
                        };
                    if let Some((v, original)) = replacement {
                        b[p..p + 4].copy_from_slice(&v.to_le_bytes());
                        patches.push(j!({"offset":at-c.preferred_base,"original":original,"replacement":format!("brk #{:#x}",(v>>5)&65535)}));
                        handled = true;
                    }
                    // Global PAC strip: dyld runs an arm64 main executable with
                    // signing keys off, so every authenticating instruction in
                    // the cached arm64e images must behave as its plain arm64
                    // equivalent. Rewrites are 4-for-4 and never move a branch.
                    if !handled
                        && pac_mode == pacstrip::PacMode::Strip
                        && pacstrip::may_contain_pac(w)
                    {
                        match pacstrip::rewrite_word(w) {
                            (Some(replacement), Some(class)) => {
                                let is_ldra = matches!(class, "LDRAA" | "LDRAB");
                                if !is_ldra || ldra_allowed {
                                    b[p..p + 4].copy_from_slice(&replacement.to_le_bytes());
                                    // PAC rewrites are deterministic from the source
                                    // instruction and code section. Keep class counts;
                                    // millions of JSON patch objects otherwise dwarf
                                    // the cache and exhaust the build host's memory.
                                    pac_report.rewrite(class);
                                } else {
                                    // Data-in-code that only looks like an
                                    // authenticated load must not be touched.
                                    pac_report.left.push((class, at - c.preferred_base));
                                }
                            }
                            (None, Some(class)) => {
                                pac_report.left.push((class, at - c.preferred_base));
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        r.packed_sha256 = hash(&b);
        let piece = out.join(format!("pages-{i:03}.bin"));
        write(&piece, b)?;
        if r.data_offset.is_some() {
            writeln!(
                asm,
                ".section .rodata.hm_cache_data,\"a\",%progbits\n.incbin \"{}\"",
                piece.display()
            )
            .unwrap();
            continue;
        }
        let flags = if r.protection & 4 != 0 {
            "ax"
        } else if r.protection & 2 != 0 {
            "aw"
        } else {
            "a"
        };
        writeln!(
            asm,
            ".section .hm_cache_{i},\"{flags}\",%progbits\n.p2align 14"
        )
        .unwrap();
        if i == 0 {
            if r.offset != 0 {
                return Err("missing cache base".into());
            }
            asm.push_str(".global hm_ios_cache_base\nhm_ios_cache_base:\n")
        }
        writeln!(asm, ".incbin \"{}\"", piece.display()).unwrap();
        let flags = (if r.protection & 1 != 0 { 4 } else { 0 })
            | (if r.protection & 2 != 0 { 2 } else { 0 })
            | (if r.protection & 4 != 0 { 1 } else { 0 });
        writeln!(ph, "cache{i} PT_LOAD FLAGS({flags});").unwrap();
        writeln!(
            layout,
            ".hm_cache_{i} (HM_CACHE_START + {}) : {{ *(.hm_cache_{i}) }} :cache{i}",
            r.offset
        )
        .unwrap();
    }
    if used.len() != custom.len() {
        return Err("instruction patch outside selected code".into());
    }
    let tail = round(c.region_size) - PAGE;
    if ranges.iter().map(|r| r.offset + r.size).max().unwrap_or(0) <= tail {
        writeln!(
            asm,
            ".section .hm_cache_reserve,\"a\",%nobits\n.p2align 14\n.zero {PAGE}"
        )
        .unwrap();
        ph.push_str("reserve PT_LOAD FLAGS(4);\n");
        writeln!(layout,".hm_cache_reserve (HM_CACHE_START + {tail}) (NOLOAD) : {{ *(.hm_cache_reserve) }} :reserve").unwrap()
    }
    asm.push_str(".section .rodata.hm_cache_data,\"a\",%progbits\n.global hm_ios_cache_data_end\nhm_ios_cache_data_end:\n.section .note.GNU-stack,\"\",%progbits\n");
    ph.push_str("stack PT_GNU_STACK FLAGS(6); }\n");
    let header_bytes =
        64 + (ranges.iter().filter(|r| r.data_offset.is_none()).count() as u64 + 4) * 56;
    let start = round(header_bytes + descriptor.len() as u64 + data_size + 65536);
    let ld=format!("{ph}SECTIONS {{ . = SIZEOF_HEADERS;\nHM_CACHE_START = {start};\n{layout} /DISCARD/ : {{ *(.comment) *(.note*) }}\n}}\n");
    write(&out.join("cache.S"), asm)?;
    write(&out.join("cache.ld"), ld)?;
    let obj = out.join("cache.o");
    let library = out.join("libhm_ioscache.so");
    run(Command::new(clang)
        .arg("--target=aarch64-linux-ohos")
        .arg("-c")
        .arg(out.join("cache.S"))
        .arg("-o")
        .arg(&obj))?;
    let bin = clang.parent().ok_or("clang directory")?;
    run(Command::new(bin.join("ld.lld"))
        .args([
            "-shared",
            "--hash-style=both",
            "-soname",
            "libhm_ioscache.so",
            "-T",
        ])
        .arg(out.join("cache.ld"))
        .arg(&obj)
        .arg("-o")
        .arg(&library))?;
    let syms = run(Command::new(bin.join("llvm-nm"))
        .args(["-D", "--defined-only"])
        .arg(&library))?;
    let blob = syms
        .lines()
        .find_map(|s| {
            let p = s.split_whitespace().collect::<Vec<_>>();
            if p.last() == Some(&"hm_ios_cache_data") {
                u64::from_str_radix(p[0], 16).ok()
            } else {
                None
            }
        })
        .ok_or("missing cache data symbol")?;
    elf_verify(&library, &ranges, start, c.region_size, blob, limit)?;
    let manifest = j!({"scope":if full{"full-cache"}else{"dyld-demand-pages"},"runtimeComplete":false,"primaryUUID":c.files[0].uuid,"regionSize":c.region_size,"ranges":ranges,"selectedBytes":ranges.iter().map(|r|r.size).sum::<u64>(),"demandImages":images,"demandPages":demand["pages"],"demandRanges":demand["ranges"],"dataBlobBytes":data_size,"descriptorVersion":version,"dataPaging":lazy,"cacheTextStubs":yes("stubs"),"cacheImageHeaders":yes("headers"),"cacheThreadVariables":yes("tlv"),"cacheObjCSelectors":yes("objcSelectors"),"instructionAuditImages":audited,"relocations":summary,"syscallPatches":patches,"pacMode":match pac_mode { pacstrip::PacMode::Strip => "strip", pacstrip::PacMode::None => "none" },"pacRewritten":pac_report.rewritten,"pacLeftUnrewritten":pac_report.left,"library":library});
    let mut manifest = manifest;
    manifest["pacTransformVersion"] = j!(pacstrip::TRANSFORM_VERSION);
    write_json(&out.join("package.json"), &manifest)?;
    Ok(manifest)
}


/// Images the guest loads through `dlopen`/XPC at runtime rather than through a
/// static `LC_LOAD_DYLIB` entry. UIKit's scene bring-up opens the BackBoard HID
/// delivery service through `BSServiceConnection`, so those frameworks are not
/// reachable from the App's own dependency walk and must be named here.
///
/// This list belongs to the toolchain, not to a hand-edited JSON demand file:
/// every entry is a private framework whose mach service UIKit looks up during
/// scene connection.
const RUNTIME_SERVICE_IMAGES: [&str; 7] = [
    // SFSymbols resolves UIImage(systemName:) for every SwiftUI icon; without
    // it mapped the resolve path returns nil and SwiftUICore asserts (BRK #1).
    "/System/Library/PrivateFrameworks/SFSymbols.framework/SFSymbols",
    "/System/Library/PrivateFrameworks/BackBoardServices.framework/BackBoardServices",
    "/System/Library/PrivateFrameworks/BackBoardHIDEventFoundation.framework/BackBoardHIDEventFoundation",
    "/System/Library/PrivateFrameworks/BaseBoard.framework/BaseBoard",
    "/System/Library/PrivateFrameworks/BoardServices.framework/BoardServices",
    "/System/Library/PrivateFrameworks/FrontBoardServices.framework/FrontBoardServices",
    "/System/Library/PrivateFrameworks/GraphicsServices.framework/GraphicsServices",
];

/// Build the cache demand from the App's own dependency closure.
///
/// `explicit` names every image that must be present regardless of what the App
/// links; `overrides` carries feature switches (`lazyData`, `headers`, ...) and
/// optional extra `pages`/`ranges`. Nothing here is hand-maintained per App: the
/// image list is derived from the Mach-O `LC_LOAD_DYLIB` commands plus the
/// runtime services UIKit opens lazily.
pub fn derive_demand(
    primary: &Path,
    app_executable: &Path,
    overrides: Option<&Path>,
) -> Result<Value> {
    let c = cache::load(primary)?;
    let bytes = super::read(app_executable)?;
    let image = harmonios_runtime::macho::parse(&bytes)?;
    let mut images: Vec<String> = Vec::new();
    let mut missing: Vec<String> = Vec::new();
    for dependency in &image.dependencies {
        match c.images.iter().find(|i| i.path == dependency.path) {
            Some(_) => {
                if !images.iter().any(|p| p == &dependency.path) {
                    images.push(dependency.path.clone())
                }
            }
            None => missing.push(dependency.path.clone()),
        }
    }
    if images.is_empty() {
        return Err("App links no image present in the selected cache".into());
    }
    for service in RUNTIME_SERVICE_IMAGES {
        let present = c.images.iter().any(|i| i.path == service);
        if present && !images.iter().any(|p| p == service) {
            images.push(service.to_string())
        }
    }
    let base = overrides.map(json).transpose()?.unwrap_or_else(|| j!({}));
    let mut demand = j!({
        "primaryUUID": &c.files[0].uuid,
        "dependencies": true,
        "lazyData": base["lazyData"].as_bool().unwrap_or(true),
        "maxProgramHeaderBytes": base["maxProgramHeaderBytes"].as_u64().unwrap_or(16384),
        "headers": base["headers"].as_bool().unwrap_or(true),
        "tlv": base["tlv"].as_bool().unwrap_or(true),
        "objcSelectors": base["objcSelectors"].as_bool().unwrap_or(true),
        "reexports": base["reexports"].as_bool().unwrap_or(true),
        "stubs": base["stubs"].as_bool().unwrap_or(true),
        "images": Value::Array(images.into_iter().map(Value::String).collect()),
        "missingDependencies": Value::Array(missing.into_iter().map(Value::String).collect()),
    });
    for key in ["pages", "ranges", "instructionPatches", "breakpoints"] {
        if let Some(value) = base.get(key) {
            demand[key] = value.clone();
        }
    }
    Ok(demand)
}


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn branch_targets_are_signed_and_only_direct() {
        assert_eq!(branch(0x1000, 0x17ffffff), Some(0xffc));
        assert_eq!(branch(0x1000, 0x94000004), Some(0x1010));
        assert_eq!(branch(0x1000, 0xd61f0200), None);
    }
    #[test]
    fn selection_cannot_merge_across_rx_mapping_boundaries() {
        let c = CacheSet {
            architecture: "arm64e".into(),
            platform: 2,
            os_version: 27 << 16,
            preferred_base: 0x180000000,
            region_size: 0x10000,
            dyld_header_address: 0,
            dyld_entry_address: 0,
            images: vec![],
            files: vec![harmonios_runtime::cache::CacheFile {
                path: PathBuf::from("cache"),
                uuid: String::new(),
                size: 0x10000,
                mappings: vec![
                    harmonios_runtime::cache::Mapping {
                        address: 0x180000000,
                        size: 0x8000,
                        file_offset: 0,
                        max_protection: 5,
                        protection: 5,
                        slide_info_offset: 0,
                        slide_info_size: 0,
                        flags: 0,
                        slide_version: None,
                    },
                    harmonios_runtime::cache::Mapping {
                        address: 0x180008000,
                        size: 0x8000,
                        file_offset: 0x8000,
                        max_protection: 5,
                        protection: 5,
                        slide_info_offset: 0,
                        slide_info_size: 0,
                        flags: 0,
                        slide_version: None,
                    },
                ],
            }],
        };
        let ranges = merge(
            &c,
            &[(0x180000000, 0x180004000), (0x18000c000, 0x180010000)],
            true,
        )
        .unwrap();
        assert!(coalesce(&c, ranges, 1).is_err());
    }
}
