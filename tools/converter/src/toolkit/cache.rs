use super::Result;
use harmonios_runtime::cache::{CacheFile, CacheSet, Mapping};
use std::{
    collections::BTreeSet,
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
};
pub fn load(p: &Path) -> Result<CacheSet> {
    harmonios_runtime::cache::read(p)
}
pub fn location(c: &CacheSet, a: u64, n: u64) -> Result<(&CacheFile, &Mapping, u64)> {
    let end = a.checked_add(n).ok_or("cache range overflow")?;
    for f in &c.files {
        for m in &f.mappings {
            if m.address <= a && end <= m.address + m.size {
                return Ok((f, m, m.file_offset + a - m.address));
            }
        }
    }
    Err(format!("cache range outside mappings: {a:#x}+{n:#x}"))
}
pub fn vm(c: &CacheSet, a: u64, n: usize) -> Result<Vec<u8>> {
    if n > 64 * 1024 * 1024 {
        return Err("cache read too large".into());
    }
    let (f, _, o) = location(c, a, n as u64)?;
    let mut s = File::open(&f.path).map_err(|e| e.to_string())?;
    s.seek(SeekFrom::Start(o)).map_err(|e| e.to_string())?;
    let mut b = vec![0; n];
    s.read_exact(&mut b).map_err(|e| e.to_string())?;
    Ok(b)
}
pub fn u32le(b: &[u8], p: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        b.get(p..p.checked_add(4).ok_or("offset overflow")?)
            .ok_or("truncated u32")?
            .try_into()
            .unwrap(),
    ))
}
pub fn u64le(b: &[u8], p: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        b.get(p..p.checked_add(8).ok_or("offset overflow")?)
            .ok_or("truncated u64")?
            .try_into()
            .unwrap(),
    ))
}
pub fn name(b: &[u8]) -> Result<String> {
    let n = b.iter().position(|v| *v == 0).unwrap_or(b.len());
    String::from_utf8(b[..n].to_vec()).map_err(|e| e.to_string())
}
#[derive(Clone)]
pub struct Section {
    pub segment: String,
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub flags: u32,
}
#[derive(Clone)]
#[allow(dead_code)]
pub struct Segment {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub protection: u32,
    pub file_offset: u64,
    pub file_size: u64,
}
pub struct Image {
    pub segments: Vec<Segment>,
    pub sections: Vec<Section>,
    pub dependencies: Vec<String>,
    pub reexports: Vec<String>,
    pub exports: Option<(u64, usize)>,
    pub function_starts: Option<(u64, usize)>,
}
pub fn image(c: &CacheSet, a: u64) -> Result<Image> {
    let h = vm(c, a, 32)?;
    let n = u32le(&h, 16)? as usize;
    let size = u32le(&h, 20)? as usize;
    if u32le(&h, 0)? != 0xfeedfacf
        || u32le(&h, 4)? != 0x100000c
        || n > 4096
        || size > 1024 * 1024
        || !matches!(u32le(&h, 12)?, 6 | 7)
    {
        return Err("invalid cached Mach-O header".into());
    }
    let b = vm(c, a + 32, size)?;
    let mut o = Image {
        segments: vec![],
        sections: vec![],
        dependencies: vec![],
        reexports: vec![],
        exports: None,
        function_starts: None,
    };
    let mut p = 0;
    let mut exp = None;
    let mut starts = None;
    for _ in 0..n {
        let cmd = u32le(&b, p)?;
        let len = u32le(&b, p + 4)? as usize;
        if len < 8 || !len.is_multiple_of(8) || p + len > b.len() {
            return Err("invalid cached load command".into());
        }
        let d = &b[p..p + len];
        match cmd {
            0x26 => {
                if len != 16 || starts.is_some() {
                    return Err("invalid function starts command".into());
                }
                starts = Some((u32le(d, 8)? as u64, u32le(d, 12)? as u64));
            }
            25 => {
                if len < 72 {
                    return Err("truncated segment".into());
                }
                let s = Segment {
                    name: name(&d[8..24])?,
                    address: u64le(d, 24)?,
                    size: u64le(d, 32)?,
                    file_offset: u64le(d, 40)?,
                    file_size: u64le(d, 48)?,
                    protection: u32le(d, 60)?,
                };
                let count = u32le(d, 64)? as usize;
                if s.file_size > s.size || count > (len - 72) / 80 {
                    return Err("invalid cached segment".into());
                }
                location(c, s.address, s.size)?;
                for i in 0..count {
                    let q = 72 + i * 80;
                    let sec = Section {
                        segment: s.name.clone(),
                        name: name(&d[q..q + 16])?,
                        address: u64le(d, q + 32)?,
                        size: u64le(d, q + 40)?,
                        flags: u32le(d, q + 64)?,
                    };
                    if sec.address < s.address
                        || sec
                            .address
                            .checked_add(sec.size)
                            .filter(|v| *v <= s.address + s.size)
                            .is_none()
                    {
                        return Err("section escapes segment".into());
                    }
                    o.sections.push(sec)
                }
                o.segments.push(s)
            }
            0x80000033 => {
                if len != 16 || exp.is_some() {
                    return Err("invalid export command".into());
                }
                exp = Some((u32le(d, 8)? as u64, u32le(d, 12)? as u64))
            }
            0xc | 0x80000018 | 0x8000001f | 0x80000023 => {
                let at = u32le(d, 8)? as usize;
                if at < 24 || at >= len || !d[at..].contains(&0) {
                    return Err("invalid dylib name".into());
                }
                let v = name(&d[at..])?;
                o.dependencies.push(v.clone());
                if cmd == 0x8000001f {
                    o.reexports.push(v)
                }
            }
            _ => (),
        };
        p += len;
    }
    if p != b.len() {
        return Err("cache command count mismatch".into());
    }
    if let Some((at, len)) = exp {
        if len > 0 {
            let s = o
                .segments
                .iter()
                .find(|s| {
                    s.name == "__LINKEDIT"
                        && s.file_offset <= at
                        && at + len <= s.file_offset + s.file_size
                })
                .ok_or("exports outside LINKEDIT")?;
            o.exports = Some((s.address + at - s.file_offset, len as usize))
        }
    }
    if let Some((at, len)) = starts {
        if len > 0 {
            let s = o
                .segments
                .iter()
                .find(|s| {
                    s.name == "__LINKEDIT"
                        && s.file_offset <= at
                        && at
                            .checked_add(len)
                            .is_some_and(|end| end <= s.file_offset + s.file_size)
                })
                .ok_or("function starts outside LINKEDIT")?;
            o.function_starts = Some((s.address + at - s.file_offset, len as usize));
        }
    }
    Ok(o)
}

pub(crate) fn uleb(b: &[u8], p: &mut usize) -> Result<u64> {
    let mut v = 0;
    for shift in (0..64).step_by(7) {
        let x = *b.get(*p).ok_or("truncated ULEB")?;
        *p += 1;
        if shift == 63 && x > 1 {
            return Err("ULEB overflow".into());
        }
        v |= ((x & 127) as u64) << shift;
        if x < 128 {
            return Ok(v);
        }
    }
    Err("invalid ULEB".into())
}
#[derive(Clone, Debug)]
pub(crate) enum Export {
    Address(u64),
    Reexport(usize, String),
}
pub(crate) fn lookup(b: &[u8], symbol: &str) -> Result<Option<Export>> {
    let name = symbol.as_bytes();
    let (mut at, mut consumed) = (0, 0);
    let mut seen = BTreeSet::new();
    while seen.insert(at) && seen.len() <= name.len() + 1 {
        let mut p = at;
        let size = uleb(b, &mut p)? as usize;
        let end = p
            .checked_add(size)
            .filter(|e| *e < b.len())
            .ok_or("export terminal escapes data")?;
        if consumed == name.len() && size > 0 {
            let flags = uleb(b, &mut p)?;
            if flags & 8 != 0 {
                let ordinal = uleb(b, &mut p)? as usize;
                let t = &b[p..end];
                let n = t
                    .iter()
                    .position(|v| *v == 0)
                    .ok_or("unterminated reexport")?;
                return Ok(Some(Export::Reexport(
                    ordinal,
                    String::from_utf8(t[..n].to_vec()).map_err(|e| e.to_string())?,
                )));
            }
            if flags & !4 != 0 {
                return Err("export is not direct data".into());
            }
            let v = uleb(b, &mut p)?;
            if p > end {
                return Err("truncated export".into());
            }
            return Ok(Some(Export::Address(v)));
        }
        let count = b[end];
        p = end + 1;
        let mut found = None;
        for _ in 0..count {
            let n = b[p..]
                .iter()
                .position(|v| *v == 0)
                .ok_or("unterminated export edge")?;
            let edge = &b[p..p + n];
            p += n + 1;
            let child = uleb(b, &mut p)? as usize;
            if !edge.is_empty() && name[consumed..].starts_with(edge) {
                if found.is_some() {
                    return Err("ambiguous export edge".into());
                }
                found = Some((child, consumed + edge.len()))
            }
        }
        if let Some((a, n)) = found {
            at = a;
            consumed = n
        } else {
            return Ok(None);
        }
    }
    Err("export trie cycle".into())
}
pub fn export(c: &CacheSet, path: &str, name: &str, swift: bool) -> Result<u64> {
    let kind = if swift {
        ExportKind::SwiftDescriptor
    } else {
        ExportKind::ObjcData
    };
    resolve(c, path, name, kind, &mut BTreeSet::new())?
        .ok_or_else(|| format!("unresolved export: {path}: {name}"))
}
#[derive(Clone, Copy)]
enum ExportKind {
    SwiftDescriptor,
    ObjcData,
    Code,
}

pub fn code_export(c: &CacheSet, path: &str, name: &str) -> Result<u64> {
    resolve(c, path, name, ExportKind::Code, &mut BTreeSet::new())?
        .ok_or_else(|| format!("unresolved function export: {path}: {name}"))
}

pub fn value_witness_export(c: &CacheSet, path: &str, name: &str) -> Result<u64> {
    let offset = export(c, path, name, false)?;
    let address = c.preferred_base + offset;
    let owner = c
        .images
        .iter()
        .find(|i| i.path == path)
        .ok_or("missing witness library")?;
    let metadata = image(c, owner.address)?;
    if !address.is_multiple_of(8)
        || !metadata.sections.iter().any(|s| {
            matches!(
                s.segment.as_str(),
                "__DATA_CONST" | "__AUTH_CONST" | "__TEXT"
            ) && s.name == "__const"
                && s.flags & 0x80000400 == 0
                && s.address <= address
                && address + 88 <= s.address + s.size
        })
    {
        return Err(format!(
            "value witness export escapes constant metadata: {name}"
        ));
    }
    location(c, address, 88)?;
    Ok(offset)
}
fn resolve(
    c: &CacheSet,
    path: &str,
    symbol: &str,
    kind: ExportKind,
    seen: &mut BTreeSet<(String, String)>,
) -> Result<Option<u64>> {
    if seen.len() > 256 {
        return Err("reexport graph too large".into());
    }
    if !seen.insert((path.into(), symbol.into())) {
        return Ok(None);
    }
    let header = c
        .images
        .iter()
        .find(|i| i.path == path)
        .ok_or_else(|| format!("missing cache image: {path}"))?
        .address;
    let i = image(c, header)?;
    if let Some((a, n)) = i.exports {
        if let Some(e) = lookup(&vm(c, a, n)?, symbol)? {
            match e {
                Export::Address(off) => {
                    let addr = header.checked_add(off).ok_or("export overflow")?;
                    if matches!(kind, ExportKind::SwiftDescriptor) {
                        if addr % 4 != 0
                            || !i.sections.iter().any(|s| {
                                s.segment == "__TEXT"
                                    && matches!(s.name.as_str(), "__const" | "__constg_swiftt")
                                    && s.address <= addr
                                    && addr + 16 <= s.address + s.size
                            })
                            || i.sections.iter().any(|s| {
                                s.flags & 0x80000400 != 0
                                    && s.address < addr + 16
                                    && addr < s.address + s.size
                            })
                            || location(c, addr, 16)?.1.protection & 2 != 0
                        {
                            return Err(format!(
                                "Swift descriptor export escapes immutable metadata: {symbol}"
                            ));
                        }
                    } else if matches!(kind, ExportKind::Code) {
                        if !addr.is_multiple_of(4)
                            || location(c, addr, 4)?.1.protection & 6 != 4
                            || !i.sections.iter().any(|s| {
                                s.flags & 0x80000400 != 0
                                    && s.address <= addr
                                    && addr + 4 <= s.address + s.size
                            })
                        {
                            return Err(format!(
                                "function export escapes executable code: {symbol}"
                            ));
                        }
                    } else if location(c, addr, 40)?.1.max_protection & 4 != 0 {
                        return Err("ObjC export points into code".into());
                    }
                    return Ok(Some(addr - c.preferred_base));
                }
                Export::Reexport(n, alias) => {
                    let dep = i
                        .dependencies
                        .get(n.checked_sub(1).ok_or("invalid reexport ordinal")?)
                        .ok_or("invalid reexport ordinal")?;
                    return resolve(
                        c,
                        dep,
                        if alias.is_empty() { symbol } else { &alias },
                        kind,
                        seen,
                    );
                }
            }
        }
    }
    let mut answer = None;
    for p in i.reexports {
        if let Some(v) = resolve(c, &p, symbol, kind, seen)? {
            if answer.is_some_and(|old| old != v) {
                return Err("ambiguous reexport target".into());
            }
            answer = Some(v)
        }
    }
    Ok(answer)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn export_trie_rejects_cycles_truncation_and_ambiguous_edges() {
        assert!(lookup(&[0, 1, b'a', 0, 0], "aa").is_err());
        assert!(lookup(&[2, 0], "x").is_err());
        assert!(lookup(&[0, 2, b'a', 0, 8, b'a', 0, 8, 0, 0], "a").is_err());
    }
    #[test]
    fn export_trie_distinguishes_reexport_identity() {
        let b = [0, 1, b'a', 0, 5, 4, 8, 1, 0, 0, 0];
        match lookup(&b, "a").unwrap().unwrap() {
            Export::Reexport(1, name) => assert!(name.is_empty()),
            _ => panic!("wrong export kind"),
        }
    }
}
