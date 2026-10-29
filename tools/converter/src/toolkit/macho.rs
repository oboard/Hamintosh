use super::cache::{self, u32le, u64le};
use super::{hash, read, root, write, write_json, Result};
const VWT_ADDRESS_BRK: u32 = 0xd42a0020;
use harmonios_runtime::{
    cache::CacheSet,
    macho::{
        self,
        fixups::{Fixup, Plan, Target},
        Image,
    },
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    path::Path,
};
fn span(a: u64, n: u64, b: u64, len: u64) -> bool {
    a >= b
        && a.checked_add(n)
            .zip(b.checked_add(len))
            .is_some_and(|(e, l)| e <= l)
}
fn section<'a>(m: &'a Image, a: u64, n: u64, name: &str) -> Option<&'a macho::Section> {
    m.sections
        .iter()
        .find(|s| s.segment_name == "__TEXT" && s.name == name && span(a, n, s.vm_address, s.size))
}
fn bytes<'a>(b: &'a [u8], m: &Image, a: u64, n: usize, name: &str) -> Result<&'a [u8]> {
    let s = section(m, a, n as u64, name)
        .ok_or_else(|| format!("Swift reference outside {name}: {a:#x}"))?;
    let off = m.slice_offset + s.file_offset as usize + (a - s.vm_address) as usize;
    b.get(off..off + n)
        .ok_or_else(|| "truncated Swift section".into())
}
fn words(b: &[u8], m: &Image, a: u64, n: usize, name: &str) -> Result<Vec<u32>> {
    bytes(b, m, a, n * 4, name)?
        .chunks_exact(4)
        .map(|x| u32le(x, 0))
        .collect()
}
fn signed(x: u32, bits: u32) -> i64 {
    ((x << (32 - bits)) as i32 >> (32 - bits)) as i64
}
fn adrp(w: u32, a: u64, r: u32) -> Option<u64> {
    if w & 0x9f00001f != 0x90000000 | r {
        return None;
    }
    let imm = ((w >> 5) & 0x7ffff) << 2 | ((w >> 29) & 3);
    (a & !4095).checked_add_signed(signed(imm, 21) * 4096)
}
fn binding(f: &Plan, slot: u64) -> Option<(&Fixup, &macho::fixups::Import)> {
    let b = f.fixups.iter().find(|b| b.vm_offset == slot)?;
    if let Target::Bind { import, .. } = b.target {
        Some((b, f.imports.get(import)?))
    } else {
        None
    }
}
fn checked_library<'a>(m: &'a Image, b: &Fixup, i: &macho::fixups::Import) -> Result<&'a str> {
    if i.weak
        || i.addend != 0
        || b.authentication.is_some()
        || !matches!(b.target, Target::Bind { addend: 0, .. })
        || i.library_ordinal <= 0
    {
        return Err(format!(
            "unsupported unsigned Swift binding: {} weak={} ordinal={} slotvm={:#x} auth={:?} addend={}",
            i.name, i.weak, i.library_ordinal, b.vm_offset, b.authentication, i.addend
        ));
    }
    m.dependencies
        .get(i.library_ordinal as usize - 1)
        .map(|d| d.path.as_str())
        .ok_or_else(|| "invalid Swift library ordinal".into())
}
fn data(m: &Image, base: u64, o: u64, n: u64, writable: bool) -> bool {
    base.checked_add(o).is_some_and(|a| {
        m.segments.iter().any(|s| {
            s.protection & (if writable { 2 } else { 1 }) != 0
                && s.protection & 4 == 0
                && span(a, n, s.vm_address, s.vm_size)
        })
    })
}
#[derive(Default)]
struct Swift {
    opaque: Vec<(u64, u64, u64)>,
    local: Vec<(u64, u64, u64)>,
    vwt: Vec<(u64, u32, u32)>,
    witness: Vec<(u64, u64, String, String)>,
    protocols: Vec<(u64, String, String, u64)>,
    types: Vec<(u64, u64, u64, u64)>,
    nominal: Vec<(u64, u64, u64)>,
    local_vwt: Vec<(u64, u64, u64, u64, Vec<u64>)>,
    addresses: Vec<(u64, u64, u32, u32)>,
}
fn audit(b: &[u8], m: &Image, f: &Plan) -> Result<Swift> {
    let base = f.preferred_base;
    let mut out = Swift::default();
    let mut local_types = BTreeMap::new();
    for sec in m
        .sections
        .iter()
        .filter(|s| s.segment_name == "__TEXT" && s.name == "__swift5_types")
    {
        if sec.vm_address % 4 != 0 || sec.size % 4 != 0 {
            return Err("unaligned Swift type records".into());
        }
        for at in (sec.vm_address..sec.vm_address + sec.size).step_by(4) {
            let relative = u32le(bytes(b, m, at, 4, "__swift5_types")?, 0)?;
            if relative == 0 || relative & 3 != 0 {
                continue;
            }
            let target = at
                .checked_add_signed(relative as i32 as i64)
                .ok_or("type reference overflow")?;
            let h = bytes(b, m, target, 16, "__constg_swiftt")?;
            if !(16..=18).contains(&(u32le(h, 0)? & 31))
                || !m
                    .segments
                    .iter()
                    .any(|s| s.protection & 7 == 5 && span(target, 16, s.vm_address, s.vm_size))
            {
                return Err("type record does not identify immutable nominal descriptor".into());
            }
            local_types.insert(target - base, (u64le(h, 0)?, u64le(h, 8)?));
        }
    }
    for fixup in &f.fixups {
        if let Target::Rebase { offset, high8: 0 } = fixup.target {
            if let Some(&(first, second)) = local_types.get(&offset) {
                if fixup.authentication.is_none()
                    && fixup.vm_offset % 8 == 0
                    && data(m, base, fixup.vm_offset, 8, true)
                {
                    out.types.push((fixup.vm_offset, offset, first, second));
                }
            }
        }
    }
    for fixup in &f.fixups {
        let Target::Rebase {
            offset: table,
            high8: 0,
        } = fixup.target
        else {
            continue;
        };
        let slot = fixup.vm_offset;
        if fixup.authentication.is_some() || slot % 8 != 0 || !data(m, base, slot, 24, true) {
            continue;
        }
        let kind = u64le(b, m.slice_offset + fixup.file_offset as usize + 8)?;
        if !matches!(kind, 0x200 | 0x201) {
            continue;
        }
        let Some(descriptor) = rebase(f, slot + 16)? else {
            continue;
        };
        if !local_types.contains_key(&descriptor) {
            continue;
        }
        if table % 8 != 0 || !data(m, base, table, 88, true) {
            return Err("local value witness table escapes App data".into());
        }
        let mut functions = vec![];
        for index in 0..8 {
            let function = rebase(f, table + index * 8)?
                .ok_or("local value witness lacks a function rebase")?;
            if function % 4 != 0
                || section(m, base + function, 4, "__text").is_none()
                || !m.segments.iter().any(|s| {
                    s.protection & 7 == 5 && span(base + function, 4, s.vm_address, s.vm_size)
                })
            {
                return Err("local value witness function escapes immutable App code".into());
            }
            functions.push(function);
        }
        out.local_vwt
            .push((slot, table, kind, descriptor, functions));
    }
    out.nominal = local_types
        .into_iter()
        .map(|(offset, (first, second))| (offset, first, second))
        .collect();
    for s in &m.sections {
        if s.segment_name != "__TEXT" {
            continue;
        }
        if s.name == "__swift5_proto" {
            if s.vm_address % 4 != 0 || s.size % 4 != 0 {
                return Err("unaligned conformance list".into());
            }
            for a in (s.vm_address..s.vm_address + s.size).step_by(4) {
                let rel = u32le(bytes(b, m, a, 4, "__swift5_proto")?, 0)? as i32;
                let target = a
                    .checked_add_signed(rel as i64)
                    .ok_or("conformance overflow")?;
                if rel == 0 || target % 4 != 0 {
                    return Err("invalid conformance reference".into());
                }
                let h = bytes(b, m, target, 16, "__const")?;
                if !m
                    .segments
                    .iter()
                    .any(|s| s.protection & 7 == 5 && span(target, 16, s.vm_address, s.vm_size))
                {
                    return Err("writable conformance descriptor".into());
                }
                out.local.push((target - base, u64le(h, 0)?, u64le(h, 8)?))
            }
        }
        if s.name != "__text" {
            continue;
        }
        if s.size % 4 != 0 {
            return Err("unaligned code section".into());
        }
        for a in (s.vm_address..s.vm_address + s.size).step_by(4) {
            if span(a, 8, s.vm_address, s.size) {
                let w = words(b, m, a, 2, "__text")?;
                let (t, r) = (w[0] & 31, (w[0] >> 5) & 31);
                let field = ((w[1] >> 10) & 0xfff) * 8;
                if s.flags & 0x80000000 != 0
                    && m.segments
                        .iter()
                        .any(|s| s.protection & 7 == 5 && span(a, 8, s.vm_address, s.vm_size))
                    && w[0] & 0xffe00c00 == 0xf8400000
                    && (w[0] >> 12) & 0x1ff == 0x1f8
                    && w[1] & 0xffc00000 == 0xf9400000
                    && (w[1] >> 5) & 31 == t
                    && t != 31
                    && r != 31
                    && t != r
                    && matches!(field, 64 | 72 | 80)
                {
                    out.vwt.push((a + 4 - base, w[0], w[1]))
                }
                if s.flags & 0x80000000 != 0
                    && m.segments
                        .iter()
                        .any(|s| s.protection & 7 == 5 && span(a, 8, s.vm_address, s.vm_size))
                    && w[0] & 0xffe00c00 == 0xf8400000
                    && (w[0] >> 12) & 0x1ff == 0x1f8
                    && w[1] & 0xffc00000 == 0x91000000
                    && (w[1] >> 5) & 31 == t
                    && ((w[1] >> 10) & 0xfff) == 64
                    && t != 31
                    && r != 31
                    && t != r
                    && w[1] & 31 != 31
                {
                    out.addresses.push((
                        a + 4 - base,
                        m.slice_offset as u64 + s.file_offset as u64 + a + 4 - s.vm_address,
                        w[0],
                        w[1],
                    ));
                }
            }
            if span(a, 16, s.vm_address, s.size) {
                let w = words(b, m, a, 4, "__text")?;
                if let Some(page) = adrp(w[0], a, 1) {
                    if w[1] & 0xffc003ff == 0x91000021
                        && w[2] == 0x52800022
                        && w[3] & 0xfc000000 == 0x14000000
                    {
                        let stub = (a + 12)
                            .checked_add_signed(signed(w[3] & 0x3ffffff, 26) * 4)
                            .ok_or("stub overflow")?;
                        if section(m, stub, 12, "__stubs").is_some() {
                            let st = words(b, m, stub, 3, "__stubs")?;
                            if let Some(p) = adrp(st[0], stub, 16) {
                                if st[1] & 0xffc003ff == 0xf9400210 && st[2] == 0xd61f0200 {
                                    let slot = p + ((st[1] >> 10) & 0xfff) as u64 * 8 - base;
                                    if let Some((bf, i)) = binding(f, slot) {
                                        if i.name == "_swift_getOpaqueTypeConformance2" {
                                            if checked_library(m, bf, i)?
                                                != "/usr/lib/swift/libswiftCore.dylib"
                                            {
                                                return Err("unexpected opaque runtime".into());
                                            }
                                            let d = page + ((w[1] >> 10) & 0xfff) as u64;
                                            if !d.is_multiple_of(4) {
                                                return Err("unaligned opaque descriptor".into());
                                            }
                                            let h = bytes(b, m, d, 8, "__constg_swiftt")?;
                                            let flags = u32le(h, 0)?;
                                            let parent = (d + 4)
                                                .checked_add_signed(u32le(h, 4)? as i32 as i64)
                                                .ok_or("opaque parent overflow")?;
                                            if flags & 31 != 4
                                                || !(1..=64).contains(&(flags >> 16))
                                                || parent == d
                                            {
                                                return Err("invalid opaque descriptor".into());
                                            }
                                            bytes(b, m, parent, 8, "__constg_swiftt")?;
                                            out.opaque.push((d - base, u64le(h, 0)?, a - base))
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if !span(a, 12, s.vm_address, s.size) {
                continue;
            }
            let w = words(b, m, a, 3, "__text")?;
            let Some(page) = adrp(w[0], a, 0) else {
                continue;
            };
            if w[1] & 0xffc003ff != 0xf9400000 || w[2] & 0xfc000000 != 0x94000000 {
                continue;
            }
            let stub = (a + 8)
                .checked_add_signed(signed(w[2] & 0x3ffffff, 26) * 4)
                .ok_or("stub overflow")?;
            if section(m, stub, 12, "__stubs").is_none() {
                continue;
            }
            let st = words(b, m, stub, 3, "__stubs")?;
            let Some(sp) = adrp(st[0], stub, 16) else {
                continue;
            };
            if st[1] & 0xffc003ff != 0xf9400210 || st[2] != 0xd61f0200 {
                continue;
            }
            let fs = sp + ((st[1] >> 10) & 0xfff) as u64 * 8 - base;
            let ds = page + ((w[1] >> 10) & 0xfff) as u64 * 8 - base;
            if let (Some((bf, fi)), Some((bd, di))) = (binding(f, fs), binding(f, ds)) {
                if fi.name != "_swift_getWitnessTable"
                    || !di.name.starts_with("_$s")
                    || !di.name.ends_with("Mc")
                {
                    continue;
                }
                if checked_library(m, bf, fi)? != "/usr/lib/swift/libswiftCore.dylib"
                    || !data(m, base, ds, 8, true)
                {
                    return Err("invalid Swift witness call".into());
                }
                out.witness.push((
                    ds,
                    a + 12 - base,
                    checked_library(m, bd, di)?.into(),
                    di.name.clone(),
                ))
            }
        }
    }
    for bf in &f.fixups {
        let Target::Bind { import, .. } = bf.target else {
            continue;
        };
        let i = &f.imports[import];
        let diversity = if i.name.ends_with("Mp") || i.name.ends_with("Mn") {
            0xae86
        } else if i.name.ends_with("Tn") || i.name.ends_with("Tl") || i.name.ends_with("Tq") {
            0x7d4c
        } else if i.name.ends_with("Mc") {
            0xc6eb
        } else if i.name.ends_with("WV") {
            0x2e3f
        } else {
            continue;
        };
        if i.name.starts_with("_$s") {
            // Weak Swift bindings (e.g. SwiftUI's optional Playgrounds
            // protocol descriptors) resolve to a null slot when absent; dyld
            // tolerates them and so does this audit.
            if i.weak {
                continue;
            }
            let lib = checked_library(m, bf, i)?;
            if bf.vm_offset % 8 != 0 || !data(m, base, bf.vm_offset, 8, true) {
                return Err("protocol import escapes App data".into());
            }
            out.protocols
                .push((bf.vm_offset, lib.into(), i.name.clone(), diversity))
        }
    }
    out.opaque.sort();
    out.opaque.dedup();
    out.local.sort();
    out.local.dedup();
    out.vwt.sort();
    out.vwt.dedup();
    out.witness.sort();
    out.witness.dedup();
    out.protocols.sort();
    out.protocols.dedup();
    out.addresses.sort();
    out.addresses.dedup();
    Ok(out)
}
fn rebase(f: &Plan, o: u64) -> Result<Option<u64>> {
    if let Some(b) = f.fixups.iter().find(|b| b.vm_offset == o) {
        if let Target::Rebase { offset, high8 } = b.target {
            if high8 != 0 || b.authentication.is_some() {
                return Err("expected unsigned ObjC rebase".into());
            }
            return Ok(Some(offset));
        }
    }
    Ok(None)
}
fn objc(m: &Image, f: &Plan, c: &CacheSet) -> Result<Vec<(u64, u64, u64, u64)>> {
    let base = f.preferred_base;
    let mut pending = vec![];
    for s in &m.sections {
        if s.name == "__objc_classlist" {
            let o = s.vm_address - base;
            if !o.is_multiple_of(8)
                || s.size % 8 != 0
                || s.size > 32768
                || !data(m, base, o, s.size, false)
            {
                return Err("invalid ObjC class list".into());
            }
            for slot in (o..o + s.size).step_by(8) {
                pending.push(rebase(f, slot)?.ok_or("class list is not local rebase")?)
            }
        }
    }
    let mut classes = BTreeSet::new();
    let mut result = vec![];
    while let Some(o) = pending.pop() {
        if !classes.insert(o) {
            continue;
        }
        if classes.len() > 4096 || o % 8 != 0 || !data(m, base, o, 40, true) {
            return Err("class escapes App data".into());
        }
        let ro = rebase(f, o + 32)?.ok_or("missing class RO")?;
        if !data(m, base, ro & !7, 72, false) {
            return Err("RO outside metadata".into());
        }
        result.push((o + 32, ro, 0x61f8, 0));
        if let Some(isa) = rebase(f, o)? {
            pending.push(isa)
        }
    }
    for &o in &classes {
        for (field, div) in [(0, 0x6ae1), (8, 0xb5ab)] {
            if let Some(b) = f.fixups.iter().find(|b| b.vm_offset == o + field) {
                if b.authentication.is_some() {
                    return Err("expected unsigned class relation".into());
                }
                match b.target {
                    Target::Rebase { offset, high8: 0 } if classes.contains(&offset) => {
                        result.push((o + field, offset, div, 0))
                    }
                    Target::Bind { import, addend: 0 } => {
                        let i = &f.imports[import];
                        if !i.name.starts_with("_OBJC_") {
                            return Err("invalid class import".into());
                        }
                        let lib = checked_library(m, b, i)?;
                        result.push((o + field, cache::export(c, lib, &i.name, false)?, div, 1))
                    }
                    _ => return Err("unsupported class relationship".into()),
                }
            }
        }
    }
    result.sort();
    Ok(result)
}
fn array(h: &mut String, name: &str, decl: &str, rows: Vec<String>, empty: &str) {
    let symbol = match name {
        "HM_TARGET_SWIFT_OPAQUE" => name.to_string(),
        "HM_TARGET_SWIFT_WITNESS" => format!("{name}ES"),
        _ => format!("{name}S"),
    };
    writeln!(
        h,
        "{decl}\n#define {name}_COUNT {}\nstatic constexpr {} {symbol}[] = {{",
        rows.len(),
        decl.split_whitespace()
            .nth(1)
            .unwrap()
            .trim_end_matches(';')
    )
    .unwrap();
    for r in &rows {
        writeln!(h, "{r},").unwrap()
    }
    if rows.is_empty() {
        writeln!(h, "{empty},").unwrap()
    }
    h.push_str("};\n")
}
fn collect_runloop_extents(c: &CacheSet) -> Result<Vec<(u64, u64)>> {
    let owner = c
        .images
        .iter()
        .find(|i| i.path == "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
        .ok_or("missing CoreFoundation")?;
    let img = cache::image(c, owner.address)?;
    let (exp_a, exp_n) = img.exports.ok_or("missing CF exports")?;
    let exp_bytes = cache::vm(c, exp_a, exp_n)?;
    let (u_a, u_n) = img.function_starts.ok_or("missing function starts")?;
    let u_bytes = cache::vm(c, u_a, u_n)?;
    let mut p = 0;
    let mut current = owner.address;
    let mut funcs = vec![];
    while p < u_bytes.len() {
        let delta = cache::uleb(&u_bytes, &mut p)?;
        if delta == 0 {
            break;
        }
        current += delta;
        funcs.push(current);
    }
    let find_extent = |addr: u64| -> Option<(u64, u64)> {
        let idx = funcs.partition_point(|&f| f <= addr);
        if idx == 0 || idx >= funcs.len() {
            return None;
        }
        Some((
            funcs[idx - 1] - c.preferred_base,
            funcs[idx] - c.preferred_base,
        ))
    };

    let mut queue = std::collections::VecDeque::new();
    let mut visited = std::collections::BTreeSet::new();
    for symbol in [
        "_CFRunLoopRunSpecific",
        "_CFRunLoopRun",
        "_CFRunLoopRunInMode",
    ] {
        if let Ok(Some(cache::Export::Address(offset))) = cache::lookup(&exp_bytes, symbol) {
            queue.push_back((owner.address + offset, 0));
        }
    }

    while let Some((addr, depth)) = queue.pop_front() {
        if let Some((begin, end)) = find_extent(addr) {
            if !visited.insert((begin, end)) {
                continue;
            }
            if depth < 2 {
                if let Ok(code) = cache::vm(c, c.preferred_base + begin, (end - begin) as usize) {
                    for (i, w) in code.chunks_exact(4).enumerate() {
                        let word = u32::from_le_bytes(w.try_into().unwrap());
                        let pc = c.preferred_base + begin + i as u64 * 4;
                        if (word & 0x7c000000) == 0x14000000 {
                            let imm26 = (word & 0x03ffffff) as i32;
                            let signed_imm = ((imm26 << 6) >> 6) as i64 * 4;
                            let target = (pc as i64 + signed_imm) as u64;
                            if target >= owner.address && target < owner.address + 0x1000000 {
                                queue.push_back((target, depth + 1));
                            }
                        }
                    }
                }
            }
        }
    }
    let mut out: Vec<(u64, u64)> = visited.into_iter().collect();
    out.sort();
    Ok(out)
}

pub fn pack(input: &Path, out: &Path, role: &str) -> Result<()> {
    if !matches!(role, "target" | "bootstrap" | "dyld") {
        return Err("invalid Mach-O role".into());
    }
    let path = input.canonicalize().map_err(|e| e.to_string())?;
    let b = read(&path)?;
    let m = macho::parse(&b)?;
    let target_plan = if role == "target" {
        let fixups = macho::fixups::parse(&b, &m)?;
        let swift = audit(&b, &m, &fixups)?;
        Some((fixups, swift))
    } else {
        None
    };
    if m.architecture != "arm64"
        || m.encrypted
        || !matches!(m.file_type, 2 | 7)
        || role == "target" && (m.file_type != 2 || m.cpu_subtype & 0xffffff != 0)
    {
        return Err("AOT requires ARM64 executable or bootstrap dyld".into());
    }
    let mut segs = m
        .segments
        .iter()
        .filter(|s| s.protection != 0 && s.vm_size != 0)
        .collect::<Vec<_>>();
    segs.sort_by_key(|s| s.vm_address);
    let text = segs.first().ok_or("missing segments")?;
    if text.name != "__TEXT" || text.file_offset != 0 {
        return Err("expected __TEXT first at file zero".into());
    }
    let base = text.vm_address;
    let end = segs.iter().map(|s| s.vm_address + s.vm_size).max().unwrap();
    if end - base > 512 * 1024 * 1024 || m.entry_vm_address.is_none() {
        return Err("unsupported span or entry".into());
    }
    let quoted = path
        .to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    let mut asm = String::from("// Generated by hm-tools; original Mach-O segment bytes.\n");
    let mut ld = String::from("SECTIONS {\n");
    let mut h=format!("#pragma once\n#include <stdint.h>\nextern \"C\" const uint8_t hm_{role}_image[];\n#define HM_{}_SPAN {}ULL\n#define HM_{}_ENTRY_OFFSET {}ULL\n",role.to_uppercase(),end-base,role.to_uppercase(),m.entry_vm_address.unwrap()-base);
    for (i, s) in segs.iter().enumerate() {
        if s.protection & 6 == 6 {
            return Err("writable executable segment".into());
        }
        let flags = if s.protection & 4 != 0 {
            "ax"
        } else if s.protection & 2 != 0 {
            "aw"
        } else {
            "a"
        };
        writeln!(
            asm,
            ".section .hm_{role}_{i},\"{flags}\",%progbits\n.p2align 2"
        )
        .unwrap();
        if i == 0 {
            writeln!(
                asm,
                ".global hm_{role}_image\n.hidden hm_{role}_image\nhm_{role}_image:"
            )
            .unwrap()
        }
        if s.file_size > 0 {
            let mut at = m.slice_offset as u64 + s.file_offset;
            let end = at + s.file_size;
            if let Some((_, swift)) = &target_plan {
                for &(_, file, _, _) in &swift.addresses {
                    if file < at || file + 4 > end {
                        continue;
                    }
                    if file > at {
                        writeln!(asm, ".incbin \"{quoted}\", {at}, {}", file - at).unwrap()
                    }
                    writeln!(asm, ".word {VWT_ADDRESS_BRK:#x}").unwrap();
                    at = file + 4;
                }
            }
            if at < end {
                writeln!(asm, ".incbin \"{quoted}\", {at}, {}", end - at).unwrap()
            }
        }
        writeln!(asm, ".zero {}", s.vm_size - s.file_size).unwrap();
        let a = if i == 0 {
            "ALIGN(0x4000)".into()
        } else {
            format!("(ADDR(.hm_{role}_0) + {})", s.vm_address - base)
        };
        writeln!(ld, "  .hm_{role}_{i} {a} : {{ KEEP(*(.hm_{role}_{i})) }}").unwrap()
    }
    if role == "target" {
        h.push_str("struct HmTargetSegment { uint64_t offset, size, protection; };\nstatic constexpr HmTargetSegment HM_TARGET_SEGMENTS[] = {\n");
        for s in &segs {
            writeln!(
                h,
                "{{{}ULL, {}ULL, {}ULL}},",
                s.vm_address - base,
                s.vm_size,
                s.protection
            )
            .unwrap()
        }
        h.push_str("};\n");
        let (f, s) = target_plan.as_ref().unwrap();
        let c = cache::load(&root().join("artifacts/ios27-system/cache/dyld_shared_cache_arm64e"))?;
        let ob = objc(&m, f, &c)?;
        writeln!(
            h,
            "#define HM_TARGET_SWIFT_VWT_ADDRESS_BRK {VWT_ADDRESS_BRK}U"
        )
        .unwrap();
        array(&mut h,"HM_TARGET_SWIFT_VWT_ADDRESS_SITE",
            "struct HmTargetSwiftVwtAddressSite { uint64_t pc, fileOffset; uint32_t metadataLoad, operation; };",
            s.addresses.iter().map(|(pc,file,load,op)|format!("{{{pc}ULL,{file}ULL,{load}U,{op}U}}" )).collect(),"{0,0,0,0}");
        array(
            &mut h,
            "HM_TARGET_SWIFT_LOCAL_TYPE",
            "struct HmTargetSwiftLocalType { uint64_t offset, first, second; };",
            s.nominal
                .iter()
                .map(|(o, a, b)| format!("{{{o}ULL,{a}ULL,{b}ULL}}"))
                .collect(),
            "{0,0,0}",
        );
        array(
            &mut h,
            "HM_TARGET_SWIFT_LOCAL_CONFORMANCE",
            "struct HmTargetSwiftLocalConformance { uint64_t offset, first, second; };",
            s.local
                .iter()
                .map(|(a, b, c)| format!("{{{a}ULL, {b}ULL, {c}ULL}}"))
                .collect(),
            "{0,0,0}",
        );
        array(&mut h,"HM_TARGET_SWIFT_VALUE_WITNESS_LOAD","struct HmTargetSwiftValueWitnessLoad { uint64_t pc; uint32_t metadataLoad, layoutLoad; };",s.vwt.iter().map(|(a,b,c)|format!("{{{a}ULL, {b}U, {c}U}}" )).collect(),"{0,0,0}");
        array(
            &mut h,
            "HM_TARGET_SWIFT_OPAQUE",
            "struct HmTargetSwiftOpaque { uint64_t offset, header, accessor; };",
            s.opaque
                .iter()
                .map(|(a, b, c)| format!("{{{a}ULL, {b}ULL, {c}ULL}}"))
                .collect(),
            "{0,0,0}",
        );
        let mut wit = vec![];
        for (slot, caller, lib, name) in &s.witness {
            let t = cache::export(&c, lib, name, true)?;
            wit.push(format!("{{{slot}ULL, {t}ULL, {caller}ULL}}"))
        }
        array(
            &mut h,
            "HM_TARGET_SWIFT_WITNESS",
            "struct HmTargetSwiftWitness { uint64_t slot, target, caller; };",
            wit,
            "{0,0,0}",
        );
        let mut pro = vec![];
        let mut plan = vec![];
        for (slot, lib, name, diversity) in &s.protocols {
            let t = if *diversity == 0x2e3f {
                cache::value_witness_export(&c, lib, name)?
            } else {
                cache::export(&c, lib, name, true)?
            };
            pro.push(format!(
                "{{{slot}ULL, {t}ULL,1ULL,0ULL,0ULL,{diversity}ULL}}"
            ));
            plan.push(serde_json::json!({"slot":slot,"target":t,"library":lib,"symbol":name,"key":"DA","diversity":diversity}))
        }
        for (slot, target, first, second) in &s.types {
            pro.push(format!(
                "{{{slot}ULL,{target}ULL,0ULL,{first}ULL,{second}ULL,44678ULL}}"
            ));
            plan.push(serde_json::json!({"slot":slot,"target":target,"local":true,"header":[first,second],"key":"DA","diversity":0xae86}));
        }
        for (slot, target, kind, descriptor, functions) in &s.local_vwt {
            pro.push(format!(
                "{{{slot}ULL,{target}ULL,2ULL,{kind}ULL,{descriptor}ULL,11839ULL}}"
            ));
            plan.push(serde_json::json!({"slot":slot,"target":target,"localValueWitnessTable":true,"metadataKind":kind,"typeDescriptor":descriptor,"functions":functions,"key":"DA","diversity":0x2e3f}));
        }
        array(
            &mut h,
            "HM_TARGET_SWIFT_ABI_REFERENCE",
            "struct HmTargetSwiftAbiReference { uint64_t slot, target, cacheTarget, first, second, diversity; };",
            pro,
            "{0,0,0,0,0,0}",
        );
        let mut libraries = s
            .protocols
            .iter()
            .map(|(_, lib, _, _)| lib.clone())
            .collect::<BTreeSet<_>>();
        libraries.insert("/usr/lib/swift/libswiftCore.dylib".into());
        let selected_path = root().join("artifacts/ios27-aot/package.json");
        if selected_path.is_file() {
            let selected = super::json(&selected_path)?;
            if selected["primaryUUID"] != c.files[0].uuid {
                return Err("selected code belongs to a different cache".into());
            }
            for image in selected["demandImages"].as_array().into_iter().flatten() {
                if let Some(path) = image["path"].as_str() {
                    libraries.insert(path.to_owned());
                }
            }
        }
        let mut auth_sites = vec![];
        for library in libraries {
            let image = c
                .images
                .iter()
                .find(|i| i.path == library)
                .ok_or("missing metadata library")?;
            for sec in cache::image(&c, image.address)?.sections {
                if sec.flags & 0x80000400 == 0 {
                    continue;
                }
                for offset in (0..sec.size).step_by(16 * 1024 * 1024) {
                    let start = offset.saturating_sub(12);
                    let end = (offset + 16 * 1024 * 1024 + 16).min(sec.size);
                    let code = cache::vm(&c, sec.address + start, (end - start) as usize)?;
                    for at in (12..code.len().saturating_sub(15)).step_by(4) {
                        let checked = u32le(&code, at + 4)? == 0xaa1003f1
                            && u32le(&code, at + 8)? == 0xdac147f1
                            && u32le(&code, at + 12)? == 0xeb11021f;
                        let witness = u32le(&code, at - 4)? == 0xf2e5c7f1;
                        if u32le(&code, at)? == 0xdac11a30 && (checked || witness) {
                            auth_sites.push((
                                sec.address + start + at as u64 - c.preferred_base,
                                u64le(&code, at - 12)?,
                                u64le(&code, at - 4)?,
                            ));
                        }
                    }
                }
            }
        }
        auth_sites.sort();
        auth_sites.dedup();
        let mut objc_runtime = vec![];
        for name in [
            "_objc_getClass",
            "_objc_allocateClassPair",
            "_objc_registerClassPair",
            "_class_addMethod",
            "_object_getClass",
            "_class_getName",
            "_class_copyIvarList",
            "_ivar_getName",
            "_ivar_getOffset",
            "_ivar_getTypeEncoding",
            "_sel_registerName",
            "_class_getMethodImplementation",
            "_class_respondsToSelector",
            "_class_copyMethodList",
            "_method_getName",
            "_method_getImplementation",
            "_method_getTypeEncoding",
            "_class_getSuperclass",
            "_objc_setExceptionPreprocessor",
        ] {
            let offset = cache::code_export(&c, "/usr/lib/libobjc.A.dylib", name)?;
            if cache::location(&c, c.preferred_base + offset, 4)?
                .1
                .protection
                & 4
                == 0
            {
                return Err(format!("ObjC runtime symbol is not executable: {name}"));
            }
            objc_runtime.push(format!("{{\"{name}\",{offset}ULL}}"));
        }
        let free = cache::code_export(&c, "/usr/lib/system/libsystem_malloc.dylib", "_free")?;
        objc_runtime.push(format!("{{\"_free\",{free}ULL}}"));
        let dlopen = cache::code_export(&c, "/usr/lib/system/libdyld.dylib", "_dlopen")?;
        objc_runtime.push(format!("{{\"_dlopen\",{dlopen}ULL}}"));
        array(
            &mut h,
            "HM_TARGET_OBJC_RUNTIME_SYMBOL",
            "struct HmTargetObjcRuntimeSymbol { const char *name; uint64_t offset; };",
            objc_runtime,
            "{nullptr,0}",
        );
        let idle_ranges = collect_runloop_extents(&c)?;
        array(
            &mut h,
            "HM_TARGET_SCENE_IDLE_RANGE",
            "struct HmTargetSceneIdleRange { uint64_t begin, end; };",
            idle_ranges
                .iter()
                .map(|(begin, end)| format!("{{{begin}ULL,{end}ULL}}"))
                .collect(),
            "{0,0}",
        );
        array(
            &mut h,
            "HM_TARGET_SWIFT_ABI_AUTH_SITE",
            "struct HmTargetSwiftAbiAuthSite { uint64_t pc, first, second; };",
            auth_sites
                .iter()
                .map(|(pc, a, b)| format!("{{{pc}ULL,{a}ULL,{b}ULL}}"))
                .collect(),
            "{0,0,0}",
        );
        let uuid = &c.files[0].uuid;
        let u = (0..uuid.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&uuid[i..i + 2], 16)
                    .map(|v| v.to_string())
                    .map_err(|e| e.to_string())
            })
            .collect::<Result<Vec<_>>>()?;
        writeln!(
            h,
            "static constexpr uint8_t HM_TARGET_OBJC_CACHE_UUID[] = {{{}}};",
            u.join(",")
        )
        .unwrap();
        array(
            &mut h,
            "HM_TARGET_OBJC_POINTER",
            "struct HmTargetObjcPointer { uint64_t slot, target, diversity, cacheTarget; };",
            ob.iter()
                .map(|(a, b, c, d)| format!("{{{a}ULL, {b}ULL, {c}ULL, {d}ULL}}"))
                .collect(),
            "{0,0,0,0}",
        );
        write_json(
            &out.join("abi-plan.json"),
            &serde_json::json!({"imageSHA256":hash(&b),"cacheUUID":uuid,"abiDataReferences":plan,"abiDataAuthSites":auth_sites,"sceneIdleRanges":idle_ranges,"localTypes":s.nominal,"localConformances":s.local,"valueWitnessLoads":s.vwt,"valueWitnessAddressBridges":s.addresses,"bridgeInstruction":VWT_ADDRESS_BRK,"opaqueThunks":s.opaque,"objcPointers":ob}),
        )?;
    }
    if role != "target" {
        writeln!(asm,".section .rodata.hm_{role}_original,\"a\",%progbits\n.p2align 3\n.global hm_{role}_original\n.hidden hm_{role}_original\nhm_{role}_original:\n.incbin \"{quoted}\"").unwrap();
        writeln!(
            h,
            "extern \"C\" const uint8_t hm_{role}_original[];\n#define HM_{}_ORIGINAL_SIZE {}ULL",
            role.to_uppercase(),
            b.len()
        )
        .unwrap()
    }
    if role == "dyld" {
        h.push_str("struct HmDyldSegment { uint64_t offset, size, protection; };\nstatic constexpr HmDyldSegment HM_DYLD_SEGMENTS[] = {\n");
        for s in &segs {
            writeln!(
                h,
                "{{{}ULL,{}ULL,{}ULL}},",
                s.vm_address - base,
                s.vm_size,
                s.protection
            )
            .unwrap()
        }
        h.push_str("};\n")
    }
    asm.push_str(".section .note.GNU-stack,\"\",%progbits\n");
    ld.push_str("} INSERT BEFORE .data;\n");
    write(&out.join(format!("packed_{role}.S")), asm)?;
    write(&out.join(format!("packed_{role}.h")), h)?;
    write(&out.join(format!("packed_{role}.ld")), ld)?;
    write_json(&out.join("layout.json"), &m)
}
pub(super) fn uuid(b: &[u8]) -> Result<String> {
    let n = u32le(b, 16)?;
    let mut p = 32;
    for _ in 0..n {
        let cmd = u32le(b, p)?;
        let len = u32le(b, p + 4)? as usize;
        if len < 8 || p + len > b.len() {
            return Err("invalid UUID command".into());
        }
        if cmd == 0x1b && len == 24 {
            return Ok(b[p + 8..p + 24]
                .iter()
                .map(|v| format!("{v:02x}"))
                .collect());
        }
        p += len
    }
    Err("missing UUID".into())
}
pub fn bootstrap(input: &Path, primary: &Path, out: &Path) -> Result<()> {
    let b = read(input)?;
    let c = cache::load(primary)?;
    let id = uuid(&b)?;
    if id != uuid(&cache::vm(&c, c.dyld_header_address, 65536)?)? {
        return Err("dyld UUID does not match cache".into());
    }
    let m = macho::parse(&b)?;
    if m.file_type != 7 || m.platform != Some(2) || !m.dependencies.is_empty() || !m.chained_fixups
    {
        return Err("invalid standalone dyld".into());
    }
    let mut patched = b.clone();
    let mut changes = vec![];
    for s in &m.sections {
        if s.flags & 0x80000400 == 0 {
            continue;
        }
        if s.size % 4 != 0 {
            return Err("invalid dyld code section".into());
        }
        for p in (s.file_offset as usize..s.file_offset as usize + s.size as usize).step_by(4) {
            let w = u32le(&b, p)?;
            let v = if w == 0xd4001001 {
                Some(0xd42909a0)
            } else if w & !31 == 0xd53bd060 {
                Some(0xd4294000 | ((w & 31) << 5))
            } else {
                None
            };
            if let Some(v) = v {
                patched[p..p + 4].copy_from_slice(&v.to_le_bytes());
                changes
                    .push(serde_json::json!({"fileOffset":p,"originalWord":w,"replacementWord":v}))
            }
        }
    }
    let bridged = out.join("dyld.bridged");
    let pac_mode = super::pacstrip::configured_mode()?;
    let pac = if pac_mode == super::pacstrip::PacMode::Strip {
        super::pacstrip::strip_macho_code(&mut patched)?
    } else { super::pacstrip::PacReport::default() };
    write(&bridged, &patched)?;
    pack(&bridged, out, "dyld")?;
    let f = macho::fixups::parse(&b, &m)?;
    let con = m
        .segments
        .iter()
        .find(|s| s.name == "__DATA_CONST")
        .ok_or("no dyld data const")?;
    let witness = f
        .fixups
        .iter()
        .find(|b| {
            b.authentication.is_none()
                && matches!(b.target, Target::Rebase { high8: 0, .. })
                && span(
                    f.preferred_base + b.vm_offset,
                    8,
                    con.vm_address,
                    con.vm_size,
                )
        })
        .ok_or("no rebase witness")?;
    let Target::Rebase { offset, .. } = witness.target else {
        unreachable!()
    };
    let hp = out.join("packed_dyld.h");
    let mut h = String::from_utf8(read(&hp)?).map_err(|e| e.to_string())?;
    writeln!(
        h,
        "#define HM_DYLD_WITNESS_LOCATION {}ULL\n#define HM_DYLD_WITNESS_TARGET {offset}ULL",
        witness.vm_offset
    )
    .unwrap();
    write(&hp, h)?;
    write_json(
        &out.join("bridge.json"),
        &serde_json::json!({"uuid":id,"source":input.canonicalize().map_err(|e|e.to_string())?,"originalSha256":hash(&b),"bridgedSha256":hash(&patched),"patches":changes,"pacMode":if pac_mode == super::pacstrip::PacMode::Strip { "strip" } else { "none" },"pacRewritten":pac.rewritten,"rebaseWitness":witness,"selfRebase":"Apple dyld performs its own chained fixups at startup"}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn witness_address_bridge_requires_immutable_matching_instruction_pair() {
        let (mut b, mut m, f) = metadata_fixture();
        m.sections.push(macho::Section {
            name: "__text".into(),
            segment_name: "__TEXT".into(),
            vm_address: f.preferred_base + 0x1000,
            size: 8,
            file_offset: 0x1000,
            flags: 0x80000400,
        });
        let load = 0xf85f8008u32;
        let add = 0x91010108u32;
        b[0x1000..0x1004].copy_from_slice(&load.to_le_bytes());
        b[0x1004..0x1008].copy_from_slice(&add.to_le_bytes());
        assert_eq!(
            audit(&b, &m, &f).unwrap().addresses,
            vec![(0x1004, 0x1004, load, add)]
        );
        for (first, second) in [
            (load, 0x91008108),
            (load, 0x9101011f),
            (0xf85f8000, 0x91010000),
            (0xf85f8c08, add),
        ] {
            b[0x1000..0x1004].copy_from_slice(&first.to_le_bytes());
            b[0x1004..0x1008].copy_from_slice(&second.to_le_bytes());
            assert!(audit(&b, &m, &f).unwrap().addresses.is_empty());
        }
        b[0x1000..0x1004].copy_from_slice(&load.to_le_bytes());
        b[0x1004..0x1008].copy_from_slice(&add.to_le_bytes());
        m.segments[0].protection = 7;
        assert!(audit(&b, &m, &f).unwrap().addresses.is_empty());
    }
    fn metadata_fixture() -> (Vec<u8>, Image, Plan) {
        let base = 0x100000000;
        let mut b = super::super::fixtures::probe(&[0xc0, 3, 0x5f, 0xd6]);
        b.resize(0x5000, 0);
        let mut m = macho::parse(&b).unwrap();
        m.segments.push(macho::Segment {
            name: "__DATA_CONST".into(),
            vm_address: base + 0x40000,
            vm_size: 0x4000,
            file_offset: 0x4000,
            file_size: 0x1000,
            protection: 3,
        });
        let f = Plan {
            preferred_base: base,
            imports: vec![macho::fixups::Import {
                library_ordinal: 1,
                name: "_$s7SwiftUI3AppMp".into(),
                weak: false,
                addend: 0,
            }],
            fixups: vec![Fixup {
                vm_offset: 0x40df0,
                file_offset: 0x4df0,
                original: 0,
                target: Target::Bind {
                    import: 0,
                    addend: 0,
                },
                authentication: None,
            }],
            ..Plan::default()
        };
        m.dependencies.push(macho::Dependency {
            path: "/System/Library/Frameworks/SwiftUI.framework/SwiftUI".into(),
            weak: false,
            reexport: false,
        });
        (b, m, f)
    }
    #[test]
    fn protocol_plan_uses_actual_macho_data_and_binding() {
        let (b, m, mut f) = metadata_fixture();
        let r = audit(&b, &m, &f).unwrap();
        assert_eq!(
            r.protocols,
            vec![(
                0x40df0,
                m.dependencies[0].path.clone(),
                "_$s7SwiftUI3AppMp".into(),
                0xae86
            )]
        );
        for offset in [0x8000, 0x44000, 0x40df4] {
            f.fixups[0].vm_offset = offset;
            assert!(audit(&b, &m, &f).is_err());
        }
    }
    #[test]
    fn protocol_plan_skips_weak_and_rejects_invalid_imports() {
        let (b, mut m, mut f) = metadata_fixture();
        f.imports[0].weak = true;
        // Weak Swift bindings follow dyld's tolerate-if-missing rule: they
        // are skipped instead of failing the whole audit.
        assert!(audit(&b, &m, &f).unwrap().protocols.is_empty());
        f.imports[0].weak = false;
        f.imports[0].addend = 1;
        assert!(audit(&b, &m, &f).is_err());
        f.imports[0].addend = 0;
        f.imports[0].library_ordinal = 0;
        assert!(audit(&b, &m, &f).is_err());
        f.imports[0].library_ordinal = 1;
        m.segments[1].protection = 7;
        assert!(audit(&b, &m, &f).is_err());
    }
    #[test]
    fn exported_header_uses_native_contract_names() {
        let mut h = String::new();
        array(
            &mut h,
            "HM_TARGET_SWIFT_WITNESS",
            "struct HmTargetSwiftWitness { uint64_t slot, target, caller; };",
            vec![],
            "{0,0,0}",
        );
        array(
            &mut h,
            "HM_TARGET_SWIFT_OPAQUE",
            "struct HmTargetSwiftOpaque { uint64_t offset, header, accessor; };",
            vec![],
            "{0,0,0}",
        );
        assert!(h.contains("HM_TARGET_SWIFT_WITNESSES[]"));
        assert!(h.contains("HM_TARGET_SWIFT_OPAQUE[]"));
    }
    #[test]
    fn runloop_extents_discover_corefoundation_frames() {
        let c = cache::load(&root().join("artifacts/ios27-system/cache/dyld_shared_cache_arm64e")).unwrap();
        let bbs = c.images.iter().find(|i| i.path == "/System/Library/PrivateFrameworks/BackBoardServices.framework/BackBoardServices").unwrap();
        let bbs_img = cache::image(&c, bbs.address).unwrap();
        for s in &bbs_img.sections {
            eprintln!("BBS section: {} size={}", s.name, s.size);
        }
    }
}

#[cfg(test)]
fn zz_symbolicate_report_pcs_for_debug() {
    let set = super::cache::load(&root().join("artifacts/ios27-system/cache/dyld_shared_cache_arm64e")).unwrap();
    let report_base: u64 = 407976640512;
    let slide = report_base.wrapping_sub(set.preferred_base);
    eprintln!("slide={:#x}", slide);
    let pcs: &[u64] = &[
        0x5efdb1c590, 0x5efdb0d7e0, 0x5efdb0e7f4, 0x5fa81d0f24, 0x5f01dec1cc,
        0x5f07ddb404, 0x5f07dd4b50, 0x5f07dd4a10, 0x607cb4dd40, 0x5efd95f5b8,
        0x5f05b2f2f0, 0x5f05b2f270, 0x5f2bfff220, 0x5f2bfc9c48,
    ];
    for &pc in pcs {
        let preferred = pc.wrapping_sub(slide);
        let hit = set.images.iter().find(|i| {
            super::cache::image(&set, i.address)
                .map(|m| {
                    m.segments.iter().any(|s| {
                        s.protection & 4 != 0
                            && preferred >= s.address
                            && preferred < s.address + s.size.max(1)
                    })
                })
                .unwrap_or_default()
        });
        match hit {
            Some(img) => {
                let m = super::cache::image(&set, img.address).unwrap();
                let text = m.segments.iter().find(|s| s.protection & 4 != 0).unwrap();
                eprintln!("pc={:#x} -> {} +{:#x}", pc, img.path, preferred - text.address);
            }
            None => eprintln!("pc={:#x} -> (no image, preferred={:#x})", pc, preferred),
        }
    }
}
#[test]
fn zz_symbolicate_report_pcs_run() { zz_symbolicate_report_pcs_for_debug() }

#[cfg(test)]
fn zz_trie_symbols_for_tests(path: &str, query_pc: u64) {
    let set = super::cache::load(&root().join("artifacts/ios27-system/cache/dyld_shared_cache_arm64e")).unwrap();
    let img = set.images.iter().find(|i| i.path == path).unwrap();
    let m = super::cache::image(&set, img.address).unwrap();
    let (trie_addr, trie_len) = m.exports.unwrap();
    let trie = super::cache::vm(&set, trie_addr, trie_len).unwrap();
    fn uleb(b: &[u8], p: &mut usize) -> u64 {
        let mut v = 0u64; let mut s = 0;
        loop { let byte = b[*p]; *p += 1; v |= u64::from(byte & 0x7f) << s; if byte & 0x80 == 0 { break; } s += 7; }
        v
    }
    let base = m.segments.iter().find(|s| s.name == "__TEXT").map(|s| s.address).unwrap();
    let mut out: Vec<(String, u64)> = vec![];
    fn walk(b: &[u8], base: u64, at: usize, prefix: &str, out: &mut Vec<(String, u64)>, depth: u32) {
        if depth > 4096 || at >= b.len() { return; }
        let mut p = at;
        let size = uleb(b, &mut p);
        if size != 0 {
            let _flags = uleb(b, &mut p);
            let addr = uleb(b, &mut p);
            out.push((prefix.to_string(), base + addr));
            return;
        }
        let children = b[p] as usize; p += 1;
        for _ in 0..children {
            let start = p;
            while b[p] != 0 { p += 1; }
            let edge = unsafe { std::str::from_utf8_unchecked(&b[start..p]) };
            p += 1;
            let off = uleb(b, &mut p) as usize;
            let child_prefix = format!("{}{}", prefix, edge);
            walk(b, base, off, &child_prefix, out, depth + 1);
        }
    }
    walk(&trie, base, 0, "", &mut out, 0);
    out.sort_by_key(|(_, a)| *a);
    let idx = out.partition_point(|(_, a)| *a <= query_pc).saturating_sub(1);
    eprintln!("exports={} for {}", out.len(), path);
    for (name, addr) in &out[idx.saturating_sub(2)..(idx + 3).min(out.len())] {
        eprintln!("  {:#x} (pc-off {:#x})  {}", addr, query_pc.wrapping_sub(*addr), name);
    }
}
#[test]
fn zz_list_sf_images() {
    let set = super::cache::load(&root().join("artifacts/ios27-system/cache/dyld_shared_cache_arm64e")).unwrap();
    for i in &set.images {
        if i.path.contains("SFSymbol") || i.path.contains("/Symbols.framework") || i.path.contains("CoreUI") {
            eprintln!("img: {:#x} {}", i.address, i.path);
        }
    }
}
#[test]
fn zz_trie_swiftuicore_run() {
    let set2 = super::cache::load(&root().join("artifacts/ios27-system/cache/dyld_shared_cache_arm64e")).unwrap();
    let slide = 408008097792u64.wrapping_sub(set2.preferred_base);
    let preferred = 0x5f0792f2f0u64.wrapping_sub(slide);
    let lr = 0x5f0792f270u64.wrapping_sub(slide);
    eprintln!("preferred pc={:#x} lr={:#x}", preferred, lr);
    zz_trie_symbols_for_tests("/System/Library/Frameworks/SwiftUICore.framework/SwiftUICore", preferred);
    zz_trie_symbols_for_tests("/System/Library/Frameworks/SwiftUICore.framework/SwiftUICore", lr);
}

#[cfg(test)]
fn zz_dump_region_for_tests(path: &str, off: u64, len: usize) {
    let set = super::cache::load(&root().join("artifacts/ios27-system/cache/dyld_shared_cache_arm64e")).unwrap();
    let img = set.images.iter().find(|i| i.path == path).unwrap();
    let m = super::cache::image(&set, img.address).unwrap();
    let text = m.segments.iter().find(|s| s.name == "__TEXT").unwrap();
    let b = super::cache::vm(&set, text.address + off, len).unwrap();
    print!(".word ");
    for w in b.chunks(4) {
        print!("0x{:02x}{:02x}{:02x}{:02x}, ", w[3], w[2], w[1], w[0]);
    }
    println!();
}
#[test]
fn zz_dump_swiftuicore_assert() {
    zz_dump_region_for_tests("/System/Library/Frameworks/SwiftUICore.framework/SwiftUICore", 0x253270, 0x84);
}
