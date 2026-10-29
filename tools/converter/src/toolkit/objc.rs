use super::{
    cache::{name, u32le, u64le},
    hash, read, write, write_json, Result,
};
use serde_json::{json, Value};
use std::{collections::BTreeMap, fmt::Write as _, path::Path};
const PAGE: u64 = 0x4000;
fn be(b: &[u8], p: usize) -> Result<u32> {
    Ok(u32::from_be_bytes(
        b.get(p..p + 4)
            .ok_or("truncated signature")?
            .try_into()
            .unwrap(),
    ))
}
pub fn inspect(b: &[u8]) -> Result<Value> {
    let m = harmonios_runtime::macho::parse(b)?;
    if m.file_type != 6
        || m.cpu_subtype & 0xffffff != 2
        || m.platform != Some(2)
        || m.encrypted
        || m.segments.len() != 2
    {
        return Err("expected unencrypted iOS ARM64e trampoline dylib".into());
    }
    let (t, l) = (&m.segments[0], &m.segments[1]);
    if t.name != "__TEXT"
        || t.vm_address != 0
        || t.vm_size != 3 * PAGE
        || t.file_offset != 0
        || t.file_size != 3 * PAGE
        || t.protection != 5
        || l.name != "__LINKEDIT"
        || l.vm_address != 3 * PAGE
        || l.vm_size != 2 * PAGE
        || l.file_offset != 3 * PAGE
        || l.protection != 1
    {
        return Err("unsupported trampoline layout".into());
    }
    let mut p = 32;
    let end = 32 + u32le(b, 20)? as usize;
    let mut signature = None;
    let mut symbols = None;
    let mut id = None;
    let mut uuid = None;
    for _ in 0..u32le(b, 16)? {
        let cmd = u32le(b, p)?;
        let n = u32le(b, p + 4)? as usize;
        if n < 8 || p + n > end || end > b.len() {
            return Err("invalid trampoline commands".into());
        }
        match cmd {
            0x1d => signature = Some((u32le(b, p + 8)? as usize, u32le(b, p + 12)? as usize)),
            2 => {
                symbols = Some((
                    u32le(b, p + 8)? as usize,
                    u32le(b, p + 12)? as usize,
                    u32le(b, p + 16)? as usize,
                    u32le(b, p + 20)? as usize,
                ))
            }
            0xd => {
                let o = u32le(b, p + 8)? as usize;
                if o >= n {
                    return Err("invalid dylib ID".into());
                }
                id = Some(name(&b[p + o..p + n])?)
            }
            0x1b => {
                uuid = Some(
                    b.get(p + 8..p + 24)
                        .ok_or("truncated UUID")?
                        .iter()
                        .map(|v| format!("{v:02x}"))
                        .collect::<String>(),
                )
            }
            _ => (),
        }
        p += n
    }
    if p != end || id.as_deref() != Some("/usr/lib/libobjc-trampolines.dylib") {
        return Err("invalid trampoline identity".into());
    }
    let (so, n, st, ss) = symbols.ok_or("missing symbols")?;
    if n > 1024 || so + n * 16 > b.len() || st + ss > b.len() {
        return Err("invalid symbol table".into());
    }
    let mut exports = BTreeMap::new();
    for i in 0..n {
        let p = so + i * 16;
        let index = u32le(b, p)? as usize;
        if index >= ss {
            return Err("invalid symbol string".into());
        }
        if b[p + 4] & 1 != 0 && b[p + 4] & 0xe == 0xe {
            exports.insert(name(&b[st + index..st + ss])?, u64le(b, p + 8)?);
        }
    }
    let expected = BTreeMap::from([
        ("__objc_blockTrampolineImpl".into(), PAGE),
        ("__objc_blockTrampolineStart".into(), PAGE + 32),
        ("__objc_blockTrampolineLast".into(), 2 * PAGE - 8),
    ]);
    if exports != expected {
        return Err("unsupported trampoline exports".into());
    }
    let (off, len) = signature.ok_or("missing signature")?;
    if len < 12 || off + len != b.len() {
        return Err("invalid signature extent".into());
    }
    let size = be(b, off + 4)? as usize;
    let slots = be(b, off + 8)? as usize;
    if be(b, off)? != 0xfade0cc0 || size > len || slots > 64 || 12 + slots * 8 > size {
        return Err("invalid signature superblob".into());
    }
    let mut code_end = None;
    for i in 0..slots {
        let k = be(b, off + 12 + i * 8)?;
        let relative = be(b, off + 16 + i * 8)? as usize;
        if relative + 44 > size {
            continue;
        }
        let p = off + relative;
        if k == 0 && be(b, p)? == 0xfade0c02 {
            let limit = be(b, p + 32)? as usize;
            let shift = b[p + 39];
            if shift > 16 || limit != off {
                return Err("invalid signature code limit".into());
            }
            let page = 1usize << shift;
            code_end = Some((limit + page - 1) & !(page - 1))
        }
    }
    Ok(
        json!({"uuid":uuid.ok_or("missing UUID")?,"fileSize":b.len(),"textSize":3*PAGE,"span":5*PAGE,"signatureOffset":off,"signatureSize":len,"codeEnd":code_end.ok_or("missing CodeDirectory")?,"sha256":hash(b)}),
    )
}
pub fn pack(input: &Path, out: &Path, pools: usize) -> Result<Value> {
    if !(1..=64).contains(&pools) {
        return Err("invalid trampoline pool count".into());
    }
    let b = read(input)?;
    let mut meta = inspect(&b)?;
    let mut executable = b.clone();
    let strip = super::pacstrip::configured_mode()? == super::pacstrip::PacMode::Strip;
    let pac = if strip { super::pacstrip::strip_macho_code(&mut executable)? }
        else { super::pacstrip::PacReport::default() };
    let bridged = out.join("objc.bridged");
    write(&bridged, &executable)?;
    let source = bridged
        .canonicalize()
        .map_err(|e| e.to_string())?
        .to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    let mut asm = String::from("// Apple trampolines with audited offline PAC stripping.\n");
    let mut ld = String::from("SECTIONS {\n");
    let mut h=String::from("#pragma once\n#include <cstdint>\n#include <cstddef>\nextern \"C\" const uint8_t hm_objc_image[];\n");
    for (n, o, size, fs, flags) in [
        ("image_text", 0, 3 * PAGE, 3 * PAGE, "ax"),
        (
            "image_linkedit",
            3 * PAGE,
            2 * PAGE,
            b.len() as u64 - 3 * PAGE,
            "a",
        ),
    ] {
        writeln!(
            asm,
            ".section .hm_objc_{n},\"{flags}\",%progbits\n.p2align 14"
        )
        .unwrap();
        if o == 0 {
            asm.push_str(".global hm_objc_image\n.hidden hm_objc_image\nhm_objc_image:\n")
        }
        writeln!(asm, ".incbin \"{source}\", {o}, {fs}\n.zero {}", size - fs).unwrap();
        let a = if o == 0 {
            "ALIGN(0x4000)".into()
        } else {
            format!("(ADDR(.hm_objc_image_text) + {o})")
        };
        writeln!(ld, ".hm_objc_{n} {a} : {{ KEEP(*(.hm_objc_{n})) }}").unwrap()
    }
    for i in 0..pools {
        writeln!(h, "extern \"C\" uint8_t hm_objc_pool_{i}[];").unwrap();
        writeln!(asm,".section .hm_objc_pool_{i}_data,\"aw\",%progbits\n.p2align 14\n.global hm_objc_pool_{i}\n.hidden hm_objc_pool_{i}\nhm_objc_pool_{i}:\n.zero {PAGE}\n.section .hm_objc_pool_{i}_text,\"ax\",%progbits\n.p2align 14\n.incbin \"{source}\", 0, {}",3*PAGE).unwrap();
        writeln!(ld,".hm_objc_pool_{i}_data ALIGN(0x4000) : {{ KEEP(*(.hm_objc_pool_{i}_data)) }}\n.hm_objc_pool_{i}_text (ADDR(.hm_objc_pool_{i}_data) + {PAGE}) : {{ KEEP(*(.hm_objc_pool_{i}_text)) }}").unwrap()
    }
    asm.push_str(".section .note.GNU-stack,\"\",%progbits\n");
    ld.push_str("}\nINSERT AFTER .text;\n");
    for k in [
        "fileSize",
        "textSize",
        "span",
        "signatureOffset",
        "signatureSize",
        "codeEnd",
    ] {
        writeln!(
            h,
            "constexpr uint64_t HM_OBJC_{} = {}ULL;",
            k.to_uppercase(),
            meta[k]
        )
        .unwrap()
    }
    writeln!(h,"constexpr size_t HM_OBJC_POOL_COUNT = {pools};\nstatic uint8_t *const HM_OBJC_POOLS[] = {{{}}};",(0..pools).map(|i|format!("hm_objc_pool_{i}")).collect::<Vec<_>>().join(",")).unwrap();
    let original = input.canonicalize().map_err(|e| e.to_string())?
        .to_string_lossy().replace('\\', "\\\\").replace('"', "\\\"");
    writeln!(asm, ".section .rodata.hm_objc_source,\"a\",%progbits\n.global hm_objc_source\n.hidden hm_objc_source\nhm_objc_source:\n.incbin \"{original}\"").unwrap();
    h.push_str("extern \"C\" const uint8_t hm_objc_source[];\n");
    write(&out.join("objc_trampolines.S"), asm)?;
    write(&out.join("objc_trampolines.ld"), ld)?;
    write(&out.join("objc_trampolines.h"), h)?;
    meta["pools"] = json!(pools);
    meta["pacMode"] = json!(if strip { "strip" } else { "none" });
    meta["pacRewritten"] = json!(pac.rewritten);
    write_json(&out.join("manifest.json"), &meta)?;
    Ok(meta)
}
fn half(b: &[u8], p: usize) -> Result<usize> {
    Ok(u16::from_le_bytes(
        b.get(p..p + 2)
            .ok_or("truncated ELF half")?
            .try_into()
            .unwrap(),
    ) as usize)
}
pub fn verify(input: &Path, elf: &Path, pools: usize) -> Result<Value> {
    let original = read(input)?;
    let mut meta = inspect(&original)?;
    let b = read(elf)?;
    if b.get(..6) != Some(b"\x7fELF\x02\x01") {
        return Err("expected ELF64".into());
    }
    let ph = u64le(&b, 32)? as usize;
    let sh = u64le(&b, 40)? as usize;
    let (ps, pn, ss, sn, si) = (
        half(&b, 54)?,
        half(&b, 56)?,
        half(&b, 58)?,
        half(&b, 60)?,
        half(&b, 62)?,
    );
    if ps != 56 || ss != 64 || si >= sn || sh + sn * ss > b.len() || ph + pn * ps > b.len() {
        return Err("invalid ELF tables".into());
    }
    let strings = sh + si * ss;
    let no = u64le(&b, strings + 24)? as usize;
    let ns = u64le(&b, strings + 32)? as usize;
    let names = b.get(no..no + ns).ok_or("invalid ELF strings")?;
    let mut sections = BTreeMap::new();
    for i in 0..sn {
        let p = sh + i * ss;
        let n = u32le(&b, p)? as usize;
        let n = name(names.get(n..).ok_or("invalid ELF section name")?)?;
        if n.starts_with(".hm_objc_") && sections.insert(n, p).is_some() {
            return Err("duplicate ObjC section".into());
        }
    }
    let mut loads = vec![];
    for i in 0..pn {
        let p = ph + i * ps;
        if u32le(&b, p)? == 1 {
            let flags = u32le(&b, p + 4)?;
            if flags & 3 == 3 {
                return Err("writable executable ELF".into());
            }
            loads.push((
                flags,
                u64le(&b, p + 8)?,
                u64le(&b, p + 16)?,
                u64le(&b, p + 32)?,
            ))
        }
    }
    let check = |n: &str, expected: &[u8], flags: u32| -> Result<u64> {
        let p = *sections
            .get(n)
            .ok_or_else(|| format!("missing ObjC section: {n}"))?;
        let (a, o, size) = (u64le(&b, p + 16)?, u64le(&b, p + 24)?, u64le(&b, p + 32)?);
        if size != expected.len() as u64
            || b.get(o as usize..(o + size) as usize) != Some(expected)
            || !loads.iter().any(|&(f, fo, va, fs)| {
                f == flags && va <= a && a + size <= va + fs && fo + a - va == o
            })
        {
            return Err(format!("ObjC bytes/permissions differ: {n}"));
        }
        Ok(a)
    };
    let mut executable = original.clone();
    let strip = super::pacstrip::configured_mode()? == super::pacstrip::PacMode::Strip;
    if strip { super::pacstrip::strip_macho_code(&mut executable)?; }
    let text = &executable[..3 * PAGE as usize];
    let base = check(".hm_objc_image_text", text, 5)?;
    let mut link = original[3 * PAGE as usize..].to_vec();
    link.resize(2 * PAGE as usize, 0);
    if check(".hm_objc_image_linkedit", &link, 4)? != base + 3 * PAGE {
        return Err("ObjC image geometry changed".into());
    }
    for i in 0..pools {
        let datum = check(
            &format!(".hm_objc_pool_{i}_data"),
            &vec![0; PAGE as usize],
            6,
        )?;
        if check(&format!(".hm_objc_pool_{i}_text"), text, 5)? != datum + PAGE {
            return Err("ObjC clone geometry changed".into());
        }
    }
    meta["pools"] = json!(pools);
    meta["elf"] = json!(elf.canonicalize().map_err(|e| e.to_string())?);
    meta["verified"] = json!(true);
    meta["codeBytesUnchanged"] = json!(!strip);
    meta["pacMode"] = json!(if strip { "strip" } else { "none" });
    meta["codeBytesMatchAuditedTransform"] = json!(true);
    meta["noWritableExecutableLoads"] = json!(true);
    Ok(meta)
}
