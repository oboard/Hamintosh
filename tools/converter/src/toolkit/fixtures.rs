use super::{hash, read, root, run, write, write_json, Result};
use std::{collections::BTreeSet, fmt::Write as _, io::Read, path::Path, process::Command};
const CODE: &[u8] = &[0x40, 5, 0x80, 0x52, 0xc0, 3, 0x5f, 0xd6];
fn u32s(v: &[u32]) -> Vec<u8> {
    v.iter().flat_map(|v| v.to_le_bytes()).collect()
}
fn segment(name: &str, vo: u64, fo: u64, size: u64, prot: u32) -> Vec<u8> {
    let mut b = u32s(&[25, 72]);
    let mut n = [0; 16];
    n[..name.len()].copy_from_slice(name.as_bytes());
    b.extend(n);
    for v in [0x100000000 + vo, 0x4000, fo, size] {
        b.extend(v.to_le_bytes())
    }
    b.extend(u32s(&[prot, prot, 0, 0]));
    b
}
pub fn probe(code: &[u8]) -> Vec<u8> {
    let mut b = u32s(&[0xfeedfacf, 0x100000c, 0, 2, 2, 96, 0, 0]);
    b.extend(segment("__TEXT", 0, 0, 0x1000 + code.len() as u64, 5));
    b.extend(u32s(&[0x80000028, 24]));
    b.extend(0x1000u64.to_le_bytes());
    b.extend(0u64.to_le_bytes());
    b.resize(0x1000, 0);
    b.extend(code);
    b
}
pub fn prepare_ipa(ipa: Option<&Path>) -> Result<()> {
    let raw = root().join("harmonios/src/main/resources/rawfile");
    write(&raw.join("probes/execution_probe.bin"), CODE)?;
    write(&raw.join("probes/return42.macho"), probe(CODE))?;
    write(&root().join("tests/fixtures/return42.macho"), probe(CODE))?;
    let Some(ipa) = ipa else { return Ok(()) };
    let file = std::fs::File::open(ipa).map_err(|e| e.to_string())?;
    let mut z = zip::ZipArchive::new(file).map_err(|e| e.to_string())?;
    let mut names = BTreeSet::new();
    let mut total = 0u64;
    let mut info = None;
    for i in 0..z.len() {
        let m = z.by_index(i).map_err(|e| e.to_string())?;
        let n = m.name();
        if !names.insert(n.to_owned())
            || m.enclosed_name().is_none()
            || n.contains('\\')
            || m.unix_mode().is_some_and(|v| v & 0o170000 == 0o120000)
        {
            return Err(format!("unsafe/duplicate IPA member: {n}"));
        }
        total = total.checked_add(m.size()).ok_or("IPA size overflow")?;
        if total > 512 * 1024 * 1024 {
            return Err("IPA exceeds staging limit".into());
        }
        if n.starts_with("Payload/")
            && n.ends_with(".app/Info.plist")
            && n.matches('/').count() == 2
        {
            if info.is_some() {
                return Err("multiple top-level apps".into());
            }
            info = Some(n.to_owned())
        }
    }
    let info = info.ok_or("missing top-level App Info.plist")?;
    let mut data = vec![];
    z.by_name(&info)
        .map_err(|e| e.to_string())?
        .read_to_end(&mut data)
        .map_err(|e| e.to_string())?;
    let p = plist::Value::from_reader(std::io::Cursor::new(data)).map_err(|e| e.to_string())?;
    let dict = p.as_dictionary().ok_or("Info.plist is not dictionary")?;
    let get = |k: &str| dict.get(k).and_then(plist::Value::as_string);
    let exe = get("CFBundleExecutable").ok_or("missing executable")?;
    if exe.is_empty()
        || Path::new(exe).components().count() != 1
        || exe.contains(['/', '\\'])
        || matches!(exe, "." | "..")
    {
        return Err("invalid executable name".into());
    }
    let bundle = info.strip_suffix("/Info.plist").unwrap();
    let dir = Path::new(bundle).file_name().ok_or("invalid bundle")?;
    let imported = root().join("artifacts/imported").join(dir);
    let target = raw.join("target");
    let staged = target.join("bundle");
    for d in [&imported, &staged] {
        if d.exists() {
            std::fs::remove_dir_all(d).map_err(|e| e.to_string())?
        }
    }
    let prefix = format!("{bundle}/");
    let mut files = vec![];
    for i in 0..z.len() {
        let mut m = z.by_index(i).map_err(|e| e.to_string())?;
        if m.is_dir() {
            continue;
        }
        let Some(rel) = m.name().strip_prefix(&prefix) else {
            continue;
        };
        let rel = rel.to_owned();
        let mut b = vec![];
        m.read_to_end(&mut b).map_err(|e| e.to_string())?;
        write(&imported.join(&rel), &b)?;
        write(&staged.join(&rel), &b)?;
        files.push(rel)
    }
    files.sort();
    let binary = read(&imported.join(exe))?;
    write(&target.join("executable"), &binary)?;
    let manifest = serde_json::json!({"name":get("CFBundleDisplayName").or_else(||get("CFBundleName")).unwrap_or(exe),"bundleId":get("CFBundleIdentifier").ok_or("missing bundle ID")?,"executable":exe,"version":get("CFBundleShortVersionString").unwrap_or("unknown"),"minimumOS":get("MinimumOSVersion").unwrap_or("unknown"),"sdk":get("DTSDKName").unwrap_or("unknown"),"sha256":hash(&binary),"sourceIPA":ipa.canonicalize().map_err(|e|e.to_string())?,"bundleDirectory":dir.to_string_lossy(),"bundleFiles":files});
    write_json(&target.join("manifest.json"), &manifest)?;
    println!("{}", serde_json::to_string_pretty(&manifest).unwrap());
    Ok(())
}
pub fn pack_probe(input: &Path, out: &Path) -> Result<()> {
    let p = input.canonicalize().map_err(|e| e.to_string())?;
    if read(&p)? != probe(CODE) {
        return Err("only audited return-42 fixture is allowed".into());
    }
    let p = p
        .to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    write(out,format!("// Generated by hm-tools. Original Mach-O bytes.\n.section .text.hm_guest,\"ax\",%progbits\n.p2align 14\n.global hm_packaged_probe_image\n.hidden hm_packaged_probe_image\n.type hm_packaged_probe_image,%object\nhm_packaged_probe_image:\n.incbin \"{p}\"\n.size hm_packaged_probe_image, .-hm_packaged_probe_image\n.section .note.GNU-stack,\"\",%progbits\n"))
}
pub fn darwin(out: &Path) -> Result<()> {
    std::fs::create_dir_all(out).map_err(|e| e.to_string())?;
    let mut asm = String::from("// Generated from owned Mach-O fixtures.\n");
    let mut h = String::from("#pragma once\n#include <stdint.h>\n");
    let probes = [
        (
            "getpid",
            vec![
                0xeb1f03ff, 0xd2800290, 0xd4001001, 0x54000042, 0xd65f03c0, 0x52800000, 0xd65f03c0,
            ],
        ),
        (
            "unix_error",
            vec![
                0xd28ffff0, 0xd4001001, 0x54000043, 0xd65f03c0, 0x52800000, 0xd65f03c0,
            ],
        ),
        ("mach_self", vec![0x92800370, 0xd4001001, 0xd65f03c0]),
        (
            "mach_error",
            vec![
                0x928fffd0, 0xd4001001, 0x54000042, 0xd65f03c0, 0x52800000, 0xd65f03c0,
            ],
        ),
    ];
    for (name, code) in probes {
        let b = probe(&u32s(&code));
        let path = out.join(format!("darwin_{name}.macho"));
        write(&path, &b)?;
        let p = path
            .canonicalize()
            .map_err(|e| e.to_string())?
            .to_string_lossy()
            .replace('\\', "\\\\")
            .replace('"', "\\\"");
        let sym = format!("hm_darwin_{name}_image");
        writeln!(asm,".section .text.hm_darwin,\"ax\",%progbits\n.p2align 14\n.global {sym}\n.hidden {sym}\n{sym}:").unwrap();
        let mut start = 0;
        for (i, &w) in code.iter().enumerate() {
            if w == 0xd4001001 {
                let at = 0x1000 + i * 4;
                writeln!(
                    asm,
                    ".incbin \"{p}\",{start},{}\n.word 0xd42909a0",
                    at - start
                )
                .unwrap();
                start = at + 4
            }
        }
        writeln!(asm, ".incbin \"{p}\",{start},{}", b.len() - start).unwrap();
        writeln!(
            h,
            "extern \"C\" const uint8_t {sym}[{}];\n#define HM_DARWIN_{}_CODE_SIZE {}",
            b.len(),
            name.to_uppercase(),
            code.len() * 4
        )
        .unwrap()
    }
    asm.push_str(".section .note.GNU-stack,\"\",%progbits\n");
    write(&out.join("darwin_probes.S"), asm)?;
    write(&out.join("darwin_probes.h"), h)
}
pub fn bootstrap(out: &Path, clang: &str, objcopy: &str) -> Result<()> {
    let source = out.join("entry.S");
    write(&source,".arch armv8.3-a\n.arch_extension pauth\n.text\n.org 0x1000\n.Lentry:\n pacibsp\n stp x29,x30,[sp,#-16]!\n adr x8,.Lslot\n ldr x9,[x8]\n mov x10,x8\n movk x10,#0x1234,lsl #48\n blraa x9,x10\n ldp x29,x30,[sp],#16\n autibsp\n ret\n.org 0x1100\n.Lcallee:\n mov w0,#42\n ret\n.org 0x4000\n.Lslot:\n .quad 0x8001123400001100\n")?;
    let obj = out.join("entry.o");
    let raw = out.join("entry.bin");
    run(Command::new(clang)
        .args(["--target=aarch64-linux-ohos", "-c"])
        .arg(&source)
        .arg("-o")
        .arg(&obj))?;
    run(Command::new(objcopy)
        .arg("--dump-section")
        .arg(format!(".text={}", raw.display()))
        .arg(&obj))?;
    let text = read(&raw)?;
    if text.len() != 0x4008 {
        return Err("unexpected fixture size".into());
    }
    let adr = super::cache::u32le(&text, 0x1008)?;
    let imm = ((adr >> 5) & 0x7ffff) << 2 | ((adr >> 29) & 3);
    let imm = ((imm << 11) as i32 >> 11) as i64;
    if 0x1008 + imm != 0x4000 {
        return Err("unresolved fixture ADR".into());
    }
    let mut starts = u32s(&[3, 0, 16, 0]);
    starts.extend(24u32.to_le_bytes());
    starts.extend(0x4000u16.to_le_bytes());
    starts.extend(9u16.to_le_bytes());
    starts.extend(0x4000u64.to_le_bytes());
    starts.extend(0u32.to_le_bytes());
    starts.extend(1u16.to_le_bytes());
    starts.extend(0u16.to_le_bytes());
    let mut payload = u32s(&[
        0,
        28,
        28 + starts.len() as u32,
        28 + starts.len() as u32,
        0,
        1,
        0,
    ]);
    payload.extend(starts);
    let mut cmds = segment("__TEXT", 0, 0, 0x4000, 5);
    cmds.extend(segment("__AUTH_CONST", 0x4000, 0x4000, 0x4000, 3));
    cmds.extend(segment(
        "__LINKEDIT",
        0x8000,
        0x8000,
        payload.len() as u64,
        1,
    ));
    cmds.extend(u32s(&[5, 288, 6, 68]));
    let mut state = vec![0; 272];
    state[256..264].copy_from_slice(&0x100001000u64.to_le_bytes());
    cmds.extend(state);
    cmds.extend(u32s(&[
        0x80000034,
        16,
        0x8000,
        payload.len() as u32,
        0x32,
        24,
        2,
        27 << 16,
        27 << 16,
        0,
    ]));
    let mut header = u32s(&[
        0xfeedfacf,
        0x100000c,
        0x80000002,
        7,
        6,
        cmds.len() as u32,
        0,
        0,
    ]);
    header.extend(cmds);
    let mut b = text;
    b.resize(0x8000, 0);
    b.extend(payload);
    b[..header.len()].copy_from_slice(&header);
    write(&out.join("bootstrap.macho"), b)
}
