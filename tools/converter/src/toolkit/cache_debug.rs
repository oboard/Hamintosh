use super::{cache, run, write, Result};
use std::{path::Path, process::Command};

pub fn number(s: &str) -> Result<u64> {
    match s.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).map_err(|e| e.to_string()),
        None => s.parse::<u64>().map_err(|e| e.to_string()),
    }
}

pub fn disassemble(
    primary: &Path,
    address: u64,
    size: usize,
    out: &Path,
    llvm: &Path,
) -> Result<String> {
    if size == 0 || size > 65536 || !size.is_multiple_of(4) || !address.is_multiple_of(4) {
        return Err("disassembly needs an aligned, nonempty range of at most 64 KiB".into());
    }
    let c = cache::load(primary)?;
    let bytes = out.join("slice.bin");
    write(&bytes, cache::vm(&c, address, size)?)?;
    let quoted = bytes
        .canonicalize()
        .map_err(|e| e.to_string())?
        .to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    let assembly = out.join("slice.S");
    let object = out.join("slice.o");
    write(
        &assembly,
        format!(".text\n.global hm_cache_slice\nhm_cache_slice:\n.incbin \"{quoted}\"\n"),
    )?;
    run(Command::new(llvm.join("clang"))
        .args(["-target", "aarch64-linux-ohos", "-c"])
        .arg(&assembly)
        .arg("-o")
        .arg(&object))?;
    let text = run(Command::new(llvm.join("llvm-objdump"))
        .args(["-D", "-j", ".text", "--mattr=+pauth,+lse"])
        .arg(format!("--adjust-vma={address:#x}"))
        .arg(&object))?;
    write(&out.join("disassembly.txt"), &text)?;
    Ok(text)
}

pub fn selector(primary: &Path, address: u64) -> Result<serde_json::Value> {
    let c = cache::load(primary)?;
    let code = cache::vm(&c, address, 8)?;
    let a = cache::u32le(&code, 0)?;
    let b = cache::u32le(&code, 4)?;
    if a & 0x9f00001f != 0x90000001 || b & 0xffc003ff != 0x91000021 {
        return Err("unsupported selector stub (expected ADRP x1; ADD x1,x1)".into());
    }
    let imm = i64::from(((a >> 5) & 0x7ffff) << 2 | ((a >> 29) & 3));
    let signed = if imm & 0x100000 != 0 {
        imm - 0x200000
    } else {
        imm
    };
    let target = (address & !4095)
        .checked_add_signed(signed * 4096)
        .and_then(|v| v.checked_add(u64::from((b >> 10) & 0xfff)))
        .ok_or("selector address overflow")?;
    let bytes = cache::vm(&c, target, 256)?;
    if !bytes.contains(&0) {
        return Err("unterminated selector".into());
    }
    Ok(
        serde_json::json!({"stub":format!("{address:#x}"),"address":format!("{target:#x}"),"selector":cache::name(&bytes)?}),
    )
}

/// Resolve a cache address without assuming that an exported symbol exists.
pub fn address(primary: &Path, input: u64, runtime_base: Option<u64>) -> Result<serde_json::Value> {
    let c = cache::load(primary)?;
    let preferred = match runtime_base {
        Some(base) => c
            .preferred_base
            .checked_add(
                input
                    .checked_sub(base)
                    .ok_or("address precedes runtime cache base")?,
            )
            .ok_or("address overflow")?,
        None => input,
    };
    let mut result = serde_json::json!({"input": format!("{input:#x}"), "preferredAddress": format!("{preferred:#x}"), "cacheOffset": preferred.checked_sub(c.preferred_base).map(|v| format!("{v:#x}"))});
    for owner in &c.images {
        if owner.address > preferred {
            continue;
        }
        let image = cache::image(&c, owner.address)?;
        if let Some(segment) = image
            .segments
            .iter()
            .find(|s| preferred >= s.address && preferred - s.address < s.size)
        {
            result["image"] = owner.path.clone().into();
            result["imageOffset"] = format!("{:#x}", preferred - owner.address).into();
            result["segment"] = segment.name.clone().into();
            if let Some(section) = image
                .sections
                .iter()
                .find(|s| preferred >= s.address && preferred - s.address < s.size)
            {
                result["section"] = section.name.clone().into();
            }
            if segment.protection & 4 != 0 {
                if let Some((start, size)) = image.function_starts {
                    let bytes = cache::vm(&c, start, size)?;
                    let (mut cursor, mut current, mut previous) = (0, owner.address, None);
                    while cursor < bytes.len() {
                        let delta = cache::uleb(&bytes, &mut cursor)?;
                        if delta == 0 {
                            break;
                        }
                        current = current
                            .checked_add(delta)
                            .ok_or("function address overflow")?;
                        if current > preferred {
                            break;
                        }
                        previous = Some(current);
                    }
                    if let Some(start) = previous {
                        result["functionStart"] = format!("{start:#x}").into();
                        result["functionOffset"] = format!("{:#x}", preferred - start).into();
                    }
                }
            }
            return Ok(result);
        }
    }
    Ok(result)
}

fn rebased_pointer(c: &harmonios_runtime::cache::CacheSet, address: u64) -> Result<u64> {
    let offset = address
        .checked_sub(c.preferred_base)
        .ok_or("pointer precedes cache")?;
    let (file, mapping, _) = cache::location(c, address, 8)?;
    let mut target = None;
    harmonios_runtime::cache::slide::walk_selected(
        file,
        mapping,
        c.preferred_base,
        Some(&[offset..offset + 8]),
        |entry| {
            if entry.location_offset == offset {
                target = c.preferred_base.checked_add(entry.target_offset);
            }
            Ok(())
        },
    )?;
    target.ok_or_else(|| format!("no cache rebase at {address:#x}"))
}

/// Decode an Objective-C class reference through the cache's actual slide chains.
pub fn objc_class(primary: &Path, reference: u64) -> Result<serde_json::Value> {
    let c = cache::load(primary)?;
    let class = rebased_pointer(&c, reference)?;
    let ro = rebased_pointer(&c, class.checked_add(32).ok_or("class address overflow")?)? & !7;
    let name_address = rebased_pointer(&c, ro.checked_add(24).ok_or("class metadata overflow")?)?;
    let bytes = cache::vm(&c, name_address, 256)?;
    if !bytes.contains(&0) {
        return Err("unterminated class name".into());
    }
    Ok(
        serde_json::json!({"reference":format!("{reference:#x}"),"class":format!("{class:#x}"),"metadata":format!("{ro:#x}"),"nameAddress":format!("{name_address:#x}"),"name":cache::name(&bytes)?}),
    )
}
