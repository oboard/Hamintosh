//! Bounded chained-pointer decoding and relocation planning for dyld bootstrap.
//! No dependency loading or Objective-C/Swift initialization occurs here.
use super::{range, string, u32le, u64le, Image};
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Import {
    pub library_ordinal: i32,
    pub name: String,
    pub weak: bool,
    pub addend: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Authentication {
    pub key: u8,
    pub diversity: u16,
    pub address_diversity: bool,
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Target {
    Rebase { offset: u64, high8: u8 },
    Bind { import: usize, addend: i64 },
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Fixup {
    pub vm_offset: u64,
    pub file_offset: u64,
    pub original: u64,
    pub target: Target,
    pub authentication: Option<Authentication>,
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Plan {
    pub preferred_base: u64,
    pub imports: Vec<Import>,
    pub fixups: Vec<Fixup>,
    pub pointer_formats: BTreeSet<u16>,
}

fn u16le(b: &[u8], at: usize) -> Result<u16, String> {
    Ok(u16::from_le_bytes(range(b, at, 2)?.try_into().unwrap()))
}

fn import_ordinal(value: u32, bits: u32) -> i32 {
    if value > ((1 << bits) - 16) {
        ((value << (32 - bits)) as i32) >> (32 - bits)
    } else {
        value as i32
    }
}

fn read_imports(payload: &[u8], image: &Image) -> Result<Vec<Import>, String> {
    let offset = u32le(payload, 8)? as usize;
    let symbols_offset = u32le(payload, 12)? as usize;
    let count = u32le(payload, 16)? as usize;
    let format = u32le(payload, 20)?;
    if u32le(payload, 24)? != 0 {
        return Err("compressed chained symbols are not supported".into());
    }
    let size = match format {
        1 => 4,
        2 => 8,
        3 => 16,
        _ => return Err("unsupported chained import format".into()),
    };
    if offset < 28 || symbols_offset < 28 || count > 1_000_000 {
        return Err("invalid chained import table".into());
    }
    let entries = range(
        payload,
        offset,
        count.checked_mul(size).ok_or("import size overflow")?,
    )?;
    let symbols = payload
        .get(symbols_offset..)
        .ok_or("symbols outside fixups payload")?;
    let mut imports = Vec::with_capacity(count);
    for entry in entries.chunks_exact(size) {
        let (ordinal, name, weak, addend) = if format == 3 {
            let value = u64le(entry, 0)?;
            if (value >> 17) & 0x7fff != 0 {
                return Err("reserved import bits are nonzero".into());
            }
            (
                import_ordinal(value as u32 & 0xffff, 16),
                (value >> 32) as usize,
                value & (1 << 16) != 0,
                u64le(entry, 8)? as i64,
            )
        } else {
            let value = u32le(entry, 0)?;
            (
                import_ordinal(value & 255, 8),
                (value >> 9) as usize,
                value & (1 << 8) != 0,
                if format == 2 {
                    u32le(entry, 4)? as i32 as i64
                } else {
                    0
                },
            )
        };
        if ordinal > image.dependencies.len() as i32 || ordinal < -3 {
            return Err("chained import has invalid library ordinal".into());
        }
        let name = string(symbols, name)?;
        if name.is_empty() {
            return Err("empty chained import name".into());
        }
        imports.push(Import {
            library_ordinal: ordinal,
            name,
            weak,
            addend,
        });
    }
    Ok(imports)
}

fn decode_pointer(
    raw: u64,
    format: u16,
    base: u64,
) -> Result<(Target, Option<Authentication>, u64), String> {
    match format {
        2 | 6 => {
            let next = ((raw >> 51) & 0xfff) * 4;
            if raw >> 63 != 0 {
                if (raw >> 32) & 0x7ffff != 0 {
                    return Err("reserved bind bits are nonzero".into());
                }
                Ok((
                    Target::Bind {
                        import: (raw & 0xffffff) as usize,
                        addend: ((raw >> 24) & 255) as i64,
                    },
                    None,
                    next,
                ))
            } else {
                if (raw >> 44) & 0x7f != 0 {
                    return Err("reserved rebase bits are nonzero".into());
                }
                let value = raw & ((1 << 36) - 1);
                let offset = if format == 2 {
                    value.checked_sub(base).ok_or("rebase target below image")?
                } else {
                    value
                };
                Ok((
                    Target::Rebase {
                        offset,
                        high8: ((raw >> 36) & 255) as u8,
                    },
                    None,
                    next,
                ))
            }
        }
        1 | 9 | 12 => {
            let next = ((raw >> 51) & 0x7ff) * 8;
            let auth = raw >> 63 != 0;
            let bind = (raw >> 62) & 1 != 0;
            let authentication = auth.then_some(Authentication {
                diversity: (raw >> 32) as u16,
                address_diversity: raw & (1 << 48) != 0,
                key: ((raw >> 49) & 3) as u8,
            });
            if bind {
                let width = if format == 12 { 24 } else { 16 };
                let ordinal = (raw & ((1 << width) - 1)) as usize;
                if raw & ((0xffff_ffffu64) ^ ((1 << width) - 1)) != 0 {
                    return Err("reserved ARM64e bind bits are nonzero".into());
                }
                let addend = if auth { 0 } else { ((raw << 13) as i64) >> 45 };
                Ok((
                    Target::Bind {
                        import: ordinal,
                        addend,
                    },
                    authentication,
                    next,
                ))
            } else {
                let value = raw & if auth { 0xffff_ffff } else { (1 << 43) - 1 };
                let offset = if format == 1 && !auth {
                    value.checked_sub(base).ok_or("ARM64e target below image")?
                } else {
                    value
                };
                let high8 = if auth { 0 } else { ((raw >> 43) & 255) as u8 };
                Ok((Target::Rebase { offset, high8 }, authentication, next))
            }
        }
        _ => Err(format!("unsupported chained pointer format {format}")),
    }
}

pub fn parse(bytes: &[u8], image: &Image) -> Result<Plan, String> {
    let base = image
        .segments
        .iter()
        .find(|s| s.name == "__TEXT")
        .ok_or("fixups require __TEXT")?
        .vm_address;
    let mut plan = Plan {
        preferred_base: base,
        ..Default::default()
    };
    let Some(command) = &image.chained_fixups_data else {
        return Ok(plan);
    };
    let file = range(bytes, image.slice_offset, image.slice_size)?;
    let payload = range(file, command.file_offset as usize, command.size as usize)?;
    range(payload, 0, 28)?;
    if u32le(payload, 0)? != 0 {
        return Err("unsupported chained fixup version".into());
    }
    plan.imports = read_imports(payload, image)?;
    let starts = u32le(payload, 4)? as usize;
    if starts < 28 {
        return Err("chained starts overlap fixup header".into());
    }
    let count = u32le(payload, starts)? as usize;
    if count > image.segments.len() {
        return Err("chained segment count exceeds load commands".into());
    }
    range(payload, starts + 4, count * 4)?;
    let mut visited = BTreeSet::new();
    for (index, segment) in image.segments.iter().take(count).enumerate() {
        let relative = u32le(payload, starts + 4 + index * 4)? as usize;
        if relative == 0 {
            continue;
        }
        if relative < 4 + count * 4 {
            return Err("chained segment starts overlap offset table".into());
        }
        let at = starts
            .checked_add(relative)
            .ok_or("chained starts overflow")?;
        let size = u32le(payload, at)? as usize;
        let data = range(payload, at, size)?;
        range(data, 0, 22)?;
        let page_size = u16le(data, 4)? as usize;
        let format = u16le(data, 6)?;
        let segment_offset = u64le(data, 8)?;
        let pages = u16le(data, 20)? as usize;
        if !matches!(page_size, 0x1000 | 0x4000) || !matches!(format, 1 | 2 | 6 | 9 | 12) {
            return Err("unsupported chained page or pointer format".into());
        }
        if segment.vm_address.checked_sub(base) != Some(segment_offset)
            || segment.protection & 2 == 0
            || pages > segment.vm_size.div_ceil(page_size as u64) as usize
        {
            return Err("invalid chained segment VM layout".into());
        }
        range(data, 22, pages * 2)?;
        plan.pointer_formats.insert(format);
        for page in 0..pages {
            let value = u16le(data, 22 + page * 2)?;
            if value == 0xffff {
                continue;
            }
            let mut chains = vec![];
            if value & 0x8000 != 0 {
                let mut overflow = (value & 0x7fff) as usize;
                if overflow < pages {
                    return Err("multi-start chain overlaps page table".into());
                }
                loop {
                    let start = u16le(data, 22 + overflow * 2)?;
                    chains.push(start & 0x7fff);
                    overflow += 1;
                    if start & 0x8000 != 0 {
                        break;
                    }
                }
            } else {
                chains.push(value);
            }
            for start in chains {
                let mut offset = start as u64;
                loop {
                    if offset & 3 != 0 || offset + 8 > page_size as u64 {
                        return Err("fixup chain escapes page".into());
                    }
                    let within = page as u64 * page_size as u64 + offset;
                    if within + 8 > segment.file_size {
                        return Err("fixup escapes segment file bytes".into());
                    }
                    let vm_offset = segment_offset + within;
                    if plan.fixups.len() >= 1_000_000 || !visited.insert(vm_offset) {
                        return Err("duplicate or excessive fixup locations".into());
                    }
                    let file_offset = segment.file_offset + within;
                    let raw = u64le(file, file_offset as usize)?;
                    let (target, authentication, next) = decode_pointer(raw, format, base)?;
                    match target {
                        Target::Bind { import, .. } if import >= plan.imports.len() => {
                            return Err("fixup bind ordinal outside import table".into())
                        }
                        Target::Rebase { offset, .. } => {
                            let address =
                                base.checked_add(offset).ok_or("rebase address overflow")?;
                            if !image.segments.iter().any(|s| {
                                s.protection != 0
                                    && address >= s.vm_address
                                    && address <= s.vm_address + s.vm_size
                            }) {
                                return Err("rebase target outside mapped image".into());
                            }
                        }
                        _ => {}
                    }
                    plan.fixups.push(Fixup {
                        vm_offset,
                        file_offset,
                        original: raw,
                        target,
                        authentication,
                    });
                    if next == 0 {
                        break;
                    }
                    offset += next;
                }
            }
        }
    }
    Ok(plan)
}

impl Plan {
    /// Resolve all pointers before any writes. Missing imports and PAC support fail atomically.
    pub fn resolve(
        &self,
        mapped_base: u64,
        bindings: &[Option<u64>],
        mut sign: impl FnMut(u64, u64, &Authentication) -> Result<u64, String>,
    ) -> Result<Vec<(u64, u64)>, String> {
        let mut writes = Vec::with_capacity(self.fixups.len());
        for fixup in &self.fixups {
            let value = match fixup.target {
                Target::Rebase { offset, high8 } => {
                    mapped_base
                        .checked_add(offset)
                        .ok_or("relocated target overflow")?
                        | ((high8 as u64) << 56)
                }
                Target::Bind { import, addend } => {
                    let dependency = self
                        .imports
                        .get(import)
                        .ok_or("bind refers to absent import")?;
                    let target = match bindings.get(import).copied().flatten() {
                        Some(value) => value,
                        None if dependency.weak => 0,
                        None => return Err(format!("unresolved import {}", dependency.name)),
                    };
                    target
                        .checked_add_signed(dependency.addend)
                        .and_then(|v| v.checked_add_signed(addend))
                        .ok_or("bound symbol addend overflow")?
                }
            };
            let location = mapped_base
                .checked_add(fixup.vm_offset)
                .ok_or("fixup location overflow")?;
            let value = if let Some(authentication) = &fixup.authentication {
                if value == 0 {
                    0
                } else {
                    sign(value, location, authentication)?
                }
            } else {
                value
            };
            writes.push((fixup.vm_offset, value));
        }
        Ok(writes)
    }
}
