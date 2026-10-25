//! Bounded, read-only Mach-O inspection. Mapping and entering code belong to C++.
use serde::Serialize;
pub mod fixups;

const ARM64: u32 = 0x0100_000c;
const MAX_IMAGE: u64 = 512 * 1024 * 1024;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Segment {
    pub name: String,
    pub vm_address: u64,
    pub vm_size: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub protection: u32,
}

#[derive(Debug, Serialize)]
pub struct Dependency {
    pub path: String,
    pub weak: bool,
    pub reexport: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Section {
    pub name: String,
    pub segment_name: String,
    pub vm_address: u64,
    pub size: u64,
    pub file_offset: u32,
    pub flags: u32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkeditData {
    pub file_offset: u32,
    pub size: u32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Image {
    pub architecture: &'static str,
    pub cpu_subtype: u32,
    pub file_type: u32,
    pub slice_offset: usize,
    pub slice_size: usize,
    pub entry_file_offset: Option<u64>,
    pub entry_vm_address: Option<u64>,
    pub entry_command: Option<&'static str>,
    pub flags: u32,
    pub mapped_vm_span: u64,
    pub interpreter: Option<String>,
    pub minimum_os: Option<String>,
    pub platform: Option<u32>,
    pub encrypted: bool,
    pub chained_fixups: bool,
    pub chained_fixups_data: Option<LinkeditData>,
    pub exports_trie: bool,
    pub legacy_dyld_info: bool,
    pub segments: Vec<Segment>,
    pub sections: Vec<Section>,
    pub dependencies: Vec<Dependency>,
    pub rpaths: Vec<String>,
    pub undefined_symbols: Vec<String>,
}

fn range(b: &[u8], offset: usize, len: usize) -> Result<&[u8], String> {
    b.get(offset..offset.checked_add(len).ok_or("offset overflow")?)
        .ok_or_else(|| format!("truncated Mach-O at {offset:#x}, need {len} bytes"))
}

fn u32le(b: &[u8], offset: usize) -> Result<u32, String> {
    Ok(u32::from_le_bytes(range(b, offset, 4)?.try_into().unwrap()))
}

fn u64le(b: &[u8], offset: usize) -> Result<u64, String> {
    Ok(u64::from_le_bytes(range(b, offset, 8)?.try_into().unwrap()))
}

fn string(b: &[u8], offset: usize) -> Result<String, String> {
    let bytes = b.get(offset..).ok_or("string offset outside command")?;
    let end = bytes
        .iter()
        .position(|v| *v == 0)
        .ok_or("unterminated string")?;
    String::from_utf8(bytes[..end].to_vec()).map_err(|_| "invalid UTF-8 name".into())
}

fn command_string(cmd: &[u8], minimum: usize) -> Result<String, String> {
    let offset = u32le(cmd, 8)? as usize;
    if offset < minimum {
        return Err("string overlaps load command header".into());
    }
    string(cmd, offset)
}

fn version(v: u32) -> String {
    format!("{}.{}.{}", v >> 16, (v >> 8) & 255, v & 255)
}

fn arm_slice(bytes: &[u8]) -> Result<(usize, &[u8]), String> {
    let magic = range(bytes, 0, 4)?;
    if magic == [0xcf, 0xfa, 0xed, 0xfe] {
        return Ok((0, bytes));
    }
    let fat64 = magic == [0xca, 0xfe, 0xba, 0xbf];
    if !fat64 && magic != [0xca, 0xfe, 0xba, 0xbe] {
        return Err("expected little-endian Mach-O 64 or universal Mach-O".into());
    }
    let be32 = |o| -> Result<u32, String> {
        Ok(u32::from_be_bytes(range(bytes, o, 4)?.try_into().unwrap()))
    };
    let be64 = |o| -> Result<u64, String> {
        Ok(u64::from_be_bytes(range(bytes, o, 8)?.try_into().unwrap()))
    };
    let count = be32(4)? as usize;
    let size = if fat64 { 32 } else { 20 };
    if count > 64 {
        return Err("too many universal slices".into());
    }
    range(bytes, 8, count * size)?;
    for i in 0..count {
        let at = 8 + i * size;
        if be32(at)? == ARM64 {
            let (offset, len) = if fat64 {
                (be64(at + 8)?, be64(at + 16)?)
            } else {
                (be32(at + 8)? as u64, be32(at + 12)? as u64)
            };
            if offset < (8 + count * size) as u64 || len > MAX_IMAGE {
                return Err("invalid universal slice bounds".into());
            }
            return Ok((
                offset as usize,
                range(bytes, offset as usize, len as usize)?,
            ));
        }
    }
    Err("universal binary has no ARM64 slice".into())
}

pub fn parse(bytes: &[u8]) -> Result<Image, String> {
    let (slice_offset, b) = arm_slice(bytes)?;
    range(b, 0, 32)?;
    if u32le(b, 0)? != 0xfeed_facf || u32le(b, 4)? != ARM64 {
        return Err("only little-endian ARM64 Mach-O is supported".into());
    }
    let file_type = u32le(b, 12)?;
    if ![2, 6, 7].contains(&file_type) {
        return Err("expected executable, dylib or dyld".into());
    }
    let count = u32le(b, 16)? as usize;
    let commands_size = u32le(b, 20)? as usize;
    range(b, 32, commands_size)?;
    if count > commands_size / 8 {
        return Err("invalid load command count".into());
    }
    let end = 32 + commands_size;
    let mut image = Image {
        architecture: "arm64",
        cpu_subtype: u32le(b, 8)?,
        file_type,
        slice_offset,
        slice_size: b.len(),
        entry_file_offset: None,
        entry_vm_address: None,
        entry_command: None,
        flags: u32le(b, 24)?,
        mapped_vm_span: 0,
        interpreter: None,
        minimum_os: None,
        platform: None,
        encrypted: false,
        chained_fixups: false,
        chained_fixups_data: None,
        exports_trie: false,
        legacy_dyld_info: false,
        segments: vec![],
        sections: vec![],
        dependencies: vec![],
        rpaths: vec![],
        undefined_symbols: vec![],
    };
    let mut pos = 32;
    let mut symtab = None;
    for _ in 0..count {
        let kind = u32le(b, pos)?;
        let len = u32le(b, pos + 4)? as usize;
        if len < 8 || !len.is_multiple_of(8) || pos.checked_add(len).filter(|e| *e <= end).is_none()
        {
            return Err("invalid load command size".into());
        }
        let cmd = range(b, pos, len)?;
        match kind {
            0x19 => {
                range(cmd, 0, 72)?;
                let name = string(&cmd[8..24], 0).or_else(|_| {
                    String::from_utf8(cmd[8..24].to_vec())
                        .map_err(|_| "invalid segment name".to_string())
                })?;
                let s = Segment {
                    name,
                    vm_address: u64le(cmd, 24)?,
                    vm_size: u64le(cmd, 32)?,
                    file_offset: u64le(cmd, 40)?,
                    file_size: u64le(cmd, 48)?,
                    protection: u32le(cmd, 60)?,
                };
                if s.file_size > s.vm_size || s.file_size > MAX_IMAGE {
                    return Err("invalid segment file size".into());
                }
                if s.file_size != 0 {
                    range(b, s.file_offset as usize, s.file_size as usize)?;
                }
                let sections = u32le(cmd, 64)? as usize;
                if sections > (len - 72) / 80 {
                    return Err("truncated section table".into());
                }
                if s.vm_address.checked_add(s.vm_size).is_none() {
                    return Err("segment address overflow".into());
                }
                for i in 0..sections {
                    let section = range(cmd, 72 + i * 80, 80)?;
                    let fixed_name = |bytes: &[u8]| -> Result<String, String> {
                        let len = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
                        String::from_utf8(bytes[..len].to_vec())
                            .map_err(|_| "invalid section name".into())
                    };
                    let section = Section {
                        name: fixed_name(&section[..16])?,
                        segment_name: fixed_name(&section[16..32])?,
                        vm_address: u64le(section, 32)?,
                        size: u64le(section, 40)?,
                        file_offset: u32le(section, 48)?,
                        flags: u32le(section, 64)?,
                    };
                    if section.vm_address < s.vm_address
                        || section
                            .vm_address
                            .checked_add(section.size)
                            .filter(|end| *end <= s.vm_address + s.vm_size)
                            .is_none()
                    {
                        return Err("section escapes segment VM range".into());
                    }
                    if !matches!(section.flags & 0xff, 1 | 0xc | 0x12) && section.size != 0 {
                        range(b, section.file_offset as usize, section.size as usize)?;
                        if (section.file_offset as u64) < s.file_offset
                            || (section.file_offset as u64)
                                .checked_add(section.size)
                                .filter(|end| *end <= s.file_offset + s.file_size)
                                .is_none()
                        {
                            return Err("section escapes segment file range".into());
                        }
                    }
                    image.sections.push(section);
                }
                image.segments.push(s);
            }
            0x8000_0028 => {
                range(cmd, 0, 24)?;
                if image.entry_command.is_some() {
                    return Err("duplicate entry command".into());
                }
                image.entry_command = Some("LC_MAIN");
                image.entry_file_offset = Some(u64le(cmd, 8)?);
            }
            0x5 => {
                if image.entry_command.is_some() {
                    return Err("duplicate entry command".into());
                }
                let mut state = 8;
                while state < len {
                    let flavor = u32le(cmd, state)?;
                    let count = u32le(cmd, state + 4)? as usize;
                    let registers = range(
                        cmd,
                        state + 8,
                        count.checked_mul(4).ok_or("thread state overflow")?,
                    )?;
                    if flavor == 6 {
                        if count != 68 || image.entry_vm_address.is_some() {
                            return Err("invalid ARM_THREAD_STATE64".into());
                        }
                        image.entry_vm_address = Some(u64le(registers, 256)?);
                        image.entry_command = Some("LC_UNIXTHREAD");
                    }
                    state += 8 + registers.len();
                }
                if state != len || image.entry_vm_address.is_none() {
                    return Err("LC_UNIXTHREAD lacks ARM64 thread state".into());
                }
            }
            0xc | 0x8000_0018 | 0x8000_001f | 0x8000_0023 => {
                range(cmd, 0, 24)?;
                image.dependencies.push(Dependency {
                    path: command_string(cmd, 24)?,
                    weak: kind == 0x8000_0018,
                    reexport: kind == 0x8000_001f,
                });
            }
            0xe => image.interpreter = Some(command_string(cmd, 12)?),
            0x8000_001c => image.rpaths.push(command_string(cmd, 12)?),
            0x32 => {
                range(cmd, 0, 24)?;
                image.platform = Some(u32le(cmd, 8)?);
                image.minimum_os = Some(version(u32le(cmd, 12)?));
            }
            0x2c => {
                range(cmd, 0, 24)?;
                image.encrypted |= u32le(cmd, 16)? != 0;
            }
            0x8000_0034 | 0x8000_0033 | 0x1d | 0x26 | 0x29 => {
                range(cmd, 0, 16)?;
                range(b, u32le(cmd, 8)? as usize, u32le(cmd, 12)? as usize)?;
                image.chained_fixups |= kind == 0x8000_0034;
                if kind == 0x8000_0034 {
                    if image.chained_fixups_data.is_some() {
                        return Err("duplicate chained fixup command".into());
                    }
                    image.chained_fixups_data = Some(LinkeditData {
                        file_offset: u32le(cmd, 8)?,
                        size: u32le(cmd, 12)?,
                    });
                }
                image.exports_trie |= kind == 0x8000_0033;
            }
            0x22 | 0x8000_0022 => {
                range(cmd, 0, 48)?;
                for i in (8..48).step_by(8) {
                    range(b, u32le(cmd, i)? as usize, u32le(cmd, i + 4)? as usize)?;
                }
                image.legacy_dyld_info = true;
            }
            0x2 => {
                range(cmd, 0, 24)?;
                symtab = Some((
                    u32le(cmd, 8)? as usize,
                    u32le(cmd, 12)? as usize,
                    u32le(cmd, 16)? as usize,
                    u32le(cmd, 20)? as usize,
                ));
            }
            _ => {} // Inspection can skip well-formed commands; execution uses a stricter gate.
        }
        pos += len;
    }
    if pos != end {
        return Err("load commands do not fill sizeofcmds".into());
    }
    let mapped: Vec<_> = image
        .segments
        .iter()
        .filter(|s| s.protection != 0 && s.vm_size != 0)
        .collect();
    for (i, a) in mapped.iter().enumerate() {
        for b in &mapped[i + 1..] {
            if a.vm_address < b.vm_address + b.vm_size && b.vm_address < a.vm_address + a.vm_size {
                return Err("overlapping mapped segments".into());
            }
        }
    }
    if let (Some(first), Some(last)) = (
        mapped.iter().map(|s| s.vm_address).min(),
        mapped.iter().map(|s| s.vm_address + s.vm_size).max(),
    ) {
        image.mapped_vm_span = last - first;
    }
    if image.entry_command == Some("LC_MAIN") {
        let entry = image.entry_file_offset.unwrap();
        // LC_MAIN.entryoff is relative to __TEXT, whose file offset is zero for MH_EXECUTE.
        let text = image
            .segments
            .iter()
            .find(|s| s.name == "__TEXT")
            .ok_or("LC_MAIN without __TEXT")?;
        if text.file_offset != 0
            || text.protection & 4 == 0
            || entry < (32 + commands_size) as u64
            || entry
                .checked_add(4)
                .filter(|n| *n <= text.file_size)
                .is_none()
            || !entry.is_multiple_of(4)
        {
            return Err("entry point is outside executable __TEXT bytes".into());
        }
        image.entry_vm_address = Some(text.vm_address + entry);
    } else if let Some(pc) = image.entry_vm_address {
        if pc & 3 != 0 {
            return Err("unaligned ARM64 thread entry".into());
        }
        let segment = mapped
            .iter()
            .find(|s| {
                s.protection & 4 != 0
                    && pc >= s.vm_address
                    && pc
                        .checked_add(4)
                        .filter(|end| *end <= s.vm_address + s.file_size)
                        .is_some()
            })
            .ok_or("thread entry is outside executable file bytes")?;
        let offset = segment.file_offset + pc - segment.vm_address;
        if offset < (32 + commands_size) as u64 {
            return Err("thread entry overlaps Mach-O headers".into());
        }
        image.entry_file_offset = Some(offset);
    }
    if let Some((offset, count, strings_offset, strings_size)) = symtab {
        let symbols = range(
            b,
            offset,
            count.checked_mul(16).ok_or("symbol table overflow")?,
        )?;
        let strings = range(b, strings_offset, strings_size)?;
        for s in symbols.chunks_exact(16) {
            if s[4] & 0xe0 == 0 && s[4] & 0x0e == 0 && u64le(s, 8)? == 0 {
                image
                    .undefined_symbols
                    .push(string(strings, u32le(s, 0)? as usize)?);
            }
        }
    }
    Ok(image)
}
