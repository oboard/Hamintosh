//! Global arm64e -> arm64 PAC stripping for the AOT / dyld shared cache pipeline.
//!
//! Apple's own dyld implements the `keysOff` behaviour for arm64 main executables
//! (see `DyldProcessConfig.cpp`: an `arm64` main executable always runs with
//! signing keys off, and `ptrauth_disabled=1` forces it for any architecture).
//! XNU advertises that state through the `ptrauth_disabled=1` apple parameter on
//! the initial stack. We reproduce both halves:
//!
//! * the process advertises `ptrauth_disabled=1` on its boot stack (runtime), and
//! * every executable page of the cached images has its PAC instructions
//!   rewritten to their non-authenticating equivalents, so a guest compiled for
//!   arm64 behaves exactly like it would on a keys-off device.
//!
//! Encodings and classes mirror Bergamota's `tools/renegade-rs/src/pacstrip.rs`
//! (`rewrite_word`), which is itself the Rust port of `pacstrip.py`. Every
//! rewrite is 4 bytes for 4 bytes, so no branch target, unwind entry or chained
//! fixup moves.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PacMode {
    /// Leave executable bytes untouched (used for diagnostic-only runs).
    None,
    /// Rewrite PAC instructions to plain arm64 equivalents. This is the mode the
    /// device pipeline uses; it matches dyld's `keysOff` process semantics.
    #[default]
    Strip,
}

impl PacMode {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "none" | "off" | "0" => Some(Self::None),
            "strip" | "keysoff" | "keys-off" | "1" => Some(Self::Strip),
            _ => None,
        }
    }
}

pub const NOP: u32 = 0xD503_201F;
pub const RET: u32 = 0xD65F_03C0;
pub const TRANSFORM_VERSION: u64 = 2;

pub fn configured_mode() -> super::Result<PacMode> {
    let package = super::root().join("artifacts/ios27-aot/package.json");
    if !package.is_file() { return Ok(PacMode::Strip); }
    let config = super::json(&package)?;
    PacMode::parse(config["pacMode"].as_str().unwrap_or("none"))
        .ok_or_else(|| "invalid packaged PAC mode".into())
}

/// Cheap pre-filter: only these top bytes can start a PAC-related encoding.
#[inline]
pub fn may_contain_pac(word: u32) -> bool {
    matches!(word >> 24, 0xD5 | 0xD6 | 0xD7 | 0xDA | 0x9A | 0xF8)
}

/// `(Some(new), class)` for a rewrite, `(None, Some(class))` for a reported word
/// that must stay, `(None, None)` for everything else.
pub fn rewrite_word(word: u32) -> (Option<u32>, Option<&'static str>) {
    match word >> 24 {
        // Bergamota leaves these HINTs because its target has no PAuth.
        // Harmony hardware does have PAuth: leaving PACIBSP while replacing
        // RETAB with RET would branch to a signed return address.
        0xD5 => {
            let class = match word {
                0xd503211f => "PACIA1716", 0xd503215f => "PACIB1716",
                0xd503219f => "AUTIA1716", 0xd50321df => "AUTIB1716",
                0xd503231f => "PACIAZ", 0xd503233f => "PACIASP",
                0xd503235f => "PACIBZ", 0xd503237f => "PACIBSP",
                0xd503239f => "AUTIAZ", 0xd50323bf => "AUTIASP",
                0xd50323df => "AUTIBZ", 0xd50323ff => "AUTIBSP",
                0xd50320ff => "XPACLRI",
                _ => return (None, None),
            };
            (Some(NOP), Some(class))
        }
        0xD6 | 0xD7 => {
            if word == 0xD65F_0BFF {
                return (Some(RET), Some("RETAA"));
            }
            if word == 0xD65F_0FFF {
                return (Some(RET), Some("RETAB"));
            }
            let rn = (word >> 5) & 31;
            let b = word & 0x400 != 0;
            let z = word & 0x0100_0000 == 0;
            if word & 0xFEFF_F800 == 0xD61F_0800 {
                let class = match (b, z) {
                    (false, false) => "BRAA",
                    (false, true) => "BRAAZ",
                    (true, false) => "BRAB",
                    (true, true) => "BRABZ",
                };
                return (Some(0xD61F_0000 | rn << 5), Some(class));
            }
            if word & 0xFEFF_F800 == 0xD63F_0800 {
                let class = match (b, z) {
                    (false, false) => "BLRAA",
                    (false, true) => "BLRAAZ",
                    (true, false) => "BLRAB",
                    (true, true) => "BLRABZ",
                };
                return (Some(0xD63F_0000 | rn << 5), Some(class));
            }
            if word & 0xFFFF_F800 == 0xD69F_0800 {
                return (None, Some("ERETA"));
            }
            (None, None)
        }
        0xDA => {
            if word & 0xFFFF_C000 == 0xDAC1_0000 {
                const NAMES: [&str; 16] = [
                    "PACIA", "PACIB", "PACDA", "PACDB", "AUTIA", "AUTIB", "AUTDA", "AUTDB", "PACIAZ",
                    "PACIBZ", "PACDAZ", "PACDBZ", "AUTIAZ", "AUTIBZ", "AUTDAZ", "AUTDBZ",
                ];
                let index = ((word >> 10) & 7) as usize + if word & 0x2000 != 0 { 8 } else { 0 };
                return (Some(NOP), Some(NAMES[index]));
            }
            if word & 0xFFFF_FBE0 == 0xDAC1_43E0 {
                return (
                    Some(NOP),
                    Some(if word & 0x400 != 0 { "XPACD" } else { "XPACI" }),
                );
            }
            (None, None)
        }
        0x9A => {
            if word & 0xFFE0_FC00 == 0x9AC0_3000 {
                let (rd, rn, rm) = (word & 31, (word >> 5) & 31, (word >> 16) & 31);
                if rm == 31 {
                    // MOV Xd, Xn
                    return (Some(0xAA00_03E0 | rn << 16 | rd), Some("PACGA"));
                }
                // EOR Xd, Xn, Xm, ROR #13
                let k = 13;
                return (
                    Some(0xCA00_0000 | 3 << 22 | rm << 16 | k << 10 | rn << 5 | rd),
                    Some("PACGA"),
                );
            }
            (None, None)
        }
        0xF8 => {
            if word & 0xFF20_0400 == 0xF820_0400 {
                let m = (word >> 23) & 1;
                let s = (word >> 22) & 1;
                let imm9 = (word >> 12) & 0x1FF;
                let writeback = (word >> 11) & 1;
                let (rn, rt) = ((word >> 5) & 31, word & 31);
                let imm = (((s << 9) | imm9) as i32 - if s != 0 { 1 << 10 } else { 0 }) * 8;
                let name = if m != 0 { "LDRAB" } else { "LDRAA" };
                if writeback != 0 {
                    if (-256..=255).contains(&imm) {
                        return (
                            Some(0xF840_0C00 | ((imm as u32) & 0x1FF) << 12 | rn << 5 | rt),
                            Some(name),
                        );
                    }
                } else if imm >= 0 {
                    return (
                        Some(0xF940_0000 | ((imm / 8) as u32) << 10 | rn << 5 | rt),
                        Some(name),
                    );
                } else if imm >= -256 {
                    return (
                        Some(0xF840_0000 | ((imm as u32) & 0x1FF) << 12 | rn << 5 | rt),
                        Some(name),
                    );
                }
                return (None, Some(if m != 0 { "LDRAB" } else { "LDRAA" }));
            }
            (None, None)
        }
        _ => (None, None),
    }
}


/// Images whose code genuinely contains `LDRAA`/`LDRAB` loads. The dyld shared
/// cache builder drops `LC_DATA_IN_CODE`, so jump tables and literals can hold
/// words that decode as `LDRAA`; rewriting those would corrupt data. Every other
/// image only receives the branch/`AUT`/`PAC` rewrites.
const LDRA_WHITELIST: [&str; 8] = [
    "libc++abi",
    "libobjc.A",
    "libc++.1",
    "libdispatch",
    "libsystem_",
    "libdyld",
    "dyld",
    "libswiftCore",
];

pub fn ldra_whitelisted(image_path: &str) -> bool {
    LDRA_WHITELIST
        .iter()
        .any(|needle| image_path.contains(needle))
}

/// Transform only instruction sections of a standalone Mach-O. Literal ranges
/// in LC_DATA_IN_CODE are excluded, even when they decode as PAC instructions.
pub fn strip_macho_code(bytes: &mut [u8]) -> super::Result<PacReport> {
    let image = harmonios_runtime::macho::parse(bytes)?;
    let base = image.slice_offset;
    let mut data = Vec::new();
    let mut command = base + 32;
    for _ in 0..super::cache::u32le(bytes, base + 16)? {
        let kind = super::cache::u32le(bytes, command)?;
        let size = super::cache::u32le(bytes, command + 4)? as usize;
        if kind == 0x29 {
            let start = base + super::cache::u32le(bytes, command + 8)? as usize;
            let len = super::cache::u32le(bytes, command + 12)? as usize;
            if !len.is_multiple_of(8) || start.checked_add(len).is_none_or(|end| end > bytes.len()) {
                return Err("invalid LC_DATA_IN_CODE".into());
            }
            for at in (start..start + len).step_by(8) {
                let low = base + super::cache::u32le(bytes, at)? as usize;
                let len = u16::from_le_bytes(bytes[at + 4..at + 6].try_into().unwrap()) as usize;
                let high = low.checked_add(len).filter(|end| *end <= bytes.len())
                    .ok_or("data-in-code range outside Mach-O")?;
                data.push((low, high));
            }
        }
        command += size;
    }
    let mut report = PacReport::default();
    for section in image.sections.iter().filter(|s| s.flags & 0x80000400 != 0) {
        let low = base + section.file_offset as usize;
        let high = low.checked_add(section.size as usize).filter(|end| *end <= bytes.len())
            .ok_or("instruction section outside Mach-O")?;
        if !(high - low).is_multiple_of(4) { return Err("unaligned instruction section".into()); }
        for at in (low..high).step_by(4) {
            if data.iter().any(|&(a, b)| a < at + 4 && at < b) { continue; }
            let word = super::cache::u32le(bytes, at)?;
            if !may_contain_pac(word) { continue; }
            match rewrite_word(word) {
                (Some(after), Some(class)) => {
                    bytes[at..at + 4].copy_from_slice(&after.to_le_bytes());
                    report.rewrite(class);
                }
                (None, Some(class)) => report.left.push((class, at as u64)),
                _ => {},
            }
        }
    }
    Ok(report)
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PacReport {
    /// PAC class -> number of rewritten instructions.
    pub rewritten: std::collections::BTreeMap<&'static str, u64>,
    /// Words that look PAC-related but cannot be rewritten in place.
    pub left: Vec<(&'static str, u64)>,
    /// Total executable bytes scanned.
    pub scanned: u64,
}

impl PacReport {
    #[allow(dead_code)]
    pub fn record(&mut self, word: u32, offset: u64) {
        if !may_contain_pac(word) {
            return;
        }
        match rewrite_word(word) {
            (Some(_), Some(class)) => self.rewrite(class),
            (None, Some(class)) => self.left.push((class, offset)),
            _ => {}
        }
    }

    #[allow(dead_code)]
    pub fn total_rewritten(&self) -> u64 {
        self.rewritten.values().sum()
    }

    pub fn rewrite(&mut self, class: &'static str) {
        *self.rewritten.entry(class).or_default() += 1;
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardware_pac_hints_are_stripped_but_bti_is_preserved() {
        for word in [0xd503211f, 0xd503215f, 0xd503219f, 0xd50321df,
            0xd503231f, 0xd503233f, 0xd503235f, 0xd503237f,
            0xd503239f, 0xd50323bf, 0xd50323df, 0xd50323ff, 0xd50320ff] {
            assert!(may_contain_pac(word));
            assert_eq!(rewrite_word(word).0, Some(NOP));
        }
        assert_eq!(rewrite_word(0xd503245f).0, None); // BTI c
    }

    #[test]
    fn standalone_pass_preserves_data_in_code_and_file_geometry() {
        let mut bytes = vec![0u8; 8192];
        let put = |bytes: &mut [u8], at: usize, word: u32| bytes[at..at + 4].copy_from_slice(&word.to_le_bytes());
        for (at, word) in [(0, 0xfeedfacf), (4, 0x100000c), (12, 2), (16, 2), (20, 176),
            (32, 25), (36, 152), (56, 0), (60, 1), (64, 8192), (80, 8192),
            (88, 5), (92, 5), (96, 1), (136, 4096), (140, 1), (144, 8),
            (152, 4096), (156, 2), (168, 0x80000400), (184, 0x80000028),
            (188, 24), (192, 4096)] { put(&mut bytes, at, word); }
        bytes[40..46].copy_from_slice(b"__TEXT");
        bytes[104..110].copy_from_slice(b"__text");
        bytes[120..126].copy_from_slice(b"__TEXT");
        let image = harmonios_runtime::macho::parse(&bytes).unwrap();
        let text = image.sections.iter().find(|s| s.flags & 0x80000400 != 0).unwrap();
        assert!(text.size >= 8);
        let text_at = text.file_offset as usize;
        bytes[text_at..text_at + 8].copy_from_slice(&[0xd65f0fffu32.to_le_bytes(); 2].concat());
        let command = 32 + super::super::cache::u32le(&bytes, 20).unwrap() as usize;
        assert!(command + 16 <= text_at);
        let count = super::super::cache::u32le(&bytes, 16).unwrap();
        bytes[16..20].copy_from_slice(&(count + 1).to_le_bytes());
        bytes[20..24].copy_from_slice(&((command - 32 + 16) as u32).to_le_bytes());
        let data = bytes.len() as u32;
        for (i, word) in [0x29u32, 16, data, 8].into_iter().enumerate() {
            bytes[command + i * 4..command + i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        bytes.extend(((text_at + 4) as u32).to_le_bytes());
        bytes.extend(4u16.to_le_bytes());
        bytes.extend(1u16.to_le_bytes());
        let before = bytes.clone();
        let report = strip_macho_code(&mut bytes).unwrap();
        assert_eq!(report.rewritten["RETAB"], 1);
        assert_eq!(&bytes[text_at..text_at + 4], &RET.to_le_bytes());
        assert_eq!(&bytes[..text_at], &before[..text_at]);
        assert_eq!(&bytes[text_at + 4..], &before[text_at + 4..]);
    }

    #[test]
    fn authenticating_returns_become_plain_ret() {
        assert_eq!(rewrite_word(0xD65F_0BFF).0, Some(RET)); // RETAA
        assert_eq!(rewrite_word(0xD65F_0FFF).0, Some(RET)); // RETAB
    }

    #[test]
    fn authenticated_branches_drop_their_key() {
        // BRAA x8 -> BR x8
        assert_eq!(rewrite_word(0xD71F_0910).0, Some(0xD61F_0100));
        // BLRAA x9 -> BLR x9
        assert_eq!(rewrite_word(0xD73F_0930).0, Some(0xD63F_0120));
    }

    #[test]
    fn pac_and_aut_instructions_become_nop() {
        for word in [0xDAC1_0830u32, 0xDAC1_0BF0, 0xDAC1_43E0, 0xDAC1_47E0] {
            assert_eq!(rewrite_word(word).0, Some(NOP), "{word:#010x}");
        }
    }

    #[test]
    fn pacga_becomes_plain_data_operation() {
        let (rewritten, class) = rewrite_word(0x9AC0_3000 | 8 << 16 | 1 << 5 | 2);
        assert_eq!(class, Some("PACGA"));
        assert!(rewritten.is_some());
    }

    #[test]
    fn ldraa_becomes_plain_ldr() {
        // LDRAA x0, [x1, #8] -> LDR x0, [x1, #8]
        let word = 0xF820_1420u32;
        let (rewritten, class) = rewrite_word(word);
        assert_eq!(class, Some("LDRAA"));
        assert_eq!(rewritten, Some(0xF940_0420));
    }

    #[test]
    fn unrelated_instructions_are_untouched() {
        for word in [0xD503_201Fu32, 0xD65F_03C0, 0xA9BF_7BFD, 0xF940_0000] {
            assert_eq!(rewrite_word(word), (None, None), "{word:#010x}");
        }
    }

    #[test]
    fn report_counts_and_classifies() {
        let mut report = PacReport::default();
        report.record(0xDAC1_0830, 0); // PACIA -> rewritten
        report.record(0xD69F_0830, 4); // ERETA -> left
        report.record(0xF940_0000, 8); // unrelated
        assert_eq!(report.total_rewritten(), 1);
        assert_eq!(report.left.len(), 1);
    }

    #[test]
    fn mode_parsing_is_explicit() {
        assert_eq!(PacMode::parse("strip"), Some(PacMode::Strip));
        assert_eq!(PacMode::parse("keysoff"), Some(PacMode::Strip));
        assert_eq!(PacMode::parse("none"), Some(PacMode::None));
        assert_eq!(PacMode::parse("bogus"), None);
    }
}
