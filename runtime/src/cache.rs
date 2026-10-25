//! Read modern split dyld shared-cache layouts without loading their multi-GB contents.
use serde::Serialize;
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};
pub mod slide;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Mapping {
    pub address: u64,
    pub size: u64,
    pub file_offset: u64,
    pub max_protection: u32,
    pub protection: u32,
    pub slide_info_offset: u64,
    pub slide_info_size: u64,
    pub flags: u64,
    pub slide_version: Option<u32>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheFile {
    pub path: PathBuf,
    pub uuid: String,
    pub size: u64,
    pub mappings: Vec<Mapping>,
}

#[derive(Debug, Serialize)]
pub struct CachedImage {
    pub address: u64,
    pub path: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheSet {
    pub architecture: String,
    pub platform: u32,
    pub os_version: u32,
    pub preferred_base: u64,
    pub region_size: u64,
    pub dyld_header_address: u64,
    pub dyld_entry_address: u64,
    pub files: Vec<CacheFile>,
    pub images: Vec<CachedImage>,
}

struct Reader {
    file: File,
    size: u64,
}
impl Reader {
    fn open(path: &Path) -> Result<Self, String> {
        let file = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let size = file.metadata().map_err(|e| e.to_string())?.len();
        Ok(Self { file, size })
    }
    fn bytes(&mut self, offset: u64, size: usize) -> Result<Vec<u8>, String> {
        if size > 32 * 1024 * 1024
            || offset
                .checked_add(size as u64)
                .filter(|v| *v <= self.size)
                .is_none()
        {
            return Err("cache read exceeds file bounds or metadata limit".into());
        }
        self.file
            .seek(SeekFrom::Start(offset))
            .map_err(|e| e.to_string())?;
        let mut bytes = vec![0u8; size];
        self.file
            .read_exact(&mut bytes)
            .map_err(|e| e.to_string())?;
        Ok(bytes)
    }
    fn cstring(&mut self, offset: u64) -> Result<String, String> {
        let size = self
            .size
            .checked_sub(offset)
            .ok_or("cache string offset outside file")?
            .min(4096) as usize;
        let bytes = self.bytes(offset, size)?;
        let end = bytes
            .iter()
            .position(|v| *v == 0)
            .ok_or("unterminated cache image path")?;
        String::from_utf8(bytes[..end].to_vec()).map_err(|_| "invalid cache image path".into())
    }
}

fn word(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn quad(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}
fn uuid(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}

fn read_file(path: &Path) -> Result<(CacheFile, Vec<u8>), String> {
    let mut reader = Reader::open(path)?;
    let header = reader.bytes(0, 460)?;
    if !header.starts_with(b"dyld_v") || !header[..16].windows(5).any(|s| s == b"arm64") {
        return Err("expected ARM64 dyld shared cache".into());
    }
    let mapping_offset = word(&header, 16) as u64;
    let count = word(&header, 20) as usize;
    if !(460..=65536).contains(&mapping_offset) || count == 0 || count > 4096 {
        return Err("invalid modern cache mapping table".into());
    }
    let entries = reader.bytes(mapping_offset, count * 32)?;
    let mut mappings = vec![];
    for entry in entries.chunks_exact(32) {
        let mapping = Mapping {
            address: quad(entry, 0),
            size: quad(entry, 8),
            file_offset: quad(entry, 16),
            max_protection: word(entry, 24),
            protection: word(entry, 28),
            slide_info_offset: 0,
            slide_info_size: 0,
            flags: 0,
            slide_version: None,
        };
        if mapping.size == 0
            || mapping.address.checked_add(mapping.size).is_none()
            || mapping
                .file_offset
                .checked_add(mapping.size)
                .filter(|n| *n <= reader.size)
                .is_none()
            || mapping.protection & !7 != 0
            || mapping.protection & !mapping.max_protection != 0
        {
            return Err("invalid cache mapping range or permissions".into());
        }
        mappings.push(mapping);
    }
    let slide_offset = word(&header, 312) as u64;
    let slide_count = word(&header, 316) as usize;
    if slide_count > 0 {
        if slide_count != count {
            return Err("cache mapping and slide tables disagree".into());
        }
        let entries = reader.bytes(slide_offset, slide_count * 56)?;
        for (entry, mapping) in entries.chunks_exact(56).zip(&mut mappings) {
            if quad(entry, 0) != mapping.address
                || quad(entry, 8) != mapping.size
                || quad(entry, 16) != mapping.file_offset
                || word(entry, 48) != mapping.max_protection
                || word(entry, 52) != mapping.protection
            {
                return Err("slide mapping differs from ordinary mapping".into());
            }
            mapping.slide_info_offset = quad(entry, 24);
            mapping.slide_info_size = quad(entry, 32);
            mapping.flags = quad(entry, 40);
            if mapping.slide_info_size > 0 {
                if mapping
                    .slide_info_offset
                    .checked_add(mapping.slide_info_size)
                    .filter(|n| *n <= reader.size)
                    .is_none()
                {
                    return Err("slide info exceeds cache file".into());
                }
                mapping.slide_version = Some(word(&reader.bytes(mapping.slide_info_offset, 4)?, 0));
            }
        }
    }
    Ok((
        CacheFile {
            path: path.to_path_buf(),
            uuid: uuid(&header[88..104]),
            size: reader.size,
            mappings,
        },
        header,
    ))
}

pub fn read(path: &Path) -> Result<CacheSet, String> {
    let (primary, header) = read_file(path)?;
    let architecture = String::from_utf8_lossy(&header[8..16])
        .trim_matches([' ', '\0'])
        .to_string();
    let base = quad(&header, 224);
    let size = quad(&header, 232);
    let end = base
        .checked_add(size)
        .ok_or("shared region address overflow")?;
    if size == 0 {
        return Err("empty shared cache region".into());
    }
    let platform = word(&header, 216);
    let mut set = CacheSet {
        architecture,
        platform,
        os_version: word(&header, 364),
        preferred_base: base,
        region_size: size,
        dyld_header_address: quad(&header, 120),
        dyld_entry_address: quad(&header, 128),
        files: vec![primary],
        images: vec![],
    };
    let mut reader = Reader::open(path)?;
    let count = word(&header, 396) as usize;
    if count > 512 {
        return Err("too many shared subcaches".into());
    }
    // Modern (iOS 16+) headers use UUID / cacheVMOffset / fileSuffix entries.
    let entries = reader.bytes(word(&header, 392) as u64, count * 56)?;
    for entry in entries.chunks_exact(56) {
        let suffix = &entry[24..56];
        let len = suffix
            .iter()
            .position(|b| *b == 0)
            .ok_or("unterminated subcache suffix")?;
        let suffix = std::str::from_utf8(&suffix[..len]).map_err(|_| "invalid subcache suffix")?;
        if !suffix.starts_with('.')
            || suffix.contains("..")
            || !suffix
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err("unsafe subcache filename suffix".into());
        }
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        let (file, child_header) = read_file(Path::new(&name))?;
        if file.uuid != uuid(&entry[..16]) || word(&child_header, 216) != platform {
            return Err("subcache UUID or platform mismatch".into());
        }
        if file.mappings.iter().map(|m| m.address).min() != base.checked_add(quad(entry, 16)) {
            return Err("subcache VM offset mismatch".into());
        }
        set.files.push(file);
    }
    let mut ranges: Vec<_> = set.files.iter().flat_map(|f| &f.mappings).collect();
    ranges.sort_by_key(|m| m.address);
    for (i, mapping) in ranges.iter().enumerate() {
        if mapping.address < base
            || mapping.address + mapping.size > end
            || (i != 0 && ranges[i - 1].address + ranges[i - 1].size > mapping.address)
        {
            return Err("overlapping or out-of-region cache mappings".into());
        }
    }
    let images_offset = word(&header, 448) as u64;
    let image_count = word(&header, 452) as usize;
    if image_count > 100_000 {
        return Err("too many cached images".into());
    }
    let entries = reader.bytes(images_offset, image_count * 32)?;
    for entry in entries.chunks_exact(32) {
        let address = quad(entry, 0);
        let path = reader.cstring(word(entry, 24) as u64)?;
        if !path.starts_with('/') || !set.contains(address, 4, 1) {
            return Err("invalid cached image path or address".into());
        }
        set.images.push(CachedImage { address, path });
    }
    if set.dyld_header_address != 0 && !set.contains(set.dyld_header_address, 32, 1) {
        return Err("dyld header is outside cache mappings".into());
    }
    if set.dyld_entry_address != 0 && !set.contains(set.dyld_entry_address, 4, 4) {
        return Err("dyld entry is outside executable cache mappings".into());
    }
    Ok(set)
}

impl CacheSet {
    pub fn contains(&self, address: u64, size: u64, protection: u32) -> bool {
        self.files.iter().flat_map(|f| &f.mappings).any(|mapping| {
            address >= mapping.address
                && address
                    .checked_add(size)
                    .filter(|end| *end <= mapping.address + mapping.size)
                    .is_some()
                && mapping.protection & protection == protection
        })
    }

    pub fn file_location(&self, address: u64, size: u64) -> Option<(&Path, u64)> {
        self.files.iter().find_map(|file| {
            file.mappings.iter().find_map(|mapping| {
                if address >= mapping.address
                    && address
                        .checked_add(size)
                        .filter(|end| *end <= mapping.address + mapping.size)
                        .is_some()
                {
                    Some((
                        file.path.as_path(),
                        mapping.file_offset + address - mapping.address,
                    ))
                } else {
                    None
                }
            })
        })
    }
}
