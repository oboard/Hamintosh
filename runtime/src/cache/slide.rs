//! Streaming version-5 cache rebase chains. No multi-gigabyte pointer array is allocated.
use super::{quad, word, CacheFile, Mapping, Reader};
use crate::macho::fixups::Authentication;
use serde::Serialize;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Rebase {
    pub location_offset: u64,
    pub target_offset: u64,
    pub high8: u8,
    pub authentication: Option<Authentication>,
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub locations: u64,
    pub authenticated: u64,
    pub pages: u64,
}

pub fn walk(
    file: &CacheFile,
    mapping: &Mapping,
    cache_base: u64,
    visit: impl FnMut(&Rebase) -> Result<(), String>,
) -> Result<Summary, String> {
    walk_selected(file, mapping, cache_base, None, visit)
}

/// Read only pages intersecting the requested cache-relative ranges. Chains
/// still start at the page's original head, even when the first slot is omitted.
pub fn walk_selected(
    file: &CacheFile,
    mapping: &Mapping,
    cache_base: u64,
    ranges: Option<&[std::ops::Range<u64>]>,
    mut visit: impl FnMut(&Rebase) -> Result<(), String>,
) -> Result<Summary, String> {
    if let Some(ranges) = ranges {
        if ranges.iter().any(|r| r.start >= r.end)
            || ranges.windows(2).any(|r| r[0].end > r[1].start)
        {
            return Err("selected cache ranges overlap or are unsorted".into());
        }
    }
    if mapping.slide_info_size == 0 {
        return Ok(Summary::default());
    }
    if mapping.slide_version != Some(5) {
        return Err("only version-5 cache slides are implemented".into());
    }
    let mut reader = Reader::open(&file.path)?;
    let metadata = reader.bytes(
        mapping.slide_info_offset,
        usize::try_from(mapping.slide_info_size).map_err(|_| "slide metadata size overflow")?,
    )?;
    if metadata.len() < 24 || word(&metadata, 0) != 5 {
        return Err("invalid cache slide header".into());
    }
    let page_size = word(&metadata, 4) as usize;
    let pages = word(&metadata, 8) as usize;
    let value_add = quad(&metadata, 16);
    if !matches!(page_size, 0x1000 | 0x4000)
        || pages > 1_000_000
        || pages > mapping.size.div_ceil(page_size as u64) as usize
        || 24 + pages * 2 > metadata.len()
    {
        return Err("invalid cache slide page table".into());
    }
    let location_base = mapping
        .address
        .checked_sub(cache_base)
        .ok_or("cache mapping is below region")?;
    let mut summary = Summary::default();
    for index in 0..pages {
        let mut offset =
            u16::from_le_bytes(metadata[24 + index * 2..26 + index * 2].try_into().unwrap())
                as usize;
        if offset == 0xffff {
            continue;
        }
        let page_offset = index as u64 * page_size as u64;
        let available = (mapping.size - page_offset).min(page_size as u64) as usize;
        let page_start = location_base + page_offset;
        if ranges.is_some_and(|rs| {
            !rs.iter()
                .any(|r| r.start < page_start + available as u64 && r.end > page_start)
        }) {
            continue;
        }
        let data = reader.bytes(mapping.file_offset + page_offset, available)?;
        summary.pages += 1;
        loop {
            if offset & 7 != 0
                || offset
                    .checked_add(8)
                    .filter(|end| *end <= data.len())
                    .is_none()
            {
                return Err("cache rebase chain escapes data page".into());
            }
            let raw = quad(&data, offset);
            let auth = raw >> 63 != 0;
            if !auth && (raw >> 42) & 0x3ff != 0 {
                return Err("reserved cache rebase bits are nonzero".into());
            }
            let target = value_add
                .checked_add(raw & ((1 << 34) - 1))
                .ok_or("cache target overflow")?;
            let target_offset = target
                .checked_sub(cache_base)
                .ok_or("cache target below shared region")?;
            let rebase = Rebase {
                location_offset: location_base + page_offset + offset as u64,
                target_offset,
                high8: if auth { 0 } else { ((raw >> 34) & 255) as u8 },
                authentication: auth.then_some(Authentication {
                    key: if raw & (1 << 51) != 0 { 2 } else { 0 },
                    diversity: (raw >> 34) as u16,
                    address_diversity: raw & (1 << 50) != 0,
                }),
            };
            if ranges.is_none_or(|rs| {
                rs.iter().any(|r| {
                    r.start <= rebase.location_offset && rebase.location_offset + 8 <= r.end
                })
            }) {
                visit(&rebase)?;
                summary.locations += 1;
                summary.authenticated += auth as u64;
            }
            let next = ((raw >> 52) & 0x7ff) as usize * 8;
            if next == 0 {
                break;
            }
            offset += next;
        }
    }
    Ok(summary)
}
