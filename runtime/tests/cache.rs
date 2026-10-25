use hamintosh_runtime::cache::{self, CacheFile, Mapping};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Temporary(PathBuf);
impl Temporary {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "hamintosh-cache-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn put32(b: &mut [u8], at: usize, value: u32) {
    b[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(b: &mut [u8], at: usize, value: u64) {
    b[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
const BASE: u64 = 0x180000000;

fn cache_bytes(address: u64, id: u8, images: bool) -> Vec<u8> {
    let mut b = vec![0u8; 0x4000];
    b[..16].copy_from_slice(b"dyld_v1  arm64e\0");
    put32(&mut b, 16, 512);
    put32(&mut b, 20, 1);
    b[88..104].fill(id);
    put32(&mut b, 216, 2);
    put64(&mut b, 224, BASE);
    put64(&mut b, 232, 0x8000);
    put32(&mut b, 312, 544);
    put32(&mut b, 316, 1);
    for start in [512, 544] {
        put64(&mut b, start, address);
        put64(&mut b, start + 8, 0x2000);
        put64(&mut b, start + 16, 0);
    }
    put32(&mut b, 536, 5);
    put32(&mut b, 540, 5);
    put32(&mut b, 592, 5);
    put32(&mut b, 596, 5);
    if images {
        put64(&mut b, 120, address + 0x1000);
        put64(&mut b, 128, address + 0x1100);
        put32(&mut b, 448, 600);
        put32(&mut b, 452, 1);
        put64(&mut b, 600, address + 0x1000);
        put32(&mut b, 624, 632);
        b[632..646].copy_from_slice(b"/usr/lib/dyld\0");
    }
    b
}

#[test]
fn reads_split_cache_and_translates_vm_addresses_with_uuid_checks() {
    let tmp = Temporary::new();
    let path = tmp.0.join("cache");
    let mut primary = cache_bytes(BASE, 1, true);
    put32(&mut primary, 392, 0x800);
    put32(&mut primary, 396, 1);
    primary[0x800..0x810].fill(2);
    put64(&mut primary, 0x810, 0x4000);
    primary[0x818..0x81b].copy_from_slice(b".01");
    fs::write(&path, &primary).unwrap();
    let child = tmp.0.join("cache.01");
    fs::write(&child, cache_bytes(BASE + 0x4000, 2, false)).unwrap();
    let cache = cache::read(&path).unwrap();
    assert_eq!(cache.files.len(), 2);
    assert_eq!(cache.images[0].path, "/usr/lib/dyld");
    assert_eq!(
        cache.file_location(BASE + 0x5100, 4),
        Some((child.as_path(), 0x1100))
    );
    assert!(cache.contains(BASE + 0x1100, 4, 4));
    assert!(!cache.contains(BASE + 0x1100, 4, 2));
    assert!(cache.file_location(BASE + 0x3000, 8).is_none());
    let mut bad = cache_bytes(BASE + 0x4000, 3, false);
    fs::write(&child, &bad).unwrap();
    assert!(cache::read(&path).unwrap_err().contains("UUID"));
    bad[88..104].fill(2);
    put64(&mut bad, 512, BASE + 0x1000);
    put64(&mut bad, 544, BASE + 0x1000);
    fs::write(&child, &bad).unwrap();
    assert!(cache::read(&path).is_err());
}

#[test]
fn rejects_missing_members_unsafe_suffixes_and_truncated_ranges() {
    let tmp = Temporary::new();
    let path = tmp.0.join("cache");
    let mut b = cache_bytes(BASE, 1, true);
    put32(&mut b, 392, 0x800);
    put32(&mut b, 396, 1);
    b[0x800..0x810].fill(2);
    put64(&mut b, 0x810, 0x4000);
    b[0x818..0x81b].copy_from_slice(b".01");
    fs::write(&path, &b).unwrap();
    assert!(cache::read(&path).is_err());
    b[0x818..0x81e].copy_from_slice(b"../bad");
    fs::write(&path, &b).unwrap();
    assert!(cache::read(&path).unwrap_err().contains("unsafe"));
    let mut b = cache_bytes(BASE, 1, true);
    put64(&mut b, 520, 0x10000);
    fs::write(&path, &b).unwrap();
    assert!(cache::read(&path).is_err());
    fs::write(&path, &b[..459]).unwrap();
    assert!(cache::read(&path).is_err());
}

fn slide_fixture(path: PathBuf) -> (CacheFile, Mapping, Vec<u8>) {
    let mapping = Mapping {
        address: BASE + 0x4000,
        size: 0x1000,
        file_offset: 0x1000,
        max_protection: 3,
        protection: 1,
        slide_info_offset: 0x3000,
        slide_info_size: 26,
        flags: 4,
        slide_version: Some(5),
    };
    let mut b = vec![0u8; 0x4000];
    let auth = (1u64 << 63) | (1 << 52) | (1 << 51) | (1 << 50) | (0x1234 << 34) | 0x100;
    put64(&mut b, 0x1000, auth);
    put64(&mut b, 0x1008, (0xabu64 << 34) | 0x200);
    put32(&mut b, 0x3000, 5);
    put32(&mut b, 0x3004, 0x1000);
    put32(&mut b, 0x3008, 1);
    put64(&mut b, 0x3010, BASE);
    (
        CacheFile {
            path,
            uuid: "test".into(),
            size: b.len() as u64,
            mappings: vec![],
        },
        mapping,
        b,
    )
}

#[test]
fn cache_v5_chains_decode_data_key_diversity_and_top_byte() {
    let tmp = Temporary::new();
    let (file, mapping, b) = slide_fixture(tmp.0.join("slides"));
    fs::write(&file.path, &b).unwrap();
    let mut calls = 0;
    let result = cache::slide::walk(&file, &mapping, BASE, |rebase| {
        if calls == 0 {
            assert_eq!(rebase.location_offset, 0x4000);
            assert_eq!(rebase.target_offset, 0x100);
            let auth = rebase.authentication.as_ref().unwrap();
            assert_eq!(auth.key, 2);
            assert_eq!(auth.diversity, 0x1234);
            assert!(auth.address_diversity);
        } else {
            assert_eq!(rebase.location_offset, 0x4008);
            assert_eq!(rebase.target_offset, 0x200);
            assert_eq!(rebase.high8, 0xab);
            assert!(rebase.authentication.is_none());
        }
        calls += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(result.locations, 2);
    assert_eq!(result.authenticated, 1);
    assert_eq!(result.pages, 1);
}

#[test]
fn selected_cache_slots_follow_the_page_head_without_emitting_other_slots() {
    let tmp = Temporary::new();
    let (file, mapping, b) = slide_fixture(tmp.0.join("selected-slides"));
    fs::write(&file.path, &b).unwrap();
    let mut offsets = vec![];
    let selected = 0x4008..0x4010;
    let summary = cache::slide::walk_selected(
        &file,
        &mapping,
        BASE,
        Some(std::slice::from_ref(&selected)),
        |r| {
            offsets.push(r.location_offset);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(offsets, [0x4008]);
    assert_eq!(summary.locations, 1);
    assert_eq!(summary.authenticated, 0);
    assert_eq!(summary.pages, 1);
    let omitted = 0x8000..0x9000;
    let summary = cache::slide::walk_selected(
        &file,
        &mapping,
        BASE,
        Some(std::slice::from_ref(&omitted)),
        |_| panic!("unselected page was visited"),
    )
    .unwrap();
    assert_eq!(summary.pages, 0);
    assert!(cache::slide::walk_selected(
        &file,
        &mapping,
        BASE,
        Some(&[0x4000..0x4010, 0x4008..0x4020]),
        |_| Ok(())
    )
    .is_err());
}

#[test]
fn invalid_cache_slide_metadata_and_page_links_are_bounded() {
    let tmp = Temporary::new();
    let (file, mapping, b) = slide_fixture(tmp.0.join("slides"));
    for at in [0x3000, 0x3004, 0x3008, 0x3018, 0x3019] {
        let mut bad = b.clone();
        bad[at] = 0xff;
        fs::write(&file.path, &bad).unwrap();
        assert!(cache::slide::walk(&file, &mapping, BASE, |_| Ok(())).is_err());
    }
    let mut bad = b.clone();
    put64(&mut bad, 0x1000, (1u64 << 63) | (0x7ff << 52) | 0x100);
    fs::write(&file.path, &bad).unwrap();
    assert!(cache::slide::walk(&file, &mapping, BASE, |_| Ok(())).is_err());
}
