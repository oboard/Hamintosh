//! Generate relocation records only for pages selected for the current launch.
use hamintosh_runtime::cache::{self, slide};
use std::{
    env,
    fs::File,
    io::{BufWriter, Write},
    ops::Range,
    path::Path,
};

fn run() -> Result<(), String> {
    let args: Vec<_> = env::args().collect();
    if args.len() != 4 {
        return Err("Usage: hm-cache-plan <cache> <ranges.json> <records.bin>".into());
    }
    let cache = cache::read(Path::new(&args[1]))?;
    let selection: Vec<[u64; 2]> =
        serde_json::from_reader(File::open(&args[2]).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let ranges: Vec<Range<u64>> = selection.into_iter().map(|r| r[0]..r[1]).collect();
    if ranges
        .iter()
        .any(|r| r.start >= r.end || r.end > cache.region_size)
        || ranges.windows(2).any(|r| r[0].end > r[1].start)
    {
        return Err("invalid selected cache ranges".into());
    }
    let mut output = BufWriter::new(File::create(&args[3]).map_err(|e| e.to_string())?);
    let mut locations = 0u64;
    let mut authenticated = 0u64;
    let mut outside = 0u64;
    for file in &cache.files {
        for mapping in &file.mappings {
            let summary =
                slide::walk_selected(file, mapping, cache.preferred_base, Some(&ranges), |r| {
                    if r.target_offset >= cache.region_size {
                        return Err("cache pointer target outside shared region".into());
                    }
                    outside += (!ranges.iter().any(|s| s.contains(&r.target_offset))) as u64;
                    let mut record = [0u8; 24];
                    record[..8].copy_from_slice(&r.location_offset.to_le_bytes());
                    record[8..16].copy_from_slice(&r.target_offset.to_le_bytes());
                    record[20] = r.high8;
                    if let Some(auth) = &r.authentication {
                        record[16..18].copy_from_slice(&auth.diversity.to_le_bytes());
                        record[18] = auth.key;
                        record[19] = 1 | ((auth.address_diversity as u8) << 1);
                    }
                    output.write_all(&record).map_err(|e| e.to_string())
                })?;
            locations += summary.locations;
            authenticated += summary.authenticated;
        }
    }
    output.flush().map_err(|e| e.to_string())?;
    println!(
        "{}",
        serde_json::json!({"locations":locations,"authenticated":authenticated,"targetsOutsideSelection":outside})
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}
