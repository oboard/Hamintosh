use std::{env, path::Path, process::ExitCode};

fn main() -> ExitCode {
    let args: Vec<_> = env::args().collect();
    if args.len() < 2 || args.len() > 3 || (args.len() == 3 && args[2] != "--slides") {
        eprintln!("Usage: hm-cache-info <dyld_shared_cache_arm64e> [--slides]");
        return ExitCode::from(2);
    }
    match harmintosh_runtime::cache::read(Path::new(&args[1])) {
        Ok(cache) => {
            let mut result = serde_json::to_value(&cache).unwrap();
            if args.len() == 3 {
                let mut locations = 0u64;
                let mut authenticated = 0u64;
                let mut pages = 0u64;
                for file in &cache.files {
                    for mapping in &file.mappings {
                        let summary = harmintosh_runtime::cache::slide::walk(
                            file,
                            mapping,
                            cache.preferred_base,
                            |rebase| {
                                if rebase.target_offset > cache.region_size {
                                    return Err("cache rebase target exceeds shared region".into());
                                }
                                Ok(())
                            },
                        );
                        match summary {
                            Ok(summary) => {
                                locations += summary.locations;
                                authenticated += summary.authenticated;
                                pages += summary.pages;
                            }
                            Err(error) => {
                                eprintln!("{}: {error}", file.path.display());
                                return ExitCode::from(2);
                            }
                        }
                    }
                }
                result["slideSummary"] = serde_json::json!({"locations":locations,"authenticated":authenticated,"pages":pages});
            }
            println!("{}", serde_json::to_string_pretty(&result).unwrap());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(2)
        }
    }
}
