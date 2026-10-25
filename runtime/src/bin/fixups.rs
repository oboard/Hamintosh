use harmonios_runtime::macho;
use std::{env, fs, process::ExitCode};

fn main() -> ExitCode {
    let args: Vec<_> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: hm-fixups <Mach-O>");
        return ExitCode::from(2);
    }
    let result = fs::read(&args[1])
        .map_err(|e| e.to_string())
        .and_then(|bytes| {
            let image = macho::parse(&bytes)?;
            macho::fixups::parse(&bytes, &image)
        });
    match result {
        Ok(plan) => {
            println!("{}", serde_json::to_string_pretty(&plan).unwrap());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(2)
        }
    }
}
