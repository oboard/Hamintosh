use std::{env, path::Path, process::ExitCode};

fn main() -> ExitCode {
    let args: Vec<_> = env::args().collect();
    if args.len() < 2 || args.len() > 3 {
        eprintln!("Usage: hm-inspect <Mach-O executable> [iOS sysroot]");
        return ExitCode::from(2);
    }
    let report = hamintosh_runtime::report::inspect(
        Path::new(&args[1]),
        Path::new(args.get(2).map(String::as_str).unwrap_or("sysroot")),
    );
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
    if report["status"] == "blocked" {
        ExitCode::from(3)
    } else {
        ExitCode::from(2)
    }
}
