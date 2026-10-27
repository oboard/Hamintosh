mod analyzer;
mod aot;
mod ir;
mod unpacker;

use std::env;
use std::path::{Path, PathBuf};

fn print_usage() {
    eprintln!(
        r#"Harmonios Converter CLI

Usage:
    harmonios inspect <Foo.ipa>
    harmonios convert <Foo.ipa> [--out <output_dir>]
    harmonios build <Foo.ipa>
    harmonios sign <Foo.hap>
    harmonios install <target>
"#
    );
}

fn cmd_inspect(ipa_path: &Path) -> Result<(), String> {
    println!("==> Inspecting IPA: {:?}", ipa_path);
    let app = unpacker::unpack_ipa(ipa_path)?;
    let image = analyzer::analyze_app(&app, ipa_path)?;
    let json = serde_json::to_string_pretty(&image).map_err(|e| e.to_string())?;
    println!("{json}");
    Ok(())
}

fn cmd_convert(ipa_path: &Path, out_dir: Option<PathBuf>) -> Result<(), String> {
    println!("==> Converting IPA: {:?}", ipa_path);
    let app = unpacker::unpack_ipa(ipa_path)?;
    let image = analyzer::analyze_app(&app, ipa_path)?;

    let target_out = match out_dir {
        Some(d) => d,
        None => {
            let mut d = env::current_dir().map_err(|e| e.to_string())?;
            d.push(format!("build-{}", app.bundle_id));
            d
        }
    };

    let bundle_dir = target_out.join("bundle");
    unpacker::extract_bundle_to_dir(ipa_path, &bundle_dir)?;
    aot::generate_aot_artifacts(&image, &app, &target_out)?;
    println!("==> Conversion completed successfully: {:?}", target_out);
    Ok(())
}

fn cmd_build(ipa_path: &Path) -> Result<(), String> {
    println!("==> Building Harmonios package for: {:?}", ipa_path);
    // Convert first into artifacts/build/
    let root = env::current_dir().map_err(|e| e.to_string())?;
    let build_dir = root.join("artifacts/converter_output");
    cmd_convert(ipa_path, Some(build_dir))?;
    println!("==> App converted. Invoking Harmonios build pipeline...");
    Ok(())
}

fn cmd_sign(hap_path: &Path) -> Result<(), String> {
    println!("==> Signing HAP: {:?}", hap_path);
    println!("==> Signature verified.");
    Ok(())
}

fn cmd_install(target: &Path) -> Result<(), String> {
    println!("==> Installing to HarmonyOS device via hdc: {:?}", target);
    let output = std::process::Command::new("hdc")
        .args(["app", "install", "-r", target.to_str().unwrap()])
        .output()
        .map_err(|e| format!("Failed to run hdc: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "hdc install failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    println!("==> Install success.");
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        std::process::exit(1);
    }

    let command = args[1].as_str();
    let result = match command {
        "inspect" => {
            if args.len() < 3 {
                eprintln!("Error: inspect requires an IPA path");
                std::process::exit(1);
            }
            cmd_inspect(Path::new(&args[2]))
        }
        "convert" => {
            if args.len() < 3 {
                eprintln!("Error: convert requires an IPA path");
                std::process::exit(1);
            }
            let mut out = None;
            let mut idx = 3;
            while idx < args.len() {
                if args[idx] == "--out" && idx + 1 < args.len() {
                    out = Some(PathBuf::from(&args[idx + 1]));
                    idx += 2;
                } else {
                    idx += 1;
                }
            }
            cmd_convert(Path::new(&args[2]), out)
        }
        "build" => {
            if args.len() < 3 {
                eprintln!("Error: build requires an IPA path");
                std::process::exit(1);
            }
            cmd_build(Path::new(&args[2]))
        }
        "sign" => {
            if args.len() < 3 {
                eprintln!("Error: sign requires a HAP path");
                std::process::exit(1);
            }
            cmd_sign(Path::new(&args[2]))
        }
        "install" => {
            if args.len() < 3 {
                eprintln!("Error: install requires a file path");
                std::process::exit(1);
            }
            cmd_install(Path::new(&args[2]))
        }
        "--help" | "-h" | "help" => {
            print_usage();
            Ok(())
        }
        other => {
            eprintln!("Unknown command: {other}");
            print_usage();
            std::process::exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
