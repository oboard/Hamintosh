mod analyzer;
mod aot;
mod device;
mod ir;
mod manifest;
mod sha256;
mod toolkit;
mod unpacker;

use device::DeviceManager;
use std::env;
use std::path::{Path, PathBuf};

fn print_usage() {
    println!(
        r#"Harmonios unified Rust toolchain

Usage:
    harmonios install <App.ipa> [--device <id>] [--bundle <name>] [--no-launch]
    harmonios convert <App.ipa> [--out <output_dir>]
    harmonios inspect <App.ipa>
    harmonios list [--device <id>]
    harmonios remove <app_dir_or_bundle> [--device <id>]
    harmonios prepare-ipa <App.ipa>
    harmonios pack-macho <Mach-O> <output_dir> [--role target|bootstrap|dyld]
    harmonios prepare-bootstrap <dyld> <cache> <output_dir>
    harmonios pack-probe <image> <assembly>
    harmonios pack-darwin-probe <output_dir>
    harmonios make-bootstrap-fixture <output_dir> --clang <path> --objcopy <path>
    harmonios cache-info <cache>
    harmonios dump-backboard-headers <cache> <output_dir> --ipsw <path>
    harmonios cache-read <cache> <VM_address> <size> <output_file>
    harmonios cache-symbol <cache> <library> <symbol>
    harmonios cache-disassemble <cache> <VM_address> [--size 256] [--output <directory>]
    harmonios cache-address <cache> <address> [--runtime-base <base>]
    harmonios cache-objc-class <cache> <classref_VM_address>
    harmonios cache-selector <cache> <stub_VM_address>
    harmonios pack-cache <cache> <output_dir> --pages <config> [--clang <path>]
    harmonios pack-cache-data <cache> <output_file>
    harmonios pack-objc-trampolines <dylib> <output_dir> [--pools 8]
    harmonios pack-objc-trampolines <dylib> --verify-elf <ELF>
    harmonios build [--clean] [--output <directory>]
    harmonios sign [--output <directory>]
    harmonios run-device [--device <id>] [--skip-build] [--skip-install] [--output <directory>]
    harmonios collect-device [--device <id>] [--output <directory>]
    harmonios repeat-run-acceptance [--runs 3] [--output <directory>]
    harmonios analyze-device-fault <report.json>
    harmonios analyze-workqueue-report <report.json>
    harmonios audit-libsystem-shim <cache> <package.json> <output_dir>
    harmonios stage-sysroot <source_dir> [--output <directory>]
    harmonios stage-system-resources <source_dir> <paths...> [--output <directory>]
    harmonios fetch-zip-member <URL> <member> <output_file> [--workers 16]
    harmonios extract-sysroot <archive> <output_dir> --ipsw <path> --pem-db <path>
    harmonios extract-bootstrap <archive> <output_dir> --ipsw <path> --cache <cache>
    harmonios render-probe

Examples:
    harmonios install /path/to/MyCoolApp.ipa
    harmonios inspect /path/to/MyCoolApp.ipa
    harmonios convert /path/to/MyCoolApp.ipa --out ./dist
    harmonios list
"#
    );
}

fn cmd_inspect(ipa_path: &Path) -> Result<(), String> {
    if !ipa_path.exists() {
        return Err(format!("IPA file not found: {:?}", ipa_path));
    }
    println!("==> Inspecting IPA: {:?}", ipa_path);
    let app = unpacker::unpack_ipa(ipa_path)?;
    let image = analyzer::analyze_app(&app, ipa_path)?;
    let json = serde_json::to_string_pretty(&image).map_err(|e| e.to_string())?;
    println!("{json}");
    Ok(())
}

fn cmd_convert(ipa_path: &Path, out_dir: Option<PathBuf>) -> Result<(), String> {
    if !ipa_path.exists() {
        return Err(format!("IPA file not found: {:?}", ipa_path));
    }
    println!("==> [1/3] Unpacking IPA: {:?}", ipa_path);
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

    let app_dir = target_out.join(&app.app_dir_name);
    println!("==> [2/3] Extracting bundle resources to {:?}", app_dir);
    let bundle_result = unpacker::extract_bundle_to_dir(ipa_path, &app_dir)?;

    println!("==> [3/3] Generating AOT packaging artifacts...");
    aot::generate_aot_artifacts(&image, &app, &bundle_result, Some(ipa_path), &app_dir)?;

    println!("\n==> Conversion completed successfully: {:?}", app_dir);
    println!("    App Name:     {}", app.bundle_name);
    println!("    Bundle ID:    {}", app.bundle_id);
    println!("    Version:      {}", app.version);
    println!("    Executable:   {}", app.executable_name);
    println!("    Total Size:   {}", bundle_result.formatted_size);
    Ok(())
}

fn cmd_install(
    ipa_path: &Path,
    device_opt: Option<&str>,
    bundle_opt: Option<&str>,
    no_launch: bool,
) -> Result<(), String> {
    toolkit::install_ipa(ipa_path, device_opt, bundle_opt, no_launch)
}

fn cmd_list(device_opt: Option<&str>) -> Result<(), String> {
    let device_mgr = DeviceManager::new()?;
    let device = device_mgr.resolve_device(device_opt)?;
    println!("==> Installed applications on device ({device}):");
    let apps = device_mgr.list_apps_on_device(&device)?;
    if apps.is_empty() {
        println!("    (No extra applications installed in Harmonios sandbox)");
    } else {
        for app in apps {
            println!("    • {}", app);
        }
    }
    Ok(())
}

fn cmd_remove(target_app: &str, device_opt: Option<&str>) -> Result<(), String> {
    let device_mgr = DeviceManager::new()?;
    let device = device_mgr.resolve_device(device_opt)?;
    let app_dir = if target_app.ends_with(".app") {
        target_app.to_string()
    } else {
        format!("{}.app", target_app)
    };
    println!("==> Removing {} from device ({})...", app_dir, device);
    device_mgr.remove_app_from_device(&device, &app_dir)?;
    println!("==> Successfully removed.");
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
        "--version" | "-V" => {
            println!("harmonios {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
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
        "install" => {
            if args.len() < 3 {
                eprintln!("Error: install requires an IPA path");
                std::process::exit(1);
            }
            let ipa_path = Path::new(&args[2]);
            let mut device_opt = None;
            let mut bundle_opt = None;
            let mut no_launch = false;

            let mut idx = 3;
            while idx < args.len() {
                if args[idx] == "--device" && idx + 1 < args.len() {
                    device_opt = Some(args[idx + 1].as_str());
                    idx += 2;
                } else if args[idx] == "--bundle" && idx + 1 < args.len() {
                    bundle_opt = Some(args[idx + 1].as_str());
                    idx += 2;
                } else if args[idx] == "--no-launch" {
                    no_launch = true;
                    idx += 1;
                } else {
                    idx += 1;
                }
            }
            cmd_install(ipa_path, device_opt, bundle_opt, no_launch)
        }
        "list" => {
            let mut device_opt = None;
            if args.len() >= 4 && args[2] == "--device" {
                device_opt = Some(args[3].as_str());
            }
            cmd_list(device_opt)
        }
        "remove" => {
            if args.len() < 3 {
                eprintln!("Error: remove requires an application name");
                std::process::exit(1);
            }
            let app_name = &args[2];
            let mut device_opt = None;
            if args.len() >= 5 && args[3] == "--device" {
                device_opt = Some(args[4].as_str());
            }
            cmd_remove(app_name, device_opt)
        }
        "--help" | "-h" | "help" => {
            print_usage();
            Ok(())
        }
        "build"
        | "sign"
        | "fetch-zip-member"
        | "fetch-zip-member-aria2"
        | "extract-sysroot"
        | "extract-bootstrap"
        | "render-probe"
        | "pack-cache"
        | "derive-demand"
        | "analyze-device-fault"
        | "analyze-workqueue-report"
        | "repeat-run-acceptance"
        | "stage-sysroot"
        | "stage-system-resources"
        | "pack-cache-data"
        | "pack-objc-trampolines"
        | "run-device"
        | "collect-device"
        | "audit-libsystem-shim"
        | "prepare-ipa"
        | "pack-macho"
        | "pack-probe"
        | "pack-darwin-probe"
        | "make-bootstrap-fixture"
        | "prepare-bootstrap"
        | "cache-read"
        | "cache-symbol"
        | "cache-disassemble"
        | "cache-address"
        | "cache-objc-class"
        | "cache-selector"
        | "dump-backboard-headers"
        | "cache-info" => toolkit::dispatch(args[1..].to_vec()),
        other => {
            eprintln!("Unknown command: {other}");
            print_usage();
            std::process::exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("\nError: {e}");
        std::process::exit(1);
    }
}
