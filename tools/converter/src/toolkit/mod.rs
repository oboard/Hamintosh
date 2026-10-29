mod cache;
mod cache_debug;
mod cache_pack;
mod data_pack;
mod device;
mod download;
mod extract;
mod fixtures;
mod headers;
mod macho;
mod objc;
mod pacstrip;
mod reports;
mod staging;
use serde_json::Value;
use std::{
    path::{Path, PathBuf},
    process::Command,
};
type Result<T> = std::result::Result<T, String>;
fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}
fn read(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))
}
fn write(path: &Path, bytes: impl AsRef<[u8]>) -> Result<()> {
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p).map_err(|e| e.to_string())?;
    }
    std::fs::write(path, bytes).map_err(|e| format!("{}: {e}", path.display()))
}
#[allow(dead_code)]
fn json(path: &Path) -> Result<Value> {
    serde_json::from_slice(&read(path)?).map_err(|e| e.to_string())
}
fn write_json(path: &Path, v: &impl serde::Serialize) -> Result<()> {
    write(
        path,
        format!(
            "{}\n",
            serde_json::to_string_pretty(v).map_err(|e| e.to_string())?
        ),
    )
}
fn hash(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}
fn run(c: &mut Command) -> Result<String> {
    let o = c.output().map_err(|e| e.to_string())?;
    if !o.status.success() {
        return Err(format!(
            "{c:?}: {}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&o.stdout).into_owned())
}
fn arg(args: &[String], i: usize) -> Result<&str> {
    args.get(i)
        .map(String::as_str)
        .ok_or_else(|| "missing argument (harmonios <command> <input> <output>)".into())
}
fn option<'a>(a: &'a [String], n: &str) -> Option<&'a str> {
    a.iter()
        .position(|s| s == n)
        .and_then(|i| a.get(i + 1))
        .map(String::as_str)
}
pub fn dispatch(a: Vec<String>) -> Result<()> {
    if a.iter().any(|arg| arg == "--help" || arg == "-h") {
        crate::print_usage();
        return Ok(());
    }
    match arg(&a, 0)? {
        "dump-backboard-headers" => headers::dump(
            Path::new(arg(&a, 1)?), Path::new(arg(&a, 2)?),
            Path::new(option(&a, "--ipsw").ok_or("--ipsw required")?),
        ),
        "build" | "sign" => {
            let mut options = a[1..].to_vec();
            options.push("--build-only".into());
            device::execute(&options, false)
        }
        "fetch-zip-member" | "fetch-zip-member-aria2" => {
            let workers = option(&a, "--workers")
                .or_else(|| option(&a, "--connections"))
                .unwrap_or("16")
                .parse::<usize>()
                .map_err(|e| e.to_string())?;
            download::download(arg(&a, 1)?, arg(&a, 2)?, Path::new(arg(&a, 3)?), workers)
        }
        "extract-sysroot" => extract::sysroot(
            Path::new(arg(&a, 1)?),
            Path::new(arg(&a, 2)?),
            Path::new(option(&a, "--ipsw").ok_or("--ipsw required")?),
            Path::new(option(&a, "--pem-db").ok_or("--pem-db required")?),
        ),
        "extract-bootstrap" => extract::bootstrap(
            Path::new(arg(&a, 1)?),
            Path::new(arg(&a, 2)?),
            Path::new(option(&a, "--ipsw").ok_or("--ipsw required")?),
            Path::new(option(&a, "--cache").ok_or("--cache required")?),
        ),
        "render-probe" => {
            for (path, words) in [
                (
                    "System/Library/Frameworks/QuartzCore.framework/QuartzCore",
                    vec![
                        "kCARender",
                        "CARenderSoftware",
                        "CARenderOGL",
                        "CARenderCARP",
                    ],
                ),
                (
                    "System/Library/Frameworks/IOSurface.framework/IOSurface",
                    vec![
                        "IOSurfaceCreate",
                        "IOSurfaceLock",
                        "IOSurfaceGetBaseAddress",
                        "IOConnect",
                    ],
                ),
                (
                    "System/Library/Frameworks/IOKit.framework/Versions/A/IOKit",
                    vec!["IOConnectTrap", "IOServiceOpen"],
                ),
            ] {
                let output = run(Command::new("nm")
                    .arg("-g")
                    .arg(root().join("artifacts/ios27-extract").join(path)))?;
                println!("{path}");
                for line in output
                    .lines()
                    .filter(|line| words.iter().any(|word| line.contains(word)))
                {
                    println!("{line}")
                }
            }
            Ok(())
        }
        "derive-demand" => {
            let overrides = option(&a, "--overrides").map(Path::new);
            let demand = cache_pack::derive_demand(
                Path::new(arg(&a, 1)?),
                Path::new(arg(&a, 2)?),
                overrides,
            )?;
            println!(
                "{}",
                serde_json::to_string_pretty(&demand).map_err(|e| e.to_string())?
            );
            Ok(())
        }
        "pack-cache" => {
            let clang=option(&a,"--clang").map(PathBuf::from).unwrap_or_else(||PathBuf::from("/Applications/DevEco-Studio.app/Contents/sdk/default/hms/native/BiSheng/bin/clang"));
            let pac_mode = match option(&a, "--pac") {
                Some(value) => pacstrip::PacMode::parse(value)
                    .ok_or_else(|| "--pac expects one of: strip, none".to_string())?,
                None => pacstrip::PacMode::Strip,
            };
            let manifest = cache_pack::pack(
                Path::new(arg(&a, 1)?),
                Path::new(arg(&a, 2)?),
                &clang,
                option(&a, "--pages").map(Path::new),
                a.iter().any(|v| v == "--full"),
                pac_mode,
            )?;
            println!("{}",serde_json::to_string_pretty(&serde_json::json!({"library":manifest["library"],"selectedBytes":manifest["selectedBytes"]})).map_err(|e|e.to_string())?);
            Ok(())
        }
        "analyze-device-fault" | "analyze-workqueue-report" => {
            let value = if a[0] == "analyze-device-fault" {
                reports::fault(Path::new(arg(&a, 1)?))?
            } else {
                reports::workqueue(Path::new(arg(&a, 1)?))?
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&value).map_err(|e| e.to_string())?
            );
            Ok(())
        }
        "repeat-run-acceptance" => reports::repeat(&a[1..]),
        "stage-sysroot" => staging::sysroot(
            Path::new(arg(&a, 1)?),
            &option(&a, "--output")
                .map(PathBuf::from)
                .unwrap_or_else(|| root().join("harmonios/src/main/resources/rawfile/sysroot")),
        ),
        "stage-system-resources" => {
            let end = a.iter().position(|s| s == "--output").unwrap_or(a.len());
            let out = option(&a, "--output")
                .map(PathBuf::from)
                .unwrap_or_else(|| root().join("harmonios/src/main/resources/rawfile/sysroot"));
            let result = staging::resources(Path::new(arg(&a, 1)?), &out, &a[2..end])?;
            println!(
                "{}",
                serde_json::to_string_pretty(&result).map_err(|e| e.to_string())?
            );
            Ok(())
        }
        "pack-cache-data" => {
            let manifest = data_pack::pack(Path::new(arg(&a, 1)?), Path::new(arg(&a, 2)?))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&manifest).map_err(|e| e.to_string())?
            );
            Ok(())
        }
        "pack-objc-trampolines" => {
            let pools = option(&a, "--pools")
                .unwrap_or("8")
                .parse::<usize>()
                .map_err(|e| e.to_string())?;
            let result = if let Some(elf) = option(&a, "--verify-elf") {
                objc::verify(Path::new(arg(&a, 1)?), Path::new(elf), pools)?
            } else {
                objc::pack(Path::new(arg(&a, 1)?), Path::new(arg(&a, 2)?), pools)?
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&result).map_err(|e| e.to_string())?
            );
            Ok(())
        }
        "run-device" => device::execute(&a[1..], false),
        "collect-device" => device::execute(&a[1..], true),
        "audit-libsystem-shim" => {
            device::audit(
                Path::new(arg(&a, 1)?),
                Path::new(arg(&a, 2)?),
                Path::new(arg(&a, 3)?),
            )?;
            Ok(())
        }
        "pack-macho" => macho::pack(
            Path::new(arg(&a, 1)?),
            Path::new(arg(&a, 2)?),
            option(&a, "--role").unwrap_or("target"),
        ),
        "prepare-ipa" => fixtures::prepare_ipa(a.get(1).map(Path::new)),
        "pack-probe" => fixtures::pack_probe(Path::new(arg(&a, 1)?), Path::new(arg(&a, 2)?)),
        "pack-darwin-probe" => fixtures::darwin(Path::new(arg(&a, 1)?)),
        "make-bootstrap-fixture" => fixtures::bootstrap(
            Path::new(arg(&a, 1)?),
            option(&a, "--clang").ok_or("--clang required")?,
            option(&a, "--objcopy").ok_or("--objcopy required")?,
        ),
        "prepare-bootstrap" => macho::bootstrap(
            Path::new(arg(&a, 1)?),
            Path::new(arg(&a, 2)?),
            Path::new(arg(&a, 3)?),
        ),
        "cache-read" => {
            let parse = |s: &str| -> Result<u64> {
                if let Some(hex) = s.strip_prefix("0x") {
                    u64::from_str_radix(hex, 16).map_err(|e| e.to_string())
                } else {
                    s.parse()
                        .map_err(|e: std::num::ParseIntError| e.to_string())
                }
            };
            let c = cache::load(Path::new(arg(&a, 1)?))?;
            let address = parse(arg(&a, 2)?)?;
            let size = usize::try_from(parse(arg(&a, 3)?)?).map_err(|e| e.to_string())?;
            write(Path::new(arg(&a, 4)?), cache::vm(&c, address, size)?)
        }
        "cache-disassemble" => {
            let size = usize::try_from(cache_debug::number(option(&a, "--size").unwrap_or("256"))?)
                .map_err(|e| e.to_string())?;
            let out = option(&a, "--output")
                .map(PathBuf::from)
                .unwrap_or_else(|| root().join("artifacts/cache-disassembly"));
            let llvm = option(&a, "--llvm").unwrap_or(
                "/Applications/DevEco-Studio.app/Contents/sdk/default/openharmony/native/llvm/bin",
            );
            println!(
                "{}",
                cache_debug::disassemble(
                    Path::new(arg(&a, 1)?),
                    cache_debug::number(arg(&a, 2)?)?,
                    size,
                    &out,
                    Path::new(llvm)
                )?
            );
            Ok(())
        }
        "cache-address" => {
            let base = option(&a, "--runtime-base").map(cache_debug::number).transpose()?;
            println!("{}", cache_debug::address(Path::new(arg(&a, 1)?), cache_debug::number(arg(&a, 2)?)?, base)?);
            Ok(())
        }
        "cache-objc-class" => {
            println!("{}", cache_debug::objc_class(Path::new(arg(&a, 1)?), cache_debug::number(arg(&a, 2)?)?)?);
            Ok(())
        }
        "cache-selector" => {
            println!(
                "{}",
                cache_debug::selector(Path::new(arg(&a, 1)?), cache_debug::number(arg(&a, 2)?)?)?
            );
            Ok(())
        }
        "cache-symbol" => {
            let c = cache::load(Path::new(arg(&a, 1)?))?;
            let offset = match option(&a, "--kind").unwrap_or("code") {
                "code" => cache::code_export(&c, arg(&a, 2)?, arg(&a, 3)?)?,
                "objc" => cache::export(&c, arg(&a, 2)?, arg(&a, 3)?, false)?,
                "swift" => cache::export(&c, arg(&a, 2)?, arg(&a, 3)?, true)?,
                _ => return Err("symbol kind must be code, objc or swift".into()),
            };
            println!(
                "{}",
                serde_json::json!({"symbol":arg(&a, 3)?,"offset":offset,"address":format!("{:#x}", c.preferred_base + offset)})
            );
            Ok(())
        }
        "cache-info" => {
            let c = harmonios_runtime::cache::read(Path::new(arg(&a, 1)?))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&c).map_err(|e| e.to_string())?
            );
            Ok(())
        }
        "--help" | "help" => {
            println!("harmonios commands: prepare-ipa, pack-macho, pack-probe, pack-darwin-probe, make-bootstrap-fixture, prepare-bootstrap, cache-info");
            Ok(())
        }
        c => Err(format!("unknown command: {c}")),
    }
}

pub(crate) fn pack_target(input: &Path, out: &Path) -> Result<()> {
    macho::pack(input, out, "target")
}

pub(crate) fn install_ipa(
    ipa: &Path,
    device: Option<&str>,
    bundle: Option<&str>,
    no_launch: bool,
) -> Result<()> {
    fixtures::prepare_ipa(Some(ipa))?;
    let mut args = vec![
        "--output".into(),
        root()
            .join("artifacts/install")
            .to_string_lossy()
            .into_owned(),
    ];
    if let Some(id) = device {
        args.extend(["--device".into(), id.into()]);
    }
    if let Some(id) = bundle {
        args.extend(["--bundle".into(), id.into()]);
    }
    if no_launch {
        args.push("--no-launch".into());
    }
    device::execute(&args, false)
}
