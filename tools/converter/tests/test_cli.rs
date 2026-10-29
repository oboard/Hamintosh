use std::path::PathBuf;

#[test]
fn test_converter_inspect() {
    let _root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let ipa_path = PathBuf::from(
        "/Users/oboard/Downloads/SwiftUIHelloWorld 2026-10-25 00-46-07/SwiftUIHelloWorld.ipa",
    );
    if !ipa_path.exists() {
        return;
    }
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_harmonios"))
        .args(["inspect", ipa_path.to_str().unwrap()])
        .output()
        .expect("Failed to run harmonios inspect");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("devplaceholder.HDPAWPTN.SwiftUIHelloWorld"));
    assert!(stdout.contains("SwiftUIHelloWorld"));
}

#[test]
fn test_converter_inspect_melonx() {
    let ipa_path = PathBuf::from("/Users/oboard/Downloads/MeloNX.ipa");
    if !ipa_path.exists() {
        return;
    }
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_harmonios"))
        .args(["inspect", ipa_path.to_str().unwrap()])
        .output()
        .expect("Failed to run harmonios inspect");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("com.stossy11.MeloNX"));
    assert!(stdout.contains("MeloNX"));
    assert!(stdout.contains("\"icon\": \"AppIcon60x60@2x.png\""));
}

#[test]
fn cache_debug_resolves_device_pc_and_objc_class_when_fixture_available() {
    let cache = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../artifacts/ios27-system/cache/dyld_shared_cache_arm64e");
    if !cache.exists() { return; }
    let binary = env!("CARGO_BIN_EXE_harmonios");
    let run = |args: &[&str]| {
        let output = std::process::Command::new(binary).args(args).output().unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };
    let cache_path = cache.to_str().unwrap();
    let address = run(&["cache-address", cache_path, "0x5f074af2f0", "--runtime-base", "0x5efee58000"]);
    assert_eq!(address["preferredAddress"], "0x1886572f0");
    assert_eq!(address["functionStart"], "0x188657240");
    assert!(address["image"].as_str().unwrap().ends_with("SwiftUICore.framework/SwiftUICore"));
    let class = run(&["cache-objc-class", cache_path, "0x1e01508f0"]);
    assert_eq!(class["name"], "SFSCoreGlyphsBundle");
    let invalid = std::process::Command::new(binary)
        .args(["cache-address", cache_path, "0x10", "--runtime-base", "0x20"])
        .output().unwrap();
    assert!(!invalid.status.success());
}
