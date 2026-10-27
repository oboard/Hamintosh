use std::path::PathBuf;

#[test]
fn test_converter_inspect() {
    let _root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let ipa_path = PathBuf::from("/Users/oboard/Downloads/SwiftUIHelloWorld 2026-10-25 00-46-07/SwiftUIHelloWorld.ipa");
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
