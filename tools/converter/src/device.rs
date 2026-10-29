use std::path::PathBuf;
use std::process::Command;

pub struct DeviceManager {
    pub hdc_path: PathBuf,
}

impl DeviceManager {
    pub fn new() -> Result<Self, String> {
        let hdc_path = find_hdc().ok_or_else(|| {
            "Could not locate 'hdc' binary. Please ensure DevEco Studio toolchains are in your PATH.".to_string()
        })?;
        Ok(Self { hdc_path })
    }

    pub fn list_targets(&self) -> Result<Vec<String>, String> {
        let output = Command::new(&self.hdc_path)
            .arg("list")
            .arg("targets")
            .output()
            .map_err(|e| format!("Failed to execute hdc: {e}"))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut targets = Vec::new();
        for line in stdout.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty()
                && !trimmed.contains("[Fail]")
                && !trimmed.contains("No any target")
                && !trimmed.contains("empty")
            {
                targets.push(trimmed.to_string());
            }
        }
        Ok(targets)
    }

    pub fn resolve_device(&self, user_device: Option<&str>) -> Result<String, String> {
        let targets = self.list_targets()?;
        if targets.is_empty() {
            return Err(
                "No HarmonyOS device connected via HDC.\nPlease connect your device via USB or Wi-Fi and verify 'hdc list targets'."
                    .to_string(),
            );
        }

        if let Some(dev) = user_device {
            if targets.iter().any(|t| t == dev) {
                return Ok(dev.to_string());
            }
            return Err(format!(
                "Specified device '{dev}' not found. Available targets: {:?}",
                targets
            ));
        }

        // Default: pick first connected target
        Ok(targets[0].clone())
    }

    pub fn list_apps_on_device(&self, device: &str) -> Result<Vec<String>, String> {
        let output = Command::new(&self.hdc_path)
            .args([
                "-t",
                device,
                "shell",
                "ls",
                "/data/app/el2/100/base/fun.oboard.hamintosh/haps/harmonios/files/apps",
            ])
            .output()
            .map_err(|e| format!("Failed to list apps on device: {e}"))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut apps = Vec::new();
        for line in stdout.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() && trimmed.ends_with(".app") {
                apps.push(trimmed.to_string());
            }
        }
        Ok(apps)
    }

    pub fn remove_app_from_device(&self, device: &str, app_dir_name: &str) -> Result<(), String> {
        let target_dir = format!(
            "/data/app/el2/100/base/fun.oboard.hamintosh/haps/harmonios/files/apps/{}",
            app_dir_name
        );
        let output = Command::new(&self.hdc_path)
            .args(["-t", device, "shell", "rm", "-rf", &target_dir])
            .output()
            .map_err(|e| format!("Failed to remove app on device: {e}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Failed to delete {target_dir}: {stderr}"));
        }
        Ok(())
    }
}

fn find_hdc() -> Option<PathBuf> {
    if let Ok(path) = which::which("hdc") {
        return Some(path);
    }

    let candidates = [
        "/Applications/DevEco-Studio.app/Contents/sdk/default/openharmony/toolchains/hdc",
        "/Applications/DevEco-Studio.app/Contents/sdk/HarmonyOS-NEXT-DB6/openharmony/toolchains/hdc",
    ];

    for c in &candidates {
        let p = PathBuf::from(c);
        if p.is_file() {
            return Some(p);
        }
    }

    None
}

mod which {
    use std::env;
    use std::path::PathBuf;

    pub fn which(name: &str) -> Result<PathBuf, ()> {
        if let Ok(paths) = env::var("PATH") {
            for path_str in env::split_paths(&paths) {
                let candidate = path_str.join(name);
                if candidate.is_file() {
                    return Ok(candidate);
                }
            }
        }
        Err(())
    }
}
