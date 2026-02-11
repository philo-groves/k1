use std::fs;
use std::path::Path;
use std::process::Command;

pub fn clean() -> Result<(), String> {
    let k1_dir = Path::new(".k1");
    if k1_dir.exists() {
        fs::remove_dir_all(k1_dir)
            .map_err(|err| format!("failed to remove {}: {err}", k1_dir.display()))?;
    }

    let status = Command::new("cargo")
        .arg("clean")
        .status()
        .map_err(|err| format!("failed to run cargo clean: {err}"))?;

    if status.success() {
        Ok(())
    } else {
        Err(format!("cargo clean failed: exit status {status}"))
    }
}
