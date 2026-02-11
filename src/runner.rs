use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn run(binary: String, binary_args: Vec<String>) -> Result<(), String> {
    println!("binary: {binary}");
    crate::builder::build(binary.clone())?;

    let arch = crate::builder::detect_arch(&binary)?;
    let workspace_root = crate::builder::workspace_root_from_binary(&binary)?;
    let image_name = crate::builder::image_name_from_binary(&binary);
    let karch = arch.karch();
    let build_dir = workspace_root.join(".k1").join("build");
    let iso_path = build_dir.join(format!("{image_name}.iso"));
    let ovmf_code = build_dir.join("ovmf").join(format!("ovmf-code-{karch}.fd"));
    let ovmf_vars = build_dir.join("ovmf").join(format!("ovmf-vars-{karch}.fd"));

    let mut qemu_cmd = Command::new(format!("qemu-system-{karch}"));

    let testing_mode = is_testing_mode(&binary, &binary_args);

    let mut debugcon_path: Option<PathBuf> = None;

    match arch {
        crate::builder::Arch::X86_64 => {
            qemu_cmd
                .arg("-M")
                .arg("q35")
                .arg("-drive")
                .arg(format!(
                    "if=pflash,unit=0,format=raw,file={},readonly=on",
                    ovmf_code.display()
                ))
                .arg("-drive")
                .arg(format!(
                    "if=pflash,unit=1,format=raw,file={}",
                    ovmf_vars.display()
                ))
                .arg("-cdrom")
                .arg(&iso_path);

            if testing_mode {
                let debugcon = debugcon_output_path(&workspace_root)?;
                debugcon_path = Some(debugcon.clone());
                qemu_cmd
                    .arg("-debugcon")
                    .arg(format!("file:{}", debugcon.display()))
                    .arg("-device")
                    .arg("isa-debug-exit,iobase=0xf4,iosize=0x04")
                    .arg("-monitor")
                    .arg("none")
                    .arg("-serial")
                    .arg("none")
                    .arg("-no-reboot")
                    .arg("-nographic");
            }
        }
        crate::builder::Arch::Aarch64 => {
            qemu_cmd
                .arg("-M")
                .arg("virt")
                .arg("-cpu")
                .arg("cortex-a72")
                .arg("-device")
                .arg("ramfb")
                .arg("-device")
                .arg("qemu-xhci")
                .arg("-device")
                .arg("usb-kbd")
                .arg("-device")
                .arg("usb-mouse")
                .arg("-drive")
                .arg(format!(
                    "if=pflash,unit=0,format=raw,file={},readonly=on",
                    ovmf_code.display()
                ))
                .arg("-drive")
                .arg(format!(
                    "if=pflash,unit=1,format=raw,file={}",
                    ovmf_vars.display()
                ))
                .arg("-cdrom")
                .arg(&iso_path);

            if testing_mode {
                let debugcon = debugcon_output_path(&workspace_root)?;
                debugcon_path = Some(debugcon.clone());
                qemu_cmd
                    .arg("-serial")
                    .arg(format!("file:{}", debugcon.display()))
                    .arg("-monitor")
                    .arg("none")
                    .arg("-no-reboot")
                    .arg("-nographic");
            }
        }
    }

    if let Ok(flags) = env::var("QEMUFLAGS") {
        for flag in flags.split_whitespace() {
            qemu_cmd.arg(flag);
        }
    }

    run_command(&mut qemu_cmd, "failed to run qemu", testing_mode, arch)?;

    if let Some(path) = debugcon_path {
        finalize_debugcon_file(&path, &workspace_root)?;
    }

    Ok(())
}

fn is_testing_mode(binary: &str, binary_args: &[String]) -> bool {
    if env::var("K1_TEST").is_ok() || env::var("KERNEL_TEST").is_ok() {
        return true;
    }

    if let Ok(profile) = env::var("CARGO_PROFILE") {
        if profile == "test" {
            return true;
        }
    }

    if env::var("CARGO_CFG_TEST").is_ok() {
        return true;
    }

    if binary.contains("/deps/") || binary.contains("\\deps\\") {
        return true;
    }

    binary_args.iter().any(|arg| {
        arg == "--test"
            || arg == "--nocapture"
            || arg == "--ignored"
            || arg == "--list"
            || arg == "--exact"
            || arg.starts_with("--test-")
            || arg.starts_with("--bench")
    })
}

fn debugcon_output_path(workspace_root: &Path) -> Result<std::path::PathBuf, String> {
    let dir = workspace_root.join(".k1").join("testing");
    std::fs::create_dir_all(&dir)
        .map_err(|err| format!("failed to create {}: {err}", dir.display()))?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| format!("failed to read system time: {err}"))?;
    let file_name = format!("debugcon-{}-{}.jsonl", now.as_secs(), now.subsec_nanos());
    Ok(dir.join(file_name))
}

fn finalize_debugcon_file(path: &Path, workspace_root: &Path) -> Result<(), String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    let cleaned = strip_ansi_and_control(&raw);
    let json_candidates = extract_json_objects(&cleaned);
    let mut json_lines: Vec<String> = Vec::new();

    for candidate in json_candidates {
        let trimmed = candidate.trim();
        if serde_json::from_str::<serde_json::Value>(trimmed).is_ok() {
            json_lines.push(trimmed.to_string());
        }
    }

    if json_lines.is_empty() {
        return Err(format!(
            "missing test_group in {} (no JSON output emitted; possible early panic before kunit init)",
            path.display()
        ));
    }

    let value: serde_json::Value = serde_json::from_str(&json_lines[0])
        .map_err(|err| format!("failed to parse test_group JSON: {err}"))?;
    let test_group = value
        .get("test_group")
        .and_then(|value| value.as_str())
        .ok_or_else(|| "missing test_group in debugcon JSON".to_string())?;
    let safe_group: String = test_group
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect();
    let dir = workspace_root.join(".k1").join("testing");
    let dest = dir.join(format!("testing-{safe_group}.jsonl"));

    if dest.exists() {
        std::fs::remove_file(&dest)
            .map_err(|err| format!("failed to remove {}: {err}", dest.display()))?;
    }

    let mut output = std::fs::File::create(&dest)
        .map_err(|err| format!("failed to create {}: {err}", dest.display()))?;
    for line in json_lines {
        use std::io::Write;
        writeln!(output, "{line}")
            .map_err(|err| format!("failed to write {}: {err}", dest.display()))?;
    }

    std::fs::remove_file(path)
        .map_err(|err| format!("failed to remove {}: {err}", path.display()))?;
    Ok(())
}

fn strip_ansi_and_control(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut output = String::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == 0x1b {
            if i + 1 < bytes.len() && bytes[i + 1] == b'[' {
                i += 2;
                while i < bytes.len() {
                    let b = bytes[i];
                    if (b'@'..=b'~').contains(&b) {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
                continue;
            }
            i += 1;
            continue;
        }

        let b = bytes[i];
        if b >= 0x20 || b == b'\n' || b == b'\t' {
            output.push(b as char);
        }
        i += 1;
    }

    output
}

fn extract_json_objects(input: &str) -> Vec<String> {
    let mut results = Vec::new();
    let mut depth = 0usize;
    let mut start: Option<usize> = None;

    for (idx, ch) in input.char_indices() {
        if ch == '{' {
            if depth == 0 {
                start = Some(idx);
            }
            depth += 1;
        } else if ch == '}' {
            if depth > 0 {
                depth -= 1;
                if depth == 0 {
                    if let Some(s) = start {
                        results.push(input[s..=idx].to_string());
                    }
                    start = None;
                }
            }
        }
    }

    results
}

fn run_command(
    command: &mut Command,
    context: &str,
    testing_mode: bool,
    arch: crate::builder::Arch,
) -> Result<(), String> {
    let status = command
        .status()
        .map_err(|err| format!("{context}: {err}"))?;
    if status.success() {
        Ok(())
    } else if testing_mode {
        match arch {
            crate::builder::Arch::X86_64 => {
                if status.code() == Some(33) {
                    Ok(())
                } else {
                    Err(format!("{context}: exit status {status}"))
                }
            }
            crate::builder::Arch::Aarch64 => Ok(()),
        }
    } else {
        Err(format!("{context}: exit status {status}"))
    }
}
