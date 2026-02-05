use std::env;
use std::process::Command;

pub fn run(binary: String, _binary_args: Vec<String>) -> Result<(), String> {
    println!("binary: {binary}");
    crate::builder::build(binary.clone())?;

    let arch = crate::builder::detect_arch(&binary)?;
    let image_name = crate::builder::image_name_from_binary(&binary);
    let karch = arch.karch();
    let iso_path = format!(".build/{image_name}.iso");
    let ovmf_code = format!(".build/ovmf/ovmf-code-{karch}.fd");
    let ovmf_vars = format!(".build/ovmf/ovmf-vars-{karch}.fd");

    let mut qemu_cmd = Command::new(format!("qemu-system-{karch}"));

    match arch {
        crate::builder::Arch::X86_64 => {
            qemu_cmd
                .arg("-M")
                .arg("q35")
                .arg("-drive")
                .arg(format!(
                    "if=pflash,unit=0,format=raw,file={ovmf_code},readonly=on"
                ))
                .arg("-drive")
                .arg(format!("if=pflash,unit=1,format=raw,file={ovmf_vars}"))
                .arg("-cdrom")
                .arg(&iso_path);
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
                    "if=pflash,unit=0,format=raw,file={ovmf_code},readonly=on"
                ))
                .arg("-drive")
                .arg(format!("if=pflash,unit=1,format=raw,file={ovmf_vars}"))
                .arg("-cdrom")
                .arg(&iso_path);
        }
    }

    if let Ok(flags) = env::var("QEMUFLAGS") {
        for flag in flags.split_whitespace() {
            qemu_cmd.arg(flag);
        }
    }

    run_command(&mut qemu_cmd, "failed to run qemu")
}

fn run_command(command: &mut Command, context: &str) -> Result<(), String> {
    let status = command
        .status()
        .map_err(|err| format!("{context}: {err}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{context}: exit status {status}"))
    }
}
