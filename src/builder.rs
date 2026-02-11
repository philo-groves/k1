use cargo_metadata::MetadataCommand;
use ovmf_prebuilt::{Arch as OvmfArch, FileType, Prebuilt, Source};
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Copy)]
pub enum Arch {
    X86_64,
    Aarch64,
}

pub fn build(binary: String) -> Result<(), String> {
    let workspace_root = workspace_root_from_binary(&binary)?;
    let build_dir = workspace_root.join(".k1").join("build");
    if build_dir.exists() {
        fs::remove_dir_all(&build_dir)
            .map_err(|err| format!("failed to remove .k1/build: {err}"))?;
    }

    fs::create_dir_all(&build_dir).map_err(|err| format!("failed to create .k1/build: {err}"))?;

    let kernel_dest = build_dir.join("kernel");
    fs::copy(&binary, &kernel_dest)
        .map_err(|err| format!("failed to copy kernel binary: {err}"))?;

    let arch = detect_arch(&binary)?;
    persist_ovmf_files(&build_dir, arch)?;

    let limine_dir = build_dir.join("limine");
    let mut clone_cmd = command("git");
    clone_cmd
        .arg("clone")
        .arg("--branch")
        .arg("v10.x-binary")
        .arg("--depth")
        .arg("1")
        .arg("https://github.com/limine-bootloader/limine.git")
        .arg(&limine_dir);
    run_command(&mut clone_cmd, "failed to clone limine")?;

    let mut make_cmd = command("make");
    make_cmd.arg("all").current_dir(&limine_dir);
    run_command(&mut make_cmd, "failed to build limine")?;

    let iso_root = build_dir.join("iso_root");
    let iso_limine = iso_root.join("boot").join("limine");
    let iso_efi = iso_root.join("EFI").join("BOOT");
    fs::create_dir_all(&iso_limine)
        .map_err(|err| format!("failed to create limine boot dir: {err}"))?;
    fs::create_dir_all(&iso_efi).map_err(|err| format!("failed to create EFI boot dir: {err}"))?;

    let iso_kernel = iso_root.join("boot").join("kernel");
    fs::copy(&kernel_dest, &iso_kernel)
        .map_err(|err| format!("failed to copy kernel into ISO: {err}"))?;

    copy_limine_conf(&binary, &iso_limine)?;

    match arch {
        Arch::X86_64 => {
            copy_into(
                &limine_dir,
                &iso_limine,
                &[
                    "limine-bios.sys",
                    "limine-bios-cd.bin",
                    "limine-uefi-cd.bin",
                ],
            )?;
            copy_into(&limine_dir, &iso_efi, &["BOOTX64.EFI", "BOOTIA32.EFI"])?;
        }
        Arch::Aarch64 => {
            copy_into(&limine_dir, &iso_limine, &["limine-uefi-cd.bin"])?;
            copy_into(&limine_dir, &iso_efi, &["BOOTAA64.EFI"])?;
        }
    }

    let image_name = image_name_from_binary(&binary);
    let iso_path = build_dir.join(format!("{image_name}.iso"));

    match arch {
        Arch::X86_64 => {
            let mut mkiso_cmd = command("xorriso");
            mkiso_cmd
                .arg("-as")
                .arg("mkisofs")
                .arg("-b")
                .arg("boot/limine/limine-bios-cd.bin")
                .arg("-no-emul-boot")
                .arg("-boot-load-size")
                .arg("4")
                .arg("-boot-info-table")
                .arg("--efi-boot")
                .arg("boot/limine/limine-uefi-cd.bin")
                .arg("-efi-boot-part")
                .arg("--efi-boot-image")
                .arg("--protective-msdos-label")
                .arg(&iso_root)
                .arg("-o")
                .arg(&iso_path);
            run_command(&mut mkiso_cmd, "failed to build x86_64 ISO")?;

            let limine_exec = limine_dir.join("limine");
            let mut bios_cmd = command(limine_exec);
            bios_cmd.arg("bios-install").arg(&iso_path);
            run_command(&mut bios_cmd, "failed to install limine bios")?;
        }
        Arch::Aarch64 => {
            let mut mkiso_cmd = command("xorriso");
            mkiso_cmd
                .arg("-as")
                .arg("mkisofs")
                .arg("--efi-boot")
                .arg("boot/limine/limine-uefi-cd.bin")
                .arg("-efi-boot-part")
                .arg("--efi-boot-image")
                .arg("--protective-msdos-label")
                .arg(&iso_root)
                .arg("-o")
                .arg(&iso_path);
            run_command(&mut mkiso_cmd, "failed to build aarch64 ISO")?;
        }
    }

    println!("iso: {}", iso_path.display());
    Ok(())
}

pub fn detect_arch(binary: &str) -> Result<Arch, String> {
    if let Ok(value) = env::var("CARGO_CFG_TARGET_ARCH") {
        return parse_arch(&value).ok_or_else(|| format!("unsupported target arch: {value}"));
    }

    if let Some(arch) = parse_arch(binary) {
        return Ok(arch);
    }

    Err("unable to determine target architecture".to_string())
}

fn parse_arch(value: &str) -> Option<Arch> {
    if value.contains("x86_64") {
        Some(Arch::X86_64)
    } else if value.contains("aarch64") {
        Some(Arch::Aarch64)
    } else {
        None
    }
}

pub fn image_name_from_binary(binary: &str) -> String {
    Path::new(binary)
        .file_stem()
        .unwrap_or_else(|| OsStr::new("kernel"))
        .to_string_lossy()
        .into_owned()
}

pub fn workspace_root_from_binary(binary: &str) -> Result<PathBuf, String> {
    let kernel_root = kernel_root_from_binary(binary)?;
    let manifest_path = kernel_root.join("Cargo.toml");
    if !manifest_path.exists() {
        return Ok(kernel_root);
    }

    let metadata = MetadataCommand::new()
        .manifest_path(&manifest_path)
        .no_deps()
        .exec()
        .map_err(|err| format!("failed to run cargo metadata: {err}"))?;

    Ok(metadata.workspace_root.into_std_path_buf())
}

impl Arch {
    pub fn karch(self) -> &'static str {
        match self {
            Arch::X86_64 => "x86_64",
            Arch::Aarch64 => "aarch64",
        }
    }
}

fn persist_ovmf_files(build_dir: &Path, arch: Arch) -> Result<(), String> {
    let ovmf_dir = build_dir.join("ovmf");
    fs::create_dir_all(&ovmf_dir).map_err(|err| format!("failed to create ovmf dir: {err}"))?;

    let prebuilt = Prebuilt::fetch(Source::LATEST, &ovmf_dir)
        .map_err(|err| format!("failed to fetch ovmf prebuilts: {err}"))?;

    let (ovmf_arch, karch) = match arch {
        Arch::X86_64 => (OvmfArch::X64, "x86_64"),
        Arch::Aarch64 => (OvmfArch::Aarch64, "aarch64"),
    };

    let code_src = prebuilt.get_file(ovmf_arch, FileType::Code);
    let vars_src = prebuilt.get_file(ovmf_arch, FileType::Vars);

    let code_dest = ovmf_dir.join(format!("ovmf-code-{karch}.fd"));
    let vars_dest = ovmf_dir.join(format!("ovmf-vars-{karch}.fd"));

    fs::copy(&code_src, &code_dest)
        .map_err(|err| format!("failed to copy {}: {err}", code_src.display()))?;
    fs::copy(&vars_src, &vars_dest)
        .map_err(|err| format!("failed to copy {}: {err}", vars_src.display()))?;

    Ok(())
}

fn copy_limine_conf(binary: &str, iso_limine: &Path) -> Result<(), String> {
    let kernel_root = kernel_root_from_binary(binary)?;
    let source = kernel_root.join("limine.conf");
    let dest = iso_limine.join("limine.conf");
    fs::copy(&source, &dest)
        .map_err(|err| format!("failed to copy {}: {err}", source.display()))?;
    Ok(())
}

fn kernel_root_from_binary(binary: &str) -> Result<std::path::PathBuf, String> {
    let binary_path = Path::new(binary);
    for ancestor in binary_path.ancestors() {
        if ancestor.file_name() == Some(OsStr::new("target")) {
            if let Some(parent) = ancestor.parent() {
                return Ok(parent.to_path_buf());
            }
        }
    }
    Err("unable to determine kernel root from binary path".to_string())
}

fn copy_into(source_dir: &Path, dest_dir: &Path, names: &[&str]) -> Result<(), String> {
    for name in names {
        let source = source_dir.join(name);
        let dest = dest_dir.join(name);
        fs::copy(&source, &dest)
            .map_err(|err| format!("failed to copy {}: {err}", source.display()))?;
    }
    Ok(())
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

fn command(program: impl AsRef<OsStr>) -> Command {
    let mut command = Command::new(program);
    command.env("CARGO_INCREMENTAL", "0");
    command
}
