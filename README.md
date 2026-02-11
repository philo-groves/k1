# k1

`k1` is a Cargo runner for Rust kernel binaries. It turns a built kernel binary into a bootable ISO, prepares firmware, and starts QEMU with architecture-specific settings.

## Usage in a Kernel Project

In your kernel repository, configure Cargo to use `k1` as the runner for `target_os = "none"` binaries.

Create/update `.cargo/config.toml`:

```toml
[target.'cfg(target_os = "none")']
runner = "k1"
```

With this in place, `cargo run` (or test flows that invoke a runner) will call `k1` with the compiled kernel binary path.

## What It Does

- Accepts a kernel binary path (plus optional args) from Cargo/custom runners.
- Builds a temporary boot image layout under `.k1/build`.
- Detects target architecture (`x86_64` or `aarch64`).
- Fetches/copies OVMF firmware files and Limine boot assets.
- Produces `<kernel-name>.iso`.
- Launches QEMU, with a special testing mode for kernel test runs.

## High-Level Architecture

Code is organized as a small binary app with focused modules:

- `src/main.rs`: entrypoint; parses CLI args and dispatches command flow.
- `src/args.rs`: CLI parsing into `Args` variants (`Run`, `Clean`, `Help`, `Version`).
- `src/builder.rs`: build pipeline (workspace detection, boot assets, ISO generation).
- `src/runner.rs`: runtime pipeline (QEMU command assembly and test-output handling).
- `src/cleaner.rs`: cleanup (`.k1` + `cargo clean`).

## Command Flow

### 1) Process start (`main`)

`main` calls `args::parse()` and dispatches:

- `Help` -> prints usage text.
- `Version` -> prints package version.
- `Clean` -> runs cleaner flow.
- `Run { binary, binary_args }` -> runs build + QEMU flow.

Any parse/runtime failure prints `error: ...` and exits non-zero.

### 2) Argument parsing (`args`)

- `k1 --help` / `-h` -> help
- `k1 --version` / `-V` -> version
- `k1 clean` -> clean
- `k1 <path-to-binary> [args...]` -> run

Unknown flags and invalid `clean` usage are rejected with clear errors.

### 3) Build pipeline (`builder::build`)

Given a kernel binary path:

1. Resolve workspace root from binary location (walk up to `target`, then use `cargo_metadata` when possible).
2. Recreate `.k1/build` and ensure `.k1/cache` exists.
3. Copy kernel binary into `.k1/build/kernel`.
4. Detect architecture:
   - Prefer `CARGO_CFG_TARGET_ARCH`.
   - Fallback to path-string detection (`x86_64` / `aarch64`).
5. Fetch OVMF prebuilt firmware and persist into `.k1/build/ovmf` as:
   - `ovmf-code-x86_64.fd` / `ovmf-vars-x86_64.fd`, or
   - `ovmf-code-aarch64.fd` / `ovmf-vars-aarch64.fd`.
6. Ensure Limine repo exists at `.k1/cache/limine`:
   - Clone `v10.x-binary` (depth 1) if missing.
   - Run `make all` once after clone.
7. Create ISO root tree and copy artifacts:
   - kernel -> `iso_root/boot/kernel`
   - kernel project's `limine.conf` -> `iso_root/boot/limine/limine.conf`
   - Limine boot files + EFI bootloader files (arch-specific).
8. Build `<image-name>.iso` with `xorriso`:
   - x86_64: BIOS+UEFI hybrid setup + `limine bios-install`.
   - aarch64: UEFI setup.

Prints final ISO path on success.

### 4) Runtime pipeline (`runner::run`)

`runner::run` first calls `builder::build`, then launches QEMU:

1. Recompute workspace/build paths and firmware paths.
2. Build `qemu-system-{karch}` command with arch-specific machine/device args.
3. Detect testing mode from env/args/path:
   - env: `K1_TEST`, `KERNEL_TEST`, `CARGO_PROFILE=test`, `CARGO_CFG_TEST`
   - binary path containing `/deps/`
   - known test-like args (`--test`, `--nocapture`, etc.)
4. If testing mode:
   - Route output to a `.k1/testing/debugcon-*.jsonl` file.
   - Use QEMU options suitable for automated test runs.
5. Append extra flags from `QEMUFLAGS` (split on whitespace).
6. Run QEMU and interpret exit status:
   - Normal mode: non-zero is failure.
   - Test mode: x86_64 accepts code `33` (`isa-debug-exit` convention); aarch64 treats non-zero as acceptable.
7. Post-process test output file:
   - Strip ANSI/control bytes.
   - Extract JSON objects.
   - Require JSON with `test_group`.
   - Write normalized lines to `.k1/testing/testing-<safe-group>.jsonl`.

## Clean Flow

`k1 clean`:

- Removes local `.k1` directory if present.
- Runs `cargo clean`.

## Key Directories and Artifacts

- `.k1/build/`: transient build staging, ISO root, firmware copies, final ISO.
- `.k1/cache/`: cached third-party build assets (including `limine/` and `ovmf/`).
- `.k1/logs/`: persisted `k1` run/test logs.
- `.k1/testing/`: raw and normalized JSONL test output files.

## External Tools and Dependencies

Runtime shell tools expected on PATH:

- `git` (clone Limine)
- `make` (build Limine)
- `xorriso` (build ISO)
- `qemu-system-x86_64` and/or `qemu-system-aarch64` (run VM)

Rust dependencies:

- `cargo_metadata` for workspace-root resolution.
- `ovmf-prebuilt` for firmware retrieval.
- `serde_json` for test-output parsing/validation.

## Typical End-to-End Run

1. Cargo (or user) invokes `k1 <path-to-kernel-binary>`.
2. `k1` builds a bootable ISO under `.k1/build`.
3. `k1` writes run/test logs to `.k1/logs/k1-<mode>-<timestamp>.log`.
4. `k1` starts QEMU with firmware + ISO.
5. In test mode, `k1` captures and normalizes JSON test output into `.k1/testing/testing-<group>.jsonl`.
