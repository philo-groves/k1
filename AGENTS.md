# Agent Instructions for Rust Project

## 🦀 Project Context
- **Language:** Rust 2024 Edition (Toolchain: 1.95+)
- **Build System:** Cargo
- **Architecture:** Binary Application
- **Primary Focus:** A custom cargo target runner for Rust kernels

## 🚀 Key Commands
- `cargo build` - Build the project.
- `cargo test` - Run unit and integration tests.
- `cargo clippy -- -D warnings` - Run lints (treat warnings as errors).
- `cargo fmt --check` - Validate formatting.
- `cargo doc --no-deps --open` - Build and view documentation.

## 📂 Project Structure
- `/src` - Main application logic (binary).
- `/src/main.rs` - Main core.

## 🧠 Coding Standards & Rules
- **Idiomatic Rust:** Follow the Rust API Guidelines.
- **Safety First:** Avoid `unsafe` unless strictly necessary; if used, document why with `// SAFETY:` comments.
- **Error Handling:** Use `thiserror` for library errors and `anyhow` for application errors. Avoid `unwrap()`.
- **Memory Management:** Prefer borrowing (`&T`) over cloning (`.clone()`) where possible.
- **Async:** Use `tokio` for async runtimes.
- **Styling:** Use 4 spaces for indentation (no tabs).

## 🧪 Testing Guidelines
- Unit tests should live in the same file as the code, wrapped in `#[cfg(test)] mod tests { ... }`.
- Run `cargo test` before submitting any changes.

## 🧱 Boundaries
- NEVER use `unwrap()` in production code. Use `?` or `match`.
- DO NOT use `println!` for logging; use the `log` or `tracing` crate.
- DO NOT ignore Clippy warnings.