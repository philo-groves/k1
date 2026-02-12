use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

static WORKER_GUARD: OnceLock<Mutex<Option<tracing_appender::non_blocking::WorkerGuard>>> =
    OnceLock::new();

pub fn init(
    workspace_root: &Path,
    testing_mode: bool,
    arch: crate::builder::Arch,
) -> Result<PathBuf, String> {
    let logs_dir = workspace_root.join(".k1").join(arch.karch()).join("logs");
    std::fs::create_dir_all(&logs_dir)
        .map_err(|err| format!("failed to create {}: {err}", logs_dir.display()))?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| format!("failed to read system time: {err}"))?;
    let mode = if testing_mode { "test" } else { "run" };
    let file_name = format!("k1-{mode}-{}-{}.log", now.as_secs(), now.subsec_nanos());
    let log_path = logs_dir.join(&file_name);

    let file_appender = tracing_appender::rolling::never(&logs_dir, &file_name);
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
    let stderr_layer = tracing_subscriber::fmt::layer().with_writer(std::io::stderr);
    let file_layer = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .with_writer(non_blocking);
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(stderr_layer)
        .with(file_layer)
        .try_init();

    let guard_slot = WORKER_GUARD.get_or_init(|| Mutex::new(None));
    if let Ok(mut slot) = guard_slot.lock() {
        *slot = Some(guard);
    }

    tracing::info!(path = %log_path.display(), mode, "logging initialized");

    Ok(log_path)
}
