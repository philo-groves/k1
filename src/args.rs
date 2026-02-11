use std::env;

#[derive(Debug)]
pub enum Args {
    Run {
        binary: String,
        binary_args: Vec<String>,
    },
    Clean,
    Help,
    Version,
}

pub fn parse() -> Result<Args, String> {
    let mut iter = env::args();
    let _program = iter.next();
    let first = iter.next();

    match first.as_deref() {
        None => Err("missing runner argument".to_string()),
        Some("--help" | "-h") => Ok(Args::Help),
        Some("--version" | "-V") => Ok(Args::Version),
        Some("clean") => {
            if let Some(arg) = iter.next() {
                Err(format!("unexpected argument for clean: {arg}"))
            } else {
                Ok(Args::Clean)
            }
        }
        Some(flag) if flag.starts_with('-') => Err(format!("unknown option: {flag}")),
        Some(binary) => Ok(Args::Run {
            binary: binary.to_string(),
            binary_args: iter.collect(),
        }),
    }
}
