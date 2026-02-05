mod args;
mod builder;
mod runner;

fn main() {
    match args::parse() {
        Ok(args::Args::Help) => print_help(),
        Ok(args::Args::Version) => print_version(),
        Ok(args::Args::Run {
            binary,
            binary_args,
        }) => {
            if let Err(message) = runner::run(binary, binary_args) {
                eprintln!("error: {message}");
                std::process::exit(1);
            }
        }
        Err(message) => {
            eprintln!("error: {message}");
            print_help();
            std::process::exit(2);
        }
    }
}

fn print_help() {
    println!(
        "k1 - Cargo target runner\n\nUsage:\n  k1 <path-to-binary> [args...]\n  k1 --help\n  k1 --version"
    );
}

fn print_version() {
    println!("k1 {}", env!("CARGO_PKG_VERSION"));
}
