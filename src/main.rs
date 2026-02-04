mod args;

fn main() {
    match args::parse() {
        Ok(args::Args::Help) => print_help(),
        Ok(args::Args::Version) => print_version(),
        Ok(args::Args::Run {
            binary,
            binary_args,
        }) => {
            println!("runner target: {binary}");
            if !binary_args.is_empty() {
                println!("runner args: {binary_args:?}");
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
