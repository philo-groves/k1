pub fn run(binary: String, _binary_args: Vec<String>) -> Result<(), String> {
    println!("binary: {binary}");
    crate::builder::build(binary)
}
