// Compiles the gRPC definitions in pure Rust, so that building needs no protoc on the machine.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/consortium.proto");
    let descriptors = protox::compile(["consortium.proto"], ["proto"])?;
    tonic_prost_build::configure().compile_fds(descriptors)?;
    Ok(())
}
