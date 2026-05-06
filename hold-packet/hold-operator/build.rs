use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_path = PathBuf::from("../hold-packet/proto/holdpacket.proto");
    println!("cargo:rerun-if-changed={}", proto_path.display());
    tonic_prost_build::compile_protos(proto_path)?;
    Ok(())
}