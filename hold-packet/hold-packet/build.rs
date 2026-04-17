use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;
use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "hold-packet-ebpf")
        .ok_or_else(|| anyhow!("hold-packet-ebpf package not found"))?;
    let cargo_metadata::Package {
        name,
        manifest_path,
        ..
    } = ebpf_package;
    let ebpf_package = aya_build::Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
            .as_str(),
        ..Default::default()
    };
    aya_build::build_ebpf([ebpf_package], Toolchain::default())?;

    // Compile the gRPC protobuf definitions.
    let proto_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("proto");
    tonic_prost_build::compile_protos(proto_dir.join("holdpacket.proto"))
        .context("tonic_prost_build::compile_protos")?;

    Ok(())
}
