use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rustc-check-cfg=cfg(codex_bazel)");
    println!("cargo:rerun-if-changed=src/grpc");
    println!("cargo:rerun-if-env-changed=CM_NATIVE_PROTOC");

    let mut config = tonic_prost_build::Config::new();
    let protoc =
        std::env::var_os("CM_NATIVE_PROTOC").ok_or("Verified native ARM64 protoc is required")?;
    config.protoc_executable(PathBuf::from(protoc));
    let proto_files = glob::glob("src/grpc/*.proto")?.collect::<Result<Vec<_>, _>>()?;

    tonic_prost_build::configure()
        .build_client(/*enable*/ true)
        .build_server(/*enable*/ true)
        .compile_with_config(config, &proto_files, &[PathBuf::from("src/grpc")])?;

    Ok(())
}
