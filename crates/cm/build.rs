fn main() {
    #[cfg(windows)]
    {
        let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(file!())
            .with_file_name("native")
            .join("windows-loader.c");
        println!("cargo:rerun-if-changed={}", source.display());
        println!("cargo:rerun-if-changed={}", source.with_extension("h").display());
        cc::Build::new()
            .file(source)
            .flag("/std:c11")
            .warnings_into_errors(true)
            .compile("cm_windows_loader");
        println!("cargo:rustc-link-lib=bcrypt");
    }
}
