fn main() {
    #[cfg(windows)]
    {
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let native = if manifest.join("native/windows-loader.c").is_file() {
            manifest.join("native")
        } else {
            // The standalone PE fixture uses this build script outside its package.
            manifest.join(file!()).with_file_name("native")
        };
        let source = native.join("windows-loader.c");
        println!("cargo:rerun-if-changed={}", source.display());
        println!(
            "cargo:rerun-if-changed={}",
            source.with_extension("h").display()
        );
        cc::Build::new()
            .file(source)
            .flag("/std:c11")
            .warnings_into_errors(true)
            .compile("cm_windows_loader");
        println!("cargo:rustc-link-lib=bcrypt");
    }
}
