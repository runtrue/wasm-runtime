//! Build-time target identity exported into checkpoint compatibility metadata.

fn main() {
    println!("cargo:rerun-if-env-changed=TARGET");
    let target = std::env::var("TARGET").expect("Cargo must provide the build target triple");
    println!("cargo:rustc-env=RUNTRUE_BUILD_TARGET={target}");
}
