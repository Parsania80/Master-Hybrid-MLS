use std::{env, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=RUSTC");

    let rustc = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let output = Command::new(rustc)
        .arg("--version")
        .output()
        .expect("Cargo must provide a usable rustc compiler");
    assert!(output.status.success(), "rustc --version must succeed");
    let version = String::from_utf8(output.stdout).expect("rustc version must be UTF-8");
    println!("cargo:rustc-env=BOOTSTRAP_RUSTC_VERSION={}", version.trim());
}
