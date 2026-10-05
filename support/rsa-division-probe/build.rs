use std::{env, path::PathBuf, process::Command};

fn main() {
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let compiler = env::var_os("CC").unwrap_or_else(|| "cc".into());
    assert!(Command::new(compiler)
        .args(["-c", "src/valgrind.c", "-o"])
        .arg(output.join("valgrind.o"))
        .status()
        .expect("C compiler")
        .success());
    assert!(Command::new("ar")
        .arg("crs")
        .arg(output.join("libvalgrind_probe.a"))
        .arg(output.join("valgrind.o"))
        .status()
        .expect("archive tool")
        .success());
    println!("cargo:rustc-link-search=native={}", output.display());
    println!("cargo:rustc-link-lib=static=valgrind_probe");
    println!("cargo:rerun-if-changed=src/valgrind.c");
    println!("cargo:rerun-if-env-changed=CC");
}
