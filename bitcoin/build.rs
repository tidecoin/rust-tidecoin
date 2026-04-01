use std::env;
use std::path::{Path, PathBuf};

fn cargo_home() -> PathBuf {
    if let Some(path) = env::var_os("CARGO_HOME") {
        return PathBuf::from(path);
    }

    if let Some(home) = env::var_os("HOME") {
        return PathBuf::from(home).join(".cargo");
    }

    panic!("could not determine Cargo home")
}

fn find_registry_crate_dir(crate_name: &str, version: &str) -> PathBuf {
    let pattern = cargo_home()
        .join("registry")
        .join("src")
        .join("*")
        .join(format!("{crate_name}-{version}"));

    let pattern = pattern.to_str().expect("registry path must be valid UTF-8");
    glob::glob(pattern)
        .expect("registry glob must be valid")
        .find_map(Result::ok)
        .unwrap_or_else(|| panic!("could not locate {crate_name}-{version} in cargo registry"))
}

fn base_builder() -> cc::Build {
    let mut builder = cc::Build::new();
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("wasi") {
        let wasi_sdk_dir = env::var("WASI_SDK_DIR").expect("missing WASI_SDK_DIR for wasi target");
        builder.flag(format!("--sysroot={wasi_sdk_dir}"));
    }
    builder
}

fn build_bridge(lib_name: &str, source: &str, include_dirs: &[&Path]) {
    let mut builder = base_builder();
    builder.file(source);
    for include_dir in include_dirs {
        builder.include(include_dir);
    }
    builder.compile(lib_name);
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=c_src/");
    println!("cargo:rerun-if-env-changed=CARGO_HOME");
    println!("cargo:rerun-if-env-changed=HOME");

    let internals_include = find_registry_crate_dir("pqcrypto-internals", "0.2.11").join("include");
    let falcon_dir = find_registry_crate_dir("pqcrypto-falcon", "0.4.1");
    let mldsa_dir = find_registry_crate_dir("pqcrypto-mldsa", "0.1.2");

    let falcon_common = falcon_dir.join("pqclean").join("common");
    let falcon512_clean = falcon_dir.join("pqclean").join("crypto_sign").join("falcon-512").join("clean");
    let falcon1024_clean = falcon_dir.join("pqclean").join("crypto_sign").join("falcon-1024").join("clean");

    let mldsa_common = mldsa_dir.join("pqclean").join("common");
    let mldsa44_clean = mldsa_dir.join("pqclean").join("crypto_sign").join("ml-dsa-44").join("clean");
    let mldsa65_clean = mldsa_dir.join("pqclean").join("crypto_sign").join("ml-dsa-65").join("clean");
    let mldsa87_clean = mldsa_dir.join("pqclean").join("crypto_sign").join("ml-dsa-87").join("clean");

    build_bridge(
        "tidecoin_pq_falcon512_compat",
        "c_src/falcon512_compat.c",
        &[&internals_include, &falcon_common, &falcon512_clean],
    );
    build_bridge(
        "tidecoin_pq_falcon1024_compat",
        "c_src/falcon1024_pubkey.c",
        &[&internals_include, &falcon_common, &falcon1024_clean],
    );
    build_bridge(
        "tidecoin_pq_mldsa44_compat",
        "c_src/mldsa44_pubkey.c",
        &[&internals_include, &mldsa_common, &mldsa44_clean],
    );
    build_bridge(
        "tidecoin_pq_mldsa65_compat",
        "c_src/mldsa65_pubkey.c",
        &[&internals_include, &mldsa_common, &mldsa65_clean],
    );
    build_bridge(
        "tidecoin_pq_mldsa87_compat",
        "c_src/mldsa87_pubkey.c",
        &[&internals_include, &mldsa_common, &mldsa87_clean],
    );
}
