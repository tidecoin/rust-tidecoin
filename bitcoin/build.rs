use std::env;
use std::path::{Path, PathBuf};

fn base_builder() -> cc::Build {
    let mut builder = cc::Build::new();
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("wasi") {
        let wasi_sdk_dir = env::var("WASI_SDK_DIR").expect("missing WASI_SDK_DIR for wasi target");
        builder.flag(format!("--sysroot={wasi_sdk_dir}"));
    }
    builder
}

fn feature_enabled(name: &str) -> bool {
    let env_name = format!("CARGO_FEATURE_{}", name.replace('-', "_").to_ascii_uppercase());
    env::var_os(env_name).is_some()
}

fn node_repo_dir() -> PathBuf {
    env::var_os("TIDECOIN_NODE_REPO")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            panic!(
                "missing TIDECOIN_NODE_REPO; set it to the Tidecoin node checkout used for node-backed validation"
            )
        })
}

fn build_tidecoin_node_validation() {
    let node_repo = node_repo_dir();
    let node_src = node_repo.join("src");
    let node_pq = node_src.join("pq");
    let local_c_src = Path::new("c_src");

    if !node_src.exists() {
        panic!(
            "tidecoin-node-validation requires Tidecoin node sources at {}",
            node_repo.display()
        );
    }

    println!("cargo:rerun-if-env-changed=TIDECOIN_NODE_REPO");
    println!(
        "cargo:rerun-if-changed={}",
        node_src.join("script/interpreter.cpp").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        node_src.join("pubkey.cpp").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        local_c_src.join("tidecoin_validation_bridge.cpp").display()
    );

    let mut cpp = cc::Build::new();
    cpp.cpp(true)
        .std("c++20")
        .warnings(false)
        .flag("-fvisibility=hidden")
        .flag("-fvisibility-inlines-hidden")
        .include(&node_src)
        .include(local_c_src)
        .file(local_c_src.join("tidecoin_validation_bridge.cpp"))
        .file(node_src.join("arith_uint256.cpp"))
        .file(node_src.join("hash.cpp"))
        .file(node_src.join("pubkey.cpp"))
        .file(node_src.join("primitives/transaction.cpp"))
        .file(node_src.join("script/interpreter.cpp"))
        .file(node_src.join("script/script.cpp"))
        .file(node_src.join("script/script_error.cpp"))
        .file(node_src.join("uint256.cpp"))
        .file(node_src.join("consensus/tx_check.cpp"))
        .file(node_src.join("crypto/hex_base.cpp"))
        .file(node_src.join("crypto/ripemd160.cpp"))
        .file(node_src.join("crypto/sha1.cpp"))
        .file(node_src.join("crypto/sha256.cpp"))
        .file(node_src.join("crypto/sha512.cpp"))
        .file(node_src.join("util/strencodings.cpp"))
        .file(node_src.join("support/cleanse.cpp"))
        .compile("tidecoin_node_validation_cpp");

    let mut c = cc::Build::new();
    c.warnings(false)
        .flag("-fvisibility=hidden")
        .include(&node_src)
        .include(&node_pq)
        .include(node_pq.join("falcon-1024"))
        .include(node_pq.join("ml-dsa-44"))
        .include(node_pq.join("ml-dsa-65"))
        .include(node_pq.join("ml-dsa-87"))
        .include(local_c_src)
        .file(local_c_src.join("randombytes_stub.c"))
        .file(node_src.join("pq/fips202.c"))
        .file(node_src.join("pq/falcon-1024/codec.c"))
        .file(node_src.join("pq/falcon-1024/common.c"))
        .file(node_src.join("pq/falcon-1024/fft.c"))
        .file(node_src.join("pq/falcon-1024/fpr.c"))
        .file(node_src.join("pq/falcon-1024/pqclean.c"))
        .file(node_src.join("pq/falcon-1024/vrfy.c"))
        .file(node_src.join("pq/ml-dsa-44/ntt.c"))
        .file(node_src.join("pq/ml-dsa-44/packing.c"))
        .file(node_src.join("pq/ml-dsa-44/poly.c"))
        .file(node_src.join("pq/ml-dsa-44/polyvec.c"))
        .file(node_src.join("pq/ml-dsa-44/reduce.c"))
        .file(node_src.join("pq/ml-dsa-44/rounding.c"))
        .file(node_src.join("pq/ml-dsa-44/sign.c"))
        .file(node_src.join("pq/ml-dsa-44/symmetric-shake.c"))
        .file(node_src.join("pq/ml-dsa-65/ntt.c"))
        .file(node_src.join("pq/ml-dsa-65/packing.c"))
        .file(node_src.join("pq/ml-dsa-65/poly.c"))
        .file(node_src.join("pq/ml-dsa-65/polyvec.c"))
        .file(node_src.join("pq/ml-dsa-65/reduce.c"))
        .file(node_src.join("pq/ml-dsa-65/rounding.c"))
        .file(node_src.join("pq/ml-dsa-65/sign.c"))
        .file(node_src.join("pq/ml-dsa-65/symmetric-shake.c"))
        .file(node_src.join("pq/ml-dsa-87/ntt.c"))
        .file(node_src.join("pq/ml-dsa-87/packing.c"))
        .file(node_src.join("pq/ml-dsa-87/poly.c"))
        .file(node_src.join("pq/ml-dsa-87/polyvec.c"))
        .file(node_src.join("pq/ml-dsa-87/reduce.c"))
        .file(node_src.join("pq/ml-dsa-87/rounding.c"))
        .file(node_src.join("pq/ml-dsa-87/sign.c"))
        .file(node_src.join("pq/ml-dsa-87/symmetric-shake.c"))
        .compile("tidecoin_node_validation_pq");
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    if feature_enabled("tidecoin-node-validation") {
        build_tidecoin_node_validation();
    }
}
