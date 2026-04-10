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

fn node_repo_dir() -> Option<PathBuf> {
    env::var_os("TIDECOIN_NODE_REPO").map(PathBuf::from)
}

fn assert_node_src_exists(node_repo: &Path) {
    let script_interpreter = node_repo.join("src/script/interpreter.cpp");
    assert!(
        script_interpreter.exists(),
        "TIDECOIN_NODE_REPO={} does not appear to be a Tidecoin node checkout",
        node_repo.display()
    );
}

fn build_stub_bridge(local_c_src: &Path) {
    println!("cargo:rerun-if-changed={}", local_c_src.join("tidecoin_validation_stub.c").display());
    base_builder()
        .warnings(false)
        .include(local_c_src)
        .file(local_c_src.join("tidecoin_validation_stub.c"))
        .compile("tidecoin_node_validation_stub");
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=TIDECOIN_NODE_REPO");

    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("missing CARGO_MANIFEST_DIR"));
    let local_c_src = manifest_dir.join("c_src");

    let Some(node_repo) = node_repo_dir() else {
        build_stub_bridge(&local_c_src);
        return;
    };
    assert_node_src_exists(&node_repo);

    let node_src = node_repo.join("src");
    let node_pq = node_src.join("pq");

    println!("cargo:rerun-if-changed={}", node_src.join("script/interpreter.cpp").display());
    println!("cargo:rerun-if-changed={}", node_src.join("pubkey.cpp").display());
    println!("cargo:rerun-if-changed={}", node_src.join("pq/pqhd_kdf.cpp").display());
    println!("cargo:rerun-if-changed={}", node_src.join("pq/pqhd_keygen.cpp").display());
    println!(
        "cargo:rerun-if-changed={}",
        local_c_src.join("tidecoin_validation_bridge.cpp").display()
    );
    println!("cargo:rerun-if-changed={}", local_c_src.join("randombytes_stub.c").display());

    let mut cpp = base_builder();
    cpp.cpp(true)
        .std("c++20")
        .warnings(false)
        .flag("-fvisibility=hidden")
        .flag("-fvisibility-inlines-hidden")
        .include(&node_src)
        .include(&local_c_src)
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
        .file(node_src.join("crypto/hmac_sha512.cpp"))
        .file(node_src.join("crypto/ripemd160.cpp"))
        .file(node_src.join("crypto/sha1.cpp"))
        .file(node_src.join("crypto/sha256.cpp"))
        .file(node_src.join("crypto/sha512.cpp"))
        .file(node_src.join("pq/pqhd_kdf.cpp"))
        .file(node_src.join("pq/pqhd_keygen.cpp"))
        .file(node_src.join("util/strencodings.cpp"))
        .file(node_src.join("support/cleanse.cpp"))
        .file(node_src.join("support/lockedpool.cpp"))
        .compile("tidecoin_node_validation_cpp");

    let mut c = base_builder();
    c.warnings(false)
        .flag("-fvisibility=hidden")
        .include(&node_src)
        .include(&node_pq)
        .include(node_pq.join("falcon-512"))
        .include(node_pq.join("falcon-1024"))
        .include(node_pq.join("ml-dsa-44"))
        .include(node_pq.join("ml-dsa-65"))
        .include(node_pq.join("ml-dsa-87"))
        .include(node_pq.join("ml-kem-512"))
        .include(&local_c_src)
        .file(local_c_src.join("randombytes_stub.c"))
        .file(node_src.join("pq/fips202.c"))
        .file(node_src.join("pq/falcon512.c"))
        .file(node_src.join("pq/falcon1024.c"))
        .file(node_src.join("pq/mldsa44.c"))
        .file(node_src.join("pq/mldsa65.c"))
        .file(node_src.join("pq/mldsa87.c"))
        .file(node_src.join("pq/falcon-512/codec.c"))
        .file(node_src.join("pq/falcon-512/common.c"))
        .file(node_src.join("pq/falcon-512/fft.c"))
        .file(node_src.join("pq/falcon-512/fpr.c"))
        .file(node_src.join("pq/falcon-512/keygen.c"))
        .file(node_src.join("pq/falcon-512/pqclean.c"))
        .file(node_src.join("pq/falcon-512/rng.c"))
        .file(node_src.join("pq/falcon-512/sign.c"))
        .file(node_src.join("pq/falcon-512/vrfy.c"))
        .file(node_src.join("pq/falcon-1024/codec.c"))
        .file(node_src.join("pq/falcon-1024/common.c"))
        .file(node_src.join("pq/falcon-1024/fft.c"))
        .file(node_src.join("pq/falcon-1024/fpr.c"))
        .file(node_src.join("pq/falcon-1024/keygen.c"))
        .file(node_src.join("pq/falcon-1024/pqclean.c"))
        .file(node_src.join("pq/falcon-1024/rng.c"))
        .file(node_src.join("pq/falcon-1024/sign.c"))
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
        .file(node_src.join("pq/ml-kem-512/cbd.c"))
        .file(node_src.join("pq/ml-kem-512/indcpa.c"))
        .file(node_src.join("pq/ml-kem-512/kem.c"))
        .file(node_src.join("pq/ml-kem-512/ntt.c"))
        .file(node_src.join("pq/ml-kem-512/poly.c"))
        .file(node_src.join("pq/ml-kem-512/polyvec.c"))
        .file(node_src.join("pq/ml-kem-512/reduce.c"))
        .file(node_src.join("pq/ml-kem-512/symmetric-shake.c"))
        .file(node_src.join("pq/ml-kem-512/verify.c"))
        .compile("tidecoin_node_validation_pq");
}
