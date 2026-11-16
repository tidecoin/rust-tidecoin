#![cfg_attr(fuzzing, no_main)]
//! Compares Rust script verification with the original Tidecoin node.
//!
//! Requires `--features node-oracle`. Without it the target still builds, so
//! workspace-wide tools such as `cargo kani` and `cargo mutants` can name
//! every binary, but running it fails instead of fuzzing nothing.
#[cfg(not(fuzzing))]
fn main() {}

#[cfg(feature = "node-oracle")]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    use node_parity::TidecoinNodeHarness;
    static NODE: std::sync::OnceLock<TidecoinNodeHarness> = std::sync::OnceLock::new();
    let node = NODE
        .get_or_init(|| TidecoinNodeHarness::from_env().expect("original node oracle required"));
    tidecoin_fuzz::differential::run(node, data);
});

#[cfg(not(feature = "node-oracle"))]
libfuzzer_sys::fuzz_target!(|_data: &[u8]| {
    panic!("consensus_node_differential requires --features node-oracle");
});
