#![cfg_attr(fuzzing, no_main)]
use libfuzzer_sys::fuzz_target;
use node_parity::TidecoinNodeHarness;
use tidecoin_fuzz::differential::run;
#[cfg(not(fuzzing))]
fn main() {}
fuzz_target!(|data: &[u8]| {
    static NODE: std::sync::OnceLock<TidecoinNodeHarness> = std::sync::OnceLock::new();
    let node = NODE
        .get_or_init(|| TidecoinNodeHarness::from_env().expect("original node oracle required"));
    run(node, data);
});
