#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use libfuzzer_sys::fuzz_target;
use tidecoin_consensus_encoding::decode_from_slice;

#[cfg(not(fuzzing))]
fn main() {}

fn do_test(data: &[u8]) {
    let _: Result<p2p::address::AddrV2, _> = decode_from_slice(data);
}

fuzz_target!(|data| {
    do_test(data);
});
