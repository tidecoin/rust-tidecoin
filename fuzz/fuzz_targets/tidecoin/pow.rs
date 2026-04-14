#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use tidecoin::block::{Header, HeaderExt as _};
use tidecoin::hashes::Hash as _;
use tidecoin::network::NetworkExt as _;
use tidecoin::pow;
use tidecoin::{BlockHeight, BlockHeightInterval, BlockTime, CompactTarget, Network};

#[cfg(not(fuzzing))]
fn main() {}

fn do_test(data: &[u8]) {
    let mut u = Unstructured::new(data);
    let Ok(header) = Header::arbitrary(&mut u) else {
        return;
    };
    let network = select_network(&mut u);
    let params = network.params();
    let height = select_height(&mut u);

    let _ = pow::pow_hash_algorithm_at_height(params, height);
    let _ = pow::derive_target(header.bits, params);
    let _ = pow::scrypt_pow_hash(&header);
    let _ = pow::yespower_pow_hash(&header);
    let _ = pow::mining_hash_for_height(&header, params, height);
    let _ = pow::validate_pow_at_height(&header, params, height);
    let _ = pow::validate_pow_any(&header, params);
    let _ = pow::validate_auxpow_context(&header, params, Some(height));
    let _ = header.difficulty(params);
    let _ = header.difficulty_float(params);
    let _ = header.work();

    if let Ok(target) = pow::derive_target(header.bits, params) {
        let _ = pow::validate_pow_at_height_against_target(&header, params, height, target);
        let _ = header.validate_pow(params, height, target);
    }

    let candidate_bits = CompactTarget::from_consensus(u32::arbitrary(&mut u).unwrap_or_default());
    let _ = pow::permitted_difficulty_transition(params, height, header.bits, candidate_bits);

    let next_time =
        u.arbitrary::<u32>().ok().map(BlockTime::from_u32).unwrap_or(header.time).to_u32();
    let history = synthetic_header_history(&header, height);
    let _ = pow::next_target_after(header, height, params, Some(next_time), |requested_height| {
        Ok::<_, ()>(header_for_height(&history, requested_height))
    });
}

fn select_network(u: &mut Unstructured<'_>) -> Network {
    match u.int_in_range::<u8>(0..=2).unwrap_or_default() {
        0 => Network::Tidecoin,
        1 => Network::Testnet,
        _ => Network::Regtest,
    }
}

fn select_height(u: &mut Unstructured<'_>) -> BlockHeight {
    BlockHeight::from_u32(u.int_in_range::<u32>(0..=10_000).unwrap_or_default())
}

fn synthetic_header_history(seed: &Header, current_height: BlockHeight) -> Vec<Header> {
    let window = current_height.to_u32().min(64);
    let start = current_height.saturating_sub(BlockHeightInterval::from_u32(window));
    (start.to_u32()..=current_height.to_u32())
        .map(|height| {
            let mut header = seed.clone();
            header.time =
                BlockTime::from_u32(seed.time.to_u32().saturating_sub(
                    current_height.to_u32().saturating_sub(height).saturating_mul(60),
                ));
            header
        })
        .collect()
}

fn header_for_height(history: &[Header], height: BlockHeight) -> Header {
    let index = usize::try_from(height.to_u32()).unwrap_or_default() % history.len().max(1);
    history.get(index).cloned().unwrap_or_else(|| Header {
        version: tidecoin::BlockVersion::NO_SOFT_FORK_SIGNALLING,
        prev_blockhash: tidecoin::BlockHash::GENESIS_PREVIOUS_BLOCK_HASH,
        merkle_root: tidecoin::TxMerkleNode::from_byte_array([0u8; 32]),
        time: BlockTime::from_u32(0),
        bits: CompactTarget::from_consensus(0),
        nonce: 0,
        auxpow: None,
    })
}

fuzz_target!(|data| {
    do_test(data);
});
