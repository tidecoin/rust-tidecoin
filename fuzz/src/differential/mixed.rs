// SPDX-License-Identifier: CC0-1.0
//! Complete three-input spends with independently selectable signed hash modes.

pub mod shapes;

use std::sync::OnceLock;

use super::{compare_each_input, sign_layout, Case};
use node_parity::{ScriptError, TidecoinNodeHarness};
use tidecoin::{network::Params, Amount, PqScheme, PqSchemeCryptoExt, Sequence, Witness};

/// Five post-activation scheme rotations and one historical Falcon-512 layout.
pub const LAYOUTS: usize = PqScheme::KNOWN.len() + 1;

pub fn boundary_flags(active: bool) -> u32 {
    let at = Params::TESTNET.auxpow_start_height.unwrap().to_u32();
    let height = if active { at } else { at - 1 };
    consensus::height_to_flags_with_auxpow_start_height(height, Some(at))
}

/// Select one of the six signatures independently at each input. Mode indexes
/// are ALL, NONE, SINGLE, then those three with ANYONECANPAY.
pub fn signed(layout: usize, modes: [u8; 3]) -> Case {
    static TEMPLATES: [OnceLock<Vec<Case>>; LAYOUTS] = [const { OnceLock::new() }; LAYOUTS];
    let rows = TEMPLATES[layout].get_or_init(|| {
        let active = layout < PqScheme::KNOWN.len();
        let keys: Vec<_> = (0..3)
            .map(|i| {
                let scheme = if active {
                    PqScheme::KNOWN[(layout + i) % PqScheme::KNOWN.len()]
                } else {
                    PqScheme::Falcon512
                };
                scheme
                    .generate_keypair_from_seed(&vec![
                        93 + i as u8;
                        scheme.deterministic_seed_len()
                    ])
                    .unwrap()
            })
            .collect();
        // Base or P2SH, native or wrapped witness-v0, and native witness-v1.
        // Before activation the third signature uses wrapped v0 as well.
        let forms = [
            if layout.is_multiple_of(2) { 0 } else { 1 },
            if layout.is_multiple_of(2) { 2 } else { 4 },
            if active { 3 } else { 4 },
        ];
        // Distinct output amounts make a wrong SINGLE output index observable.
        sign_layout(&keys, forms, boundary_flags(active), [1, 3, 5])
    });
    let mut case = rows[0].clone();
    case.eval.clear();
    for (i, mode) in modes.into_iter().enumerate() {
        case.tx.inputs[i] = rows[usize::from(mode % 6)].tx.inputs[i].clone();
    }
    case
}

/// Apply two edits to different parts of the same transaction/context.
pub fn mutate(case: &mut Case, selector: u8, i: usize, j: usize) {
    match selector % 4 {
        0 => {
            case.spent[i].amount = case.spent[i].amount.checked_add(Amount::ONE_SAT).unwrap();
            case.tx.outputs[j].amount =
                case.tx.outputs[j].amount.checked_add(Amount::ONE_SAT).unwrap();
        }
        1 => {
            // Move the previous output together with the input it belongs to.
            let other = (i + 1) % 3;
            case.tx.inputs.swap(i, other);
            case.spent.swap(i, other);
            case.tx.inputs[j].sequence = Sequence::from_consensus(17);
        }
        2 => {
            case.tx.inputs[i].previous_output.vout ^= 0x80;
            case.tx.outputs.push(case.tx.outputs[j].clone());
        }
        _ => {
            // Drop both witness signatures while keeping the executing scripts.
            for input in &mut case.tx.inputs[1..] {
                let mut witness = input.witness.to_vec();
                witness[0].clear();
                input.witness = Witness::from(witness);
            }
        }
    }
}

/// Check each input independently, then the product API that shares one cache
/// across inputs and returns the first failing script in transaction order.
pub fn compare_signed(
    node: &TidecoinNodeHarness,
    case: &Case,
    mut check: impl FnMut(usize, Result<(), ScriptError>),
) {
    use tidecoin::consensus_validation::{
        verify_transaction_with_flags, TxVerifyError, ValidationError,
    };
    let mut first_failure = Ok(());
    compare_each_input(node, case, |i, verdict| {
        first_failure = first_failure.and(verdict);
        check(i, verdict);
    });
    let product = verify_transaction_with_flags(
        &case.tx,
        |outpoint| {
            case.tx
                .inputs
                .iter()
                .position(|input| input.previous_output == *outpoint)
                .map(|index| case.spent[index].clone())
        },
        case.flags,
    )
    .map_err(|err| match err {
        TxVerifyError::ScriptVerification(ValidationError::Tidecoin(
            consensus_core::TidecoinValidationError::Script(code),
        )) => super::map_rust_script_error(code),
        other => panic!("unexpected whole-transaction error: {other:?}"),
    });
    assert_eq!(product, first_failure, "whole transaction vs original inputs: {case:?}");
}

pub(super) fn fuzz(node: &TidecoinNodeHarness, data: &[u8]) {
    let b = |i| data.get(i).copied().unwrap_or(0);
    let layout = usize::from(b(0)) % LAYOUTS;
    let mut case = signed(layout, [b(1), b(2), b(3)]);
    compare_signed(node, &case, |_, verdict| verdict.unwrap());
    mutate(&mut case, b(4), usize::from(b(5) % 3), usize::from(b(6) % 3));
    if b(7) & 1 != 0 {
        case.flags = boundary_flags(layout == LAYOUTS - 1);
    }
    compare_signed(node, &case, |_, _| {});
}
