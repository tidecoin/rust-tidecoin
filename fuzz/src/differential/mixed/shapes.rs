// SPDX-License-Identifier: CC0-1.0
//! Signed transaction shapes for the rc3 comparison driver.

use std::sync::OnceLock;

use super::{boundary_flags, compare_signed, Case};
use crate::differential::{hex, push, script_case, transaction};
use consensus_core::{SighashCache, SpentOutputs, TxSighashType, WitnessV1SighashError};
use node_parity::{ScriptError, SighashVersion, SpentOutput, TidecoinNodeHarness};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use tidecoin::{
    Amount, PqPublicKey, PqScheme, PqSchemeCryptoExt, PqSecretKey, PqSignature, Witness,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Spend {
    Legacy,
    V0,
    V1,
    Multi,
    Branch,
}

impl Spend {
    fn form(self) -> u8 {
        match self {
            Self::Legacy => 0,
            Self::V0 | Self::Multi => 2,
            Self::V1 | Self::Branch => 3,
        }
    }

    fn script(self, keys: &[(PqPublicKey, PqSecretKey)]) -> Vec<u8> {
        let pk = |i: usize| push(&keys[i].0.to_prefixed_bytes());
        match self {
            // 2 <A> <B> 2 CHECKMULTISIG
            Self::Multi => [vec![0x52], pk(0), pk(1), vec![0x52, 0xae]].concat(),
            // IF <A> ELSE <B> ENDIF CHECKSIG
            Self::Branch => [vec![0x63], pk(0), vec![0x67], pk(1), vec![0x68, 0xac]].concat(),
            _ => [pk(0), vec![0xac]].concat(),
        }
    }
}

/// Sign the node's digests so that a corresponding error in Rust signing and
/// verification cannot make a positive fixture pass. A missing v1 SINGLE keeps
/// its real signature from the transaction with the matching output.
fn signed_case(
    node: &TidecoinNodeHarness,
    spends: &[Spend],
    missing: bool,
    true_branch: bool,
) -> Case {
    static KEYS: OnceLock<Vec<(PqPublicKey, PqSecretKey)>> = OnceLock::new();
    let keys = KEYS.get_or_init(|| {
        let scheme = PqScheme::Falcon512;
        [111, 112]
            .map(|seed| {
                scheme
                    .generate_keypair_from_seed(&vec![seed; scheme.deterministic_seed_len()])
                    .unwrap()
            })
            .to_vec()
    });
    let flags = boundary_flags(true) | consensus_core::VERIFY_MINIMALIF;
    let scripts: Vec<_> = spends.iter().map(|role| role.script(keys)).collect();
    let mut tx = transaction(vec![], vec![]);
    let mut spent = Vec::new();
    for (i, (&role, script)) in spends.iter().zip(&scripts).enumerate() {
        let mut part = script_case(role.form(), script.clone(), vec![], flags);
        let index = i as u32;
        let mut input = part.tx.inputs.pop().unwrap();
        input.previous_output.vout = index;
        if i == 0 {
            tx.inputs[0] = input;
        } else {
            tx.inputs.push(input);
            tx.outputs.push(tx.outputs[0].clone());
        }
        tx.outputs[i].amount = Amount::from_sat_u32(1 + index);
        let mut prevout = part.spent.pop().unwrap();
        prevout.amount = Amount::from_sat_u32(100 + index);
        spent.push(prevout);
    }

    let last = spends.len() - 1;
    let missing_v1 = missing && spends[last] == Spend::V1;
    if missing && !missing_v1 {
        tx.outputs.pop();
    }
    let bytes = tidecoin_consensus_encoding::encode_to_vec(&tx);
    let outputs: Vec<_> = spent
        .iter()
        .map(|o| SpentOutput {
            amount: o.amount.to_sat() as i64,
            script_pubkey: o.script_pubkey.as_bytes(),
        })
        .collect();
    for (i, (&role, script)) in spends.iter().zip(&scripts).enumerate() {
        // Earlier NONE signatures still verify after the last output is removed.
        let mode = if i == last { TxSighashType::Single } else { TxSighashType::None };
        let arguments = if role.form() == 3 {
            let hash = node
                .signature_hash_512(
                    &hex(&bytes),
                    i,
                    script,
                    outputs[i].amount,
                    mode.to_u32() as i32,
                    &outputs,
                )
                .unwrap()
                .unwrap();
            let signer = usize::from(role == Spend::Branch && !true_branch);
            let mut rng = ChaCha20Rng::from_seed(hash[..32].try_into().unwrap());
            let mut sig = PqSignature::sign_msg64_with_rng(&hash, &keys[signer].1, &mut rng)
                .unwrap()
                .as_bytes()
                .to_vec();
            sig.push(mode.to_u32() as u8);
            let mut args = vec![sig];
            if role == Spend::Branch {
                args.push(if true_branch { vec![1] } else { vec![] });
            }
            args
        } else {
            let version = if role == Spend::Legacy {
                SighashVersion::Legacy
            } else {
                SighashVersion::WitnessV0
            };
            let hash = node
                .signature_hashes(
                    &bytes,
                    i,
                    version,
                    outputs[i].amount,
                    &[(mode.to_u32() as i32, script)],
                )
                .unwrap()[0];
            if missing && i == last && role == Spend::Legacy {
                let mut one = [0; 32];
                one[0] = 1;
                assert_eq!(hash, one);
            }
            let mut rng = ChaCha20Rng::from_seed(hash);
            let mut args = Vec::new();
            let signers = if role == Spend::Multi {
                args.push(vec![]);
                2
            } else {
                1
            };
            for (_, key) in &keys[..signers] {
                let mut sig = PqSignature::sign_msg32_with_rng(&hash, key, &mut rng)
                    .unwrap()
                    .as_bytes()
                    .to_vec();
                sig.push(mode.to_u32() as u8);
                args.push(sig);
            }
            args
        };
        let signed = script_case(role.form(), script.clone(), arguments, flags);
        tx.inputs[i].script_sig = signed.tx.inputs[0].script_sig.clone();
        tx.inputs[i].witness = signed.tx.inputs[0].witness.clone();
    }
    if missing_v1 {
        tx.outputs.pop();
        let script = &scripts[last];
        let mode = TxSighashType::Single;
        let mut cache =
            SighashCache::new_with_spent_outputs(&tx, SpentOutputs::from_txouts(spent.clone()))
                .unwrap();
        assert_eq!(
            cache.p2wsh512_signature_hash(last, script, spent[last].amount, mode),
            Err(WitnessV1SighashError::SingleMissingOutput)
        );
        let bytes = tidecoin_consensus_encoding::encode_to_vec(&tx);
        assert_eq!(
            node.signature_hash_512(
                &hex(&bytes),
                last,
                script,
                outputs[last].amount,
                mode.to_u32() as i32,
                &outputs
            )
            .unwrap(),
            None
        );
    }
    Case { tx, spent, flags, eval: vec![] }
}

/// With one input retain an output so the case passes transaction sanity.
/// With two and four inputs also exercise SINGLE beyond the final output.
pub fn single_boundary(node: &TidecoinNodeHarness, size: u8, version: u8, remove: bool) -> Case {
    static CASES: [OnceLock<Case>; 18] = [const { OnceLock::new() }; 18];
    let size = usize::from(size % 3);
    let version = usize::from(version % 3);
    let count = [1, 2, 4][size];
    let missing = remove && count > 1;
    let case = CASES[(size * 3 + version) * 2 + usize::from(missing)].get_or_init(|| {
        let mut roles = vec![Spend::Legacy; count];
        roles[count - 1] = [Spend::Legacy, Spend::V0, Spend::V1][version];
        signed_case(node, &roles, missing, true)
    });
    compare_signed(node, case, |i, result| {
        let rejects = missing && version == 2 && i == count - 1;
        assert_eq!(result, if rejects { Err(ScriptError::EvalFalse) } else { Ok(()) });
    });
    case.clone()
}

/// Re-sign both input orders. Edits touch witness arguments only, keeping all
/// other inputs' signatures valid. Bits select the multisig dummy, IF selector
/// and first multisig signature respectively.
pub fn script_mix(
    node: &TidecoinNodeHarness,
    branch_first: bool,
    true_branch: bool,
    edit: u8,
) -> Case {
    static CASES: [OnceLock<Case>; 4] = [const { OnceLock::new() }; 4];
    let (multi, branch) = if branch_first { (2, 1) } else { (1, 2) };
    let baseline =
        CASES[usize::from(branch_first) * 2 + usize::from(true_branch)].get_or_init(|| {
            let mut roles = [Spend::Legacy, Spend::Multi, Spend::Branch, Spend::V0];
            roles[multi] = Spend::Multi;
            roles[branch] = Spend::Branch;
            signed_case(node, &roles, false, true_branch)
        });
    let mut case = baseline.clone();
    let mut multi_stack = case.tx.inputs[multi].witness.to_vec();
    let mut branch_stack = case.tx.inputs[branch].witness.to_vec();
    if edit & 1 != 0 {
        multi_stack[0] = vec![1];
    }
    if edit & 2 != 0 {
        branch_stack[1] = vec![2];
    } else if edit & 8 != 0 {
        branch_stack[1] = if true_branch { vec![] } else { vec![1] };
    }
    if edit & 4 != 0 {
        multi_stack[1].clear();
    }
    case.tx.inputs[multi].witness = Witness::from(multi_stack);
    case.tx.inputs[branch].witness = Witness::from(branch_stack);
    compare_signed(node, &case, |i, result| {
        let expected = if i == multi && edit & 1 != 0 {
            Err(ScriptError::SigNullDummy)
        } else if i == branch && edit & 2 != 0 {
            Err(ScriptError::MinimalIf)
        } else if (i == multi && edit & 4 != 0) || (i == branch && edit & 8 != 0) {
            Err(ScriptError::EvalFalse)
        } else {
            Ok(())
        };
        assert_eq!(
            result, expected,
            "input={i} branch_first={branch_first} true_branch={true_branch} edit={edit}"
        );
    });
    case
}

/// Rebuild a pinned shape from `data`, then compare up to two further edits
/// with rc3 without pinned expectations.
pub fn fuzz(node: &TidecoinNodeHarness, data: &[u8]) {
    let b = |i: usize| data.get(i).copied().unwrap_or(0);
    let mut case = if b(0) & 1 == 0 {
        single_boundary(node, b(1), b(2), b(3) & 1 != 0)
    } else {
        // Both branch-selector edits rewrite one witness item; keep one.
        let edit = b(3) & 0b1111;
        let edit = if edit & 0b1010 == 0b1010 { edit & !0b1000 } else { edit };
        script_mix(node, b(1) & 1 != 0, b(2) & 1 != 0, edit)
    };
    for round in 0..usize::from(b(4) % 3) {
        let at = 5 + round * 5;
        edit_case(&mut case, [b(at), b(at + 1), b(at + 2), b(at + 3), b(at + 4)]);
    }
    compare_signed(node, &case, |_, _| {});
}

/// One unpinned edit from five bytes: selector (low three bits choose the edit,
/// the next three a bit index), input, then `c`, `d` and `e`. Offsets use two
/// bytes, reaching every byte of a Falcon-512 signature or a script containing
/// a large public key. Keeps at least one output and distinct outpoints, so
/// every difference from rc3 is a script verdict.
fn edit_case(case: &mut Case, [selector, a, c, d, e]: [u8; 5]) {
    let inputs = case.tx.inputs.len();
    let i = usize::from(a) % inputs;
    let j = usize::from(c) % inputs;
    let offset = usize::from(u16::from_le_bytes([d, e]));
    let bit = 1u8 << (selector >> 3 & 7);
    let value = u32::from_le_bytes([c, d, e, 0]);
    match selector % 8 {
        0 => case.spent[i].amount = case.spent[i].amount.checked_add(Amount::ONE_SAT).unwrap(),
        1 => {
            // Flip one bit in a witness item, or in the scriptSig without one.
            let mut items = case.tx.inputs[i].witness.to_vec();
            if items.is_empty() {
                let mut sig = case.tx.inputs[i].script_sig.as_bytes().to_vec();
                if !sig.is_empty() {
                    let at = offset % sig.len();
                    sig[at] ^= bit;
                }
                case.tx.inputs[i].script_sig = tidecoin::script::ScriptSigBuf::from_bytes(sig);
            } else {
                let item = usize::from(c) % items.len();
                if !items[item].is_empty() {
                    let at = offset % items[item].len();
                    items[item][at] ^= bit;
                }
                case.tx.inputs[i].witness = Witness::from(items);
            }
        }
        2 => case.tx.inputs[i].sequence = tidecoin::Sequence::from_consensus(value),
        3 => {
            if case.tx.outputs.len() > 1 {
                case.tx.outputs.pop();
            }
        }
        4 => {
            let output = case.tx.outputs[usize::from(c) % case.tx.outputs.len()].clone();
            case.tx.outputs.push(output);
        }
        5 => {
            case.tx.inputs.swap(i, j);
            case.spent.swap(i, j);
        }
        6 => case.tx.lock_time = tidecoin::absolute::LockTime::from_consensus(value),
        // Keep the fixtures' extra MINIMALIF flag across the activation switch.
        _ => {
            case.flags = boundary_flags(false) | (case.flags & consensus_core::VERIFY_MINIMALIF);
        }
    }
}
