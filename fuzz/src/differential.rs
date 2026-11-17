// SPDX-License-Identifier: CC0-1.0
//! Identical-context comparisons with the original pinned C++ interpreter.
use consensus_core as core;
use node_parity::{NodeParityError, ScriptError, SpentOutput, TidecoinNodeHarness};
use tidecoin::hashes::{hash160, sha256, sha512};
use tidecoin::script::{ScriptPubKeyBuf, ScriptSigBuf};
use tidecoin::{
    absolute, Amount, OutPoint, Sequence, Transaction, TransactionVersion, TxIn, TxOut, Txid,
    Witness,
};
use tidecoin_consensus_encoding as encoding;

pub fn map_rust_script_error(err: core::ScriptError) -> ScriptError {
    match err {
        core::ScriptError::Ok => ScriptError::Ok,
        core::ScriptError::Unknown => ScriptError::UnknownError,
        core::ScriptError::EvalFalse => ScriptError::EvalFalse,
        core::ScriptError::OpReturn => ScriptError::OpReturn,
        core::ScriptError::ScriptSize => ScriptError::ScriptSize,
        core::ScriptError::PushSize => ScriptError::PushSize,
        core::ScriptError::OpCount => ScriptError::OpCount,
        core::ScriptError::StackSize => ScriptError::StackSize,
        core::ScriptError::SigCount => ScriptError::SigCount,
        core::ScriptError::PubkeyCount => ScriptError::PubkeyCount,
        core::ScriptError::Verify => ScriptError::Verify,
        core::ScriptError::EqualVerify => ScriptError::EqualVerify,
        core::ScriptError::CheckSigVerify => ScriptError::CheckSigVerify,
        core::ScriptError::CheckMultiSigVerify => ScriptError::CheckMultisigVerify,
        core::ScriptError::NumEqualVerify => ScriptError::NumEqualVerify,
        core::ScriptError::BadOpcode => ScriptError::BadOpcode,
        core::ScriptError::OpCodeSeparator => ScriptError::OpCodeSeparator,
        core::ScriptError::DisabledOpcode => ScriptError::DisabledOpcode,
        core::ScriptError::InvalidStackOperation => ScriptError::InvalidStackOperation,
        core::ScriptError::InvalidAltstackOperation => ScriptError::InvalidAltstackOperation,
        core::ScriptError::UnbalancedConditional => ScriptError::UnbalancedConditional,
        core::ScriptError::NegativeLockTime => ScriptError::NegativeLocktime,
        core::ScriptError::UnsatisfiedLockTime => ScriptError::UnsatisfiedLocktime,
        core::ScriptError::SigHashType => ScriptError::SigHashType,
        core::ScriptError::SigFalconEncoding => ScriptError::SigFalconEncoding,
        core::ScriptError::MinimalData => ScriptError::MinimalData,
        core::ScriptError::SigPushOnly => ScriptError::SigPushOnly,
        core::ScriptError::SigNullDummy => ScriptError::SigNullDummy,
        core::ScriptError::CleanStack => ScriptError::Cleanstack,
        core::ScriptError::MinimalIf => ScriptError::MinimalIf,
        core::ScriptError::NullFail => ScriptError::NullFail,
        core::ScriptError::DiscourageUpgradableNops => ScriptError::DiscourageUpgradableNops,
        core::ScriptError::DiscourageUpgradableWitnessProgram => {
            ScriptError::DiscourageUpgradableWitnessProgram
        }
        core::ScriptError::WitnessProgramWrongLength => ScriptError::WitnessProgramWrongLength,
        core::ScriptError::WitnessProgramWitnessEmpty => ScriptError::WitnessProgramWitnessEmpty,
        core::ScriptError::WitnessProgramMismatch => ScriptError::WitnessProgramMismatch,
        core::ScriptError::WitnessMalleated => ScriptError::WitnessMalleated,
        core::ScriptError::WitnessMalleatedP2SH => ScriptError::WitnessMalleatedP2sh,
        core::ScriptError::WitnessUnexpected => ScriptError::WitnessUnexpected,
        core::ScriptError::SigFindAndDelete => ScriptError::SigFindAndDelete,
    }
}

pub fn node_script_result(result: Result<(), NodeParityError>) -> Result<(), ScriptError> {
    match result {
        Ok(()) => Ok(()),
        Err(NodeParityError::Script(err)) => Err(err),
        Err(err) => panic!("unexpected Tidecoin-node harness failure: {err}"),
    }
}

/// One complete script-verification context. All outpoints are synthetic and distinct.
#[derive(Clone, Debug)]
pub struct Case {
    pub tx: Transaction,
    pub spent: Vec<TxOut>,
    pub flags: u32,
    /// Scripts to also run through original `EvalScript`, comparing final stacks.
    pub eval: Vec<EvalCase>,
}

/// One script and starting stack for an input of [`Case::tx`]. Verdicts alone
/// miss wrong intermediate values (a misordered `ROT` usually leaves a true
/// top element), so the whole resulting stack is compared under every
/// sigversion.
#[derive(Clone, Debug)]
pub struct EvalCase {
    pub input: usize,
    pub script: Vec<u8>,
    pub stack: Vec<Vec<u8>>,
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Respect original VerifyScript flag preconditions on both sides; no verdict filtering.
pub fn flags(bits: u32) -> u32 {
    let known = core::VERIFY_ALL_TIDECOIN
        | core::VERIFY_FALCON_CANONICAL
        | core::VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
        | core::VERIFY_CONST_SCRIPTCODE
        | core::VERIFY_SIGPUSHONLY
        | core::VERIFY_MINIMALDATA
        | core::VERIFY_CLEANSTACK
        | core::VERIFY_MINIMALIF
        | core::VERIFY_NULLFAIL
        | core::VERIFY_DISCOURAGE_UPGRADABLE_NOPS
        | core::VERIFY_DEFINED_HASHTYPE;
    let mut flags = bits & known;
    if flags & core::VERIFY_CLEANSTACK != 0 {
        flags |= core::VERIFY_WITNESS;
    }
    if flags & core::VERIFY_WITNESS != 0 {
        flags |= core::VERIFY_P2SH;
    }
    flags
}

pub fn transaction(script_sig: Vec<u8>, witness: Vec<Vec<u8>>) -> Transaction {
    Transaction {
        version: TransactionVersion::TWO,
        lock_time: absolute::LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint { txid: Txid::from_byte_array([1; 32]), vout: 0 },
            script_sig: ScriptSigBuf::from_bytes(script_sig),
            sequence: Sequence::MAX,
            witness: Witness::from(witness),
        }],
        outputs: vec![TxOut {
            amount: Amount::from_sat_u32(1),
            script_pubkey: ScriptPubKeyBuf::new(),
        }],
    }
}

pub fn push(bytes: &[u8]) -> Vec<u8> {
    // Encode data, including deliberately over-limit cases. Builder's size
    // restrictions must not filter inputs before either interpreter sees them.
    let mut out = if bytes.len() < 76 {
        vec![bytes.len() as u8]
    } else if bytes.len() <= 255 {
        vec![0x4c, bytes.len() as u8]
    } else if bytes.len() <= 65535 {
        [vec![0x4d], (bytes.len() as u16).to_le_bytes().to_vec()].concat()
    } else {
        [vec![0x4e], (bytes.len() as u32).to_le_bytes().to_vec()].concat()
    };
    out.extend_from_slice(bytes);
    out
}

/// Base, P2SH, native v0/v1, and wrapped v0/v1 contexts for the same script.
pub fn script_case(mode: u8, script: Vec<u8>, arguments: Vec<Vec<u8>>, bits: u32) -> Case {
    let eval = vec![EvalCase { input: 0, script: script.clone(), stack: arguments.clone() }];
    let mut witness = Vec::new();
    let (sig, locking) = match mode % 6 {
        0 => (arguments.iter().flat_map(|item| push(item)).collect(), script),
        1 => {
            let locking =
                [vec![0xa9, 20], hash160::Hash::hash(&script).to_byte_array().to_vec(), vec![0x87]]
                    .concat();
            let mut sig: Vec<u8> = arguments.iter().flat_map(|item| push(item)).collect();
            sig.extend(push(&script));
            (sig, locking)
        }
        mode => {
            let program = if mode == 2 || mode == 4 {
                [vec![0, 32], sha256::Hash::hash(&script).to_byte_array().to_vec()].concat()
            } else {
                [vec![0x51, 64], sha512::Hash::hash(&script).to_byte_array().to_vec()].concat()
            };
            witness = arguments;
            witness.push(script);
            if mode >= 4 {
                (
                    push(&program),
                    [
                        vec![0xa9, 20],
                        hash160::Hash::hash(&program).to_byte_array().to_vec(),
                        vec![0x87],
                    ]
                    .concat(),
                )
            } else {
                (vec![], program)
            }
        }
    };
    Case {
        tx: transaction(sig, witness),
        spent: vec![TxOut {
            amount: Amount::from_sat_u32(2),
            script_pubkey: ScriptPubKeyBuf::from_bytes(locking),
        }],
        flags: flags(bits),
        eval,
    }
}

/// Compare errors as well as acceptance, and repeat each low-level interpreter.
/// Infrastructure/context failures panic instead of being counted as script rejection.
pub fn compare(node: &TidecoinNodeHarness, case: &Case) {
    let bytes = encoding::encode_to_vec(&case.tx);
    let tx_hex = hex(&bytes);
    let outputs: Vec<_> = case
        .spent
        .iter()
        .map(|o| SpentOutput {
            amount: o.amount.to_sat() as i64,
            script_pubkey: o.script_pubkey.as_bytes(),
        })
        .collect();
    let raw: Vec<_> = case
        .spent
        .iter()
        .map(|o| consensus::Utxo {
            script_pubkey: o.script_pubkey.as_bytes(),
            value: o.amount.to_sat() as i64,
        })
        .collect();
    let ctx = core::TransactionContext::new(&case.tx);
    for (index, output) in case.spent.iter().enumerate() {
        let node_result = node_script_result(node.verify_tx_input_with_spent_outputs(
            &tx_hex,
            index,
            output.script_pubkey.as_bytes(),
            output.amount.to_sat() as i64,
            case.flags,
            &outputs,
        ));
        let make_spend = || {
            core::SpendContext::new(
                output.script_pubkey.as_bytes(),
                Some(core::SpentOutputs::from_txouts(case.spent.clone())),
                output.amount.to_sat(),
                true,
            )
        };
        let fresh = core::verify_script_input_detailed(&case.tx, index, make_spend(), case.flags)
            .map_err(|failure| map_rust_script_error(failure.script_error));
        assert_eq!(fresh, node_result, "fresh index={index} case={case:?}");
        let byte_result = consensus::verify_with_flags_detailed(
            output.script_pubkey.as_bytes(),
            output.amount.to_sat(),
            &bytes,
            Some(&raw),
            index,
            case.flags,
        );
        if tidecoin::transaction::check_transaction_sanity(&case.tx).is_ok() {
            assert_eq!(
                byte_result.map_err(|failure| map_rust_script_error(failure.script_error)),
                node_result,
                "byte API index={index} case={case:?}"
            );
        } else {
            // The byte API performs CheckTransaction during decode; the original
            // script oracle and typed interpreter deliberately do not.
            assert_eq!(node.transaction_decode_status(&bytes).unwrap(), 1);
            assert_eq!(byte_result.unwrap_err().error, consensus::Error::ERR_TX_DESERIALIZE);
        }
        let mut engine = core::Interpreter::new(
            &ctx,
            index,
            make_spend(),
            core::ScriptFlags::from_bits(case.flags).unwrap(),
        )
        .unwrap();
        for attempt in 0..3 {
            let result =
                engine.verify().map_err(|_| map_rust_script_error(engine.last_script_error()));
            assert_eq!(result, node_result, "repeat={attempt} index={index} case={case:?}");
        }
    }
    for eval in &case.eval {
        compare_eval(node, case, &tx_hex, &outputs, eval);
    }
}

/// Runs only the `EvalScript` comparison for `script` on `stack`, in a minimal
/// one-input transaction. Cheaper than [`compare`] for large opcode matrices.
pub fn compare_eval_only(node: &TidecoinNodeHarness, script: &[u8], stack: &[Vec<u8>], bits: u32) {
    let case = script_case(0, script.to_vec(), stack.to_vec(), bits);
    let tx_hex = hex(&encoding::encode_to_vec(&case.tx));
    let outputs: Vec<_> = case
        .spent
        .iter()
        .map(|o| SpentOutput {
            amount: o.amount.to_sat() as i64,
            script_pubkey: o.script_pubkey.as_bytes(),
        })
        .collect();
    compare_eval(node, &case, &tx_hex, &outputs, &case.eval[0]);
}

/// Compares original `EvalScript` with `Interpreter::eval_script`: the error on
/// failure, and every stack element on success.
fn compare_eval(
    node: &TidecoinNodeHarness,
    case: &Case,
    tx_hex: &str,
    outputs: &[SpentOutput<'_>],
    eval: &EvalCase,
) {
    // The Rust stack type enforces the element size limit on construction;
    // the original checks it before EvalScript, not inside it. Oversized
    // elements are covered by the verdict comparison above.
    let Ok(start) = core::ScriptStack::from_items(eval.stack.clone()) else { return };
    let output = &case.spent[eval.input];
    let ctx = core::TransactionContext::new(&case.tx);
    for (code, sigversion) in [
        (0, core::SigVersion::Base),
        (1, core::SigVersion::WitnessV0),
        (2, core::SigVersion::WitnessV1_512),
    ] {
        let node_result = node
            .eval_script(
                tx_hex,
                eval.input,
                output.amount.to_sat() as i64,
                case.flags,
                outputs,
                &eval.script,
                &eval.stack,
                code,
            )
            .map_err(|err| match err {
                NodeParityError::Script(err) => err,
                err => panic!("unexpected Tidecoin-node harness failure: {err}"),
            });
        let spend = core::SpendContext::new(
            output.script_pubkey.as_bytes(),
            Some(core::SpentOutputs::from_txouts(case.spent.clone())),
            output.amount.to_sat(),
            true,
        );
        let mut engine = core::Interpreter::new(
            &ctx,
            eval.input,
            spend,
            core::ScriptFlags::from_bits(case.flags).unwrap(),
        )
        .unwrap();
        let mut stack = start.clone();
        let rust_result = engine
            .eval_script(&mut stack, &eval.script, sigversion)
            .map(|()| stack.as_slice().to_vec())
            .map_err(|_| map_rust_script_error(engine.last_script_error()));
        assert_eq!(
            rust_result,
            node_result,
            "eval sigversion={sigversion:?} script={} stack={:?} case={case:?}",
            hex(&eval.script),
            eval.stack.iter().map(|item| hex(item)).collect::<Vec<_>>()
        );
    }
}

/// Compact fuzz input expands selected consensus boundaries without huge corpus files.
pub fn generated(data: &[u8]) -> Case {
    let byte = |i| data.get(i).copied().unwrap_or(0);
    let mode = byte(0) % 6;
    let bits = u32::from_le_bytes([byte(1), byte(2), byte(3), byte(4)]);
    let n =
        [0, 1, 75, 76, 252, 253, 255, 256, 999, 1000, 1001, 8191, 8192, 8193, 65535, 65536, 65537]
            [byte(6) as usize % 17];
    let mut args = vec![];
    let script = match byte(5) % 7 {
        0 => data.get(7..).unwrap_or(&[]).iter().take(2048).copied().collect(),
        1 => vec![0x51; n],
        2 => [push(&vec![byte(7); n]), vec![0x75, 0x51]].concat(),
        3 => {
            args.push(vec![byte(7); n]);
            vec![0x75, 0x51]
        }
        4 => {
            args = vec![vec![]; n.min(1001)];
            vec![0x51]
        }
        5 => vec![0x51, 0x6e, 0x75, 0x75, 0x75],
        _ => vec![0x00, 0x63, byte(7), 0x68, 0x51],
    };
    script_case(mode, script, args, bits)
}

/// Rust's decoder includes transaction sanity; compare against both original
/// stages, rather than treating C++ syntactic decoding as full validation.
pub fn compare_transaction_bytes(node: &TidecoinNodeHarness, bytes: &[u8]) {
    let node_status = node.transaction_decode_status(bytes).expect("node wire oracle unavailable");
    let rust = encoding::decode_from_slice::<Transaction>(bytes);
    assert_eq!(
        rust.is_ok(),
        node_status == 2,
        "wire={} original_stage={node_status} rust={rust:?}",
        hex(bytes)
    );
    if let Ok(tx) = rust {
        assert_eq!(encoding::encode_to_vec(&tx), bytes, "accepted noncanonical encoding");
    }
}

/// V1 commits to ordered spent-output context; compare complete and missing
/// context with one reused cache and fresh caches across all six hash modes.
pub fn compare_sighashes(node: &TidecoinNodeHarness, data: &[u8]) {
    let mut case = generated(data);
    let second = script_case(2, vec![0x51], vec![], case.flags);
    case.tx.inputs.push(second.tx.inputs[0].clone());
    case.tx.inputs[1].previous_output.vout = 1;
    case.spent.push(second.spent[0].clone());
    case.spent[1].amount = Amount::from_sat_u32(3);
    if data.first().copied().unwrap_or(0) & 1 != 0 {
        case.spent.swap(0, 1);
    }
    if data.get(1).copied().unwrap_or(0) & 1 != 0 {
        case.tx.outputs.clear();
    }
    let tx_hex = hex(&encoding::encode_to_vec(&case.tx));
    let outputs: Vec<_> = case
        .spent
        .iter()
        .map(|o| SpentOutput {
            amount: o.amount.to_sat() as i64,
            script_pubkey: o.script_pubkey.as_bytes(),
        })
        .collect();
    let mut cache = core::SighashCache::new_with_spent_outputs(
        &case.tx,
        core::SpentOutputs::from_txouts(case.spent.clone()),
    )
    .unwrap();
    for index in [1, 0, 1] {
        for mode in [
            core::TxSighashType::All,
            core::TxSighashType::None,
            core::TxSighashType::Single,
            core::TxSighashType::AllPlusAnyoneCanPay,
            core::TxSighashType::NonePlusAnyoneCanPay,
            core::TxSighashType::SinglePlusAnyoneCanPay,
        ] {
            let script = data.get(7..).unwrap_or(&[]);
            let amount = case.spent[index].amount;
            let rust = cache
                .p2wsh512_signature_hash(index, script, amount, mode)
                .ok()
                .map(|h| h.to_byte_array());
            let original = node
                .signature_hash_512(
                    &tx_hex,
                    index,
                    script,
                    amount.to_sat() as i64,
                    mode.to_u32() as i32,
                    &outputs,
                )
                .unwrap();
            assert_eq!(rust, original, "v1 cached index={index} mode={mode:?}");
            let fresh = core::SighashCache::new_with_spent_outputs(
                &case.tx,
                core::SpentOutputs::from_txouts(case.spent.clone()),
            )
            .unwrap()
            .p2wsh512_signature_hash(index, script, amount, mode)
            .ok()
            .map(|h| h.to_byte_array());
            assert_eq!(rust, fresh);
            let missing = core::SighashCache::new(&case.tx)
                .p2wsh512_signature_hash(index, script, amount, mode)
                .ok()
                .map(|h| h.to_byte_array());
            assert_eq!(
                missing,
                node.signature_hash_512(
                    &tx_hex,
                    index,
                    script,
                    amount.to_sat() as i64,
                    mode.to_u32() as i32,
                    &[]
                )
                .unwrap()
            );
        }
    }
}

/// Reads fuzz bytes, repeating zero once exhausted.
struct Bytes<'a>(&'a [u8]);

impl Bytes<'_> {
    fn byte(&mut self) -> u8 {
        let (first, rest) = self.0.split_first().map_or((0, &[][..]), |(b, r)| (*b, r));
        self.0 = rest;
        first
    }
    fn u32(&mut self) -> u32 {
        u32::from_le_bytes([self.byte(), self.byte(), self.byte(), self.byte()])
    }
    fn vec(&mut self, max: usize) -> Vec<u8> {
        let len = self.byte() as usize % (max + 1);
        (0..len).map(|_| self.byte()).collect()
    }
    /// Boundary-heavy 32-bit value: common consensus values or raw bytes.
    fn u32_boundary(&mut self) -> u32 {
        match self.byte() % 8 {
            0 => 0,
            1 => u32::MAX,
            2 => u32::MAX - 1,
            3 => 1 << 31,
            4 => 1 << 22,
            5 => self.byte().into(),
            _ => self.u32(),
        }
    }
    /// Script code biased towards `OP_CODESEPARATOR`, pushes and truncated pushes.
    fn script(&mut self) -> Vec<u8> {
        let len = self.byte() as usize % 24;
        (0..len)
            .map(|_| match self.byte() % 8 {
                0 | 1 => 0xab,
                2 => self.byte() % 0x4c,
                3 => 0x4c + self.byte() % 3,
                _ => self.byte(),
            })
            .collect()
    }
    /// Raw hash type: every byte value is consensus-valid for legacy and v0.
    fn hash_type(&mut self) -> u32 {
        match self.byte() % 4 {
            0 => [1, 2, 3, 0x81, 0x82, 0x83][self.byte() as usize % 6],
            1 => self.byte().into(),
            2 => self.u32(),
            _ => u32::from(self.byte()) | (u32::from(self.byte()) << 8),
        }
    }
}

/// Transaction shape, input index and spent outputs drawn from fuzz bytes.
fn sighash_transaction(data: &[u8]) -> (Transaction, Vec<TxOut>, usize, Bytes<'_>) {
    let mut b = Bytes(data);
    let inputs = 1 + b.byte() as usize % 5;
    let outputs = b.byte() as usize % 6;
    let amount = |b: &mut Bytes<'_>| {
        let raw = u64::from(b.u32()) << (b.byte() % 26);
        Amount::from_sat(raw % (Amount::MAX_MONEY.to_sat() + 1)).unwrap()
    };
    let tx = Transaction {
        version: TransactionVersion::maybe_non_standard(b.u32_boundary()),
        lock_time: absolute::LockTime::from_consensus(b.u32_boundary()),
        inputs: (0..inputs)
            .map(|i| TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([b.byte() ^ i as u8; 32]),
                    vout: b.u32_boundary(),
                },
                script_sig: ScriptSigBuf::from_bytes(b.vec(12)),
                sequence: Sequence::from_consensus(b.u32_boundary()),
                // Witnesses are not committed; they only vary the wire encoding.
                witness: Witness::from((0..b.byte() % 3).map(|_| b.vec(8)).collect::<Vec<_>>()),
            })
            .collect(),
        outputs: (0..outputs)
            .map(|_| TxOut {
                amount: amount(&mut b),
                script_pubkey: ScriptPubKeyBuf::from_bytes(b.vec(40)),
            })
            .collect(),
    };
    let spent = (0..inputs)
        .map(|_| TxOut {
            amount: amount(&mut b),
            script_pubkey: ScriptPubKeyBuf::from_bytes(b.vec(40)),
        })
        .collect();
    let index = b.byte() as usize % inputs;
    (tx, spent, index, b)
}

/// Compares legacy, witness-v0 and witness-v1-512 digests for generated
/// transaction shapes. Each version reuses one Rust cache across several
/// script codes and raw hash types, as the node shares one per input.
pub fn compare_random_sighashes(node: &TidecoinNodeHarness, data: &[u8]) {
    let (tx, spent, index, mut b) = sighash_transaction(data);
    let tx_bytes = encoding::encode_to_vec(&tx);
    let amount = spent[index].amount;
    let queries: Vec<(u32, Vec<u8>)> =
        (0..1 + b.byte() % 6).map(|_| (b.hash_type(), b.script())).collect();
    let node_queries: Vec<(i32, &[u8])> =
        queries.iter().map(|(t, s)| (*t as i32, s.as_slice())).collect();
    let context = |version| format!("{version:?} index={index} tx={}", hex(&tx_bytes));

    let legacy = core::SighashCache::new(&tx);
    let original = node
        .signature_hashes(&tx_bytes, index, node_parity::SighashVersion::Legacy, 0, &node_queries)
        .unwrap();
    for ((hash_type, script), original) in queries.iter().zip(&original) {
        // Raw script code on both sides: like node SignatureHash, the Rust digest
        // must remove OP_CODESEPARATOR while serializing legacy script code.
        let rust = legacy.legacy_signature_hash(index, script, *hash_type).unwrap();
        assert_eq!(
            rust.to_byte_array(),
            *original,
            "legacy hash_type={hash_type:#x} script={} {}",
            hex(script),
            context("legacy")
        );
    }

    let mut v0 = core::SighashCache::new(&tx);
    let original = node
        .signature_hashes(
            &tx_bytes,
            index,
            node_parity::SighashVersion::WitnessV0,
            amount.to_sat() as i64,
            &node_queries,
        )
        .unwrap();
    for ((hash_type, script), original) in queries.iter().zip(&original) {
        let rust = v0.p2wsh_signature_hash_raw(index, script, amount, *hash_type).unwrap();
        assert_eq!(
            rust.to_byte_array(),
            *original,
            "v0 hash_type={hash_type:#x} script={} {}",
            hex(script),
            context("v0")
        );
    }

    // Witness v1 rejects undefined hash types before hashing, so only the six
    // defined modes reach SignatureHash512.
    let outputs: Vec<_> = spent
        .iter()
        .map(|o| SpentOutput {
            amount: o.amount.to_sat() as i64,
            script_pubkey: o.script_pubkey.as_bytes(),
        })
        .collect();
    let tx_hex = hex(&tx_bytes);
    let mut v1 = core::SighashCache::new_with_spent_outputs(
        &tx,
        core::SpentOutputs::from_txouts(spent.clone()),
    )
    .unwrap();
    for (hash_type, script) in &queries {
        let mode = core::TxSighashType::from_consensus(*hash_type);
        let rust =
            v1.p2wsh512_signature_hash(index, script, amount, mode).ok().map(|h| h.to_byte_array());
        let original = node
            .signature_hash_512(
                &tx_hex,
                index,
                script,
                amount.to_sat() as i64,
                mode.to_u32() as i32,
                &outputs,
            )
            .unwrap_or_else(|e| {
                panic!("{e} mode={mode:?} script={} {}", hex(script), context("v1"))
            });
        assert_eq!(rust, original, "v1 mode={mode:?} script={} {}", hex(script), context("v1"));
    }
}

/// Valid mixed legacy/v0/v1 spends reach real cryptography before mutation.
/// Deterministic key seeds belong only to this test corpus, never production.
pub fn signed_cases(node: &TidecoinNodeHarness) -> Vec<Case> {
    use tidecoin::{PqScheme, PqSchemeCryptoExt, PqSignature};
    let schemes = [PqScheme::Falcon512, PqScheme::MlDsa44, PqScheme::Falcon1024];
    let keys: Vec<_> = schemes
        .into_iter()
        .map(|scheme| {
            scheme.generate_keypair_from_seed(&vec![73; scheme.deterministic_seed_len()]).unwrap()
        })
        .collect();
    let scripts: Vec<_> =
        keys.iter().map(|(pk, _)| [push(&pk.to_prefixed_bytes()), vec![0xac]].concat()).collect();
    let mut cases = Vec::new();
    for mode in [
        core::TxSighashType::All,
        core::TxSighashType::None,
        core::TxSighashType::Single,
        core::TxSighashType::AllPlusAnyoneCanPay,
        core::TxSighashType::NonePlusAnyoneCanPay,
        core::TxSighashType::SinglePlusAnyoneCanPay,
    ] {
        let mut case = script_case(0, scripts[0].clone(), vec![], core::VERIFY_ALL_TIDECOIN);
        for (index, kind) in [(1, 2), (2, 3)] {
            let part = script_case(kind, scripts[index].clone(), vec![], case.flags);
            case.tx.inputs.push(part.tx.inputs[0].clone());
            case.spent.push(part.spent[0].clone());
            case.tx.inputs[index].previous_output.vout = index as u32;
            case.spent[index].amount = Amount::from_sat_u32(100 + index as u32);
            case.tx.outputs.push(case.tx.outputs[0].clone());
        }
        // Each input's script with its real signature: a successful CHECKSIG.
        case.eval.clear();
        for index in 0..3 {
            let mut cache = core::SighashCache::new_with_spent_outputs(
                &case.tx,
                core::SpentOutputs::from_txouts(case.spent.clone()),
            )
            .unwrap();
            let mut signature = if index == 2 {
                let hash = cache
                    .p2wsh512_signature_hash(index, &scripts[index], case.spent[index].amount, mode)
                    .unwrap();
                PqSignature::sign_msg64(&hash.to_byte_array(), &keys[index].1)
                    .unwrap()
                    .as_bytes()
                    .to_vec()
            } else {
                let hash = if index == 0 {
                    cache
                        .legacy_signature_hash(index, &scripts[index], mode.to_u32())
                        .unwrap()
                        .to_byte_array()
                } else {
                    cache
                        .p2wsh_signature_hash(
                            index,
                            &scripts[index],
                            case.spent[index].amount,
                            mode,
                        )
                        .unwrap()
                        .to_byte_array()
                };
                PqSignature::sign_msg32(&hash, &keys[index].1).unwrap().as_bytes().to_vec()
            };
            signature.push(mode.to_u32() as u8);
            case.eval.push(EvalCase {
                input: index,
                script: scripts[index].clone(),
                stack: vec![signature.clone()],
            });
            if index == 0 {
                case.tx.inputs[index].script_sig = ScriptSigBuf::from_bytes(push(&signature));
            } else {
                case.tx.inputs[index].witness =
                    Witness::from(vec![signature, scripts[index].clone()]);
            }
        }
        compare(node, &case);
        // Positive corpus controls must actually pass, not merely agree on rejection.
        core::verify_transaction_inputs(
            &case.tx,
            core::SpentOutputs::from_txouts(case.spent.clone()),
            case.flags,
        )
        .unwrap();
        cases.push(case);
    }
    cases
}

pub fn mutate_signed(case: &mut Case, data: &[u8]) {
    let b = |i| data.get(i).copied().unwrap_or(0);
    let index = b(1) as usize % case.tx.inputs.len();
    match b(0) % 10 {
        0 => {}
        1 => case.spent.swap(0, 2),
        2 => case.spent[index].amount = Amount::from_sat_u32(b(2) as u32),
        3 => case.spent[index].script_pubkey = ScriptPubKeyBuf::from_bytes(vec![b(2)]),
        4 => case.tx.inputs[index].sequence = Sequence::from_consensus(b(2) as u32),
        5 => case.tx.outputs.truncate(b(2) as usize % 4),
        6 => case.tx.inputs[index].previous_output.vout ^= 0x80,
        7 => {
            let mut items = case.tx.inputs[2].witness.to_vec();
            if let Some(last) = items[0].last_mut() {
                *last = b(2);
            }
            case.tx.inputs[2].witness = Witness::from(items);
        }
        8 => {
            let mut items = case.tx.inputs[1].witness.to_vec();
            let at = b(2) as usize % items[0].len();
            items[0][at] ^= 0x80;
            case.tx.inputs[1].witness = Witness::from(items);
        }
        _ => case.flags = flags(u32::from_le_bytes([b(1), b(2), b(3), b(4)])),
    }
}

/// Entry point shared by deterministic smoke tests and coverage-guided fuzzing.
pub fn run(node: &TidecoinNodeHarness, data: &[u8]) {
    // Kind 4 takes one first-byte value, leaving every other byte's meaning
    // unchanged. Saved corpora from before kind 4 used 0x04 for kind 0: rewrite
    // those entries' first byte to 0x00 to keep their coverage.
    let kind = match data.first().copied().unwrap_or(0) {
        4 => 4,
        byte => byte % 4,
    };
    let payload = data.get(1..).unwrap_or(&[]);
    match kind {
        0 => compare(node, &generated(payload)),
        4 => compare_random_sighashes(node, payload),
        1 => compare_transaction_bytes(node, payload),
        2 => compare_sighashes(node, payload),
        _ => {
            static SIGNED: std::sync::OnceLock<Vec<Case>> = std::sync::OnceLock::new();
            let cases = SIGNED.get_or_init(|| signed_cases(node));
            let mut case =
                cases[payload.first().copied().unwrap_or(0) as usize % cases.len()].clone();
            mutate_signed(&mut case, payload.get(1..).unwrap_or(&[]));
            compare(node, &case);
        }
    }
}
