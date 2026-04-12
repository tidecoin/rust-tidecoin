use consensus_core::{SighashCache, TxSighashType};
use encoding::encode_to_vec;
use hashes::sha256d;
use primitives::{
    absolute::LockTime,
    opcodes::all,
    script::{ScriptBuf as PrimitiveScriptBuf, ScriptPubKeyBuf, ScriptSigBuf},
    Amount, OutPoint, Sequence, Transaction, TransactionVersion, TxIn, TxOut, Txid, Witness,
};

type ScriptBuf = PrimitiveScriptBuf<()>;

const SIGHASH_NONE: u32 = 0x02;
const SIGHASH_SINGLE: u32 = 0x03;
const SIGHASH_ANYONECANPAY: u32 = 0x80;
const RANDOM_TESTS: usize = 10_000;

#[derive(Clone)]
struct DeterministicRng(u64);

impl DeterministicRng {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn rand_bool(&mut self) -> bool {
        self.next_u32() & 1 == 1
    }

    fn randbits(&mut self, bits: u32) -> u32 {
        if bits == 32 {
            self.next_u32()
        } else {
            self.next_u32() & ((1u32 << bits) - 1)
        }
    }

    fn range(&mut self, upper: usize) -> usize {
        assert!(upper > 0, "upper bound must be positive");
        (self.next_u64() as usize) % upper
    }
}

fn to_one_hash() -> sha256d::Hash {
    let mut bytes = [0u8; 32];
    bytes[0] = 1;
    sha256d::Hash::from_byte_array(bytes)
}

fn remove_op_codeseparator(script: &ScriptBuf) -> ScriptBuf {
    let bytes = script.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        let start = i;
        let opcode = bytes[i];
        i += 1;

        let push_len = if opcode <= 0x4b {
            Some(opcode as usize)
        } else if opcode == all::OP_PUSHDATA1.to_u8() {
            if i >= bytes.len() {
                break;
            }
            let len = bytes[i] as usize;
            i += 1;
            Some(len)
        } else if opcode == all::OP_PUSHDATA2.to_u8() {
            if i + 1 >= bytes.len() {
                break;
            }
            let len = u16::from_le_bytes([bytes[i], bytes[i + 1]]) as usize;
            i += 2;
            Some(len)
        } else if opcode == all::OP_PUSHDATA4.to_u8() {
            if i + 3 >= bytes.len() {
                break;
            }
            let len =
                u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]) as usize;
            i += 4;
            Some(len)
        } else {
            None
        };

        if let Some(len) = push_len {
            let end = i.saturating_add(len).min(bytes.len());
            out.extend_from_slice(&bytes[start..end]);
            i = end;
            continue;
        }

        if opcode != all::OP_CODESEPARATOR.to_u8() {
            out.push(opcode);
        }
    }
    ScriptBuf::from_bytes(out)
}

fn append_true(script: &ScriptBuf) -> ScriptBuf {
    let mut bytes = script.as_bytes().to_vec();
    bytes.push(all::OP_PUSHNUM_1.to_u8());
    ScriptBuf::from_bytes(bytes)
}

fn legacy_signature_hash_old(
    script_code: &ScriptBuf,
    tx: &Transaction,
    input_index: usize,
    hash_type: u32,
) -> sha256d::Hash {
    if input_index >= tx.inputs.len() {
        return to_one_hash();
    }

    let stripped_script = remove_op_codeseparator(script_code);
    let sighash_mode = hash_type & 0x1f;

    if sighash_mode == SIGHASH_SINGLE && input_index >= tx.outputs.len() {
        return to_one_hash();
    }

    let mut encoded = Vec::new();
    encoded.extend_from_slice(&encode_to_vec(&tx.version));

    if hash_type & SIGHASH_ANYONECANPAY != 0 {
        write_compact_size(1, &mut encoded);
        let input = &tx.inputs[input_index];
        encoded.extend_from_slice(&encode_to_vec(&input.previous_output));
        write_script_bytes(stripped_script.as_bytes(), &mut encoded);
        encoded.extend_from_slice(&input.sequence.to_consensus_u32().to_le_bytes());
    } else {
        write_compact_size(tx.inputs.len(), &mut encoded);
        for (idx, input) in tx.inputs.iter().enumerate() {
            encoded.extend_from_slice(&encode_to_vec(&input.previous_output));
            if idx == input_index {
                write_script_bytes(stripped_script.as_bytes(), &mut encoded);
            } else {
                write_script_bytes(&[], &mut encoded);
            }
            let sequence = if idx != input_index
                && (sighash_mode == SIGHASH_SINGLE || sighash_mode == SIGHASH_NONE)
            {
                Sequence::ZERO
            } else {
                input.sequence
            };
            encoded.extend_from_slice(&sequence.to_consensus_u32().to_le_bytes());
        }
    }

    match sighash_mode {
        0x01 => {
            write_compact_size(tx.outputs.len(), &mut encoded);
            for output in &tx.outputs {
                encoded.extend_from_slice(&encode_to_vec(output));
            }
        }
        SIGHASH_SINGLE => {
            write_compact_size(input_index + 1, &mut encoded);
            for _ in 0..input_index {
                encoded.extend_from_slice(&[0xFF; 8]);
                encoded.push(0x00);
            }
            encoded.extend_from_slice(&encode_to_vec(&tx.outputs[input_index]));
        }
        SIGHASH_NONE => {
            write_compact_size(0, &mut encoded);
        }
        _ => {
            write_compact_size(tx.outputs.len(), &mut encoded);
            for output in &tx.outputs {
                encoded.extend_from_slice(&encode_to_vec(output));
            }
        }
    }

    encoded.extend_from_slice(&encode_to_vec(&tx.lock_time));
    encoded.extend_from_slice(&hash_type.to_le_bytes());
    sha256d::Hash::hash(&encoded)
}

fn write_compact_size(value: usize, out: &mut Vec<u8>) {
    match value {
        0..=252 => out.push(value as u8),
        253..=0xFFFF => {
            out.push(0xFD);
            out.extend_from_slice(&(value as u16).to_le_bytes());
        }
        0x1_0000..=0xFFFF_FFFF => {
            out.push(0xFE);
            out.extend_from_slice(&(value as u32).to_le_bytes());
        }
        _ => {
            out.push(0xFF);
            out.extend_from_slice(&(value as u64).to_le_bytes());
        }
    }
}

fn write_script_bytes(script: &[u8], out: &mut Vec<u8>) {
    write_compact_size(script.len(), out);
    out.extend_from_slice(script);
}

fn random_script(rng: &mut DeterministicRng) -> ScriptBuf {
    let opcodes: &[u8] = &[
        all::OP_PUSHBYTES_0.to_u8(),
        all::OP_PUSHNUM_1.to_u8(),
        all::OP_PUSHNUM_2.to_u8(),
        all::OP_PUSHNUM_3.to_u8(),
        all::OP_CHECKSIG.to_u8(),
        all::OP_IF.to_u8(),
        all::OP_VERIF.to_u8(),
        all::OP_RETURN.to_u8(),
        all::OP_CODESEPARATOR.to_u8(),
    ];
    let ops = rng.range(10);
    let mut bytes = Vec::with_capacity(ops);
    for _ in 0..ops {
        bytes.push(opcodes[rng.range(opcodes.len())]);
    }
    ScriptBuf::from_bytes(bytes)
}

fn random_txid(rng: &mut DeterministicRng) -> Txid {
    let mut bytes = [0u8; 32];
    for chunk in bytes.chunks_exact_mut(8) {
        chunk.copy_from_slice(&rng.next_u64().to_le_bytes());
    }
    Txid::from_byte_array(bytes)
}

fn random_transaction(rng: &mut DeterministicRng, force_single: bool) -> Transaction {
    let input_count = (rng.randbits(2) + 1) as usize;
    let output_count = if force_single { input_count } else { (rng.randbits(2) + 1) as usize };

    let mut inputs = Vec::with_capacity(input_count);
    for _ in 0..input_count {
        inputs.push(TxIn {
            previous_output: OutPoint { txid: random_txid(rng), vout: rng.randbits(2) },
            script_sig: ScriptSigBuf::from(random_script(rng).into_bytes()),
            sequence: if rng.rand_bool() {
                Sequence::from_consensus(rng.next_u32())
            } else {
                Sequence::MAX
            },
            witness: Witness::new(),
        });
    }

    let mut outputs = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        outputs.push(TxOut {
            amount: Amount::from_sat(rng.next_u64() % 2_100_000_000_000_000).unwrap(),
            script_pubkey: ScriptPubKeyBuf::from(random_script(rng).into_bytes()),
        });
    }

    Transaction {
        version: TransactionVersion::maybe_non_standard(rng.next_u32()),
        lock_time: if rng.rand_bool() {
            LockTime::from_consensus(rng.next_u32())
        } else {
            LockTime::ZERO
        },
        inputs,
        outputs,
    }
}

fn hash_types_for_case(rng: &mut DeterministicRng) -> Vec<u32> {
    let mut hash_types = vec![
        1,
        SIGHASH_SINGLE,
        SIGHASH_NONE,
        1 | SIGHASH_ANYONECANPAY,
        SIGHASH_SINGLE | SIGHASH_ANYONECANPAY,
        SIGHASH_NONE | SIGHASH_ANYONECANPAY,
        SIGHASH_ANYONECANPAY,
        0,
        i32::MAX as u32,
    ];
    for i in 0..10 {
        hash_types.push(if i % 2 == 0 { (rng.next_u32() as i8) as u32 } else { rng.next_u32() });
    }
    hash_types
}

#[test]
fn tidecoin_randomized_legacy_sighash_parity() {
    let mut rng = DeterministicRng::new(0x3b4d_6a2f_d915_7cbe);

    for i in 0..RANDOM_TESTS {
        let hash_type = rng.next_u32();
        let tx = random_transaction(&mut rng, (hash_type & 0x1f) == SIGHASH_SINGLE);
        let script_code = remove_op_codeseparator(&random_script(&mut rng));
        let input_index = rng.range(tx.inputs.len());

        let old = legacy_signature_hash_old(&script_code, &tx, input_index, hash_type);
        let current = SighashCache::new(&tx)
            .legacy_signature_hash(input_index, script_code.as_bytes(), hash_type)
            .expect("legacy sighash calculation");

        assert_eq!(
            old.to_byte_array(),
            *current.as_byte_array(),
            "legacy sighash mismatch at iteration {i} (input_index={input_index}, hash_type={hash_type:#x})"
        );
    }
}

#[test]
fn tidecoin_sighash_cache_parity() {
    let mut rng = DeterministicRng::new(0x8f23_01bc_4112_d9aa);

    for _ in 0..512 {
        let tx = random_transaction(&mut rng, false);
        let input_index = rng.range(tx.inputs.len());
        let amount = Amount::from_sat((rng.next_u64() % 50_000_000_000) + 1).unwrap();

        let script_base = remove_op_codeseparator(&random_script(&mut rng));
        let script_base_diff = append_true(&script_base);
        let script_witness = random_script(&mut rng);
        let script_witness_diff = append_true(&script_witness);

        let hash_types = hash_types_for_case(&mut rng);

        let legacy_cache = SighashCache::new(&tx);
        let mut segwit_cache = SighashCache::new(&tx);

        for hash_type in hash_types {
            let legacy_with_cache = legacy_cache
                .legacy_signature_hash(input_index, script_base.as_bytes(), hash_type)
                .expect("legacy sighash with cache")
                .as_byte_array()
                .to_owned();
            let legacy_no_cache = SighashCache::new(&tx)
                .legacy_signature_hash(input_index, script_base.as_bytes(), hash_type)
                .expect("legacy sighash without cache")
                .as_byte_array()
                .to_owned();
            assert_eq!(legacy_with_cache, legacy_no_cache);

            let legacy_repeat = legacy_cache
                .legacy_signature_hash(input_index, script_base.as_bytes(), hash_type)
                .expect("legacy repeat with cache")
                .as_byte_array()
                .to_owned();
            assert_eq!(legacy_with_cache, legacy_repeat);

            let legacy_with_cache_diff = legacy_cache
                .legacy_signature_hash(input_index, script_base_diff.as_bytes(), hash_type)
                .expect("legacy diff script with cache")
                .as_byte_array()
                .to_owned();
            let legacy_no_cache_diff = SighashCache::new(&tx)
                .legacy_signature_hash(input_index, script_base_diff.as_bytes(), hash_type)
                .expect("legacy diff script without cache")
                .as_byte_array()
                .to_owned();
            assert_eq!(legacy_with_cache_diff, legacy_no_cache_diff);

            let expect_one =
                (hash_type & 0x1f) == SIGHASH_SINGLE && input_index >= tx.outputs.len();
            if expect_one {
                assert_eq!(legacy_with_cache, to_one_hash().to_byte_array());
                assert_eq!(legacy_with_cache_diff, to_one_hash().to_byte_array());
            } else {
                assert_ne!(legacy_with_cache, legacy_with_cache_diff);
            }

            let legacy_roundtrip = legacy_cache
                .legacy_signature_hash(input_index, script_base.as_bytes(), hash_type)
                .expect("legacy script-key roundtrip")
                .as_byte_array()
                .to_owned();
            assert_eq!(legacy_roundtrip, legacy_with_cache);

            let sighash_type = TxSighashType::from_consensus(hash_type);
            let wit_with_cache = segwit_cache
                .p2wsh_signature_hash(input_index, script_witness.as_bytes(), amount, sighash_type)
                .expect("witness sighash with cache")
                .as_byte_array()
                .to_owned();
            let wit_no_cache = SighashCache::new(&tx)
                .p2wsh_signature_hash(input_index, script_witness.as_bytes(), amount, sighash_type)
                .expect("witness sighash without cache")
                .as_byte_array()
                .to_owned();
            assert_eq!(wit_with_cache, wit_no_cache);

            let wit_repeat = segwit_cache
                .p2wsh_signature_hash(input_index, script_witness.as_bytes(), amount, sighash_type)
                .expect("witness repeat with cache")
                .as_byte_array()
                .to_owned();
            assert_eq!(wit_repeat, wit_with_cache);

            let wit_with_cache_diff = segwit_cache
                .p2wsh_signature_hash(
                    input_index,
                    script_witness_diff.as_bytes(),
                    amount,
                    sighash_type,
                )
                .expect("witness diff script with cache")
                .as_byte_array()
                .to_owned();
            let wit_no_cache_diff = SighashCache::new(&tx)
                .p2wsh_signature_hash(
                    input_index,
                    script_witness_diff.as_bytes(),
                    amount,
                    sighash_type,
                )
                .expect("witness diff script without cache")
                .as_byte_array()
                .to_owned();
            assert_eq!(wit_with_cache_diff, wit_no_cache_diff);
            assert_ne!(wit_with_cache, wit_with_cache_diff);

            let wit_roundtrip = segwit_cache
                .p2wsh_signature_hash(input_index, script_witness.as_bytes(), amount, sighash_type)
                .expect("witness script-key roundtrip")
                .as_byte_array()
                .to_owned();
            assert_eq!(wit_roundtrip, wit_with_cache);
        }
    }
}
