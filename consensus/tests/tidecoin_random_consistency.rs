use std::collections::BTreeMap;

use consensus::{verify_with_flags_detailed, ScriptFailure};
use consensus_core::{
    VERIFY_CLEANSTACK, VERIFY_MINIMALDATA, VERIFY_MINIMALIF, VERIFY_NONE, VERIFY_P2SH,
    VERIFY_SHA512, VERIFY_WITNESS, VERIFY_WITNESS_V1_512,
};
use hashes::{hash160, sha256, sha512};
use primitives::{
    opcodes::all,
    script::{Builder as BuilderT, ScriptBuf as PrimitiveScriptBuf},
    Witness,
};

mod tidecoin_test_support;

use tidecoin_test_support::{
    build_test_transaction, map_rust_script_error, node_script_result, normalize_flags, try_harness,
};

type Builder = BuilderT<()>;
type ScriptBuf = PrimitiveScriptBuf<()>;

const RANDOM_CASES: usize = 1024;

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

    fn range(&mut self, upper: usize) -> usize {
        assert!(upper > 0, "upper bound must be positive");
        (self.next_u64() as usize) % upper
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            out.push(self.next_u32() as u8);
        }
        out
    }

    fn small_i64(&mut self) -> i64 {
        (self.next_u32() % 2001) as i64 - 1000
    }
}

#[derive(Clone)]
struct RandomCase {
    label: &'static str,
    script_sig: ScriptBuf,
    script_pubkey: ScriptBuf,
    witness: Witness,
    amount: u64,
    flags: u32,
}

fn random_extra_flags(rng: &mut DeterministicRng, allowed: &[u32]) -> u32 {
    let mut flags = VERIFY_NONE;
    for flag in allowed {
        if rng.rand_bool() {
            flags |= *flag;
        }
    }
    flags
}

fn p2sh_script_pubkey(redeem_script: &ScriptBuf) -> ScriptBuf {
    let redeem_hash = hash160::Hash::hash(redeem_script.as_bytes());
    Builder::new()
        .push_opcode(all::OP_HASH160)
        .push_slice(redeem_hash.to_byte_array())
        .push_opcode(all::OP_EQUAL)
        .into_script()
}

fn p2wsh_script_pubkey(witness_script: &ScriptBuf) -> ScriptBuf {
    let program = sha256::Hash::hash(witness_script.as_bytes());
    Builder::new()
        .push_opcode(all::OP_PUSHBYTES_0)
        .push_slice(program.to_byte_array())
        .into_script()
}

fn witness_v1_512_script_pubkey(witness_script: &ScriptBuf) -> ScriptBuf {
    let program = sha512::Hash::hash(witness_script.as_bytes());
    Builder::new().push_opcode(all::OP_PUSHNUM_1).push_slice(program.to_byte_array()).into_script()
}

fn build_push_script(pushes: &[(Vec<u8>, bool)]) -> ScriptBuf {
    let mut bytes = Vec::new();
    for (data, minimal) in pushes {
        if *minimal {
            encode_minimal_push(&mut bytes, data);
        } else {
            encode_non_minimal_push(&mut bytes, data);
        }
    }
    ScriptBuf::from_bytes(bytes)
}

fn encode_minimal_push(script: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    if len == 0 {
        script.push(0x00);
    } else if len <= 75 {
        script.push(len as u8);
    } else if len <= u8::MAX as usize {
        script.push(all::OP_PUSHDATA1.to_u8());
        script.push(len as u8);
    } else if len <= u16::MAX as usize {
        script.push(all::OP_PUSHDATA2.to_u8());
        script.extend_from_slice(&(len as u16).to_le_bytes());
    } else {
        script.push(all::OP_PUSHDATA4.to_u8());
        script.extend_from_slice(&(len as u32).to_le_bytes());
    }
    script.extend_from_slice(data);
}

fn encode_non_minimal_push(script: &mut Vec<u8>, data: &[u8]) {
    let len = data.len() as u32;
    script.push(all::OP_PUSHDATA4.to_u8());
    script.extend_from_slice(&len.to_le_bytes());
    script.extend_from_slice(data);
}

fn legacy_arithmetic_case(rng: &mut DeterministicRng) -> RandomCase {
    let a = rng.small_i64() as i32;
    let b = rng.small_i64() as i32;
    let sum = a.saturating_add(b);
    let script_sig = Builder::new()
        .push_int(a)
        .expect("small int")
        .push_int(b)
        .expect("small int")
        .into_script();
    let script_pubkey = Builder::new()
        .push_opcode(all::OP_ADD)
        .push_int(sum)
        .expect("small int")
        .push_opcode(all::OP_EQUAL)
        .into_script();
    RandomCase {
        label: "legacy_arithmetic",
        script_sig,
        script_pubkey,
        witness: Witness::new(),
        amount: 0,
        flags: random_extra_flags(rng, &[VERIFY_CLEANSTACK]),
    }
}

fn minimaldata_case(rng: &mut DeterministicRng) -> RandomCase {
    let item_count = 1 + rng.range(3);
    let pushes: Vec<(Vec<u8>, bool)> = (0..item_count)
        .map(|_| {
            let len = 1 + rng.range(16);
            (rng.bytes(len), false)
        })
        .collect();
    let mut builder = Builder::new();
    for _ in 0..item_count {
        builder = builder.push_opcode(all::OP_DROP);
    }
    builder = builder.push_opcode(all::OP_PUSHNUM_1);
    RandomCase {
        label: "minimaldata",
        script_sig: build_push_script(&pushes),
        script_pubkey: builder.into_script(),
        witness: Witness::new(),
        amount: 0,
        flags: VERIFY_MINIMALDATA | random_extra_flags(rng, &[VERIFY_CLEANSTACK]),
    }
}

fn control_flow_case(rng: &mut DeterministicRng) -> RandomCase {
    let cond_true = rng.rand_bool();
    let violate_min_if = rng.rand_bool();
    let script_sig = if violate_min_if {
        build_push_script(&[(vec![2u8], true)])
    } else {
        Builder::new().push_int(if cond_true { 1 } else { 0 }).expect("bool int").into_script()
    };
    let script_pubkey = Builder::new()
        .push_opcode(all::OP_IF)
        .push_opcode(all::OP_PUSHNUM_1)
        .push_opcode(all::OP_ELSE)
        .push_opcode(all::OP_PUSHBYTES_0)
        .push_opcode(all::OP_ENDIF)
        .into_script();
    let mut flags = random_extra_flags(rng, &[VERIFY_CLEANSTACK]);
    if violate_min_if {
        flags |= VERIFY_MINIMALIF;
    }
    RandomCase {
        label: "control_flow",
        script_sig,
        script_pubkey,
        witness: Witness::new(),
        amount: 0,
        flags,
    }
}

fn p2sh_case(rng: &mut DeterministicRng) -> RandomCase {
    let len = 1 + rng.range(20);
    let item = rng.bytes(len);
    let redeem_script = Builder::new()
        .push_opcode(all::OP_SHA256)
        .push_slice(sha256::Hash::hash(&item).to_byte_array())
        .push_opcode(all::OP_EQUAL)
        .into_script();
    let script_pubkey = p2sh_script_pubkey(&redeem_script);
    let script_sig = build_push_script(&[(item, true), (redeem_script.as_bytes().to_vec(), true)]);
    RandomCase {
        label: "p2sh",
        script_sig,
        script_pubkey,
        witness: Witness::new(),
        amount: 0,
        flags: VERIFY_P2SH | random_extra_flags(rng, &[VERIFY_CLEANSTACK, VERIFY_MINIMALDATA]),
    }
}

fn witness_v0_case(rng: &mut DeterministicRng) -> RandomCase {
    let len = 1 + rng.range(20);
    let item = rng.bytes(len);
    let witness_script = Builder::new()
        .push_opcode(all::OP_SHA256)
        .push_slice(sha256::Hash::hash(&item).to_byte_array())
        .push_opcode(all::OP_EQUAL)
        .into_script();
    let script_pubkey = p2wsh_script_pubkey(&witness_script);
    let witness = Witness::from(vec![item, witness_script.as_bytes().to_vec()]);
    RandomCase {
        label: "witness_v0",
        script_sig: ScriptBuf::new(),
        script_pubkey,
        witness,
        amount: 1_000 + rng.range(100_000) as u64,
        flags: VERIFY_WITNESS | random_extra_flags(rng, &[VERIFY_CLEANSTACK]),
    }
}

fn witness_v1_512_case(rng: &mut DeterministicRng) -> RandomCase {
    let len = 1 + rng.range(20);
    let item = rng.bytes(len);
    let witness_script = Builder::new()
        .push_opcode(all::OP_SHA512)
        .push_slice(sha512::Hash::hash(&item).to_byte_array())
        .push_opcode(all::OP_EQUAL)
        .into_script();
    let script_pubkey = witness_v1_512_script_pubkey(&witness_script);
    let witness = Witness::from(vec![item, witness_script.as_bytes().to_vec()]);
    RandomCase {
        label: "witness_v1_512",
        script_sig: ScriptBuf::new(),
        script_pubkey,
        witness,
        amount: 1_000 + rng.range(100_000) as u64,
        flags: VERIFY_WITNESS
            | VERIFY_WITNESS_V1_512
            | VERIFY_SHA512
            | random_extra_flags(rng, &[VERIFY_CLEANSTACK]),
    }
}

fn random_case(rng: &mut DeterministicRng) -> RandomCase {
    match rng.range(6) {
        0 => legacy_arithmetic_case(rng),
        1 => minimaldata_case(rng),
        2 => control_flow_case(rng),
        3 => p2sh_case(rng),
        4 => witness_v0_case(rng),
        _ => witness_v1_512_case(rng),
    }
}

fn run_case(
    harness: &node_parity::TidecoinNodeHarness,
    case: &RandomCase,
) -> Result<(), ScriptFailure> {
    let mut flags = normalize_flags(case.flags);
    if flags & VERIFY_WITNESS != 0 {
        flags |= VERIFY_P2SH;
    }

    let witness_items: Vec<Vec<u8>> = case.witness.iter().map(|item| item.to_vec()).collect();
    let tx_bytes = build_test_transaction(
        case.script_pubkey.as_bytes(),
        case.script_sig.as_bytes(),
        &witness_items,
        case.amount,
    );
    let ours = verify_with_flags_detailed(
        case.script_pubkey.as_bytes(),
        case.amount,
        &tx_bytes,
        None,
        0,
        flags,
    );

    let witness_refs: Vec<&[u8]> = case.witness.iter().collect();
    let node = node_script_result(harness.verify_script_case(
        case.script_sig.as_bytes(),
        case.script_pubkey.as_bytes(),
        &witness_refs,
        case.amount as i64,
        flags,
    ));

    match (&ours, node) {
        (Ok(()), Ok(())) => {}
        (Err(failure), Err(node_err)) => {
            let ours_err = map_rust_script_error(failure.script_error);
            assert_eq!(
                ours_err, node_err,
                "{}: node/runtime script error mismatch",
                case.label
            );
        }
        (lhs, rhs) => panic!(
            "{}: node/runtime acceptance mismatch: ours={lhs:?} node={rhs:?}\nflags={:#x}\nscript_sig={:?}\nscript_pubkey={:?}\nwitness={:?}",
            case.label,
            flags,
            case.script_sig,
            case.script_pubkey,
            case.witness
        ),
    }

    ours
}

#[test]
fn tidecoin_random_consistency_matches_node() {
    let Some(harness) = try_harness() else {
        eprintln!(
            "skipping Tidecoin random consistency test: TIDECOIN_NODE_REPO is not configured"
        );
        return;
    };

    let mut rng = DeterministicRng::new(0x52f7_34c1_a90d_ee18);
    let mut scenario_counts = BTreeMap::<&'static str, usize>::new();

    for _ in 0..RANDOM_CASES {
        let case = random_case(&mut rng);
        *scenario_counts.entry(case.label).or_insert(0) += 1;
        let _ = run_case(&harness, &case);
    }

    assert_eq!(
        scenario_counts.values().sum::<usize>(),
        RANDOM_CASES,
        "random consistency case accounting mismatch"
    );
    assert!(
        scenario_counts.len() >= 5,
        "random consistency did not exercise enough scenario classes: {scenario_counts:?}"
    );
    println!("tidecoin_random_consistency coverage: {scenario_counts:?}");
}
