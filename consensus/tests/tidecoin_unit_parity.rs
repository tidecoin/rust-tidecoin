use consensus::{
    verify_with_flags_detailed, ScriptError, ScriptFailure, VERIFY_CONST_SCRIPTCODE,
    VERIFY_DISCOURAGE_UPGRADABLE_NOPS, VERIFY_NONE, VERIFY_P2SH, VERIFY_SHA512,
};
use encoding::encode_to_vec;
use hashes::{hash160, sha512};
use primitives::{
    absolute::LockTime,
    opcodes::{all, Opcode},
    script::{Builder as BuilderT, ScriptBuf as PrimitiveScriptBuf, ScriptPubKeyBuf, ScriptSigBuf},
    Amount, OutPoint, Sequence, Transaction, TransactionVersion, TxIn, TxOut, Txid, Witness,
};

mod tidecoin_test_support;

use tidecoin_test_support::{map_rust_script_error, node_script_result, try_harness};

type Builder = BuilderT<()>;
type ScriptBuf = PrimitiveScriptBuf<()>;

const VALUES: [i64; 13] = [
    0,
    1,
    -2,
    127,
    128,
    -255,
    256,
    (1i64 << 15) - 1,
    -(1i64 << 16),
    (1i64 << 24) - 1,
    1i64 << 31,
    1 - (1i64 << 32),
    1i64 << 40,
];

const OFFSETS: [i64; 9] = [1, 0x79, 0x80, 0x81, 0xFF, 0x7FFF, 0x8000, 0xFFFF, 0x10000];

fn dummy_outpoint() -> OutPoint {
    OutPoint { txid: Txid::from_byte_array([1u8; 32]), vout: 0 }
}

fn spending_tx(script_sig: ScriptBuf) -> Transaction {
    Transaction {
        version: TransactionVersion::TWO,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: dummy_outpoint(),
            script_sig: ScriptSigBuf::from(script_sig.into_bytes()),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut { amount: Amount::ZERO, script_pubkey: ScriptPubKeyBuf::new() }],
    }
}

fn run_script(
    script_sig: ScriptBuf,
    script_pubkey: ScriptBuf,
    flags: u32,
) -> Result<(), ScriptFailure> {
    let tx = spending_tx(script_sig);
    let tx_bytes = encode_to_vec(&tx);
    verify_with_flags_detailed(script_pubkey.as_bytes(), 0, &tx_bytes, None, 0, flags)
}

fn assert_runtime_matches_node(
    harness: &Option<node_parity::TidecoinNodeHarness>,
    script_sig: &ScriptBuf,
    script_pubkey: &ScriptBuf,
    flags: u32,
    ours: &Result<(), ScriptFailure>,
    context: &str,
) {
    let Some(harness) = harness else {
        return;
    };

    let node = node_script_result(harness.verify_script_case(
        script_sig.as_bytes(),
        script_pubkey.as_bytes(),
        &[],
        0,
        flags,
    ));

    match (ours, node) {
        (Ok(()), Ok(())) => {}
        (Err(failure), Err(node_err)) => {
            let ours_err = map_rust_script_error(failure.script_error);
            assert_eq!(ours_err, node_err, "{context}: node/runtime script error mismatch");
        }
        (lhs, rhs) => {
            panic!("{context}: node/runtime acceptance mismatch: ours={lhs:?} node={rhs:?}")
        }
    }
}

fn push_data_script(data: &[u8]) -> ScriptBuf {
    Builder::new().push_slice(data).into_script()
}

fn raw_pushdata_script(len: usize) -> ScriptBuf {
    let mut bytes = Vec::with_capacity(len + 5);
    if len <= 75 {
        bytes.push(len as u8);
    } else if len <= u16::MAX as usize {
        bytes.push(all::OP_PUSHDATA2.to_u8());
        bytes.extend_from_slice(&(len as u16).to_le_bytes());
    } else {
        bytes.push(all::OP_PUSHDATA4.to_u8());
        bytes.extend_from_slice(&(len as u32).to_le_bytes());
    }
    bytes.resize(bytes.len() + len, 0x42);
    ScriptBuf::from_bytes(bytes)
}

fn sized_drop_script(len: usize) -> ScriptBuf {
    let mut bytes = Vec::new();
    for _ in 0..7 {
        bytes.push(all::OP_PUSHDATA2.to_u8());
        bytes.extend_from_slice(&8192u16.to_le_bytes());
        bytes.resize(bytes.len() + 8192, 0x42);
        bytes.push(all::OP_DROP.to_u8());
    }

    let tail_len =
        len.checked_sub(bytes.len() + 5).expect("test script size must fit synthetic fixture");
    assert!(tail_len <= 8192, "test helper expects one final push");
    bytes.push(all::OP_PUSHDATA2.to_u8());
    bytes.extend_from_slice(&(tail_len as u16).to_le_bytes());
    bytes.resize(bytes.len() + tail_len, 0x24);
    bytes.push(all::OP_DROP.to_u8());
    bytes.push(all::OP_PUSHNUM_1.to_u8());
    assert_eq!(bytes.len(), len);
    ScriptBuf::from_bytes(bytes)
}

fn p2sh_script_pubkey(redeem_script: &ScriptBuf) -> ScriptBuf {
    let redeem_hash = hash160::Hash::hash(redeem_script.as_bytes());
    Builder::new()
        .push_opcode(all::OP_HASH160)
        .push_slice(redeem_hash.to_byte_array())
        .push_opcode(all::OP_EQUAL)
        .into_script()
}

fn is_p2sh(script: &[u8]) -> bool {
    script.len() == 23
        && script[0] == all::OP_HASH160.to_u8()
        && script[1] == 20
        && script[22] == all::OP_EQUAL.to_u8()
}

#[test]
fn tidecoin_sha512_opcode_flag_boundary_matches_node() {
    let harness = try_harness();
    let input = vec![0x01, 0x02, 0x03];
    let expected = sha512::Hash::hash(&input).to_byte_array();

    let enabled_script = Builder::new()
        .push_slice(input.clone())
        .push_opcode(all::OP_SHA512)
        .push_slice(expected)
        .push_opcode(all::OP_EQUAL)
        .into_script();
    let enabled = run_script(ScriptBuf::new(), enabled_script.clone(), VERIFY_SHA512);
    assert_runtime_matches_node(
        &harness,
        &ScriptBuf::new(),
        &enabled_script,
        VERIFY_SHA512,
        &enabled,
        "OP_SHA512 enabled",
    );
    enabled.unwrap();

    let disabled_nop_script = Builder::new()
        .push_slice(input.clone())
        .push_opcode(all::OP_SHA512)
        .push_slice(input)
        .push_opcode(all::OP_EQUAL)
        .into_script();
    let disabled = run_script(ScriptBuf::new(), disabled_nop_script.clone(), VERIFY_NONE);
    assert_runtime_matches_node(
        &harness,
        &ScriptBuf::new(),
        &disabled_nop_script,
        VERIFY_NONE,
        &disabled,
        "OP_SHA512 disabled behaves as upgradeable NOP without discourage flag",
    );
    disabled.unwrap();

    let discouraged = run_script(
        ScriptBuf::new(),
        disabled_nop_script.clone(),
        VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
    );
    assert_runtime_matches_node(
        &harness,
        &ScriptBuf::new(),
        &disabled_nop_script,
        VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
        &discouraged,
        "OP_SHA512 disabled with discourage-upgradable-nops",
    );
    assert_eq!(discouraged.unwrap_err().script_error, ScriptError::DiscourageUpgradableNops);
}

#[test]
fn tidecoin_const_scriptcode_and_script_size_boundaries_match_node() {
    let harness = try_harness();

    let codeseparator_script = Builder::new()
        .push_opcode(all::OP_FALSE)
        .push_opcode(all::OP_IF)
        .push_opcode(all::OP_CODESEPARATOR)
        .push_opcode(all::OP_ENDIF)
        .push_opcode(all::OP_PUSHNUM_1)
        .into_script();
    let relaxed = run_script(ScriptBuf::new(), codeseparator_script.clone(), VERIFY_NONE);
    assert_runtime_matches_node(
        &harness,
        &ScriptBuf::new(),
        &codeseparator_script,
        VERIFY_NONE,
        &relaxed,
        "unexecuted OP_CODESEPARATOR without CONST_SCRIPTCODE",
    );
    relaxed.unwrap();

    let strict =
        run_script(ScriptBuf::new(), codeseparator_script.clone(), VERIFY_CONST_SCRIPTCODE);
    assert_runtime_matches_node(
        &harness,
        &ScriptBuf::new(),
        &codeseparator_script,
        VERIFY_CONST_SCRIPTCODE,
        &strict,
        "unexecuted OP_CODESEPARATOR with CONST_SCRIPTCODE",
    );
    assert_eq!(strict.unwrap_err().script_error, ScriptError::OpCodeSeparator);

    let max_script = sized_drop_script(65_536);
    let max_result = run_script(ScriptBuf::new(), max_script.clone(), VERIFY_NONE);
    assert_runtime_matches_node(
        &harness,
        &ScriptBuf::new(),
        &max_script,
        VERIFY_NONE,
        &max_result,
        "script size at consensus limit",
    );
    max_result.unwrap();

    let oversized_script = sized_drop_script(65_537);
    let oversized = run_script(ScriptBuf::new(), oversized_script.clone(), VERIFY_NONE);
    assert_runtime_matches_node(
        &harness,
        &ScriptBuf::new(),
        &oversized_script,
        VERIFY_NONE,
        &oversized,
        "script size above consensus limit",
    );
    assert_eq!(oversized.unwrap_err().script_error, ScriptError::ScriptSize);
}

#[test]
fn tidecoin_push_size_boundary_matches_node() {
    let harness = try_harness();
    let spend_script =
        Builder::new().push_opcode(all::OP_DROP).push_opcode(all::OP_PUSHNUM_1).into_script();

    let max_push = raw_pushdata_script(8192);
    let max_result = run_script(max_push.clone(), spend_script.clone(), VERIFY_NONE);
    assert_runtime_matches_node(
        &harness,
        &max_push,
        &spend_script,
        VERIFY_NONE,
        &max_result,
        "push element at consensus limit",
    );
    max_result.unwrap();

    let oversized_push = raw_pushdata_script(8193);
    let oversized = run_script(oversized_push.clone(), spend_script.clone(), VERIFY_NONE);
    assert_runtime_matches_node(
        &harness,
        &oversized_push,
        &spend_script,
        VERIFY_NONE,
        &oversized,
        "push element above consensus limit",
    );
    assert_eq!(oversized.unwrap_err().script_error, ScriptError::PushSize);
}

fn encode_scriptnum(num: i64) -> Vec<u8> {
    if num == 0 {
        return Vec::new();
    }

    let negative = num < 0;
    let mut abs = if negative { (-num) as u64 } else { num as u64 };
    let mut out = Vec::new();
    while abs > 0 {
        out.push((abs & 0xff) as u8);
        abs >>= 8;
    }

    if out[out.len() - 1] & 0x80 != 0 {
        out.push(if negative { 0x80 } else { 0x00 });
    } else if negative {
        let last = out.len() - 1;
        out[last] |= 0x80;
    }

    out
}

fn push_scriptnum(builder: Builder, num: i64) -> Builder {
    builder.push_slice(encode_scriptnum(num))
}

fn fits_default_scriptnum(num: i64) -> bool {
    encode_scriptnum(num).len() <= 4
}

fn assert_scriptnum_case(
    harness: &Option<node_parity::TidecoinNodeHarness>,
    script_sig: ScriptBuf,
    script_pubkey: ScriptBuf,
    expect_ok: bool,
    context: &str,
) {
    let result = run_script(script_sig.clone(), script_pubkey.clone(), VERIFY_NONE);
    assert_runtime_matches_node(
        harness,
        &script_sig,
        &script_pubkey,
        VERIFY_NONE,
        &result,
        context,
    );

    if expect_ok {
        result.unwrap_or_else(|failure| panic!("{context}: expected success, got {failure:?}"));
    } else {
        let failure = result.expect_err(context);
        assert_eq!(
            failure.script_error,
            ScriptError::Unknown,
            "{context}: expected ScriptError::Unknown, got {failure:?}"
        );
    }
}

fn assert_creation_case(harness: &Option<node_parity::TidecoinNodeHarness>, num: i64) {
    let script_sig = push_scriptnum(push_scriptnum(Builder::new(), num), 0).into_script();
    let script_pubkey = push_scriptnum(Builder::new().push_opcode(all::OP_ADD), num)
        .push_opcode(all::OP_NUMEQUAL)
        .into_script();
    let context = format!("creation case num={num}");
    assert_scriptnum_case(
        harness,
        script_sig,
        script_pubkey,
        fits_default_scriptnum(num),
        &context,
    );
}

fn assert_binary_op_case(
    harness: &Option<node_parity::TidecoinNodeHarness>,
    a: i64,
    b: i64,
    opcode: Opcode,
    expected: i64,
    context: &str,
) {
    let script_sig = push_scriptnum(push_scriptnum(Builder::new(), a), b).into_script();
    let script_pubkey = push_scriptnum(Builder::new().push_opcode(opcode), expected)
        .push_opcode(all::OP_NUMEQUAL)
        .into_script();
    assert_scriptnum_case(harness, script_sig, script_pubkey, true, context);
}

fn assert_compare_case(
    harness: &Option<node_parity::TidecoinNodeHarness>,
    a: i64,
    b: i64,
    opcode: Opcode,
    expected: bool,
    context: &str,
) {
    assert_binary_op_case(harness, a, b, opcode, if expected { 1 } else { 0 }, context);
}

fn assert_negate_case(
    harness: &Option<node_parity::TidecoinNodeHarness>,
    num: i64,
    expected: i64,
    context: &str,
) {
    let script_sig = push_scriptnum(Builder::new(), num).into_script();
    let script_pubkey = push_scriptnum(Builder::new().push_opcode(all::OP_NEGATE), expected)
        .push_opcode(all::OP_NUMEQUAL)
        .into_script();
    assert_scriptnum_case(harness, script_sig, script_pubkey, true, context);
}

fn run_operator_pair(harness: &Option<node_parity::TidecoinNodeHarness>, a: i64, b: i64) {
    if !fits_default_scriptnum(a) || !fits_default_scriptnum(b) {
        return;
    }

    if let Some(sum) = a.checked_add(b).filter(|value| fits_default_scriptnum(*value)) {
        assert_binary_op_case(harness, a, b, all::OP_ADD, sum, &format!("add {a} + {b}"));
    }
    if let Some(diff) = a.checked_sub(b).filter(|value| fits_default_scriptnum(*value)) {
        assert_binary_op_case(harness, a, b, all::OP_SUB, diff, &format!("sub {a} - {b}"));
    }
    if let Some(neg) = a.checked_neg().filter(|value| fits_default_scriptnum(*value)) {
        assert_negate_case(harness, a, neg, &format!("negate {a}"));
    }

    assert_compare_case(harness, a, b, all::OP_NUMEQUAL, a == b, &format!("eq {a} == {b}"));
    assert_compare_case(harness, a, b, all::OP_NUMNOTEQUAL, a != b, &format!("ne {a} != {b}"));
    assert_compare_case(harness, a, b, all::OP_LESSTHAN, a < b, &format!("lt {a} < {b}"));
    assert_compare_case(harness, a, b, all::OP_GREATERTHAN, a > b, &format!("gt {a} > {b}"));
    assert_compare_case(harness, a, b, all::OP_LESSTHANOREQUAL, a <= b, &format!("le {a} <= {b}"));
    assert_compare_case(
        harness,
        a,
        b,
        all::OP_GREATERTHANOREQUAL,
        a >= b,
        &format!("ge {a} >= {b}"),
    );
}

#[test]
fn tidecoin_scriptnum_creation_matrix_default_max_num_size() {
    let harness = try_harness();
    for value in VALUES {
        for offset in OFFSETS {
            assert_creation_case(&harness, value);
            assert_creation_case(&harness, value + offset);
            assert_creation_case(&harness, value - offset);
        }
    }
}

#[test]
fn tidecoin_scriptnum_operator_matrix_default_max_num_size() {
    let harness = try_harness();
    for value in VALUES {
        for base in VALUES.iter().take(OFFSETS.len()).copied() {
            let pairs = [
                (value, value),
                (value, -value),
                (value, base),
                (value, -base),
                (value + base, base),
                (value + base, -base),
                (value - base, base),
                (value - base, -base),
                (value + base, value + base),
                (value + base, value - base),
                (value - base, value + base),
                (value - base, value - base),
            ];

            for (a, b) in pairs {
                run_operator_pair(&harness, a, b);
            }
        }
    }
}

#[test]
fn tidecoin_script_p2sh_is_detection_matrix() {
    let mut canonical = vec![all::OP_HASH160.to_u8(), 20];
    canonical.extend([0u8; 20]);
    canonical.push(all::OP_EQUAL.to_u8());
    assert!(is_p2sh(&canonical));

    let mut pushdata1 = vec![all::OP_HASH160.to_u8(), all::OP_PUSHDATA1.to_u8(), 20];
    pushdata1.extend([0u8; 20]);
    pushdata1.push(all::OP_EQUAL.to_u8());
    assert!(!is_p2sh(&pushdata1));

    let mut pushdata2 = vec![all::OP_HASH160.to_u8(), all::OP_PUSHDATA2.to_u8(), 20, 0];
    pushdata2.extend([0u8; 20]);
    pushdata2.push(all::OP_EQUAL.to_u8());
    assert!(!is_p2sh(&pushdata2));

    let mut pushdata4 = vec![all::OP_HASH160.to_u8(), all::OP_PUSHDATA4.to_u8(), 20, 0, 0, 0];
    pushdata4.extend([0u8; 20]);
    pushdata4.push(all::OP_EQUAL.to_u8());
    assert!(!is_p2sh(&pushdata4));

    assert!(!is_p2sh(&[]));
    assert!(!is_p2sh(
        Builder::new()
            .push_opcode(all::OP_HASH160)
            .push_opcode(all::OP_PUSHBYTES_20)
            .push_opcode(all::OP_PUSHBYTES_20)
            .push_opcode(all::OP_EQUAL)
            .into_script()
            .as_bytes()
    ));
    assert!(!is_p2sh(
        Builder::new()
            .push_opcode(all::OP_NOP)
            .push_opcode(all::OP_PUSHBYTES_20)
            .push_opcode(all::OP_EQUAL)
            .into_script()
            .as_bytes()
    ));
}

#[test]
fn tidecoin_script_p2sh_norecurse_parity() {
    let harness = try_harness();

    let invalid_as_script = Builder::new()
        .push_opcode(all::OP_INVALIDOPCODE)
        .push_opcode(all::OP_INVALIDOPCODE)
        .into_script();
    let p2sh = p2sh_script_pubkey(&invalid_as_script);

    let non_recursive =
        run_script(push_data_script(invalid_as_script.as_bytes()), p2sh.clone(), VERIFY_P2SH)
            .expect_err("single-layer p2sh should execute redeem script and fail");
    assert_eq!(non_recursive.script_error, ScriptError::BadOpcode);
    assert_runtime_matches_node(
        &harness,
        &push_data_script(invalid_as_script.as_bytes()),
        &p2sh,
        VERIFY_P2SH,
        &Err(non_recursive),
        "p2sh norecurse single-layer",
    );

    let p2sh2 = p2sh_script_pubkey(&p2sh);
    let nested_sig = Builder::new()
        .push_slice(invalid_as_script.as_bytes())
        .push_slice(p2sh.as_bytes())
        .into_script();
    let nested = run_script(nested_sig.clone(), p2sh2.clone(), VERIFY_P2SH);
    assert_runtime_matches_node(
        &harness,
        &nested_sig,
        &p2sh2,
        VERIFY_P2SH,
        &nested,
        "p2sh norecurse nested",
    );
    nested.expect("nested p2sh should hash-check inner p2sh and stop recursion");
}

#[test]
fn tidecoin_script_p2sh_switchover_old_vs_new_rules() {
    let harness = try_harness();

    let redeem_script = Builder::new()
        .push_opcode(all::OP_PUSHNUM_11)
        .push_opcode(all::OP_PUSHNUM_12)
        .push_opcode(all::OP_EQUALVERIFY)
        .into_script();
    let spent_script = p2sh_script_pubkey(&redeem_script);
    let script_sig = push_data_script(redeem_script.as_bytes());

    let no_p2sh = run_script(script_sig.clone(), spent_script.clone(), VERIFY_NONE);
    assert_runtime_matches_node(
        &harness,
        &script_sig,
        &spent_script,
        VERIFY_NONE,
        &no_p2sh,
        "p2sh switchover old rules",
    );
    no_p2sh.expect("without P2SH rules, scriptSig hash preimage push is accepted");

    let p2sh = run_script(script_sig.clone(), spent_script.clone(), VERIFY_P2SH);
    assert_runtime_matches_node(
        &harness,
        &script_sig,
        &spent_script,
        VERIFY_P2SH,
        &p2sh,
        "p2sh switchover new rules",
    );
    let failure = p2sh.expect_err("with P2SH redeem script executes and must fail");
    assert_eq!(failure.script_error, ScriptError::EqualVerify);
}
