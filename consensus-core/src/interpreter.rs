//! Script interpreter.

use alloc::vec;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

use core::{cell::RefCell, mem};

use crate::{
    PqPublicKey, PqSignature, ScriptError, SegwitV0Sighash, Sighash512, SighashCache, SpentOutputs,
    TidecoinValidationError, TransactionContext, TxSighashType, WitnessExecutionPlan,
    WitnessProgram, WitnessSigVersion, WitnessSigops, WitnessV1SighashError,
    VERIFY_CHECKLOCKTIMEVERIFY, VERIFY_CHECKSEQUENCEVERIFY, VERIFY_CLEANSTACK,
    VERIFY_CONST_SCRIPTCODE, VERIFY_DEFINED_HASHTYPE, VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
    VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, VERIFY_FALCON_CANONICAL, VERIFY_MINIMALDATA,
    VERIFY_MINIMALIF, VERIFY_NULLDUMMY, VERIFY_NULLFAIL, VERIFY_P2SH, VERIFY_PQ_STRICT,
    VERIFY_SHA512, VERIFY_SIGPUSHONLY, VERIFY_WITNESS, VERIFY_WITNESS_V1_512,
};
use hashes::{hash160, ripemd160, sha1, sha256, sha256d, sha512};
use primitives::{
    absolute::LOCK_TIME_THRESHOLD,
    opcodes::{all, Opcode},
    script::{
        encode_scriptnum, read_scriptbool, read_scriptnum, Builder as ScriptBuilderT, Instruction,
        PushBytesBuf, Script as ScriptT, ScriptBuf as ScriptBufT, ScriptIntError,
    },
    Amount, Sequence, Transaction, Witness,
};

type Builder = ScriptBuilderT<()>;
type RawScript = ScriptT<()>;
type RawScriptBuf = ScriptBufT<()>;
type Error = TidecoinValidationError;

fn script_unknown() -> TidecoinValidationError {
    TidecoinValidationError::Script(ScriptError::Unknown)
}

const SUPPORTED_FLAGS: u32 = VERIFY_P2SH
    | VERIFY_NULLDUMMY
    | VERIFY_SIGPUSHONLY
    | VERIFY_CHECKLOCKTIMEVERIFY
    | VERIFY_CHECKSEQUENCEVERIFY
    | VERIFY_WITNESS
    | VERIFY_MINIMALDATA
    | VERIFY_DISCOURAGE_UPGRADABLE_NOPS
    | VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
    | VERIFY_CLEANSTACK
    | VERIFY_MINIMALIF
    | VERIFY_NULLFAIL
    | VERIFY_PQ_STRICT
    | VERIFY_WITNESS_V1_512
    | VERIFY_SHA512
    | VERIFY_CONST_SCRIPTCODE
    | VERIFY_DEFINED_HASHTYPE
    | VERIFY_FALCON_CANONICAL;

const MAX_STACK_SIZE: usize = 1000;
const MAX_SCRIPT_SIZE: usize = 65_536;
const MAX_SCRIPT_ELEMENT_SIZE: usize = 8192;
const MAX_OPS_PER_SCRIPT: usize = 201;
const SCRIPTNUM_MAX_LEN: usize = 4;
const SCRIPTNUM_MAX_LEN_EXTENDED: usize = 5;
const MAX_PUBKEYS_PER_MULTISIG: usize = 20;
const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;
const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;
const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000ffff;
/// Wrapper for script verification flags.
#[derive(Debug, Clone, Copy)]
pub struct ScriptFlags(u32);

impl ScriptFlags {
    /// Validates raw verification bits against the supported Tidecoin flag set.
    pub fn from_bits(bits: u32) -> Result<Self, TidecoinValidationError> {
        if bits & !SUPPORTED_FLAGS != 0 {
            return Err(TidecoinValidationError::InvalidFlags);
        }
        Ok(Self(bits))
    }

    /// Returns the raw verification bits.
    pub fn bits(self) -> u32 {
        self.0
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum SigVersion {
    Base,
    WitnessV0,
    WitnessV1_512,
}

#[derive(Default)]
struct ScriptCodeCache {
    identity: ScriptIdentity,
    code_separator: usize,
    strip_codeseparators: bool,
    script: RawScriptBuf,
}

#[derive(Copy, Clone, Default, PartialEq, Eq)]
struct ScriptIdentity {
    digest: [u8; 32],
    len: usize,
}

impl ScriptIdentity {
    fn new(script: &RawScript) -> Self {
        let digest = sha256::Hash::hash(script.as_bytes()).to_byte_array();
        Self { digest, len: script.as_bytes().len() }
    }
}

impl ScriptCodeCache {
    fn matches(
        &self,
        identity: ScriptIdentity,
        code_separator: usize,
        strip_codeseparators: bool,
    ) -> bool {
        self.identity == identity
            && self.code_separator == code_separator
            && self.strip_codeseparators == strip_codeseparators
    }
}

/// Minimal stack abstraction used by the interpreter.
#[derive(Debug, Default, Clone)]
pub struct ScriptStack {
    items: Vec<Vec<u8>>,
}

impl ScriptStack {
    /// Creates an empty script stack.
    pub fn new() -> Self {
        Self { items: Vec::new() }
    }

    /// Builds a stack from raw items after enforcing script-element limits.
    pub fn from_items(items: Vec<Vec<u8>>) -> Result<Self, ScriptError> {
        if items.len() > MAX_STACK_SIZE {
            return Err(ScriptError::StackSize);
        }
        for item in &items {
            if item.len() > MAX_SCRIPT_ELEMENT_SIZE {
                return Err(ScriptError::PushSize);
            }
        }
        Ok(Self { items })
    }

    /// Pushes a raw stack element after enforcing the script-element limit.
    pub fn push(&mut self, data: Vec<u8>) -> Result<(), ScriptError> {
        if data.len() > MAX_SCRIPT_ELEMENT_SIZE {
            return Err(ScriptError::PushSize);
        }
        self.items.push(data);
        Ok(())
    }

    /// Pushes the canonical boolean stack encoding.
    pub fn push_bool(&mut self, value: bool) -> Result<(), ScriptError> {
        if value {
            self.push(vec![1])
        } else {
            self.push(Vec::new())
        }
    }

    /// Pops the top element as raw bytes.
    pub fn pop_bytes(&mut self) -> Result<Vec<u8>, Error> {
        self.items.pop().ok_or(script_unknown())
    }

    /// Borrows the top stack element.
    pub fn last(&self) -> Option<&Vec<u8>> {
        self.items.last()
    }

    /// Returns the number of stack elements.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Returns whether the stack is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// Input-specific data required to run the interpreter.
pub struct SpendContext<'script> {
    /// Serialized script pubkey being spent.
    pub script_pubkey: &'script [u8],
    /// Complete previous outputs in input order, or `None` when unavailable.
    pub spent_outputs: Option<SpentOutputs>,
    /// Amount of the spent output in satoshis.
    pub amount: u64,
    /// Whether the amount is known at this boundary.
    pub has_amount: bool,
}

impl<'script> SpendContext<'script> {
    /// Creates a spend context for a single input verification.
    pub fn new(
        script_pubkey: &'script [u8],
        spent_outputs: Option<SpentOutputs>,
        amount: u64,
        has_amount: bool,
    ) -> Self {
        Self { script_pubkey, spent_outputs, amount, has_amount }
    }
}

/// High-level script verification context.
pub struct Interpreter<'tx, 'script> {
    flags: ScriptFlags,
    amount: u64,
    has_amount: bool,
    spent_output_script: &'script [u8],
    tx_ctx: &'tx TransactionContext<'tx>,
    input_index: usize,
    script_code_cache: Option<ScriptCodeCache>,
    sighash_cache: RefCell<SighashCache<&'tx Transaction>>,
    stack: ScriptStack,
    exec_stack: Vec<bool>,
    last_error: ScriptError,
    op_count: usize,
    sigops: u32,
    had_witness: bool,
}

impl<'tx, 'script> Interpreter<'tx, 'script> {
    /// Creates an interpreter for one transaction input.
    pub fn new(
        tx_ctx: &'tx TransactionContext<'tx>,
        input_index: usize,
        mut spend: SpendContext<'script>,
        flags: ScriptFlags,
    ) -> Result<Self, TidecoinValidationError> {
        let cache = match spend.spent_outputs.take() {
            Some(outputs) => SighashCache::new_with_spent_outputs(tx_ctx.tx(), outputs)?,
            None => SighashCache::new(tx_ctx.tx()),
        };
        Self::with_cache(tx_ctx, input_index, spend, flags, cache)
    }

    pub(crate) fn with_cache(
        tx_ctx: &'tx TransactionContext<'tx>,
        input_index: usize,
        spend: SpendContext<'script>,
        flags: ScriptFlags,
        sighash_cache: SighashCache<&'tx Transaction>,
    ) -> Result<Self, TidecoinValidationError> {
        tx_ctx.ensure_input_index(input_index)?;
        let SpendContext { script_pubkey, amount, has_amount, .. } = spend;
        if let Some(outputs) = sighash_cache.spent_outputs() {
            outputs.validate_current(input_index, amount, script_pubkey)?;
        }
        Ok(Self {
            flags,
            amount,
            has_amount,
            spent_output_script: script_pubkey,
            tx_ctx,
            input_index,
            script_code_cache: None,
            sighash_cache: RefCell::new(sighash_cache),
            stack: ScriptStack::new(),
            exec_stack: Vec::new(),
            last_error: ScriptError::Ok,
            op_count: 0,
            sigops: 0,
            had_witness: false,
        })
    }

    pub(crate) fn into_sighash_cache(self) -> SighashCache<&'tx Transaction> {
        self.sighash_cache.into_inner()
    }

    /// Executes script verification for the configured input from fresh execution state.
    /// Repeated calls have the same verdict, including after a failed attempt.
    pub fn verify(&mut self) -> Result<(), TidecoinValidationError> {
        // Only transaction-bound sighash data survives calls. Reset before any
        // early return, just like the node's VerifyScript local execution state.
        self.stack = ScriptStack::new();
        self.exec_stack.clear();
        self.op_count = 0;
        self.sigops = 0;
        self.last_error = ScriptError::Ok;
        self.had_witness = false;
        self.script_code_cache = None;
        let txin = &self.tx_ctx.tx().inputs[self.input_index];
        let witness_enabled = self.flags.bits() & VERIFY_WITNESS != 0;
        let p2sh_enabled = self.flags.bits() & VERIFY_P2SH != 0;
        let spent_is_p2sh = is_p2sh(self.spent_output_script);
        if self.flags.bits() & VERIFY_SIGPUSHONLY != 0 && !is_push_only(txin.script_sig.as_bytes())
        {
            return Err(self.fail(ScriptError::SigPushOnly));
        }
        self.initialize_sigops(txin.script_sig.as_bytes())?;
        if witness_enabled && !txin.witness.is_empty() && !self.has_amount {
            return Err(TidecoinValidationError::AmountRequired);
        }

        let sig_script_res = self.run_on_main_stack(txin.script_sig.as_bytes(), SigVersion::Base);
        self.track_script_error(sig_script_res)?;
        let mut p2sh_stack =
            if p2sh_enabled && spent_is_p2sh { Some(self.stack.clone()) } else { None };
        let spent_script_res = self.run_on_main_stack(self.spent_output_script, SigVersion::Base);
        self.track_script_error(spent_script_res)?;
        if self.stack.is_empty() || !read_scriptbool(self.stack.last().unwrap()) {
            return Err(self.fail(ScriptError::EvalFalse));
        }
        if witness_enabled {
            if let Some(witness_program) =
                WitnessProgram::parse_for_flags(self.spent_output_script, self.flags.bits())
            {
                self.had_witness = true;
                if !txin.script_sig.is_empty() {
                    return Err(self.fail(ScriptError::WitnessMalleated));
                }
                let witness_res = self.execute_witness_program(
                    witness_program.version(),
                    witness_program.program(),
                    &txin.witness,
                    false,
                );
                self.track_script_error(witness_res)?;
                let mut stack = ScriptStack::new();
                self.push_bool_element(&mut stack, true)?;
                self.stack = stack;
            }
        }

        if p2sh_enabled && spent_is_p2sh {
            if !is_push_only(txin.script_sig.as_bytes()) {
                return Err(self.fail(ScriptError::SigPushOnly));
            }

            let mut stack_copy =
                p2sh_stack.take().expect("P2SH spend requires preserved stack state");
            if stack_copy.is_empty() {
                return Err(self.fail(ScriptError::EvalFalse));
            }

            let redeem_script = stack_copy.pop_bytes()?;
            self.run_script(&mut stack_copy, &redeem_script, SigVersion::Base)?;
            if stack_copy.is_empty() || !read_scriptbool(stack_copy.last().unwrap()) {
                return Err(self.fail(ScriptError::EvalFalse));
            }

            if witness_enabled {
                if let Some(witness_program) = WitnessProgram::parse_for_flags_in_context(
                    &redeem_script,
                    self.flags.bits(),
                    true,
                ) {
                    self.had_witness = true;
                    let expected = single_push_script(&redeem_script)
                        .map_err(|_| self.fail(ScriptError::SigPushOnly))?;
                    if txin.script_sig.as_bytes() != expected.as_bytes() {
                        return Err(self.fail(ScriptError::WitnessMalleatedP2SH));
                    }
                    let witness_res = self.execute_witness_program(
                        witness_program.version(),
                        witness_program.program(),
                        &txin.witness,
                        true,
                    );
                    self.track_script_error(witness_res)?;
                    stack_copy = ScriptStack::new();
                    self.push_element(&mut stack_copy, vec![1])?;
                }
            }

            self.add_sigops_from_script(&redeem_script, true)?;
            self.stack = stack_copy;
        }

        if self.stack.is_empty() || !read_scriptbool(self.stack.last().unwrap()) {
            return Err(self.fail(ScriptError::EvalFalse));
        }

        if self.flags.bits() & VERIFY_CLEANSTACK != 0 {
            self.require_clean_stack(&self.stack).map_err(|err| self.fail(err))?;
        }

        if witness_enabled && !self.had_witness && !txin.witness.is_empty() {
            return Err(self.fail(ScriptError::WitnessUnexpected));
        }

        Ok(())
    }

    /// Returns the most recent script error recorded by the interpreter.
    #[inline]
    pub fn last_script_error(&self) -> ScriptError {
        self.last_error
    }

    fn fail(&mut self, error: ScriptError) -> Error {
        self.last_error = error;
        script_unknown()
    }

    fn map_failure<T>(
        &mut self,
        result: Result<T, TidecoinValidationError>,
        error: ScriptError,
    ) -> Result<T, TidecoinValidationError> {
        result.map_err(|_| self.fail(error))
    }

    fn track_script_error<T>(
        &mut self,
        result: Result<T, TidecoinValidationError>,
    ) -> Result<T, TidecoinValidationError> {
        match result {
            Err(err) if err == script_unknown() => {
                if matches!(self.last_error, ScriptError::Ok) {
                    self.last_error = ScriptError::Unknown;
                }
                Err(err)
            }
            other => other,
        }
    }

    fn initialize_sigops(&mut self, script_sig: &[u8]) -> Result<(), TidecoinValidationError> {
        let sigops_sig = count_sigops_bytes(script_sig, false)?;
        let sigops_spent = count_sigops_bytes(self.spent_output_script, true)?;
        self.sigops = sigops_sig.checked_add(sigops_spent).ok_or(script_unknown())?;
        Ok(())
    }

    fn add_sigops_from_script(
        &mut self,
        script_bytes: &[u8],
        accurate: bool,
    ) -> Result<(), TidecoinValidationError> {
        let count = count_sigops_bytes(script_bytes, accurate)?;
        self.add_sigops(count)
    }

    fn add_sigops(&mut self, count: u32) -> Result<(), TidecoinValidationError> {
        self.sigops = self.sigops.checked_add(count).ok_or(script_unknown())?;
        Ok(())
    }

    fn push_element(
        &mut self,
        stack: &mut ScriptStack,
        data: Vec<u8>,
    ) -> Result<(), TidecoinValidationError> {
        stack.push(data).map_err(|err| self.fail(err))
    }

    fn push_bool_element(
        &mut self,
        stack: &mut ScriptStack,
        value: bool,
    ) -> Result<(), TidecoinValidationError> {
        stack.push_bool(value).map_err(|err| self.fail(err))
    }

    fn add_ops(&mut self, count: usize) -> Result<(), TidecoinValidationError> {
        self.op_count += count;
        if self.op_count > MAX_OPS_PER_SCRIPT {
            Err(self.fail(ScriptError::OpCount))
        } else {
            Ok(())
        }
    }

    fn run_script(
        &mut self,
        stack: &mut ScriptStack,
        script_bytes: &[u8],
        sigversion: SigVersion,
    ) -> Result<(), TidecoinValidationError> {
        if script_bytes.is_empty() {
            return Ok(());
        }
        if script_bytes.len() > MAX_SCRIPT_SIZE {
            return Err(self.fail(ScriptError::ScriptSize));
        }

        self.exec_stack.clear();
        self.op_count = 0;
        let script = RawScript::from_bytes(script_bytes);
        let bytes = script.as_bytes();
        let mut altstack: Vec<Vec<u8>> = Vec::new();
        let mut code_separator = 0usize;
        let mut cursor = 0usize;
        let mut opcode_pos: u32 = 0;
        let script_len = bytes.len();

        while cursor < script_len {
            let opcode = bytes[cursor];
            cursor += 1;
            let should_execute = self.exec_stack.iter().all(|&cond| cond);

            if (0x01..=0x4b).contains(&opcode) {
                let push_len = opcode as usize;
                if cursor + push_len > script_len {
                    return Err(self.fail(ScriptError::BadOpcode));
                }
                if push_len > MAX_SCRIPT_ELEMENT_SIZE {
                    return Err(self.fail(ScriptError::PushSize));
                }
                if should_execute
                    && self.flags.bits() & VERIFY_MINIMALDATA != 0
                    && !is_minimal_push(opcode, &bytes[cursor..cursor + push_len])
                {
                    return Err(self.fail(ScriptError::MinimalData));
                }
                if should_execute {
                    self.push_element(stack, bytes[cursor..cursor + push_len].to_vec())?;
                }
                cursor += push_len;
            } else if opcode == all::OP_PUSHDATA1.to_u8()
                || opcode == all::OP_PUSHDATA2.to_u8()
                || opcode == all::OP_PUSHDATA4.to_u8()
            {
                let width = match opcode {
                    x if x == all::OP_PUSHDATA1.to_u8() => 1,
                    x if x == all::OP_PUSHDATA2.to_u8() => 2,
                    _ => 4,
                };
                let mut len_cursor = cursor;
                let push_len = read_push_length(bytes, &mut len_cursor, width)
                    .map_err(|err| self.fail(err))?;
                if len_cursor + push_len > script_len {
                    return Err(self.fail(ScriptError::BadOpcode));
                }
                if push_len > MAX_SCRIPT_ELEMENT_SIZE {
                    return Err(self.fail(ScriptError::PushSize));
                }
                if should_execute
                    && self.flags.bits() & VERIFY_MINIMALDATA != 0
                    && !is_minimal_push(opcode, &bytes[len_cursor..len_cursor + push_len])
                {
                    return Err(self.fail(ScriptError::MinimalData));
                }
                if should_execute {
                    self.push_element(stack, bytes[len_cursor..len_cursor + push_len].to_vec())?;
                }
                cursor = len_cursor + push_len;
            } else {
                let op = Opcode::from(opcode);
                if opcode > all::OP_PUSHNUM_16.to_u8() {
                    self.add_ops(1)?;
                }

                if matches!(op, all::OP_VERIF | all::OP_VERNOTIF) {
                    return Err(self.fail(ScriptError::BadOpcode));
                }
                if matches!(
                    op,
                    all::OP_CAT
                        | all::OP_SUBSTR
                        | all::OP_LEFT
                        | all::OP_RIGHT
                        | all::OP_INVERT
                        | all::OP_AND
                        | all::OP_OR
                        | all::OP_XOR
                        | all::OP_2MUL
                        | all::OP_2DIV
                        | all::OP_MUL
                        | all::OP_DIV
                        | all::OP_MOD
                        | all::OP_LSHIFT
                        | all::OP_RSHIFT
                ) {
                    return Err(self.fail(ScriptError::DisabledOpcode));
                }
                if op == all::OP_CODESEPARATOR
                    && sigversion == SigVersion::Base
                    && self.flags.bits() & VERIFY_CONST_SCRIPTCODE != 0
                {
                    return Err(self.fail(ScriptError::OpCodeSeparator));
                }

                if is_control_flow(op) {
                    let control_res =
                        self.handle_control_flow(stack, op, should_execute, sigversion);
                    self.track_script_error(control_res)?;
                } else if should_execute {
                    if op == all::OP_CODESEPARATOR {
                        code_separator = cursor;
                    } else {
                        let opcode_res = self.execute_opcode(
                            stack,
                            &mut altstack,
                            op,
                            script,
                            code_separator,
                            sigversion,
                        );
                        self.track_script_error(opcode_res)?;
                    }
                }
            }

            let limit_res = self.ensure_stack_limit(stack.len(), altstack.len());
            self.track_script_error(limit_res)?;
            opcode_pos = opcode_pos.wrapping_add(1);
        }

        if !self.exec_stack.is_empty() {
            return Err(self.fail(ScriptError::UnbalancedConditional));
        }

        Ok(())
    }

    fn run_on_main_stack(
        &mut self,
        script_bytes: &[u8],
        sigversion: SigVersion,
    ) -> Result<(), TidecoinValidationError> {
        let mut stack = mem::take(&mut self.stack);
        let run_res = self.run_script(&mut stack, script_bytes, sigversion);
        let result = self.track_script_error(run_res);
        self.stack = stack;
        result
    }

    // Keep each opcode's operation together, matching the original interpreter.
    #[allow(clippy::collapsible_match)]
    fn execute_opcode(
        &mut self,
        stack: &mut ScriptStack,
        altstack: &mut Vec<Vec<u8>>,
        op: Opcode,
        script: &RawScript,
        code_separator: usize,
        sigversion: SigVersion,
    ) -> Result<(), TidecoinValidationError> {
        use all::*;

        let opcode = op.to_u8();
        let require_minimal = self.flags.bits() & VERIFY_MINIMALDATA != 0;

        if matches!(op, OP_RESERVED | OP_RESERVED1 | OP_RESERVED2 | OP_VER | OP_INVALIDOPCODE) {
            return Err(self.fail(ScriptError::BadOpcode));
        }

        if matches!(
            op,
            OP_CAT
                | OP_SUBSTR
                | OP_LEFT
                | OP_RIGHT
                | OP_INVERT
                | OP_AND
                | OP_OR
                | OP_XOR
                | OP_2MUL
                | OP_2DIV
                | OP_MUL
                | OP_DIV
                | OP_MOD
                | OP_LSHIFT
                | OP_RSHIFT
        ) {
            return Err(self.fail(ScriptError::DisabledOpcode));
        }

        if opcode == OP_PUSHBYTES_0.to_u8() {
            return self.push_element(stack, Vec::new());
        }
        if opcode >= OP_PUSHNUM_1.to_u8() && opcode <= OP_PUSHNUM_16.to_u8() {
            let value = (opcode - OP_PUSHNUM_1.to_u8() + 1) as i32;
            return self.push_element(stack, encode_scriptnum(value as i64));
        }

        match op {
            OP_TOALTSTACK => {
                let value =
                    self.map_failure(stack.pop_bytes(), ScriptError::InvalidStackOperation)?;
                altstack.push(value);
            }
            OP_FROMALTSTACK => {
                let value = altstack
                    .pop()
                    .ok_or_else(|| self.fail(ScriptError::InvalidAltstackOperation))?;
                self.push_element(stack, value)?;
            }
            OP_IFDUP => {
                let value = stack
                    .last()
                    .ok_or_else(|| self.fail(ScriptError::InvalidStackOperation))?
                    .clone();
                if read_scriptbool(&value) {
                    self.push_element(stack, value)?;
                }
            }
            OP_DEPTH => {
                let depth = encode_scriptnum(stack.len() as i64);
                self.push_element(stack, depth)?;
            }
            OP_PUSHNUM_NEG1 => {
                self.push_element(stack, encode_scriptnum(-1))?;
            }
            OP_NOP => {}
            OP_NOP1 | OP_NOP5 | OP_NOP6 | OP_NOP7 | OP_NOP8 | OP_NOP9 | OP_NOP10 => {
                if self.flags.bits() & VERIFY_DISCOURAGE_UPGRADABLE_NOPS != 0 {
                    return Err(self.fail(ScriptError::DiscourageUpgradableNops));
                }
            }
            OP_DUP => {
                let value = stack
                    .last()
                    .ok_or_else(|| self.fail(ScriptError::InvalidStackOperation))?
                    .clone();
                self.push_element(stack, value)?;
            }
            OP_DROP => {
                self.map_failure(stack.pop_bytes(), ScriptError::InvalidStackOperation)?;
            }
            OP_NIP => {
                if stack.len() < 2 {
                    return Err(self.fail(ScriptError::InvalidStackOperation));
                }
                let idx = stack.len() - 2;
                stack.items.remove(idx);
            }
            OP_OVER => {
                if stack.len() < 2 {
                    return Err(self.fail(ScriptError::InvalidStackOperation));
                }
                let value = stack.items[stack.len() - 2].clone();
                self.push_element(stack, value)?;
            }
            OP_ROT => {
                if stack.len() < 3 {
                    return Err(self.fail(ScriptError::InvalidStackOperation));
                }
                let len = stack.len();
                stack.items.swap(len - 3, len - 2);
                stack.items.swap(len - 2, len - 1);
            }
            OP_SWAP => {
                if stack.len() < 2 {
                    return Err(self.fail(ScriptError::InvalidStackOperation));
                }
                let len = stack.len();
                stack.items.swap(len - 2, len - 1);
            }
            OP_TUCK => {
                if stack.len() < 2 {
                    return Err(self.fail(ScriptError::InvalidStackOperation));
                }
                let len = stack.len();
                let value = stack.items[len - 1].clone();
                stack.items.insert(len - 2, value);
            }
            OP_2DROP => {
                if stack.len() < 2 {
                    return Err(self.fail(ScriptError::InvalidStackOperation));
                }
                self.map_failure(stack.pop_bytes(), ScriptError::InvalidStackOperation)?;
                self.map_failure(stack.pop_bytes(), ScriptError::InvalidStackOperation)?;
            }
            OP_2DUP => {
                if stack.len() < 2 {
                    return Err(self.fail(ScriptError::InvalidStackOperation));
                }
                let len = stack.len();
                let first = stack.items[len - 2].clone();
                let second = stack.items[len - 1].clone();
                self.push_element(stack, first)?;
                self.push_element(stack, second)?;
            }
            OP_PICK => {
                self.require_stack_items(stack, 2)?;
                let depth = self.pop_scriptnum(stack, require_minimal, SCRIPTNUM_MAX_LEN)?;
                if depth < 0 {
                    return Err(self.fail(ScriptError::InvalidStackOperation));
                }
                let depth = depth as usize;
                if depth >= stack.len() {
                    return Err(self.fail(ScriptError::InvalidStackOperation));
                }
                let idx = stack.len() - 1 - depth;
                let value = stack.items[idx].clone();
                self.push_element(stack, value)?;
            }
            OP_ROLL => {
                self.require_stack_items(stack, 2)?;
                let depth = self.pop_scriptnum(stack, require_minimal, SCRIPTNUM_MAX_LEN)?;
                if depth < 0 {
                    return Err(self.fail(ScriptError::InvalidStackOperation));
                }
                let depth = depth as usize;
                if depth >= stack.len() {
                    return Err(self.fail(ScriptError::InvalidStackOperation));
                }
                let idx = stack.len() - 1 - depth;
                let value = stack.items.remove(idx);
                self.push_element(stack, value)?;
            }
            OP_3DUP => {
                if stack.len() < 3 {
                    return Err(self.fail(ScriptError::InvalidStackOperation));
                }
                let len = stack.len();
                let first = stack.items[len - 3].clone();
                let second = stack.items[len - 2].clone();
                let third = stack.items[len - 1].clone();
                self.push_element(stack, first)?;
                self.push_element(stack, second)?;
                self.push_element(stack, third)?;
            }
            OP_2OVER => {
                if stack.len() < 4 {
                    return Err(self.fail(ScriptError::InvalidStackOperation));
                }
                let len = stack.len();
                let first = stack.items[len - 4].clone();
                let second = stack.items[len - 3].clone();
                self.push_element(stack, first)?;
                self.push_element(stack, second)?;
            }
            OP_2ROT => {
                if stack.len() < 6 {
                    return Err(self.fail(ScriptError::InvalidStackOperation));
                }
                let len = stack.len();
                let first = stack.items[len - 6].clone();
                let second = stack.items[len - 5].clone();
                stack.items.drain(len - 6..len - 4);
                self.push_element(stack, first)?;
                self.push_element(stack, second)?;
            }
            OP_2SWAP => {
                if stack.len() < 4 {
                    return Err(self.fail(ScriptError::InvalidStackOperation));
                }
                let len = stack.len();
                stack.items.swap(len - 4, len - 2);
                stack.items.swap(len - 3, len - 1);
            }
            OP_SIZE => {
                let value =
                    stack.last().ok_or_else(|| self.fail(ScriptError::InvalidStackOperation))?;
                let size = encode_scriptnum(value.len() as i64);
                self.push_element(stack, size)?;
            }
            OP_1ADD | OP_1SUB | OP_NEGATE | OP_ABS | OP_NOT | OP_0NOTEQUAL => {
                let mut num = self.pop_scriptnum(stack, require_minimal, SCRIPTNUM_MAX_LEN)?;
                match op {
                    OP_1ADD => num += 1,
                    OP_1SUB => num -= 1,
                    OP_NEGATE => num = -num,
                    OP_ABS => {
                        if num < 0 {
                            num = -num;
                        }
                    }
                    OP_NOT => num = if num == 0 { 1 } else { 0 },
                    OP_0NOTEQUAL => num = if num != 0 { 1 } else { 0 },
                    _ => {}
                }
                let encoded = encode_scriptnum(num);
                self.push_element(stack, encoded)?;
            }
            OP_ADD
            | OP_SUB
            | OP_BOOLAND
            | OP_BOOLOR
            | OP_NUMEQUAL
            | OP_NUMEQUALVERIFY
            | OP_NUMNOTEQUAL
            | OP_LESSTHAN
            | OP_GREATERTHAN
            | OP_LESSTHANOREQUAL
            | OP_GREATERTHANOREQUAL
            | OP_MIN
            | OP_MAX => {
                self.require_stack_items(stack, 2)?;
                let b = self.pop_scriptnum(stack, require_minimal, SCRIPTNUM_MAX_LEN)?;
                let a = self.pop_scriptnum(stack, require_minimal, SCRIPTNUM_MAX_LEN)?;
                let result = match op {
                    OP_ADD => a.checked_add(b).ok_or(script_unknown())?,
                    OP_SUB => a.checked_sub(b).ok_or(script_unknown())?,
                    OP_BOOLAND => {
                        if a != 0 && b != 0 {
                            1
                        } else {
                            0
                        }
                    }
                    OP_BOOLOR => {
                        if a != 0 || b != 0 {
                            1
                        } else {
                            0
                        }
                    }
                    OP_NUMEQUAL | OP_NUMEQUALVERIFY => {
                        if a == b {
                            1
                        } else {
                            0
                        }
                    }
                    OP_NUMNOTEQUAL => {
                        if a != b {
                            1
                        } else {
                            0
                        }
                    }
                    OP_LESSTHAN => {
                        if a < b {
                            1
                        } else {
                            0
                        }
                    }
                    OP_GREATERTHAN => {
                        if a > b {
                            1
                        } else {
                            0
                        }
                    }
                    OP_LESSTHANOREQUAL => {
                        if a <= b {
                            1
                        } else {
                            0
                        }
                    }
                    OP_GREATERTHANOREQUAL => {
                        if a >= b {
                            1
                        } else {
                            0
                        }
                    }
                    OP_MIN => {
                        if a < b {
                            a
                        } else {
                            b
                        }
                    }
                    OP_MAX => {
                        if a > b {
                            a
                        } else {
                            b
                        }
                    }
                    _ => 0,
                };
                self.push_element(stack, encode_scriptnum(result))?;
                if op == OP_NUMEQUALVERIFY {
                    self.op_verify_with_code(stack, ScriptError::NumEqualVerify)?;
                }
            }
            OP_WITHIN => {
                self.require_stack_items(stack, 3)?;
                let max = self.pop_scriptnum(stack, require_minimal, SCRIPTNUM_MAX_LEN)?;
                let min = self.pop_scriptnum(stack, require_minimal, SCRIPTNUM_MAX_LEN)?;
                let value = self.pop_scriptnum(stack, require_minimal, SCRIPTNUM_MAX_LEN)?;
                self.push_bool_element(stack, value >= min && value < max)?;
            }
            OP_CLTV => {
                if self.flags.bits() & VERIFY_CHECKLOCKTIMEVERIFY != 0 {
                    let locktime =
                        self.peek_scriptnum(stack, require_minimal, SCRIPTNUM_MAX_LEN_EXTENDED)?;
                    if locktime < 0 {
                        return Err(self.fail(ScriptError::NegativeLockTime));
                    }
                    let check = self.check_lock_time(locktime as u64);
                    if let Err(err) = check {
                        return Err(self.fail(err));
                    }
                }
            }
            OP_CSV => {
                if self.flags.bits() & VERIFY_CHECKSEQUENCEVERIFY != 0 {
                    let sequence =
                        self.peek_scriptnum(stack, require_minimal, SCRIPTNUM_MAX_LEN_EXTENDED)?;
                    if sequence < 0 {
                        return Err(self.fail(ScriptError::NegativeLockTime));
                    }
                    let check = self.check_sequence(sequence as u64);
                    if let Err(err) = check {
                        return Err(self.fail(err));
                    }
                }
            }
            OP_RIPEMD160 => self.op_ripemd160(stack)?,
            OP_SHA1 => self.op_sha1(stack)?,
            OP_SHA256 => self.op_sha256(stack)?,
            OP_HASH160 => self.op_hash160(stack)?,
            OP_HASH256 => self.op_hash256(stack)?,
            _ if opcode == all::OP_NOP4.to_u8() => self.op_sha512(stack)?,
            OP_EQUAL => self.op_equal(stack)?,
            OP_EQUALVERIFY => {
                self.op_equal(stack)?;
                self.op_verify_with_code(stack, ScriptError::EqualVerify)?;
            }
            OP_VERIFY => self.op_verify(stack)?,
            OP_RETURN => return Err(self.fail(ScriptError::OpReturn)),
            OP_CHECKSIG => self.op_checksig(stack, script, code_separator, sigversion)?,
            OP_CHECKSIGVERIFY => {
                self.op_checksig(stack, script, code_separator, sigversion)?;
                self.op_verify_with_code(stack, ScriptError::CheckSigVerify)?;
            }
            OP_CHECKSIGADD => {
                self.op_checksigadd(stack, sigversion)?;
            }
            OP_CHECKMULTISIG => {
                self.op_checkmultisig(stack, script, code_separator, sigversion)?;
            }
            OP_CHECKMULTISIGVERIFY => {
                self.op_checkmultisig(stack, script, code_separator, sigversion)?;
                self.op_verify_with_code(stack, ScriptError::CheckMultiSigVerify)?;
            }
            _ => return Err(self.fail(ScriptError::BadOpcode)),
        }

        Ok(())
    }

    // Keep control-flow mutation inside the matching opcode arm.
    #[allow(clippy::collapsible_match)]
    fn handle_control_flow(
        &mut self,
        stack: &mut ScriptStack,
        op: Opcode,
        should_execute: bool,
        sigversion: SigVersion,
    ) -> Result<(), TidecoinValidationError> {
        use all::*;

        match op {
            OP_IF | OP_NOTIF => {
                let mut value = false;
                if should_execute {
                    let condition =
                        self.map_failure(stack.pop_bytes(), ScriptError::UnbalancedConditional)?;
                    let enforce_minimal_if = match sigversion {
                        SigVersion::WitnessV0 | SigVersion::WitnessV1_512 => {
                            self.flags.bits() & VERIFY_MINIMALIF != 0
                        }
                        SigVersion::Base => false,
                    };
                    if enforce_minimal_if
                        && !condition.is_empty()
                        && !is_minimal_if_condition(&condition)
                    {
                        return Err(self.fail(ScriptError::MinimalIf));
                    }
                    value = read_scriptbool(&condition);
                    if op == OP_NOTIF {
                        value = !value;
                    }
                }
                self.exec_stack.push(value);
            }
            OP_ELSE => {
                let Some(top) = self.exec_stack.last_mut() else {
                    return Err(self.fail(ScriptError::UnbalancedConditional));
                };
                *top = !*top;
            }
            OP_ENDIF => {
                if self.exec_stack.pop().is_none() {
                    return Err(self.fail(ScriptError::UnbalancedConditional));
                }
            }
            _ => {}
        }

        Ok(())
    }

    fn ensure_stack_limit(
        &mut self,
        stack_size: usize,
        altstack_size: usize,
    ) -> Result<(), TidecoinValidationError> {
        if stack_size + altstack_size > MAX_STACK_SIZE {
            Err(self.fail(ScriptError::StackSize))
        } else {
            Ok(())
        }
    }

    fn op_hash160(&mut self, stack: &mut ScriptStack) -> Result<(), TidecoinValidationError> {
        let data = self.map_failure(stack.pop_bytes(), ScriptError::InvalidStackOperation)?;
        let hash = hash160::Hash::hash(&data);
        self.push_element(stack, hash.to_byte_array().to_vec())
    }

    fn op_ripemd160(&mut self, stack: &mut ScriptStack) -> Result<(), TidecoinValidationError> {
        let data = self.map_failure(stack.pop_bytes(), ScriptError::InvalidStackOperation)?;
        let hash = ripemd160::Hash::hash(&data);
        self.push_element(stack, hash.to_byte_array().to_vec())
    }

    fn op_sha1(&mut self, stack: &mut ScriptStack) -> Result<(), TidecoinValidationError> {
        let data = self.map_failure(stack.pop_bytes(), ScriptError::InvalidStackOperation)?;
        let hash = sha1::Hash::hash(&data);
        self.push_element(stack, hash.to_byte_array().to_vec())
    }

    fn op_sha256(&mut self, stack: &mut ScriptStack) -> Result<(), TidecoinValidationError> {
        let data = self.map_failure(stack.pop_bytes(), ScriptError::InvalidStackOperation)?;
        let hash = sha256::Hash::hash(&data);
        self.push_element(stack, hash.to_byte_array().to_vec())
    }

    fn op_hash256(&mut self, stack: &mut ScriptStack) -> Result<(), TidecoinValidationError> {
        let data = self.map_failure(stack.pop_bytes(), ScriptError::InvalidStackOperation)?;
        let hash = sha256d::Hash::hash(&data);
        self.push_element(stack, hash.to_byte_array().to_vec())
    }

    fn op_sha512(&mut self, stack: &mut ScriptStack) -> Result<(), TidecoinValidationError> {
        if self.flags.bits() & VERIFY_SHA512 == 0 {
            if self.flags.bits() & VERIFY_DISCOURAGE_UPGRADABLE_NOPS != 0 {
                return Err(self.fail(ScriptError::DiscourageUpgradableNops));
            }
            return Ok(());
        }

        let data = self.map_failure(stack.pop_bytes(), ScriptError::InvalidStackOperation)?;
        let hash = sha512::Hash::hash(&data);
        self.push_element(stack, hash.to_byte_array().to_vec())
    }

    fn op_equal(&mut self, stack: &mut ScriptStack) -> Result<(), TidecoinValidationError> {
        let a = self.map_failure(stack.pop_bytes(), ScriptError::InvalidStackOperation)?;
        let b = self.map_failure(stack.pop_bytes(), ScriptError::InvalidStackOperation)?;
        self.push_bool_element(stack, a == b)
    }

    fn op_verify(&mut self, stack: &mut ScriptStack) -> Result<(), TidecoinValidationError> {
        self.op_verify_with_code(stack, ScriptError::Verify)
    }

    fn op_verify_with_code(
        &mut self,
        stack: &mut ScriptStack,
        error: ScriptError,
    ) -> Result<(), TidecoinValidationError> {
        let value = self.map_failure(stack.pop_bytes(), ScriptError::InvalidStackOperation)?;
        if !read_scriptbool(&value) {
            return Err(self.fail(error));
        }
        Ok(())
    }

    fn op_checksig(
        &mut self,
        stack: &mut ScriptStack,
        script: &RawScript,
        code_separator: usize,
        sigversion: SigVersion,
    ) -> Result<(), TidecoinValidationError> {
        let pubkey = self.map_failure(stack.pop_bytes(), ScriptError::InvalidStackOperation)?;
        let sig = self.map_failure(stack.pop_bytes(), ScriptError::InvalidStackOperation)?;
        let script_code =
            self.build_signature_script_code(script, code_separator, sigversion, &[&sig])?;
        self.check_signature_hash_type(&sig, sigversion)?;
        self.check_falcon_encoding(&sig)?;
        let result =
            self.verify_signature_against_code(&sig, &pubkey, script_code.as_script(), sigversion)?;
        if !result && self.flags.bits() & VERIFY_NULLFAIL != 0 && !sig.is_empty() {
            return Err(self.fail(ScriptError::NullFail));
        }
        self.push_bool_element(stack, result)
    }

    fn op_checkmultisig(
        &mut self,
        stack: &mut ScriptStack,
        script: &RawScript,
        code_separator: usize,
        sigversion: SigVersion,
    ) -> Result<(), TidecoinValidationError> {
        let require_minimal = self.flags.bits() & VERIFY_MINIMALDATA != 0;
        let n_keys = self.pop_scriptnum(stack, require_minimal, SCRIPTNUM_MAX_LEN)?;
        if n_keys < 0 || n_keys as usize > MAX_PUBKEYS_PER_MULTISIG {
            return Err(self.fail(ScriptError::PubkeyCount));
        }
        let n_keys = n_keys as usize;
        self.add_ops(n_keys)?;
        if stack.len() < n_keys {
            return Err(self.fail(ScriptError::InvalidStackOperation));
        }

        let mut pubkeys = Vec::with_capacity(n_keys);
        for _ in 0..n_keys {
            let key = self.map_failure(stack.pop_bytes(), ScriptError::InvalidStackOperation)?;
            pubkeys.push(key);
        }

        let n_sigs = self.pop_scriptnum(stack, require_minimal, SCRIPTNUM_MAX_LEN)?;
        if n_sigs < 0 || n_sigs as usize > n_keys {
            return Err(self.fail(ScriptError::SigCount));
        }
        let n_sigs = n_sigs as usize;
        if stack.len() < n_sigs + 1 {
            return Err(self.fail(ScriptError::InvalidStackOperation));
        }

        let mut sigs = Vec::with_capacity(n_sigs);
        for _ in 0..n_sigs {
            let sig = self.map_failure(stack.pop_bytes(), ScriptError::InvalidStackOperation)?;
            sigs.push(sig);
        }

        let mut script_code = self.build_script_code(script, code_separator, sigversion)?;
        for signature in &sigs {
            // Match node order: validate each argument before its FindAndDelete,
            // including signatures the matching loop will never reach.
            self.check_signature_hash_type(signature, sigversion)?;
            self.check_falcon_encoding(signature)?;
            if sigversion == SigVersion::Base {
                script_code =
                    self.apply_legacy_find_and_delete(script_code.as_script(), &[signature])?;
            }
        }
        let dummy = self.map_failure(stack.pop_bytes(), ScriptError::InvalidStackOperation)?;

        let mut success = true;
        let mut sig_index = 0usize;
        let mut key_index = 0usize;
        let enforce_nullfail = self.flags.bits() & VERIFY_NULLFAIL != 0;

        while success && sig_index < sigs.len() {
            if pubkeys.len() - key_index < sigs.len() - sig_index {
                success = false;
                break;
            }

            let sig_valid = self.verify_signature_against_code(
                &sigs[sig_index],
                &pubkeys[key_index],
                script_code.as_script(),
                sigversion,
            )?;
            if sig_valid {
                sig_index += 1;
            }
            key_index += 1;
        }

        if !success && enforce_nullfail {
            let has_non_empty = sigs.iter().any(|sig| !sig.is_empty());
            if has_non_empty {
                return Err(self.fail(ScriptError::NullFail));
            }
        }

        let remaining_keys = pubkeys.len().saturating_sub(key_index);
        let remaining_sigs = sigs.len().saturating_sub(sig_index);
        if remaining_sigs > remaining_keys {
            success = false;
        }

        if self.flags.bits() & VERIFY_NULLDUMMY != 0 && !dummy.is_empty() {
            return Err(self.fail(ScriptError::SigNullDummy));
        }
        self.push_bool_element(stack, success)
    }

    fn op_checksigadd(
        &mut self,
        _stack: &mut ScriptStack,
        _sigversion: SigVersion,
    ) -> Result<(), TidecoinValidationError> {
        Err(self.fail(ScriptError::BadOpcode))
    }

    /// Match `EvalScript`: reject a short stack before `CScriptNum` can raise
    /// `SCRIPT_ERR_UNKNOWN_ERROR` for overflow or a non-minimal encoding.
    fn require_stack_items(
        &mut self,
        stack: &ScriptStack,
        needed: usize,
    ) -> Result<(), TidecoinValidationError> {
        if stack.len() < needed {
            return Err(self.fail(ScriptError::InvalidStackOperation));
        }
        Ok(())
    }

    fn pop_scriptnum(
        &mut self,
        stack: &mut ScriptStack,
        minimal: bool,
        max_len: usize,
    ) -> Result<i64, TidecoinValidationError> {
        let bytes = self.map_failure(stack.pop_bytes(), ScriptError::InvalidStackOperation)?;
        self.decode_scriptnum(&bytes, minimal, max_len)
    }

    fn peek_scriptnum(
        &mut self,
        stack: &ScriptStack,
        minimal: bool,
        max_len: usize,
    ) -> Result<i64, TidecoinValidationError> {
        let bytes = stack.last().ok_or_else(|| self.fail(ScriptError::InvalidStackOperation))?;
        self.decode_scriptnum(bytes, minimal, max_len)
    }

    fn decode_scriptnum(
        &mut self,
        bytes: &[u8],
        minimal: bool,
        max_len: usize,
    ) -> Result<i64, TidecoinValidationError> {
        parse_scriptnum(bytes, minimal, max_len).map_err(|err| self.fail(err))
    }

    fn check_lock_time(&self, locktime: u64) -> Result<(), ScriptError> {
        if locktime > u32::MAX as u64 {
            return Err(ScriptError::UnsatisfiedLockTime);
        }

        let tx = self.tx_ctx.tx();
        let tx_lock = tx.lock_time.to_consensus_u32();
        let locktime_u32 = locktime as u32;
        if tx_lock < locktime_u32 {
            return Err(ScriptError::UnsatisfiedLockTime);
        }

        if (tx_lock < LOCK_TIME_THRESHOLD) != (locktime_u32 < LOCK_TIME_THRESHOLD) {
            return Err(ScriptError::UnsatisfiedLockTime);
        }

        let sequence = tx.inputs[self.input_index].sequence.to_consensus_u32();
        if sequence == Sequence::MAX.to_consensus_u32() {
            return Err(ScriptError::UnsatisfiedLockTime);
        }

        Ok(())
    }

    fn check_sequence(&self, sequence: u64) -> Result<(), ScriptError> {
        if (sequence as u32) & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
            return Ok(());
        }
        // CSV version gating uses unsigned transaction-version semantics.
        // That means negative serialized values (e.g. 0xffffffff) are treated
        // as large versions and satisfy the version gate.
        if self.tx_ctx.tx().version.to_u32() < 2 {
            return Err(ScriptError::UnsatisfiedLockTime);
        }

        let tx_sequence = self.tx_ctx.tx().inputs[self.input_index].sequence.to_consensus_u32();
        if tx_sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
            return Err(ScriptError::UnsatisfiedLockTime);
        }

        let locktime_mask = SEQUENCE_LOCKTIME_TYPE_FLAG | SEQUENCE_LOCKTIME_MASK;
        let tx_sequence_masked = tx_sequence & locktime_mask;
        let sequence_masked = (sequence as u32) & locktime_mask;
        let tx_is_time = tx_sequence_masked >= SEQUENCE_LOCKTIME_TYPE_FLAG;
        let sequence_is_time = sequence_masked >= SEQUENCE_LOCKTIME_TYPE_FLAG;
        if tx_is_time != sequence_is_time {
            return Err(ScriptError::UnsatisfiedLockTime);
        }

        if sequence_masked > tx_sequence_masked {
            return Err(ScriptError::UnsatisfiedLockTime);
        }

        Ok(())
    }

    fn build_script_code(
        &mut self,
        script: &RawScript,
        code_separator: usize,
        sigversion: SigVersion,
    ) -> Result<RawScriptBuf, TidecoinValidationError> {
        let strip_codeseparators = matches!(sigversion, SigVersion::Base);
        let identity = ScriptIdentity::new(script);
        let needs_refresh = self
            .script_code_cache
            .as_ref()
            .map(|cache| !cache.matches(identity, code_separator, strip_codeseparators))
            .unwrap_or(true);
        if needs_refresh {
            let script_buf =
                Self::materialize_script_code(script, code_separator, strip_codeseparators)?;
            self.script_code_cache = Some(ScriptCodeCache {
                identity,
                code_separator,
                strip_codeseparators,
                script: script_buf,
            });
        }
        Ok(self
            .script_code_cache
            .as_ref()
            .expect("script code cache is initialized")
            .script
            .clone())
    }

    fn materialize_script_code(
        script: &RawScript,
        code_separator: usize,
        strip_codeseparators: bool,
    ) -> Result<RawScriptBuf, TidecoinValidationError> {
        if code_separator > script.as_bytes().len() {
            return Err(script_unknown());
        }
        let tail = &script.as_bytes()[code_separator..];
        if strip_codeseparators {
            let stripped = strip_opcode(tail, all::OP_CODESEPARATOR);
            Ok(RawScriptBuf::from_bytes(stripped))
        } else {
            Ok(RawScriptBuf::from_bytes(tail.to_vec()))
        }
    }

    fn execute_witness_program(
        &mut self,
        version: u8,
        program: &[u8],
        witness: &'tx Witness,
        is_p2sh: bool,
    ) -> Result<(), TidecoinValidationError> {
        let _ = is_p2sh;
        let plan = WitnessProgram::parse_program(version, program)
            .execution_plan(self.flags.bits(), witness)
            .map_err(|err| self.fail(map_core_script_error(err)))?;
        match plan {
            WitnessExecutionPlan::Upgradable => Ok(()),
            WitnessExecutionPlan::Execute { sigversion, script_bytes, stack_items, sigops } => {
                match sigops {
                    WitnessSigops::None => {}
                    WitnessSigops::Fixed(count) => self.add_sigops(count)?,
                    WitnessSigops::CountExecutedScript => {
                        self.add_sigops_from_script(&script_bytes, true)?
                    }
                }

                let mut stack =
                    ScriptStack::from_items(stack_items).map_err(|err| self.fail(err))?;
                let sigversion = match sigversion {
                    WitnessSigVersion::V0 => SigVersion::WitnessV0,
                    WitnessSigVersion::V1_512 => SigVersion::WitnessV1_512,
                };
                self.run_script(&mut stack, &script_bytes, sigversion)?;
                self.ensure_witness_success(&stack)
            }
        }
    }

    fn require_clean_stack(&self, stack: &ScriptStack) -> Result<(), ScriptError> {
        if stack.len() != 1 {
            return Err(ScriptError::CleanStack);
        }
        if !read_scriptbool(stack.last().expect("stack length checked")) {
            return Err(ScriptError::CleanStack);
        }
        Ok(())
    }

    fn ensure_witness_success(
        &mut self,
        stack: &ScriptStack,
    ) -> Result<(), TidecoinValidationError> {
        if stack.len() != 1 {
            return Err(self.fail(ScriptError::CleanStack));
        }
        if !read_scriptbool(stack.last().expect("stack length checked")) {
            return Err(self.fail(ScriptError::EvalFalse));
        }
        Ok(())
    }

    fn check_falcon_encoding(&mut self, signature: &[u8]) -> Result<(), TidecoinValidationError> {
        if self.flags.bits() & VERIFY_FALCON_CANONICAL != 0
            && self.flags.bits() & VERIFY_PQ_STRICT == 0
            && signature
                .split_last()
                .is_some_and(|(_, raw)| crate::pq::is_noncanonical_legacy_falcon512(raw))
        {
            return Err(self.fail(ScriptError::SigFalconEncoding));
        }
        Ok(())
    }

    fn check_signature_hash_type(
        &mut self,
        sig: &[u8],
        version: SigVersion,
    ) -> Result<(), TidecoinValidationError> {
        if let Some(hash_type) = sig.last() {
            if (version == SigVersion::WitnessV1_512
                || self.flags.bits() & VERIFY_DEFINED_HASHTYPE != 0)
                && TxSighashType::from_standard(*hash_type as u32).is_err()
            {
                return Err(self.fail(ScriptError::SigHashType));
            }
        }
        Ok(())
    }

    fn verify_signature_against_code(
        &mut self,
        sig_with_hash_type: &[u8],
        pubkey_bytes: &[u8],
        script_code: &RawScript,
        sigversion: SigVersion,
    ) -> Result<bool, TidecoinValidationError> {
        if let Ok(pubkey) = PqPublicKey::from_prefixed_slice(pubkey_bytes) {
            return self.verify_pq_signature_against_code(
                sig_with_hash_type,
                &pubkey,
                script_code,
                sigversion,
            );
        }
        Ok(false)
    }

    fn verify_pq_signature_against_code(
        &mut self,
        sig_with_hash_type: &[u8],
        pubkey: &PqPublicKey,
        script_code: &RawScript,
        sigversion: SigVersion,
    ) -> Result<bool, TidecoinValidationError> {
        if self.flags.bits() & VERIFY_PQ_STRICT == 0
            && pubkey.scheme() != crate::PqScheme::Falcon512
        {
            return Ok(false);
        }
        let (sig_bytes, hash_type) = split_signature_hash_type(sig_with_hash_type);
        if sig_bytes.is_empty() {
            return Ok(false);
        }
        let sig = PqSignature::from_slice(sig_bytes);
        let verified = match sigversion {
            SigVersion::Base => {
                let sighash = self
                    .sighash_cache
                    .borrow()
                    .legacy_signature_hash(
                        self.input_index,
                        script_code.as_bytes(),
                        hash_type as u32,
                    )
                    .map_err(|_| script_unknown())?;
                let msg = *sighash.as_byte_array();
                if self.flags.bits() & VERIFY_PQ_STRICT != 0 {
                    sig.verify_msg32(&msg, pubkey).is_ok()
                } else {
                    sig.verify_msg32_legacy(&msg, pubkey).is_ok()
                }
            }
            SigVersion::WitnessV0 => {
                let sighash = self.segwit_v0_signature_hash(script_code, hash_type as u32)?;
                let msg = *sighash.as_byte_array();
                if self.flags.bits() & VERIFY_PQ_STRICT != 0 {
                    sig.verify_msg32(&msg, pubkey).is_ok()
                } else {
                    sig.verify_msg32_legacy(&msg, pubkey).is_ok()
                }
            }
            SigVersion::WitnessV1_512 => {
                let Some(sighash) =
                    self.witness_v1_512_signature_hash(script_code, hash_type as u32)?
                else {
                    // Node CheckSig treats an unavailable digest as a failed signature,
                    // allowing the script (e.g. CHECKSIG NOT) to handle that boolean.
                    return Ok(false);
                };
                sig.verify_msg64(sighash.as_byte_array(), pubkey).is_ok()
            }
        };
        Ok(verified)
    }

    fn build_signature_script_code(
        &mut self,
        script: &RawScript,
        code_separator: usize,
        sigversion: SigVersion,
        signatures: &[&[u8]],
    ) -> Result<RawScriptBuf, TidecoinValidationError> {
        let mut script_code = self.build_script_code(script, code_separator, sigversion)?;
        if sigversion == SigVersion::Base {
            script_code = self.apply_legacy_find_and_delete(script_code.as_script(), signatures)?;
        }
        Ok(script_code)
    }

    fn apply_legacy_find_and_delete(
        &mut self,
        script_code: &RawScript,
        signatures: &[&[u8]],
    ) -> Result<RawScriptBuf, TidecoinValidationError> {
        let mut script_bytes = script_code.as_bytes().to_vec();
        for signature in signatures {
            let sig_push = single_push_script(signature).map_err(|_| script_unknown())?;
            let (filtered, removed) = find_and_delete(&script_bytes, sig_push.as_bytes());
            if removed > 0 && self.flags.bits() & VERIFY_CONST_SCRIPTCODE != 0 {
                return Err(self.fail(ScriptError::SigFindAndDelete));
            }
            script_bytes = filtered;
        }
        Ok(RawScriptBuf::from_bytes(script_bytes))
    }

    fn segwit_v0_signature_hash(
        &mut self,
        script_code: &RawScript,
        raw_sighash_type: u32,
    ) -> Result<SegwitV0Sighash, TidecoinValidationError> {
        self.sighash_cache
            .borrow_mut()
            .p2wsh_signature_hash_raw(
                self.input_index,
                script_code.as_bytes(),
                Amount::from_sat(self.amount)
                    .map_err(|_| TidecoinValidationError::AmountRequired)?,
                raw_sighash_type,
            )
            .map_err(|_| script_unknown())
    }

    fn witness_v1_512_signature_hash(
        &mut self,
        script_code: &RawScript,
        raw_sighash_type: u32,
    ) -> Result<Option<Sighash512>, TidecoinValidationError> {
        let sighash_type = TxSighashType::from_consensus(raw_sighash_type);
        match self.sighash_cache.borrow_mut().p2wsh512_signature_hash(
            self.input_index,
            script_code.as_bytes(),
            Amount::from_sat(self.amount).map_err(|_| TidecoinValidationError::AmountRequired)?,
            sighash_type,
        ) {
            Ok(hash) => Ok(Some(hash)),
            Err(
                WitnessV1SighashError::SingleMissingOutput
                | WitnessV1SighashError::SpentOutputsRequired,
            ) => Ok(None),
            Err(WitnessV1SighashError::SpentOutputs(err)) => Err(err.into()),
            Err(WitnessV1SighashError::InputIndex(err)) => {
                Err(TidecoinValidationError::InvalidInputIndex {
                    index: err.index,
                    inputs: err.length,
                })
            }
        }
    }
}

fn parse_scriptnum(bytes: &[u8], minimal: bool, max_len: usize) -> Result<i64, ScriptError> {
    match read_scriptnum(bytes, minimal, max_len) {
        Ok(value) => Ok(value),
        Err(ScriptIntError::NumericOverflow | ScriptIntError::NonMinimal) => {
            Err(ScriptError::Unknown)
        }
        Err(_) => Err(ScriptError::Unknown),
    }
}

fn is_push_only(script_bytes: &[u8]) -> bool {
    let mut offset = 0usize;
    while let Some((_, instruction)) = next_instruction(script_bytes, &mut offset, false) {
        match instruction {
            Ok(Instruction::PushBytes(_)) => {}
            Ok(Instruction::Op(op)) if op.to_u8() <= 0x60 => {}
            Ok(Instruction::Op(_)) | Err(_) => return false,
        }
    }
    true
}

fn is_p2sh(script_bytes: &[u8]) -> bool {
    script_bytes.len() == 23
        && script_bytes[0] == all::OP_HASH160.to_u8()
        && script_bytes[1] == all::OP_PUSHBYTES_20.to_u8()
        && script_bytes[22] == all::OP_EQUAL.to_u8()
}

/// Encodes `data` as original `CScript() << data` does: always a length-prefixed
/// push, never a small-integer opcode. This is the FindAndDelete search pattern.
fn single_push_script(data: &[u8]) -> Result<RawScriptBuf, primitives::script::PushBytesError> {
    let push = PushBytesBuf::try_from(data.to_vec())?;
    Ok(Builder::new().push_slice_non_minimal(push).into_script())
}

fn map_core_script_error(error: ScriptError) -> ScriptError {
    error
}

fn is_control_flow(op: Opcode) -> bool {
    use all::*;

    matches!(op, OP_IF | OP_NOTIF | OP_ELSE | OP_ENDIF)
}

fn is_minimal_if_condition(data: &[u8]) -> bool {
    data.len() == 1 && data[0] == 1
}

fn split_signature_hash_type(sig: &[u8]) -> (&[u8], u8) {
    match sig.split_last() {
        Some((&hash_type, body)) => (body, hash_type),
        None => (&[], 0),
    }
}

fn is_minimal_push(opcode: u8, data: &[u8]) -> bool {
    use all::*;

    if data.is_empty() {
        return opcode == OP_PUSHBYTES_0.to_u8();
    }

    if data.len() == 1 {
        let value = data[0];
        if value == 0x81 {
            return opcode == OP_PUSHNUM_NEG1.to_u8();
        }
        if (1..=16).contains(&value) {
            return opcode == OP_PUSHNUM_1.to_u8() + value - 1;
        }
    }

    if data.len() <= 75 {
        return opcode as usize == data.len();
    }
    if data.len() <= 0xff {
        return opcode == OP_PUSHDATA1.to_u8();
    }
    if data.len() <= 0xffff {
        return opcode == OP_PUSHDATA2.to_u8();
    }
    opcode == OP_PUSHDATA4.to_u8()
}

fn strip_opcode(script_bytes: &[u8], opcode: Opcode) -> Vec<u8> {
    // Original CTransactionSignatureSerializer stops GetOp at a malformed
    // instruction and preserves the remaining bytes. Preparing scriptCode must
    // not reject a tail before execution reaches it (or before an earlier error).
    let mut stripped = Vec::with_capacity(script_bytes.len());
    let mut pos = 0;
    while let Some(next) = next_instruction_offset(script_bytes, pos) {
        if next != pos + 1 || script_bytes[pos] != opcode.to_u8() {
            stripped.extend_from_slice(&script_bytes[pos..next]);
        }
        pos = next;
    }
    stripped.extend_from_slice(&script_bytes[pos..]);
    stripped
}

fn find_and_delete(script_bytes: &[u8], pattern: &[u8]) -> (Vec<u8>, usize) {
    if pattern.is_empty() {
        return (script_bytes.to_vec(), 0);
    }
    if script_bytes.len() < pattern.len() {
        return (script_bytes.to_vec(), 0);
    }

    let mut removed = 0usize;
    let mut result = Vec::with_capacity(script_bytes.len());
    let mut pc = 0usize;
    let mut pc2 = 0usize;
    let end = script_bytes.len();

    loop {
        result.extend_from_slice(&script_bytes[pc2..pc]);
        while pc + pattern.len() <= end && &script_bytes[pc..pc + pattern.len()] == pattern {
            pc += pattern.len();
            removed += 1;
        }
        pc2 = pc;
        let Some(next_pc) = next_instruction_offset(script_bytes, pc) else {
            break;
        };
        pc = next_pc;
    }

    if removed > 0 {
        result.extend_from_slice(&script_bytes[pc2..end]);
        (result, removed)
    } else {
        (script_bytes.to_vec(), 0)
    }
}

fn next_instruction_offset(script_bytes: &[u8], offset: usize) -> Option<usize> {
    if offset >= script_bytes.len() {
        return None;
    }

    let opcode = script_bytes[offset];
    let mut cursor = offset + 1;
    match opcode {
        0x01..=0x4b => {
            let push_len = opcode as usize;
            cursor = cursor.checked_add(push_len)?;
            if cursor <= script_bytes.len() {
                Some(cursor)
            } else {
                None
            }
        }
        0x4c => {
            let len = *script_bytes.get(cursor)? as usize;
            cursor += 1;
            cursor = cursor.checked_add(len)?;
            (cursor <= script_bytes.len()).then_some(cursor)
        }
        0x4d => {
            let bytes = script_bytes.get(cursor..cursor + 2)?;
            let len = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
            cursor += 2;
            cursor = cursor.checked_add(len)?;
            (cursor <= script_bytes.len()).then_some(cursor)
        }
        0x4e => {
            let bytes = script_bytes.get(cursor..cursor + 4)?;
            let len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
            cursor += 4;
            cursor = cursor.checked_add(len)?;
            (cursor <= script_bytes.len()).then_some(cursor)
        }
        _ => Some(cursor),
    }
}

fn read_push_length(bytes: &[u8], index: &mut usize, width: usize) -> Result<usize, ScriptError> {
    if bytes.len() < *index + width {
        return Err(ScriptError::BadOpcode);
    }
    let mut len: usize = 0;
    for i in 0..width {
        len |= (bytes[*index + i] as usize) << (8 * i);
    }
    *index += width;
    Ok(len)
}

fn count_sigops_bytes(script_bytes: &[u8], accurate: bool) -> Result<u32, TidecoinValidationError> {
    count_sigops(script_bytes, accurate)
}

fn count_sigops(script_bytes: &[u8], accurate: bool) -> Result<u32, TidecoinValidationError> {
    use all::*;

    let mut total: u32 = 0;
    let mut last_op: Option<Opcode> = None;
    let mut offset = 0usize;
    while let Some((_, instruction)) = next_instruction(script_bytes, &mut offset, false) {
        let Ok(instruction) = instruction else {
            // Stop counting when decoding fails and return the count
            // accumulated so far.
            break;
        };
        match instruction {
            Instruction::Op(opcode) => {
                match opcode {
                    OP_CHECKSIG | OP_CHECKSIGVERIFY => {
                        total = total.checked_add(1).ok_or(script_unknown())?;
                    }
                    OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY => {
                        let add = if accurate {
                            decode_op_n(last_op).unwrap_or(MAX_PUBKEYS_PER_MULTISIG as u32)
                        } else {
                            MAX_PUBKEYS_PER_MULTISIG as u32
                        };
                        total = total.checked_add(add).ok_or(script_unknown())?;
                    }
                    _ => {}
                }
                last_op = Some(opcode);
            }
            Instruction::PushBytes(_) => {
                last_op = None;
            }
        }
    }

    Ok(total)
}

#[cfg(test)]
fn collect_instruction_indices<'a>(
    script_bytes: &'a [u8],
    enforce_minimal: bool,
) -> Result<Vec<(usize, Instruction<'a>)>, ScriptError> {
    let mut offset = 0usize;
    let mut out = Vec::new();
    while let Some((pos, instruction)) =
        next_instruction(script_bytes, &mut offset, enforce_minimal)
    {
        out.push((pos, instruction?));
    }
    Ok(out)
}

fn next_instruction<'a>(
    script_bytes: &'a [u8],
    offset: &mut usize,
    enforce_minimal: bool,
) -> Option<(usize, Result<Instruction<'a>, ScriptError>)> {
    if *offset >= script_bytes.len() {
        return None;
    }

    let pos = *offset;
    let opcode = script_bytes[*offset];
    *offset += 1;

    let push_len = match opcode {
        0x01..=0x4b => Some(opcode as usize),
        0x4c => match script_bytes.get(*offset) {
            Some(&len) => {
                *offset += 1;
                Some(len as usize)
            }
            None => return Some((pos, Err(ScriptError::BadOpcode))),
        },
        0x4d => match script_bytes.get(*offset..*offset + 2) {
            Some(bytes) => {
                *offset += 2;
                Some(u16::from_le_bytes([bytes[0], bytes[1]]) as usize)
            }
            None => return Some((pos, Err(ScriptError::BadOpcode))),
        },
        0x4e => match script_bytes.get(*offset..*offset + 4) {
            Some(bytes) => {
                *offset += 4;
                Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize)
            }
            None => return Some((pos, Err(ScriptError::BadOpcode))),
        },
        _ => None,
    };

    if let Some(push_len) = push_len {
        let data = match script_bytes.get(*offset..*offset + push_len) {
            Some(data) => data,
            None => return Some((pos, Err(ScriptError::BadOpcode))),
        };
        if enforce_minimal && !is_minimal_push(opcode, data) {
            return Some((pos, Err(ScriptError::BadOpcode)));
        }
        *offset += push_len;
        let push_bytes: &primitives::script::PushBytes =
            data.try_into().expect("push slice length came from script bytes");
        return Some((pos, Ok(Instruction::PushBytes(push_bytes))));
    }

    Some((pos, Ok(Instruction::Op(Opcode::from(opcode)))))
}

fn decode_op_n(opcode: Option<Opcode>) -> Option<u32> {
    use all::*;

    let op = opcode?;
    let value = op.to_u8();
    if value >= OP_PUSHNUM_1.to_u8() && value <= OP_PUSHNUM_16.to_u8() {
        Some((value - OP_PUSHNUM_1.to_u8() + 1) as u32)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{VERIFY_MINIMALDATA, VERIFY_P2SH, VERIFY_SIGPUSHONLY, VERIFY_WITNESS};
    use alloc::vec;
    use hashes::sha256;
    use primitives::{
        absolute::LockTime,
        opcodes::all,
        script::{
            Builder as BuilderT, PushBytesBuf, ScriptBuf as ScriptBufT, ScriptPubKeyBuf,
            ScriptSigBuf,
        },
        Amount, OutPoint, Sequence, Transaction, TransactionVersion, TxIn, TxOut, Txid, Witness,
    };

    type Builder = BuilderT<()>;
    type ScriptBuf = ScriptBufT<()>;

    fn hex_bytes(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2), "hex string must have an even length");
        s.as_bytes()
            .chunks_exact(2)
            .map(|chunk| {
                let hi = (chunk[0] as char).to_digit(16).expect("valid hex") as u8;
                let lo = (chunk[1] as char).to_digit(16).expect("valid hex") as u8;
                (hi << 4) | lo
            })
            .collect()
    }

    fn dummy_outpoint() -> OutPoint {
        OutPoint { txid: Txid::from_byte_array([1u8; 32]), vout: 0 }
    }

    #[test]
    fn rejects_unknown_flags() {
        let invalid_bit = 1 << 31;
        ScriptFlags::from_bits(invalid_bit).expect_err("invalid flag");
    }

    #[test]
    fn flag_roundtrip_without_implied_bits_is_lossless() {
        let bits = VERIFY_P2SH | VERIFY_SIGPUSHONLY;
        let flags = ScriptFlags::from_bits(bits).unwrap();
        assert_eq!(flags.bits(), bits);
    }

    #[test]
    fn witness_flag_does_not_imply_p2sh() {
        let flags = ScriptFlags::from_bits(VERIFY_WITNESS).unwrap();
        assert_eq!(flags.bits(), VERIFY_WITNESS);
    }

    #[test]
    fn truncated_push_is_error() {
        let script: ScriptBuf = ScriptBuf::from_bytes(vec![0x4c, 0x01]);
        let instructions = collect_instruction_indices(script.as_bytes(), false);
        assert!(instructions.is_err());
    }

    #[test]
    fn sigop_counter_counts_checksig_ops() {
        let script = Builder::new()
            .push_opcode(all::OP_DUP)
            .push_opcode(all::OP_CHECKSIG)
            .push_opcode(all::OP_CHECKSIGVERIFY)
            .into_script();
        assert_eq!(count_sigops_bytes(script.as_bytes(), true).unwrap(), 2);
        assert_eq!(count_sigops_bytes(script.as_bytes(), false).unwrap(), 2);
    }

    #[test]
    fn sigop_counter_handles_multisig_precision() {
        let key1 = PushBytesBuf::try_from(vec![0x02; 33]).unwrap();
        let key2 = PushBytesBuf::try_from(vec![0x03; 33]).unwrap();
        let script = Builder::new()
            .push_opcode(all::OP_PUSHNUM_2)
            .push_slice(key1)
            .push_slice(key2)
            .push_opcode(all::OP_PUSHNUM_2)
            .push_opcode(all::OP_CHECKMULTISIG)
            .into_script();
        assert_eq!(count_sigops_bytes(script.as_bytes(), true).unwrap(), 2);
        assert_eq!(
            count_sigops_bytes(script.as_bytes(), false).unwrap(),
            MAX_PUBKEYS_PER_MULTISIG as u32
        );
    }

    #[test]
    fn sigop_counter_ignores_checksigadd() {
        let script = Builder::new()
            .push_opcode(all::OP_CHECKSIG)
            .push_opcode(all::OP_CHECKSIGADD)
            .push_opcode(all::OP_CHECKSIGVERIFY)
            .into_script();
        assert_eq!(count_sigops_bytes(script.as_bytes(), true).unwrap(), 2);
    }

    #[test]
    fn sigop_counter_stops_at_malformed_pushdata() {
        let malformed: ScriptBuf =
            ScriptBuf::from_bytes(vec![all::OP_CHECKSIG.to_u8(), all::OP_PUSHDATA1.to_u8(), 0x01]);
        assert_eq!(count_sigops_bytes(malformed.as_bytes(), true).unwrap(), 1);
    }

    #[test]
    fn witness_v0_p2wpkh_path_charges_single_sigop() {
        let witness = Witness::from(vec![vec![], vec![0x02; 33]]);
        let tx = Transaction {
            version: TransactionVersion::TWO,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: dummy_outpoint(),
                script_sig: ScriptSigBuf::new(),
                sequence: Sequence::MAX,
                witness,
            }],
            outputs: vec![TxOut { amount: Amount::ZERO, script_pubkey: ScriptPubKeyBuf::new() }],
        };
        let tx_ctx = TransactionContext::new(&tx);
        let spent_script = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        let spend_context = SpendContext::new(spent_script.as_bytes(), None, 0, true);
        let flags = ScriptFlags::from_bits(VERIFY_WITNESS | VERIFY_P2SH).expect("flags");
        let mut interpreter =
            Interpreter::new(&tx_ctx, 0, spend_context, flags).expect("interpreter");

        let program = [0u8; 20];
        let _ =
            interpreter.execute_witness_program(0, &program, &tx_ctx.tx().inputs[0].witness, false);
        assert_eq!(interpreter.sigops, 1);
    }

    #[test]
    fn witness_v0_p2wsh_path_charges_redeem_sigops() {
        let witness_script = Builder::new()
            .push_opcode(all::OP_CHECKSIG)
            .push_opcode(all::OP_CHECKSIGVERIFY)
            .into_script();
        let witness_script_bytes = witness_script.as_bytes().to_vec();
        let witness_program = sha256::Hash::hash(&witness_script_bytes);
        let witness = Witness::from(vec![vec![], vec![0x02; 33], witness_script_bytes]);
        let tx = Transaction {
            version: TransactionVersion::TWO,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: dummy_outpoint(),
                script_sig: ScriptSigBuf::new(),
                sequence: Sequence::MAX,
                witness,
            }],
            outputs: vec![TxOut { amount: Amount::ZERO, script_pubkey: ScriptPubKeyBuf::new() }],
        };
        let tx_ctx = TransactionContext::new(&tx);
        let spent_script = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        let spend_context = SpendContext::new(spent_script.as_bytes(), None, 0, true);
        let flags = ScriptFlags::from_bits(VERIFY_WITNESS | VERIFY_P2SH).expect("flags");
        let mut interpreter =
            Interpreter::new(&tx_ctx, 0, spend_context, flags).expect("interpreter");

        let _ = interpreter.execute_witness_program(
            0,
            &witness_program.to_byte_array(),
            &tx_ctx.tx().inputs[0].witness,
            false,
        );
        assert_eq!(interpreter.sigops, 2);
    }

    #[test]
    fn p2sh_redeem_script_sigops_use_accurate_multisig_count() {
        let tx = Transaction {
            version: TransactionVersion::TWO,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: dummy_outpoint(),
                script_sig: ScriptSigBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut { amount: Amount::ZERO, script_pubkey: ScriptPubKeyBuf::new() }],
        };
        let tx_ctx = TransactionContext::new(&tx);
        let spent_script = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        let spend_context = SpendContext::new(spent_script.as_bytes(), None, 0, true);
        let flags = ScriptFlags::from_bits(VERIFY_P2SH).expect("flags");
        let mut interpreter =
            Interpreter::new(&tx_ctx, 0, spend_context, flags).expect("interpreter");

        let key1 = PushBytesBuf::try_from(vec![0x02; 33]).unwrap();
        let key2 = PushBytesBuf::try_from(vec![0x03; 33]).unwrap();
        let redeem_script = Builder::new()
            .push_opcode(all::OP_PUSHNUM_2)
            .push_slice(key1)
            .push_slice(key2)
            .push_opcode(all::OP_PUSHNUM_2)
            .push_opcode(all::OP_CHECKMULTISIG)
            .into_script();
        interpreter.add_sigops_from_script(redeem_script.as_bytes(), true).expect("sigop counting");
        assert_eq!(interpreter.sigops, 2);
    }

    #[test]
    fn find_and_delete_matches_whole_pushes() {
        let pattern = single_push_script(&[0x02, 0x03]).unwrap();
        let script = Builder::new()
            .push_slice(PushBytesBuf::try_from(vec![0x02, 0x03]).unwrap())
            .push_opcode(all::OP_ADD)
            .push_slice(PushBytesBuf::try_from(vec![0x02, 0x03]).unwrap())
            .into_script();
        let (stripped, removed) = find_and_delete(script.as_bytes(), pattern.as_bytes());
        assert_eq!(removed, 2);
        assert_eq!(stripped, vec![all::OP_ADD.to_u8()]);
    }

    #[test]
    fn signature_pattern_uses_explicit_push_encoding() {
        // Original EvalChecksigPreTapscript searches for `CScript() << vchSig`,
        // which always writes a length prefix. Values that have small-integer
        // opcodes must not be converted to OP_0/OP_1NEGATE/OP_1..OP_16.
        // Minimized from crash-bf928ece.
        assert_eq!(single_push_script(&[]).unwrap().as_bytes(), [0x00]);
        assert_eq!(single_push_script(&[0x00]).unwrap().as_bytes(), [0x01, 0x00]);
        assert_eq!(single_push_script(&[0x81]).unwrap().as_bytes(), [0x01, 0x81]);
        for value in 1..=16u8 {
            assert_eq!(single_push_script(&[value]).unwrap().as_bytes(), [0x01, value]);
        }
        assert_eq!(single_push_script(&[0x04, 0x01]).unwrap().as_bytes(), [0x02, 0x04, 0x01]);

        let script = vec![all::OP_PUSHNUM_4.to_u8(), 0x01, 0x04, all::OP_CHECKSIG.to_u8()];
        let pattern = single_push_script(&[0x04]).unwrap();
        let (stripped, removed) = find_and_delete(&script, pattern.as_bytes());
        assert_eq!(removed, 1);
        assert_eq!(stripped, vec![all::OP_PUSHNUM_4.to_u8(), all::OP_CHECKSIG.to_u8()]);
    }

    #[test]
    fn find_and_delete_does_not_match_sub_slices() {
        let pattern = single_push_script(&[0xaa]).unwrap();
        let script = Builder::new()
            .push_slice(PushBytesBuf::try_from(vec![0xaa, 0xbb]).unwrap())
            .into_script();
        let (stripped, removed) = find_and_delete(script.as_bytes(), pattern.as_bytes());
        assert_eq!(removed, 0);
        assert_eq!(stripped, script.as_bytes());
    }

    #[test]
    fn find_and_delete_matches_only_instruction_boundaries() {
        let pattern = single_push_script(&[]).unwrap();
        let script: ScriptBuf = ScriptBuf::from_bytes(vec![0x02, 0x00, 0x11, 0x00]);
        let (stripped, removed) = find_and_delete(script.as_bytes(), pattern.as_bytes());
        assert_eq!(removed, 1);
        assert_eq!(stripped, vec![0x02, 0x00, 0x11]);
    }

    #[test]
    fn find_and_delete_core_edge_cases_matrix() {
        let check =
            |script: Vec<u8>, pattern: Vec<u8>, expected: Vec<u8>, expected_removed: usize| {
                let (stripped, removed) = find_and_delete(&script, &pattern);
                assert_eq!(removed, expected_removed);
                assert_eq!(stripped, expected);
            };

        check(
            vec![all::OP_PUSHNUM_1.to_u8(), all::OP_PUSHNUM_2.to_u8()],
            vec![],
            vec![all::OP_PUSHNUM_1.to_u8(), all::OP_PUSHNUM_2.to_u8()],
            0,
        );
        check(
            vec![all::OP_PUSHNUM_1.to_u8(), all::OP_PUSHNUM_2.to_u8(), all::OP_PUSHNUM_3.to_u8()],
            vec![all::OP_PUSHNUM_2.to_u8()],
            vec![all::OP_PUSHNUM_1.to_u8(), all::OP_PUSHNUM_3.to_u8()],
            1,
        );
        check(
            vec![
                all::OP_PUSHNUM_3.to_u8(),
                all::OP_PUSHNUM_1.to_u8(),
                all::OP_PUSHNUM_3.to_u8(),
                all::OP_PUSHNUM_3.to_u8(),
                all::OP_PUSHNUM_4.to_u8(),
                all::OP_PUSHNUM_3.to_u8(),
            ],
            vec![all::OP_PUSHNUM_3.to_u8()],
            vec![all::OP_PUSHNUM_1.to_u8(), all::OP_PUSHNUM_4.to_u8()],
            4,
        );
        check(hex_bytes("0302ff03"), hex_bytes("0302ff03"), vec![], 1);
        check(hex_bytes("0302ff030302ff03"), hex_bytes("0302ff03"), vec![], 2);
        check(hex_bytes("0302ff030302ff03"), hex_bytes("02"), hex_bytes("0302ff030302ff03"), 0);
        check(hex_bytes("0302ff030302ff03"), hex_bytes("ff"), hex_bytes("0302ff030302ff03"), 0);
        check(hex_bytes("0302ff030302ff03"), hex_bytes("03"), hex_bytes("02ff0302ff03"), 2);
        check(hex_bytes("02feed5169"), hex_bytes("feed51"), hex_bytes("02feed5169"), 0);
        check(hex_bytes("02feed5169"), hex_bytes("02feed51"), hex_bytes("69"), 1);
        check(hex_bytes("516902feed5169"), hex_bytes("feed51"), hex_bytes("516902feed5169"), 0);
        check(hex_bytes("516902feed5169"), hex_bytes("02feed51"), hex_bytes("516969"), 1);
        check(
            vec![
                all::OP_PUSHBYTES_0.to_u8(),
                all::OP_PUSHBYTES_0.to_u8(),
                all::OP_PUSHNUM_1.to_u8(),
                all::OP_PUSHNUM_1.to_u8(),
            ],
            vec![all::OP_PUSHBYTES_0.to_u8(), all::OP_PUSHNUM_1.to_u8()],
            vec![all::OP_PUSHBYTES_0.to_u8(), all::OP_PUSHNUM_1.to_u8()],
            1,
        );
        check(
            vec![
                all::OP_PUSHBYTES_0.to_u8(),
                all::OP_PUSHBYTES_0.to_u8(),
                all::OP_PUSHNUM_1.to_u8(),
                all::OP_PUSHBYTES_0.to_u8(),
                all::OP_PUSHNUM_1.to_u8(),
                all::OP_PUSHNUM_1.to_u8(),
            ],
            vec![all::OP_PUSHBYTES_0.to_u8(), all::OP_PUSHNUM_1.to_u8()],
            vec![all::OP_PUSHBYTES_0.to_u8(), all::OP_PUSHNUM_1.to_u8()],
            2,
        );
        check(hex_bytes("0003feed"), hex_bytes("03feed"), hex_bytes("00"), 1);
        check(hex_bytes("0003feed"), hex_bytes("00"), hex_bytes("03feed"), 1);
    }

    #[test]
    fn script_identity_depends_on_script_content() {
        let a: ScriptBuf = ScriptBuf::from_bytes(vec![all::OP_PUSHNUM_1.to_u8()]);
        let b: ScriptBuf = ScriptBuf::from_bytes(vec![all::OP_PUSHNUM_2.to_u8()]);
        assert_eq!(a.as_bytes().len(), b.as_bytes().len());
        assert!(ScriptIdentity::new(a.as_script()) != ScriptIdentity::new(b.as_script()));
    }

    #[test]
    fn no_signature_path_needs_no_spent_output_context() {
        let spent_script = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        let tx = Transaction {
            version: TransactionVersion::TWO,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: dummy_outpoint(),
                script_sig: ScriptSigBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                amount: Amount::from_sat(50_000).expect("valid amount"),
                script_pubkey: ScriptPubKeyBuf::new(),
            }],
        };
        let tx_ctx = TransactionContext::new(&tx);
        let spend_context = SpendContext::new(spent_script.as_bytes(), None, 50_000, true);
        let flags = ScriptFlags::from_bits(0).expect("flags");
        let mut interpreter = Interpreter::new(&tx_ctx, 0, spend_context, flags).expect("new");

        interpreter.verify().expect("op_true spend should validate");
    }

    #[test]
    fn repeated_verification_starts_with_empty_execution_state() {
        for (script, valid) in [
            (vec![0x51], true),
            (vec![0x51, 0x6e, 0x75, 0x75, 0x75], false),
            (vec![0x51, 0x63], false),
            (vec![0x51, 0x6b, 0x6a], false),
        ] {
            let tx = Transaction {
                version: TransactionVersion::TWO,
                lock_time: LockTime::ZERO,
                inputs: vec![TxIn {
                    previous_output: dummy_outpoint(),
                    script_sig: ScriptSigBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    amount: Amount::from_sat(1).unwrap(),
                    script_pubkey: ScriptPubKeyBuf::new(),
                }],
            };
            let ctx = TransactionContext::new(&tx);
            let mut interpreter = Interpreter::new(
                &ctx,
                0,
                SpendContext::new(&script, None, 2, true),
                ScriptFlags::from_bits(crate::VERIFY_ALL_TIDECOIN).unwrap(),
            )
            .unwrap();
            let first = interpreter.verify();
            let error = interpreter.last_script_error();
            assert_eq!(first.is_ok(), valid);
            for _ in 0..3 {
                assert_eq!(interpreter.verify(), first, "script={script:?}");
                assert_eq!(interpreter.last_script_error(), error);
            }
        }
    }

    #[test]
    fn scriptnum_overflow_maps_to_unknown() {
        let overflow = vec![0x00, 0x00, 0x00, 0x80, 0x00];
        let err = parse_scriptnum(&overflow, false, SCRIPTNUM_MAX_LEN).unwrap_err();
        assert_eq!(err, ScriptError::Unknown);
    }

    #[test]
    fn scriptnum_minimal_violation_maps_to_unknown() {
        let non_minimal = vec![0x01, 0x00];
        let err = parse_scriptnum(&non_minimal, true, SCRIPTNUM_MAX_LEN).unwrap_err();
        assert_eq!(err, ScriptError::Unknown);
        let ok = parse_scriptnum(&non_minimal, false, SCRIPTNUM_MAX_LEN).unwrap();
        assert_eq!(ok, 1);
    }

    fn verify_legacy(
        script_sig: &[u8],
        script_pubkey: &[u8],
        flags: u32,
    ) -> Result<(), ScriptError> {
        let tx = Transaction {
            version: TransactionVersion::TWO,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: dummy_outpoint(),
                script_sig: ScriptSigBuf::from_bytes(script_sig.to_vec()),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                amount: Amount::from_sat(1).unwrap(),
                script_pubkey: ScriptPubKeyBuf::new(),
            }],
        };
        let ctx = TransactionContext::new(&tx);
        let mut interpreter = Interpreter::new(
            &ctx,
            0,
            SpendContext::new(script_pubkey, None, 2, true),
            ScriptFlags::from_bits(flags).unwrap(),
        )
        .unwrap();
        interpreter.verify().map_err(|_| interpreter.last_script_error())
    }

    #[test]
    fn numeric_opcodes_check_stack_depth_before_scriptnum_errors() {
        let oversized = [0x05, 0, 0, 0, 0, 0];
        let two = [0x01, 0x01, 0x05, 0, 0, 0, 0, 0];
        let minimal_flags = VERIFY_MINIMALDATA;
        for opcode in [0x93, 0x94, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4]
        {
            assert_eq!(
                verify_legacy(&oversized, &[opcode], 0),
                Err(ScriptError::InvalidStackOperation),
                "opcode={opcode:#x}"
            );
            assert_eq!(
                verify_legacy(&two, &[opcode], 0),
                Err(ScriptError::Unknown),
                "opcode={opcode:#x}"
            );
            assert_eq!(
                verify_legacy(&[0x02, 0x01, 0x00], &[opcode], minimal_flags),
                Err(ScriptError::InvalidStackOperation),
                "opcode={opcode:#x}"
            );
        }
        for opcode in [0x79, 0x7a] {
            let mut short = oversized.to_vec();
            short.push(opcode);
            assert_eq!(verify_legacy(&[], &short, 0), Err(ScriptError::InvalidStackOperation));
            let mut deep = two.to_vec();
            deep.push(opcode);
            assert_eq!(verify_legacy(&[], &deep, 0), Err(ScriptError::Unknown));
        }
        assert_eq!(verify_legacy(&two, &[0xa5], 0), Err(ScriptError::InvalidStackOperation));
        assert_eq!(
            verify_legacy(&[0x01, 0x01, 0x01, 0x01, 0x05, 0, 0, 0, 0, 0], &[0xa5], 0),
            Err(ScriptError::Unknown)
        );
    }

    #[test]
    fn script_code_materialization_depends_on_sigversion() {
        let script = Builder::new()
            .push_opcode(all::OP_PUSHNUM_1)
            .push_opcode(all::OP_CODESEPARATOR)
            .push_opcode(all::OP_PUSHNUM_2)
            .push_opcode(all::OP_CODESEPARATOR)
            .into_script();

        let base = Interpreter::materialize_script_code(script.as_script(), 0, true)
            .expect("base script code materializes");
        assert_eq!(base.as_bytes(), &[all::OP_PUSHNUM_1.to_u8(), all::OP_PUSHNUM_2.to_u8()]);

        let witness_v0 = Interpreter::materialize_script_code(script.as_script(), 0, false)
            .expect("witness v0 script code materializes");
        assert_eq!(witness_v0.as_bytes(), script.as_bytes());
    }
}
