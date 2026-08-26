// Vendored from rust-bitcoin-scriptexec (CC0-1.0, Steven Roose and BitVM
// contributors) and extended: covenant deployments (BIP-119 CTV, BIP-348
// CSFS, BIP-347 CAT, BIP-118 APO), tapscript OP_SUCCESSx semantics, initial
// stack limits, and opcode-indexed codeseparator positions.

extern crate alloc;
extern crate core;

use alloc::borrow::Cow;
use core::cmp;

use bitcoin::consensus::Encodable;
use bitcoin::hashes::{hash160, ripemd160, sha1, sha256, sha256d, Hash};
use bitcoin::opcodes::{all::*, Opcode};
use bitcoin::script::{self, Instruction, Instructions, Script, ScriptBuf};
use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::sighash::SighashCache;
use bitcoin::taproot::{self, TapLeafHash};
use bitcoin::transaction::{self, Transaction, TxOut};

#[macro_use]
mod macros;

mod utils;
use utils::ConditionStack;

mod signatures;

mod error;
pub use error::{Error, ExecError};

pub use covenants_core::{parse_opcode, FromAsm, FromAsmError, FromAsmErrorKind};

mod data_structures;
pub use data_structures::Stack;

/// Maximum number of non-push operations per script
const MAX_OPS_PER_SCRIPT: usize = 201;

/// Maximum number of bytes pushable to the stack
const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;

/// Maximum number of values on script interpreter stack
const MAX_STACK_SIZE: usize = 1000;

/// The default maximum size of scriptints.
const DEFAULT_MAX_SCRIPTINT_SIZE: usize = 4;

/// If this flag is set, CTxIn::nSequence is NOT interpreted as a
/// relative lock-time.
/// It skips SequenceLocks() for any input that has it set (BIP 68).
/// It fails OP_CHECKSEQUENCEVERIFY/CheckSequence() for any input that has
/// it set (BIP 112).
const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;

/// How much weight budget is added to the witness size (Tapscript only, see BIP 342).
const VALIDATION_WEIGHT_OFFSET: i64 = 50;

/// Validation weight per passing signature (Tapscript only, see BIP 342).
const VALIDATION_WEIGHT_PER_SIGOP_PASSED: i64 = 50;

// BIP-346 charges a TxHash half of what a passed sigop costs.
const VALIDATION_WEIGHT_PER_TXHASH: i64 = 25;

// Maximum number of public keys per multisig
const _MAX_PUBKEYS_PER_MULTISIG: i64 = 20;

/// Covenant soft-fork deployments, toggled per execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deployments {
    /// BIP-119 OP_CHECKTEMPLATEVERIFY (0xb3, all script contexts).
    pub ctv: bool,
    /// BIP-348 OP_CHECKSIGFROMSTACK (0xcc, tapscript only).
    pub csfs: bool,
    /// BIP-347 OP_CAT (0x7e, tapscript only).
    pub cat: bool,
    /// BIP-118 SIGHASH_ANYPREVOUT public keys (tapscript only).
    pub apo: bool,
    /// BIP-446 OP_TEMPLATEHASH (0xce, tapscript only).
    pub templatehash: bool,
    /// BIP-349 OP_INTERNALKEY (0xcb, tapscript only).
    pub internalkey: bool,
    /// BIP-442 OP_PAIRCOMMIT (0xcd, tapscript only).
    pub paircommit: bool,
    /// BIP-346 OP_TXHASH (0xbd, tapscript only).
    pub txhash: bool,
    /// BIP-443 OP_CHECKCONTRACTVERIFY (0xbb, tapscript only).
    pub ccv: bool,
}

impl Default for Deployments {
    fn default() -> Self {
        Deployments {
            ctv: true,
            csfs: true,
            cat: true,
            apo: true,
            templatehash: true,
            internalkey: true,
            paircommit: true,
            txhash: true,
            ccv: true,
        }
    }
}

/// Used to fine-tune different variables during execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// Require data pushes be minimally encoded.
    pub require_minimal: bool, //TODO(stevenroose) double check all fRequireMinimal usage in Core
    /// Verify OP_CHECKLOCKTIMEVERIFY.
    pub verify_cltv: bool,
    /// Verify OP_CHECKSEQUENCEVERIFY.
    pub verify_csv: bool,
    /// Verify conditionals are minimally encoded.
    pub verify_minimal_if: bool,
    /// Enfore a strict limit of 1000 total stack items.
    pub enforce_stack_limit: bool,

    pub deployments: Deployments,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            require_minimal: true,
            verify_cltv: true,
            verify_csv: true,
            verify_minimal_if: true,
            enforce_stack_limit: true,
            deployments: Deployments::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecCtx {
    Legacy,
    SegwitV0,
    Tapscript,
}

pub struct TxTemplate {
    pub tx: Transaction,
    pub prevouts: Vec<TxOut>,
    pub input_idx: usize,
    pub taproot_annex_scriptleaf: Option<(TapLeafHash, Option<Vec<u8>>)>,
    /// Taproot internal key of the output being spent. Required to verify a
    /// BIP-118 signature against the 1-byte 0x01 public key.
    pub internal_key: Option<XOnlyPublicKey>,
    /// Serialized size of the complete input witness (stack, script, control
    /// block, annex). The BIP-342 validation weight budget derives from this;
    /// when absent, the budget falls back to the initial stack size alone,
    /// which understates the real budget.
    pub full_witness_size: Option<usize>,
    /// Serialized control block of the input being spent. BIP-346 commits to
    /// it, and this tool's transactions carry empty witnesses, so it cannot
    /// be recovered from the input the way a signed transaction allows.
    pub control_block: Option<Vec<u8>>,
    /// Merkle root of the current input's tapscript tree, which BIP-443
    /// substitutes when a taptree of -1 is given.
    pub taptree_root: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionResult {
    pub success: bool,
    pub error: Option<ExecError>,
    pub opcode: Option<Opcode>,
    pub final_stack: Stack,
}

impl ExecutionResult {
    fn from_final_stack(ctx: ExecCtx, final_stack: Stack) -> ExecutionResult {
        ExecutionResult {
            success: match ctx {
                ExecCtx::Legacy => {
                    if final_stack.is_empty() {
                        false
                    } else {
                        !(!script::read_scriptbool(&final_stack.last().unwrap()))
                    }
                }
                ExecCtx::SegwitV0 | ExecCtx::Tapscript => {
                    if final_stack.len() != 1 {
                        false
                    } else {
                        !(!script::read_scriptbool(&final_stack.last().unwrap()))
                    }
                }
            },
            final_stack,
            error: None,
            opcode: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct ExecStats {
    /// The highest number of stack items occurred during execution.
    /// This counts both the stack and the altstack.
    pub max_nb_stack_items: usize,

    /// The number of opcodes executed, plus an additional one
    /// per signature in CHECKMULTISIG.
    pub opcode_count: usize,

    /// The validation weight execution started with.
    pub start_validation_weight: i64,
    /// The current remaining validation weight.
    pub validation_weight: i64,
}

/// Partial execution of a script.
pub struct Exec {
    ctx: ExecCtx,
    opt: Options,
    tx: TxTemplate,
    result: Option<ExecutionResult>,

    sighashcache: SighashCache<Transaction>,
    script: &'static Script,
    instructions: Instructions<'static>,
    current_position: usize,
    cond_stack: ConditionStack,
    stack: Stack,
    altstack: Stack,
    last_codeseparator_pos: Option<u32>,
    // BIP-342 codesep_pos counts decoded opcodes, not bytes; a multi-byte
    // push is one opcode.
    opcode_pos: u32,
    current_opcode_pos: u32,
    // Initially set to the whole script, but updated when
    // OP_CODESEPARATOR is encountered.
    script_code: &'static Script,

    opcode_count: usize,
    validation_weight: i64,

    // BIP-443 amount tracking. The spec initialises these once per
    // transaction and lets every input's script mutate them. This runs one
    // input, so they cover the calls this script makes; a sibling input
    // constraining the same output is not modelled.
    ccv_output_min_amount: Vec<u64>,
    ccv_output_checked_default: Vec<bool>,
    ccv_output_checked_deduct: Vec<bool>,
    ccv_residual_input_amount: u64,
    // Set when an opcode succeeds the input outright rather than failing or
    // continuing, which BIP-443 does for a mode it does not define.
    succeed_now: bool,

    // runtime statistics
    stats: ExecStats,
}

impl std::ops::Drop for Exec {
    fn drop(&mut self) {
        // we need to safely drop the script we allocated
        unsafe {
            let script = core::mem::replace(&mut self.script, Script::from_bytes(&[]));
            let _ = Box::from_raw(script as *const Script as *mut Script);
        }
    }
}

impl Exec {
    pub fn new(
        ctx: ExecCtx,
        opt: Options,
        tx: TxTemplate,
        script: ScriptBuf,
        script_witness: Vec<Vec<u8>>,
    ) -> Result<Exec, Error> {
        if ctx == ExecCtx::Tapscript {
            if tx.taproot_annex_scriptleaf.is_none() {
                return Err(Error::Other("missing taproot tx info in tapscript context"));
            }

            if let Some((_, Some(ref annex))) = tx.taproot_annex_scriptleaf {
                if annex.first() != Some(&taproot::TAPROOT_ANNEX_PREFIX) {
                    return Err(Error::Other("invalid annex: missing prefix"));
                }
            }
        }

        // BIP-342: scan for OP_SUCCESSx before any other validation. A hit
        // makes the script pass unconditionally, even if later bytes fail to
        // decode and even if the initial stack breaks resource limits.
        let mut pre_success: Option<Opcode> = None;
        if ctx == ExecCtx::Tapscript {
            if let TapscriptScan::Success(op) = scan_tapscript_op_success(&script, &opt.deployments)
            {
                pre_success = Some(Opcode::from(op));
            }
        }

        if pre_success.is_none() {
            // We want to make sure the script is valid so we don't have to throw parsing errors
            // while executing.
            let instructions = if opt.require_minimal {
                script.instructions_minimal()
            } else {
                script.instructions()
            };
            if let Some(err) = instructions.clone().find_map(|res| res.err()) {
                return Err(Error::InvalidScript(err));
            }

            if ctx != ExecCtx::Legacy {
                if opt.enforce_stack_limit && script_witness.len() > MAX_STACK_SIZE {
                    return Err(Error::Exec(ExecError::StackSize));
                }
                if script_witness
                    .iter()
                    .any(|e| e.len() > MAX_SCRIPT_ELEMENT_SIZE)
                {
                    return Err(Error::Exec(ExecError::PushSize));
                }
            }
        }

        // *****
        // Make sure there is no more possible exit path after this point!
        // Otherwise we are leaking memory.
        // *****

        // We box alocate the script to get a static Instructions iterator.
        // We will manually drop this allocation in the ops::Drop impl.
        let script = Box::leak(script.into_boxed_script()) as &'static Script;
        let instructions = if opt.require_minimal {
            script.instructions_minimal()
        } else {
            script.instructions()
        };

        let witness_size = match tx.full_witness_size {
            Some(s) => s,
            None => Encodable::consensus_encode(&script_witness, &mut bitcoin::io::sink()).unwrap(),
        };
        let start_validation_weight = VALIDATION_WEIGHT_OFFSET + witness_size as i64;

        let n_outputs = tx.tx.output.len();
        // The residual starts at the whole amount this input is spending.
        let residual = tx
            .prevouts
            .get(tx.input_idx)
            .map(|p| p.value.to_sat())
            .unwrap_or(0);

        let mut ret = Exec {
            ctx,
            result: None,

            sighashcache: SighashCache::new(tx.tx.clone()),
            script,
            instructions,
            current_position: 0,
            cond_stack: ConditionStack::new(),
            //TODO(stevenroose) does this need to be reversed?
            stack: Stack::from_u8_vec(script_witness),
            altstack: Stack::new(),
            opcode_count: 0,
            validation_weight: start_validation_weight,
            ccv_output_min_amount: vec![0; n_outputs],
            ccv_output_checked_default: vec![false; n_outputs],
            ccv_output_checked_deduct: vec![false; n_outputs],
            ccv_residual_input_amount: residual,
            succeed_now: false,
            last_codeseparator_pos: None,
            opcode_pos: 0,
            current_opcode_pos: 0,
            script_code: script,

            opt,
            tx,

            stats: ExecStats {
                start_validation_weight,
                validation_weight: start_validation_weight,
                ..Default::default()
            },
        };
        ret.update_stats();
        if let Some(op) = pre_success {
            ret.result = Some(ExecutionResult {
                success: true,
                error: None,
                opcode: Some(op),
                final_stack: ret.stack.clone(),
            });
        }
        Ok(ret)
    }

    pub fn with_stack(
        ctx: ExecCtx,
        opt: Options,
        tx: TxTemplate,
        script: ScriptBuf,
        script_witness: Vec<Vec<u8>>,
        stack: Stack,
        altstack: Stack,
    ) -> Result<Exec, Error> {
        let mut ret = Self::new(ctx, opt, tx, script, script_witness);
        if let Ok(exec) = &mut ret {
            exec.stack = stack;
            exec.altstack = altstack;
        }
        ret
    }
    //////////////////
    // SOME GETTERS //
    //////////////////

    pub fn result(&self) -> Option<&ExecutionResult> {
        self.result.as_ref()
    }

    pub fn script_position(&self) -> usize {
        self.script.len() - self.instructions.as_script().len()
    }

    pub fn remaining_script(&self) -> &Script {
        let pos = self.script_position();
        &self.script[pos..]
    }

    pub fn stack(&self) -> &Stack {
        &self.stack
    }

    pub fn altstack(&self) -> &Stack {
        &self.altstack
    }

    pub fn stats(&self) -> &ExecStats {
        &self.stats
    }

    pub fn cond_stack(&self) -> &ConditionStack {
        &self.cond_stack
    }

    ///////////////
    // UTILITIES //
    ///////////////

    fn fail(&mut self, err: ExecError) -> Result<(), &ExecutionResult> {
        let res = ExecutionResult {
            success: false,
            error: Some(err),
            opcode: None,
            final_stack: self.stack.clone(),
        };
        self.result = Some(res);
        Err(self.result.as_ref().unwrap())
    }

    fn failop(&mut self, err: ExecError, op: Opcode) -> Result<(), &ExecutionResult> {
        let res = ExecutionResult {
            success: false,
            error: Some(err),
            opcode: Some(op),
            final_stack: self.stack.clone(),
        };
        self.result = Some(res);
        Err(self.result.as_ref().unwrap())
    }

    fn check_lock_time(&mut self, lock_time: i64) -> bool {
        use bitcoin::locktime::absolute::LockTime;
        let lock_time = match lock_time.try_into() {
            Ok(l) => LockTime::from_consensus(l),
            Err(_) => return false,
        };

        match (lock_time, self.tx.tx.lock_time) {
            (LockTime::Blocks(h1), LockTime::Blocks(h2)) if h1 > h2 => return false,
            (LockTime::Seconds(t1), LockTime::Seconds(t2)) if t1 > t2 => return false,
            (LockTime::Blocks(_), LockTime::Seconds(_)) => return false,
            (LockTime::Seconds(_), LockTime::Blocks(_)) => return false,
            _ => {}
        }

        if self.tx.tx.input[self.tx.input_idx].sequence.is_final() {
            return false;
        }

        true
    }

    fn check_sequence(&mut self, sequence: i64) -> bool {
        use bitcoin::locktime::relative::LockTime;

        // Fail if the transaction's version number is not set high
        // enough to trigger BIP 68 rules.
        if self.tx.tx.version < transaction::Version::TWO {
            return false;
        }

        let input_sequence = self.tx.tx.input[self.tx.input_idx].sequence;
        let input_lock_time = match input_sequence.to_relative_lock_time() {
            Some(lt) => lt,
            None => return false,
        };

        let lock_time =
            match LockTime::from_consensus(u32::try_from(sequence).expect("sequence is u32")) {
                Ok(lt) => lt,
                Err(_) => return false,
            };

        match (lock_time, input_lock_time) {
            (LockTime::Blocks(h1), LockTime::Blocks(h2)) if h1 > h2 => return false,
            (LockTime::Time(t1), LockTime::Time(t2)) if t1 > t2 => return false,
            (LockTime::Blocks(_), LockTime::Time(_)) => return false,
            (LockTime::Time(_), LockTime::Blocks(_)) => return false,
            _ => {}
        }

        true
    }

    fn check_sig_pre_tap(&mut self, sig: &[u8], pk: &[u8]) -> Result<bool, ExecError> {
        //TODO(stevenroose) somehow sigops limit should be checked somewhere

        // Drop the signature in pre-segwit scripts but not segwit scripts
        let mut scriptcode = Cow::Borrowed(self.script_code.as_bytes());
        if self.ctx == ExecCtx::Legacy {
            let mut i = 0;
            while i < scriptcode.len() - sig.len() {
                if &scriptcode[i..i + sig.len()] == sig {
                    scriptcode.to_mut().drain(i..i + sig.len());
                } else {
                    i += 1;
                }
            }
        }

        //TODO(stevenroose) the signature and pk encoding checks we use here
        // might not be exactly identical to Core's

        if self.ctx == ExecCtx::SegwitV0 && pk.len() == 65 {
            return Err(ExecError::WitnessPubkeyType);
        }

        Ok(self.check_sig_ecdsa(sig, pk, &scriptcode))
    }

    fn check_sig_tap(&mut self, sig: &[u8], pk: &[u8]) -> Result<bool, ExecError> {
        if !sig.is_empty() {
            self.validation_weight -= VALIDATION_WEIGHT_PER_SIGOP_PASSED;
            if self.validation_weight < 0 {
                return Err(ExecError::TapscriptValidationWeight);
            }
        }

        if pk.is_empty() {
            Err(ExecError::PubkeyType)
        } else if pk.len() == 32 {
            if !sig.is_empty() {
                self.check_sig_schnorr(sig, pk)?;
                Ok(true)
            } else {
                Ok(false)
            }
        } else if self.opt.deployments.apo && pk[0] == 0x01 && (pk.len() == 1 || pk.len() == 33) {
            if !sig.is_empty() {
                self.check_sig_schnorr_apo(sig, pk)?;
                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            // BIP-342 unknown public key type: verification succeeds for a
            // non-empty signature, but an empty signature still pushes false.
            Ok(!sig.is_empty())
        }
    }

    fn check_sig(&mut self, sig: &[u8], pk: &[u8]) -> Result<bool, ExecError> {
        match self.ctx {
            ExecCtx::Legacy | ExecCtx::SegwitV0 => self.check_sig_pre_tap(sig, pk),
            ExecCtx::Tapscript => self.check_sig_tap(sig, pk),
        }
    }

    ///////////////
    // EXECUTION //
    ///////////////

    /// Returns true when execution is done.
    pub fn exec_next(&mut self) -> Result<(), &ExecutionResult> {
        if let Some(ref res) = self.result {
            return Err(res);
        }

        self.current_position = self.script.len() - self.instructions.as_script().len();
        let instruction = match self.instructions.next() {
            Some(Ok(i)) => i,
            None => {
                if !self.cond_stack.is_empty() {
                    return self.fail(ExecError::UnbalancedConditional);
                }
                let res = ExecutionResult::from_final_stack(self.ctx, self.stack.clone());
                self.result = Some(res);
                return Err(self.result.as_ref().unwrap());
            }
            Some(Err(_)) => unreachable!("we checked the script beforehand"),
        };

        self.current_opcode_pos = self.opcode_pos;
        self.opcode_pos += 1;

        let exec = self.cond_stack.all_true();
        match instruction {
            Instruction::PushBytes(p) => {
                if p.len() > MAX_SCRIPT_ELEMENT_SIZE {
                    return self.fail(ExecError::PushSize);
                }
                if exec {
                    self.stack.pushstr(p.as_bytes());
                }
            }
            Instruction::Op(op) => {
                // Some things we do even when we're not executing.

                // Note how OP_RESERVED does not count towards the opcode limit.
                if (self.ctx == ExecCtx::Legacy || self.ctx == ExecCtx::SegwitV0)
                    && op.to_u8() > OP_PUSHNUM_16.to_u8()
                {
                    self.opcode_count += 1;
                    if self.opcode_count > MAX_OPS_PER_SCRIPT {
                        return self.fail(ExecError::OpCount);
                    }
                }

                match op {
                    OP_CAT if self.ctx != ExecCtx::Tapscript => {
                        return self.failop(ExecError::DisabledOpcode, op);
                    }
                    OP_SUBSTR | OP_LEFT | OP_RIGHT | OP_INVERT | OP_AND | OP_OR | OP_XOR
                    | OP_2MUL | OP_2DIV | OP_MUL | OP_DIV | OP_MOD | OP_LSHIFT | OP_RSHIFT => {
                        return self.failop(ExecError::DisabledOpcode, op);
                    }
                    OP_RESERVED => {
                        return self.failop(ExecError::Debug, op);
                    }

                    _ => {}
                }

                if exec || (op.to_u8() >= OP_IF.to_u8() && op.to_u8() <= OP_ENDIF.to_u8()) {
                    if let Err(err) = self.exec_opcode(op) {
                        return self.failop(err, op);
                    }
                    if self.succeed_now {
                        self.result = Some(ExecutionResult {
                            success: true,
                            error: None,
                            opcode: Some(op),
                            final_stack: self.stack.clone(),
                        });
                        return Err(self.result.as_ref().unwrap());
                    }
                }
            }
        }

        self.update_stats();
        Ok(())
    }

    fn exec_opcode(&mut self, op: Opcode) -> Result<(), ExecError> {
        let exec = self.cond_stack.all_true();

        // Remember to leave stack intact until all errors have occurred.
        match op {
            //
            // Push value
            OP_PUSHNUM_NEG1 | OP_PUSHNUM_1 | OP_PUSHNUM_2 | OP_PUSHNUM_3 | OP_PUSHNUM_4
            | OP_PUSHNUM_5 | OP_PUSHNUM_6 | OP_PUSHNUM_7 | OP_PUSHNUM_8 | OP_PUSHNUM_9
            | OP_PUSHNUM_10 | OP_PUSHNUM_11 | OP_PUSHNUM_12 | OP_PUSHNUM_13 | OP_PUSHNUM_14
            | OP_PUSHNUM_15 | OP_PUSHNUM_16 => {
                let n = op.to_u8() - (OP_PUSHNUM_1.to_u8() - 2);
                self.stack.pushnum((n as i64) - 1);
            }

            //
            // Control
            OP_NOP => {}

            OP_CLTV if self.opt.verify_cltv => {
                let top = self.stack.topstr(-1)?;

                // Note that elsewhere numeric opcodes are limited to
                // operands in the range -2**31+1 to 2**31-1, however it is
                // legal for opcodes to produce results exceeding that
                // range. This limitation is implemented by CScriptNum's
                // default 4-byte limit.
                //
                // If we kept to that limit we'd have a year 2038 problem,
                // even though the nLockTime field in transactions
                // themselves is uint32 which only becomes meaningless
                // after the year 2106.
                //
                // Thus as a special case we tell CScriptNum to accept up
                // to 5-byte bignums, which are good until 2**39-1, well
                // beyond the 2**32-1 limit of the nLockTime field itself.
                let n = read_scriptint(&top, 5, self.opt.require_minimal)?;

                if n < 0 {
                    return Err(ExecError::NegativeLocktime);
                }

                if !self.check_lock_time(n) {
                    return Err(ExecError::UnsatisfiedLocktime);
                }
            }
            OP_CLTV => {} // otherwise nop

            OP_CSV if self.opt.verify_csv => {
                let top = self.stack.topstr(-1)?;

                // nSequence, like nLockTime, is a 32-bit unsigned integer
                // field. See the comment in CHECKLOCKTIMEVERIFY regarding
                // 5-byte numeric operands.
                let n = read_scriptint(&top, 5, self.opt.require_minimal)?;

                if n < 0 {
                    return Err(ExecError::NegativeLocktime);
                }

                //TODO(stevenroose) check this logic
                //TODO(stevenroose) check if this cast is ok
                if n & SEQUENCE_LOCKTIME_DISABLE_FLAG as i64 == 0 && !self.check_sequence(n) {
                    return Err(ExecError::UnsatisfiedLocktime);
                }
            }
            OP_CSV => {} // otherwise nop

            OP_NOP4 if self.opt.deployments.ctv => {
                // BIP-119: a non-32-byte argument is a NOP for upgradability,
                // and the argument stays on the stack either way.
                let top = self.stack.topstr(-1)?;
                if top.len() == 32 {
                    let hash = covenants_core::ctv::default_template_hash(
                        &self.tx.tx,
                        self.tx.input_idx as u32,
                    );
                    if top[..] != hash {
                        return Err(ExecError::TemplateMismatch);
                    }
                }
            }

            OP_NOP1 | OP_NOP4 | OP_NOP5 | OP_NOP6 | OP_NOP7 | OP_NOP8 | OP_NOP9 | OP_NOP10 => {
                // nops
            }

            OP_IF | OP_NOTIF => {
                if exec {
                    let top = self.stack.topstr(-1)?;

                    // Tapscript requires minimal IF/NOTIF inputs as a consensus rule.
                    if self.ctx == ExecCtx::Tapscript {
                        // The input argument to the OP_IF and OP_NOTIF opcodes must be either
                        // exactly 0 (the empty vector) or exactly 1 (the one-byte vector with value 1).
                        if top.len() > 1 || (top.len() == 1 && top[0] != 1) {
                            return Err(ExecError::TapscriptMinimalIf);
                        }
                    }
                    // Under segwit v0 only enabled as policy.
                    if self.opt.verify_minimal_if
                        && self.ctx == ExecCtx::SegwitV0
                        && (top.len() > 1 || (top.len() == 1 && top[0] != 1))
                    {
                        return Err(ExecError::TapscriptMinimalIf);
                    }
                    let b = if op == OP_NOTIF {
                        !script::read_scriptbool(&top)
                    } else {
                        script::read_scriptbool(&top)
                    };
                    self.stack.pop().unwrap();
                    self.cond_stack.push(b);
                } else {
                    self.cond_stack.push(false);
                }
            }

            OP_ELSE => {
                if !self.cond_stack.toggle_top() {
                    return Err(ExecError::UnbalancedConditional);
                }
            }

            OP_ENDIF => {
                if !self.cond_stack.pop() {
                    return Err(ExecError::UnbalancedConditional);
                }
            }

            OP_VERIFY => {
                let top = self.stack.topstr(-1)?;

                if !script::read_scriptbool(&top) {
                    return Err(ExecError::Verify);
                } else {
                    self.stack.pop().unwrap();
                }
            }

            OP_RETURN => return Err(ExecError::OpReturn),

            //
            // Stack operations
            OP_TOALTSTACK => {
                let top = self.stack.pop().ok_or(ExecError::InvalidStackOperation)?;
                self.altstack.push(top);
            }

            OP_FROMALTSTACK => {
                let top = self
                    .altstack
                    .pop()
                    .ok_or(ExecError::InvalidStackOperation)?;
                self.stack.push(top);
            }

            OP_2DROP => {
                // (x1 x2 -- )
                self.stack.needn(2)?;
                self.stack.popn(2).unwrap();
            }

            OP_2DUP => {
                // (x1 x2 -- x1 x2 x1 x2)
                let x1 = self.stack.top(-2)?.clone();
                let x2 = self.stack.top(-1)?.clone();
                self.stack.push(x1);
                self.stack.push(x2);
            }

            OP_3DUP => {
                // (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
                let x1 = self.stack.top(-3)?.clone();
                let x2 = self.stack.top(-2)?.clone();
                let x3 = self.stack.top(-1)?.clone();
                self.stack.push(x1);
                self.stack.push(x2);
                self.stack.push(x3);
            }

            OP_2OVER => {
                // (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
                self.stack.needn(4)?;
                let x1 = self.stack.top(-4)?.clone();
                let x2 = self.stack.top(-3)?.clone();
                self.stack.push(x1);
                self.stack.push(x2);
            }

            OP_2ROT => {
                // (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
                self.stack.needn(6)?;
                let x6 = self.stack.pop().unwrap();
                let x5 = self.stack.pop().unwrap();
                let x4 = self.stack.pop().unwrap();
                let x3 = self.stack.pop().unwrap();
                let x2 = self.stack.pop().unwrap();
                let x1 = self.stack.pop().unwrap();
                self.stack.push(x3);
                self.stack.push(x4);
                self.stack.push(x5);
                self.stack.push(x6);
                self.stack.push(x1);
                self.stack.push(x2);
            }

            OP_2SWAP => {
                // (x1 x2 x3 x4 -- x3 x4 x1 x2)
                self.stack.needn(4)?;
                let x4 = self.stack.pop().unwrap();
                let x3 = self.stack.pop().unwrap();
                let x2 = self.stack.pop().unwrap();
                let x1 = self.stack.pop().unwrap();
                self.stack.push(x3);
                self.stack.push(x4);
                self.stack.push(x1);
                self.stack.push(x2);
            }

            OP_IFDUP => {
                // (x - 0 | x x)
                let top = self.stack.topstr(-1)?;
                if script::read_scriptbool(&top) {
                    self.stack.push(self.stack.top(-1)?.clone());
                }
            }

            OP_DEPTH => {
                // -- stacksize
                self.stack.pushnum(self.stack.len() as i64);
            }

            OP_DROP => {
                // (x -- )
                if self.stack.pop().is_none() {
                    return Err(ExecError::InvalidStackOperation);
                }
            }

            OP_DUP => {
                // (x -- x x)
                let top = self.stack.top(-1)?.clone();
                self.stack.push(top);
            }

            OP_NIP => {
                // (x1 x2 -- x2)
                self.stack.needn(2)?;
                let x2 = self.stack.pop().unwrap();
                self.stack.pop().unwrap();
                self.stack.push(x2);
            }

            OP_OVER => {
                // (x1 x2 -- x1 x2 x1)
                let under_top = self.stack.top(-2)?.clone();
                self.stack.push(under_top);
            }

            OP_PICK | OP_ROLL => {
                // (xn ... x2 x1 x0 n - xn ... x2 x1 x0 xn)
                // (xn ... x2 x1 x0 n - ... x2 x1 x0 xn)
                let x = self.stack.topnum(-1, self.opt.require_minimal)?;
                if x < 0 || x >= self.stack.len() as i64 {
                    return Err(ExecError::InvalidStackOperation);
                }
                self.stack.pop().unwrap();
                let elem = self.stack.top(-x as isize - 1).unwrap().clone();
                if op == OP_ROLL {
                    self.stack.remove(self.stack.len() - x as usize - 1);
                }
                self.stack.push(elem);
            }

            OP_ROT => {
                // (x1 x2 x3 -- x2 x3 x1)
                self.stack.needn(3)?;
                let x3 = self.stack.pop().unwrap();
                let x2 = self.stack.pop().unwrap();
                let x1 = self.stack.pop().unwrap();
                self.stack.push(x2);
                self.stack.push(x3);
                self.stack.push(x1);
            }

            OP_SWAP => {
                // (x1 x2 -- x2 x1)
                self.stack.needn(2)?;
                let x2 = self.stack.pop().unwrap();
                let x1 = self.stack.pop().unwrap();
                self.stack.push(x2);
                self.stack.push(x1);
            }

            OP_TUCK => {
                // (x1 x2 -- x2 x1 x2)
                self.stack.needn(2)?;
                let x2 = self.stack.pop().unwrap();
                let x1 = self.stack.pop().unwrap();
                self.stack.push(x2.clone());
                self.stack.push(x1);
                self.stack.push(x2);
            }

            OP_CAT if self.opt.deployments.cat && self.ctx == ExecCtx::Tapscript => {
                // (x1 x2 -- x1|x2)
                self.stack.needn(2)?;
                let x2 = self.stack.popstr().unwrap();
                let x1 = self.stack.popstr().unwrap();
                let ret: Vec<u8> = x1.into_iter().chain(x2).collect();
                if ret.len() > MAX_SCRIPT_ELEMENT_SIZE {
                    return Err(ExecError::PushSize);
                }
                self.stack.pushstr(&ret);
            }

            OP_SIZE => {
                // (in -- in size)
                let top = self.stack.topstr(-1)?;
                self.stack.pushnum(top.len() as i64);
            }

            //
            // Bitwise logic
            OP_EQUAL | OP_EQUALVERIFY => {
                // (x1 x2 - bool)
                self.stack.needn(2)?;
                let x2 = self.stack.popstr().unwrap();
                let x1 = self.stack.popstr().unwrap();
                let equal = x1 == x2;
                if op == OP_EQUALVERIFY && !equal {
                    return Err(ExecError::EqualVerify);
                }
                if op == OP_EQUAL {
                    let item = if equal { 1 } else { 0 };
                    self.stack.pushnum(item);
                }
            }

            //
            // Numeric
            OP_1ADD | OP_1SUB | OP_NEGATE | OP_ABS | OP_NOT | OP_0NOTEQUAL => {
                // (in -- out)
                let x = self.stack.topnum(-1, self.opt.require_minimal)?;
                let res = match op {
                    OP_1ADD => x
                        .checked_add(1)
                        .ok_or(ExecError::ScriptIntNumericOverflow)?,
                    OP_1SUB => x
                        .checked_sub(1)
                        .ok_or(ExecError::ScriptIntNumericOverflow)?,
                    OP_NEGATE => x.checked_neg().ok_or(ExecError::ScriptIntNumericOverflow)?,
                    OP_ABS => x.abs(),
                    OP_NOT => (x == 0) as i64,
                    OP_0NOTEQUAL => (x != 0) as i64,
                    _ => unreachable!(),
                };
                self.stack.pop().unwrap();
                self.stack.pushnum(res);
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
                // (x1 x2 -- out)
                let x1 = self.stack.topnum(-2, self.opt.require_minimal)?;
                let x2 = self.stack.topnum(-1, self.opt.require_minimal)?;
                let res = match op {
                    OP_ADD => x1
                        .checked_add(x2)
                        .ok_or(ExecError::ScriptIntNumericOverflow)?,
                    OP_SUB => x1
                        .checked_sub(x2)
                        .ok_or(ExecError::ScriptIntNumericOverflow)?,
                    OP_BOOLAND => (x1 != 0 && x2 != 0) as i64,
                    OP_BOOLOR => (x1 != 0 || x2 != 0) as i64,
                    OP_NUMEQUAL => (x1 == x2) as i64,
                    OP_NUMEQUALVERIFY => (x1 == x2) as i64,
                    OP_NUMNOTEQUAL => (x1 != x2) as i64,
                    OP_LESSTHAN => (x1 < x2) as i64,
                    OP_GREATERTHAN => (x1 > x2) as i64,
                    OP_LESSTHANOREQUAL => (x1 <= x2) as i64,
                    OP_GREATERTHANOREQUAL => (x1 >= x2) as i64,
                    OP_MIN => cmp::min(x1, x2),
                    OP_MAX => cmp::max(x1, x2),
                    _ => unreachable!(),
                };
                if op == OP_NUMEQUALVERIFY && res == 0 {
                    return Err(ExecError::NumEqualVerify);
                }
                self.stack.popn(2).unwrap();
                if op != OP_NUMEQUALVERIFY {
                    self.stack.pushnum(res);
                }
            }

            OP_WITHIN => {
                // (x min max -- out)
                let x1 = self.stack.topnum(-3, self.opt.require_minimal)?;
                let x2 = self.stack.topnum(-2, self.opt.require_minimal)?;
                let x3 = self.stack.topnum(-1, self.opt.require_minimal)?;
                self.stack.popn(3).unwrap();
                let res = x2 <= x1 && x1 < x3;
                let item = if res { 1 } else { 0 };
                self.stack.pushnum(item);
            }

            //
            // Crypto

            // (in -- hash)
            OP_RIPEMD160 => {
                let top = self.stack.popstr()?;
                self.stack
                    .pushstr(ripemd160::Hash::hash(&top[..]).to_byte_array().as_ref());
            }
            OP_SHA1 => {
                let top = self.stack.popstr()?;
                self.stack
                    .pushstr(sha1::Hash::hash(&top[..]).to_byte_array().as_ref());
            }
            OP_SHA256 => {
                let top = self.stack.popstr()?;
                self.stack
                    .pushstr(sha256::Hash::hash(&top[..]).to_byte_array().as_ref());
            }
            OP_HASH160 => {
                let top = self.stack.popstr()?;
                self.stack
                    .pushstr(hash160::Hash::hash(&top[..]).to_byte_array().as_ref());
            }
            OP_HASH256 => {
                let top = self.stack.popstr()?;
                self.stack
                    .pushstr(sha256d::Hash::hash(&top[..]).to_byte_array().as_ref());
            }

            OP_CODESEPARATOR => {
                // Tapscript sighashes commit to the opcode index (BIP-342);
                // the legacy scriptcode update works on byte offsets.
                self.last_codeseparator_pos = Some(self.current_opcode_pos);
                self.script_code = &self.script[self.current_position..];
            }

            OP_CHECKSIG | OP_CHECKSIGVERIFY => {
                let sig = self.stack.topstr(-2)?.clone();
                let pk = self.stack.topstr(-1)?.clone();
                let res = self.check_sig(&sig, &pk)?;
                self.stack.popn(2).unwrap();
                if op == OP_CHECKSIGVERIFY && !res {
                    return Err(ExecError::CheckSigVerify);
                }
                if op == OP_CHECKSIG {
                    let ret = if res { 1 } else { 0 };
                    self.stack.pushnum(ret);
                }
            }

            OP_CHECKSIGADD => {
                if self.ctx == ExecCtx::Legacy || self.ctx == ExecCtx::SegwitV0 {
                    return Err(ExecError::BadOpcode);
                }
                let sig = self.stack.topstr(-3)?.clone();
                let mut n = self.stack.topnum(-2, self.opt.require_minimal)?;
                let pk = self.stack.topstr(-1)?.clone();
                let res = self.check_sig(&sig, &pk)?;
                self.stack.popn(3).unwrap();
                if res {
                    n += 1;
                }
                self.stack.pushnum(n);
            }

            OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY => {
                if self.ctx == ExecCtx::Tapscript {
                    return Err(ExecError::TapscriptCheckMultiSig);
                }
                return Err(ExecError::BadOpcode);
            }

            // BIP-446. Pushes the template hash of the spending
            // transaction: everything about it except which coins it
            // spends. Pushing rather than verifying is what lets a
            // signature be checked against it, which is BIP-448's
            // rebindable signature.
            OP_RETURN_206
                if self.ctx == ExecCtx::Tapscript && self.opt.deployments.templatehash =>
            {
                let annex = match &self.tx.taproot_annex_scriptleaf {
                    Some((_, annex)) => annex.as_deref(),
                    None => None,
                };
                let hash = covenants_core::templatehash::template_hash(
                    &self.tx.tx,
                    self.tx.input_idx,
                    annex,
                )
                .map_err(|_| ExecError::TemplateHashInputIndex)?;
                self.stack.pushstr(&hash);
            }

            // BIP-442. Commits to two elements at once. Each is prefixed
            // with its own length, so a pair cannot be forged by moving the
            // boundary between them.
            OP_RETURN_205 if self.ctx == ExecCtx::Tapscript && self.opt.deployments.paircommit => {
                // (x1 x2 -- pc)
                self.stack.needn(2)?;
                let x2 = self.stack.popstr().unwrap();
                let x1 = self.stack.popstr().unwrap();
                let pc = covenants_core::paircommit::pair_commit(&x1, &x2);
                self.stack.pushstr(&pc);
            }

            // BIP-346. Hashes the fields the selector names. The empty
            // selector covers what CTV covers, so this generalises it, and
            // paired with CSFS the script defines its own signature hash.
            OP_RETURN_189 if self.ctx == ExecCtx::Tapscript && self.opt.deployments.txhash => {
                // (txfs -- txhash)
                self.stack.needn(1)?;
                // Each hash costs the same budget a passed sigop does, halved,
                // because the fields it covers are all cacheable.
                self.validation_weight -= VALIDATION_WEIGHT_PER_TXHASH;
                if self.validation_weight < 0 {
                    return Err(ExecError::TapscriptValidationWeight);
                }
                let txfs = self.stack.popstr().unwrap();
                let annex = self
                    .tx
                    .taproot_annex_scriptleaf
                    .as_ref()
                    .and_then(|(_, annex)| annex.as_deref());
                let current = covenants_core::txhash::CurrentInput {
                    control_block: self.tx.control_block.as_deref(),
                    // The leaf being executed is the spent script; a leaf is
                    // always version 0xc0 here, since no other is defined.
                    leaf: Some((0xc0, self.script)),
                    annex,
                    last_codeseparator_pos: self.last_codeseparator_pos,
                };
                let hash = covenants_core::txhash::tx_hash(
                    &txfs,
                    &self.tx.tx,
                    &self.tx.prevouts,
                    self.tx.input_idx,
                    &current,
                )
                .map_err(ExecError::TxFieldSelector)?;
                self.stack.pushstr(&hash);
            }

            // BIP-443. Checks that an input or output of this transaction is
            // the contract the script names: a naked key tweaked by data,
            // then taptweaked by a tree. Stack, bottom to top, is
            // <data> <index> <pk> <taptree> <mode>, and all five are dropped.
            OP_RETURN_187 if self.ctx == ExecCtx::Tapscript && self.opt.deployments.ccv => {
                use covenants_core::ccv::{self, CcvMode};

                self.stack.needn(5)?;
                let mode_num = self.stack.topnum(-1, self.opt.require_minimal)?;
                let taptree = self.stack.topstr(-2)?;
                let pk = self.stack.topstr(-3)?;
                let index_raw = self.stack.topstr(-4)?;
                let data = self.stack.topstr(-5)?;

                // An undefined mode is left for a later deployment to give
                // meaning to, and succeeds the input outright.
                let Some(mode) = CcvMode::from_i64(mode_num) else {
                    self.succeed_now = true;
                    return Ok(());
                };

                let index = if index_raw.is_empty() {
                    0i64
                } else {
                    read_scriptint(
                        &index_raw,
                        DEFAULT_MAX_SCRIPTINT_SIZE,
                        self.opt.require_minimal,
                    )?
                };
                let index = if index == -1 {
                    self.tx.input_idx as i64
                } else if index >= 0 {
                    index
                } else {
                    return Err(ExecError::CcvParameter);
                };

                let target_script = if mode.targets_input() {
                    let i = usize::try_from(index).map_err(|_| ExecError::CcvIndexOutOfBounds)?;
                    &self
                        .tx
                        .prevouts
                        .get(i)
                        .ok_or(ExecError::CcvIndexOutOfBounds)?
                        .script_pubkey
                } else {
                    let i = usize::try_from(index).map_err(|_| ExecError::CcvIndexOutOfBounds)?;
                    &self
                        .tx
                        .tx
                        .output
                        .get(i)
                        .ok_or(ExecError::CcvIndexOutOfBounds)?
                        .script_pubkey
                };

                // -1 means the current input's tree; empty means no taptweak
                // at all, which is a different thing from an empty tree.
                let taptree = if taptree.is_empty() {
                    None
                } else if taptree.len() == 32 {
                    Some(<[u8; 32]>::try_from(&taptree[..]).unwrap())
                } else if read_scriptint(&taptree, DEFAULT_MAX_SCRIPTINT_SIZE, false) == Ok(-1) {
                    Some(self.tx.taptree_root.ok_or(ExecError::CcvTaptreeMissing)?)
                } else {
                    return Err(ExecError::CcvParameter);
                };

                // Empty means the NUMS point, so the contract has no key path.
                let naked = if pk.is_empty() {
                    covenants_core::taproot::nums_internal_key()
                } else if pk.len() == 32 {
                    XOnlyPublicKey::from_slice(&pk).map_err(|_| ExecError::CcvParameter)?
                } else if read_scriptint(&pk, DEFAULT_MAX_SCRIPTINT_SIZE, false) == Ok(-1) {
                    self.tx
                        .internal_key
                        .ok_or(ExecError::CcvInternalKeyMissing)?
                } else {
                    return Err(ExecError::CcvParameter);
                };

                let expected = ccv::expected_script_pubkey(&naked, &data, taptree)
                    .map_err(ExecError::CcvKey)?;
                if target_script.as_bytes() != expected.as_bytes() {
                    return Err(ExecError::CcvMismatch);
                }

                if !mode.targets_input() {
                    let i = index as usize;
                    let out_amount = self.tx.tx.output[i].value.to_sat();
                    match mode {
                        CcvMode::CheckOutput => {
                            if self.ccv_output_checked_deduct[i] {
                                return Err(ExecError::CcvAmount);
                            }
                            self.ccv_output_min_amount[i] = self.ccv_output_min_amount[i]
                                .saturating_add(self.ccv_residual_input_amount);
                            self.ccv_residual_input_amount = 0;
                            if out_amount < self.ccv_output_min_amount[i] {
                                return Err(ExecError::CcvAmount);
                            }
                            self.ccv_output_checked_default[i] = true;
                        }
                        CcvMode::CheckOutputDeductAmount => {
                            if self.ccv_residual_input_amount < out_amount {
                                return Err(ExecError::CcvAmount);
                            }
                            if self.ccv_output_checked_default[i]
                                || self.ccv_output_checked_deduct[i]
                            {
                                return Err(ExecError::CcvAmount);
                            }
                            self.ccv_residual_input_amount -= out_amount;
                            self.ccv_output_checked_deduct[i] = true;
                        }
                        CcvMode::CheckOutputIgnoreAmount | CcvMode::CheckInput => {}
                    }
                }

                self.stack.popn(5).unwrap();
            }

            // BIP-349. Pushes the taproot internal key, so a leaf can name
            // the key its own output was built from without repeating it.
            OP_RETURN_203 if self.ctx == ExecCtx::Tapscript && self.opt.deployments.internalkey => {
                let key = self.tx.internal_key.ok_or(ExecError::InternalKeyMissing)?;
                self.stack.pushstr(&key.serialize());
            }

            OP_RETURN_204 if self.ctx == ExecCtx::Tapscript && self.opt.deployments.csfs => {
                // BIP-348. Stack: <sig> <msg> <pk>, message not pre-hashed.
                let pk = self.stack.topstr(-1)?;
                let msg = self.stack.topstr(-2)?;
                let sig = self.stack.topstr(-3)?;

                if !sig.is_empty() {
                    self.validation_weight -= VALIDATION_WEIGHT_PER_SIGOP_PASSED;
                    if self.validation_weight < 0 {
                        return Err(ExecError::TapscriptValidationWeight);
                    }
                }
                if pk.is_empty() {
                    return Err(ExecError::PubkeyType);
                }
                if pk.len() == 32 && !sig.is_empty() {
                    self.check_csfs_schnorr(&sig, &msg, &pk)?;
                }

                self.stack.popn(3).unwrap();
                if sig.is_empty() {
                    self.stack.pushstr(&[]);
                } else {
                    self.stack.pushnum(1);
                }
            }

            // remainder
            _ => return Err(ExecError::BadOpcode),
        }

        if self.opt.enforce_stack_limit && self.stack.len() + self.altstack.len() > MAX_STACK_SIZE {
            return Err(ExecError::StackSize);
        }

        Ok(())
    }

    ////////////////
    // STATISTICS //
    ////////////////

    fn update_stats(&mut self) {
        let stack_items = self.stack.len() + self.altstack.len();
        self.stats.max_nb_stack_items = cmp::max(self.stats.max_nb_stack_items, stack_items);

        self.stats.opcode_count = self.opcode_count;
        self.stats.validation_weight = self.validation_weight;
    }
}

/// Decodes an interger in script format with flexible size limit.
///
/// Note that in the majority of cases, you will want to use either
/// [`read_scriptint`] or [`read_scriptint_non_minimal`] instead.
///
/// Panics if max_size exceeds 8.
pub fn read_scriptint_size(v: &[u8], max_size: usize, minimal: bool) -> Result<i64, script::Error> {
    assert!(max_size <= 8);

    if v.len() > max_size {
        return Err(script::Error::NumericOverflow);
    }

    if v.is_empty() {
        return Ok(0);
    }

    if minimal {
        let last = match v.last() {
            Some(last) => last,
            None => return Ok(0),
        };
        // Comment and code copied from Bitcoin Core:
        // https://github.com/bitcoin/bitcoin/blob/447f50e4aed9a8b1d80e1891cda85801aeb80b4e/src/script/script.h#L247-L262
        // If the most-significant-byte - excluding the sign bit - is zero
        // then we're not minimal. Note how this test also rejects the
        // negative-zero encoding, 0x80.
        if (*last & 0x7f) == 0 {
            // One exception: if there's more than one byte and the most
            // significant bit of the second-most-significant-byte is set
            // it would conflict with the sign bit. An example of this case
            // is +-255, which encode to 0xff00 and 0xff80 respectively.
            // (big-endian).
            if v.len() <= 1 || (v[v.len() - 2] & 0x80) == 0 {
                return Err(script::Error::NonMinimalPush);
            }
        }
    }

    Ok(scriptint_parse(v))
}

/// Caller to guarantee that `v` is not empty.
fn scriptint_parse(v: &[u8]) -> i64 {
    let (mut ret, sh) = v
        .iter()
        .fold((0, 0), |(acc, sh), n| (acc + ((*n as i64) << sh), sh + 8));
    if v[v.len() - 1] & 0x80 != 0 {
        ret &= (1 << (sh - 1)) - 1;
        ret = -ret;
    }
    ret
}

fn read_scriptint(item: &[u8], size: usize, minimal: bool) -> Result<i64, ExecError> {
    read_scriptint_size(item, size, minimal).map_err(|e| match e {
        script::Error::NonMinimalPush => ExecError::MinimalData,
        // only possible if size is 4 or lower
        script::Error::NumericOverflow => ExecError::ScriptIntNumericOverflow,
        // should never happen
        _ => unreachable!(),
    })
}

/// Decodes an integer in script format without non-minimal error.
///
/// The overflow error for slices over 4 bytes long is still there.
/// See [`read_scriptint`] for a description of some subtleties of
/// this function.
pub fn read_scriptint_non_minimal(v: &[u8]) -> Result<i64, script::Error> {
    read_scriptint_size(v, DEFAULT_MAX_SCRIPTINT_SIZE, false)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TapscriptScan {
    Clean,
    Success(u8),
    DecodeError,
}

/// BIP-342 OP_SUCCESSx set: 80, 98, 126-129, 131-134, 137-138, 141-142,
/// 149-153, 187-254.
fn is_op_success(op: u8) -> bool {
    matches!(
        op,
        80 | 98 | 126..=129 | 131..=134 | 137 | 138 | 141 | 142 | 149..=153 | 187..=254
    )
}

/// Sequential decode per BIP-342: the first OP_SUCCESSx encountered makes
/// the script pass, even when later bytes fail to decode; a truncated push
/// before any OP_SUCCESSx fails the script. Deployed opcodes (CAT, CSFS)
/// are carved out of the success set and execute normally. Consensus decode
/// does not require minimal pushes, so this must not use the minimal
/// instruction iterator.
fn scan_tapscript_op_success(script: &Script, deployments: &Deployments) -> TapscriptScan {
    let carved_out = |op: u8| {
        (deployments.cat && op == 0x7e)
            || (deployments.csfs && op == 0xcc)
            || (deployments.internalkey && op == 0xcb)
            || (deployments.templatehash && op == 0xce)
            || (deployments.paircommit && op == 0xcd)
            || (deployments.txhash && op == 0xbd)
            || (deployments.ccv && op == 0xbb)
    };
    for instruction in script.instructions() {
        match instruction {
            Ok(Instruction::Op(op)) => {
                let op = op.to_u8();
                if is_op_success(op) && !carved_out(op) {
                    return TapscriptScan::Success(op);
                }
            }
            Ok(Instruction::PushBytes(_)) => {}
            Err(_) => return TapscriptScan::DecodeError,
        }
    }
    TapscriptScan::Clean
}
