//! Opcode-by-opcode tapscript execution, with the stack captured after each
//! step. This is the part that makes a covenant legible: you watch the
//! template hash get pushed, compared, and enforced.

use std::collections::HashMap;

use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash as _;
use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash, TapNodeHash};
use bitcoin::{
    absolute, transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use covenants_core::enforce::Ruleset;
use covenants_interp::{CcvTxState, Deployments, Exec, ExecCtx, Options, TxTemplate};
use serde::{Deserialize, Serialize};
use tsify::Tsify;

use crate::asm;

fn deployments(r: &Ruleset) -> Deployments {
    Deployments {
        ctv: r.ctv,
        csfs: r.csfs,
        cat: r.cat,
        apo: r.apo,
        templatehash: r.templatehash,
        internalkey: r.internalkey,
        paircommit: r.paircommit,
        txhash: r.txhash,
        ccv: r.ccv,
    }
}

#[derive(Debug, Clone, Deserialize, Tsify)]
pub struct PrevoutSpec {
    /// Satoshis. Absent means the caller does not know, which BIP-443's
    /// amount rules refuse rather than treat as zero.
    #[serde(default)]
    #[tsify(optional)]
    pub value: Option<u64>,
    /// scriptPubKey hex.
    pub script_pubkey: String,
}

#[derive(Deserialize, Tsify)]
pub struct DebugRequest {
    /// Tapscript hex.
    pub script: String,
    /// Initial stack, bottom element first, hex. This is the witness with
    /// the script and control block already stripped.
    #[serde(default, deserialize_with = "crate::js::vec_or_empty")]
    #[tsify(optional)]
    pub stack: Vec<String>,
    /// Spending transaction hex. Omitted, a placeholder is synthesized,
    /// which is fine for pure-script experiments but will not satisfy CTV
    /// or any signature check.
    #[serde(default)]
    #[tsify(optional, type = "string")]
    pub tx: Option<String>,
    #[serde(default, deserialize_with = "crate::js::vec_or_empty")]
    #[tsify(optional)]
    pub prevouts: Vec<PrevoutSpec>,
    #[serde(default)]
    pub input_index: u32,
    /// Taproot internal key, x-only hex. Required to check a BIP-118
    /// signature made against the 1-byte `0x01` key.
    #[serde(default)]
    #[tsify(optional, type = "string")]
    pub internal_key: Option<String>,
    /// Control block hex. Only affects the reported validation weight
    /// budget, which BIP-342 derives from the full witness size.
    #[serde(default)]
    #[tsify(optional, type = "string")]
    pub control_block: Option<String>,
    #[serde(default)]
    pub ruleset: Ruleset,
    /// What earlier inputs of this transaction already accumulated under
    /// BIP-443's amount rules, as returned by a previous run. Absent means
    /// this input is judged on its own, which is only the whole story for a
    /// transaction with one input.
    #[serde(default)]
    #[tsify(optional)]
    pub ccv_state: Option<CcvStateSpec>,
}

/// BIP-443's transaction-wide amount state, in and out, so a caller running
/// one input at a time can thread it and get what a node would decide.
#[derive(Debug, Clone, Default, Deserialize, Serialize, Tsify)]
pub struct CcvStateSpec {
    #[serde(default)]
    pub output_min_amount: Vec<u64>,
    #[serde(default)]
    pub output_checked_default: Vec<bool>,
    #[serde(default)]
    pub output_checked_deduct: Vec<bool>,
}

impl From<CcvStateSpec> for CcvTxState {
    fn from(s: CcvStateSpec) -> Self {
        CcvTxState {
            output_min_amount: s.output_min_amount,
            output_checked_default: s.output_checked_default,
            output_checked_deduct: s.output_checked_deduct,
        }
    }
}

impl From<CcvTxState> for CcvStateSpec {
    fn from(s: CcvTxState) -> Self {
        CcvStateSpec {
            output_min_amount: s.output_min_amount,
            output_checked_default: s.output_checked_default,
            output_checked_deduct: s.output_checked_deduct,
        }
    }
}

#[derive(Serialize, Tsify)]
pub struct Step {
    pub index: usize,
    /// Byte offset of this instruction in the script.
    pub position: usize,
    pub op: String,
    /// Stack after the step, bottom element first, hex.
    pub stack: Vec<String>,
    pub altstack: Vec<String>,
    pub validation_weight: i64,
    /// Set when this step is the one that failed.
    pub error: Option<String>,
}

#[derive(Serialize, Tsify)]
pub struct DebugTrace {
    pub steps: Vec<Step>,
    pub success: bool,
    pub error: Option<String>,
    pub final_stack: Vec<String>,
    pub op_count: usize,
    pub validation_weight_start: i64,
    pub validation_weight_remaining: i64,
    /// The script as covenant-aware assembly.
    pub asm: String,
    /// Opcodes run whose weight no BIP has settled. Above zero, the two
    /// budget figures are a lower bound on what a node will spend rather
    /// than the figure it would arrive at.
    pub unpriced_ops: usize,
    /// BIP-443 amount state after this input, to hand to the next one.
    pub ccv_state: CcvStateSpec,
}

fn hex_bytes(s: &str, what: &str) -> Result<Vec<u8>, String> {
    Vec::<u8>::from_hex(s).map_err(|e| format!("{what}: invalid hex: {e}"))
}

pub fn trace(req: DebugRequest) -> Result<DebugTrace, String> {
    let script = ScriptBuf::from(hex_bytes(&req.script, "script")?);
    let stack = req
        .stack
        .iter()
        .map(|s| hex_bytes(s, "stack item"))
        .collect::<Result<Vec<_>, _>>()?;

    let input_index = req.input_index as usize;

    let tx: Transaction = match &req.tx {
        Some(hex) => deserialize(&hex_bytes(hex, "tx")?).map_err(|e| format!("tx: {e}"))?,
        None => Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: (0..=input_index)
                .map(|_| TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            output: vec![],
        },
    };

    if input_index >= tx.input.len() {
        return Err(format!(
            "input_index {input_index} out of range for a transaction with {} inputs",
            tx.input.len()
        ));
    }

    // Prevouts must cover every input: BIP-341 hashes all of them unless
    // ANYONECANPAY or ANYPREVOUT is set, and we cannot know in advance which
    // the script will use.
    let mut prevouts: Vec<TxOut> = Vec::with_capacity(tx.input.len());
    for i in 0..tx.input.len() {
        match req.prevouts.get(i) {
            Some(p) => prevouts.push(TxOut {
                value: Amount::from_sat(p.value.unwrap_or(0)),
                script_pubkey: ScriptBuf::from(hex_bytes(&p.script_pubkey, "prevout script")?),
            }),
            None => prevouts.push(TxOut {
                value: Amount::from_sat(0),
                script_pubkey: ScriptBuf::new(),
            }),
        }
    }

    let internal_key = match &req.internal_key {
        Some(k) => Some(
            XOnlyPublicKey::from_slice(&hex_bytes(k, "internal_key")?)
                .map_err(|e| format!("internal_key: {e}"))?,
        ),
        None => None,
    };

    // The control block carries the internal key, which a BIP-118 check
    // against the 0x01 key needs; an explicit internal_key still wins.
    let leaf = TapLeafHash::from_script(&script, LeafVersion::TapScript);

    let mut internal_key = internal_key;
    let mut control_block_bytes = None;
    let mut taptree_root = None;
    let full_witness_size = match &req.control_block {
        Some(cb) => {
            let cb = ControlBlock::decode(&hex_bytes(cb, "control_block")?)
                .map_err(|e| format!("control_block: {e}"))?;
            if internal_key.is_none() {
                internal_key = Some(cb.internal_key);
            }
            // Fold the leaf up its merkle path to recover the tree root,
            // which BIP-443 substitutes for a taptree of -1. An empty path
            // means a single-leaf tree, whose root is the leaf itself.
            // The control block says which leaf version its script was
            // committed under; assuming TapScript folds the wrong leaf hash
            // and every taptree of -1 then names the wrong contract.
            let leaf_for_tree = TapLeafHash::from_script(&script, cb.leaf_version);
            let mut node = TapNodeHash::from(leaf_for_tree);
            for step in cb.merkle_branch.as_slice() {
                node = TapNodeHash::from_node_hashes(node, *step);
            }
            taptree_root = Some(node.to_byte_array());
            let serialized = cb.serialize();
            let mut w = Witness::new();
            for item in &stack {
                w.push(item);
            }
            w.push(script.as_bytes());
            w.push(&serialized);
            control_block_bytes = Some(serialized);
            Some(w.size())
        }
        None => None,
    };
    let positions: HashMap<usize, String> = asm::instructions(&script).into_iter().collect();
    let rendered = asm::render(&script);

    let mut exec = Exec::new(
        ExecCtx::Tapscript,
        Options {
            deployments: deployments(&req.ruleset),
            ..Default::default()
        },
        TxTemplate {
            tx,
            prevouts,
            input_idx: input_index,
            taproot_annex_scriptleaf: Some((leaf, None)),
            internal_key,
            full_witness_size,
            control_block: control_block_bytes,
            ccv_state: req.ccv_state.clone().map(Into::into),
            taptree_root,
            input_amount: req.prevouts.get(input_index).and_then(|p| p.value),
        },
        script,
        stack,
    )
    .map_err(|e| format!("{e:?}"))?;

    let start_weight = exec.stats().start_validation_weight;
    let mut steps: Vec<Step> = Vec::new();

    loop {
        let position = exec.script_position();
        // The borrow of `exec` held by the Err arm has to end before the
        // stack can be read, so everything needed is cloned out here.
        let finished = match exec.exec_next() {
            Ok(()) => None,
            Err(res) => Some((
                res.success,
                res.error.as_ref().map(|e| format!("{e:?}")),
                res.final_stack.iter_str().map(hex_of).collect::<Vec<_>>(),
                res.opcode.is_some(),
            )),
        };

        match finished {
            None => {
                steps.push(Step {
                    index: steps.len(),
                    position,
                    op: op_text(&positions, position),
                    stack: exec.stack().iter_str().map(hex_of).collect(),
                    altstack: exec.altstack().iter_str().map(hex_of).collect(),
                    validation_weight: exec.stats().validation_weight,
                    error: None,
                });
            }
            Some((success, error, final_stack, ended_on_opcode)) => {
                // An opcode can end the script by succeeding outright, and it
                // still has to appear: a trace that stops with no row for the
                // opcode that stopped it reads as if nothing ran. Only from
                // mid-execution, since a script the BIP-342 pre-scan passed
                // never ran an opcode at all, and says so on the enforcement
                // line instead.
                if error.is_none() && ended_on_opcode && !steps.is_empty() {
                    steps.push(Step {
                        index: steps.len(),
                        position,
                        op: op_text(&positions, position),
                        stack: final_stack.clone(),
                        altstack: exec.altstack().iter_str().map(hex_of).collect(),
                        validation_weight: exec.stats().validation_weight,
                        error: None,
                    });
                }
                if let Some(err) = &error {
                    steps.push(Step {
                        index: steps.len(),
                        position,
                        op: op_text(&positions, position),
                        stack: final_stack.clone(),
                        altstack: exec.altstack().iter_str().map(hex_of).collect(),
                        validation_weight: exec.stats().validation_weight,
                        error: Some(err.clone()),
                    });
                }
                return Ok(DebugTrace {
                    steps,
                    success,
                    error,
                    final_stack,
                    op_count: exec.stats().opcode_count,
                    validation_weight_start: start_weight,
                    validation_weight_remaining: exec.stats().validation_weight,
                    unpriced_ops: exec.stats().unpriced_ops,
                    ccv_state: exec.ccv_state().into(),
                    asm: rendered,
                });
            }
        }
    }
}

fn hex_of(v: Vec<u8>) -> String {
    v.to_lower_hex_string()
}

fn op_text(positions: &HashMap<usize, String>, position: usize) -> String {
    positions
        .get(&position)
        .cloned()
        .unwrap_or_else(|| "<end>".to_string())
}
