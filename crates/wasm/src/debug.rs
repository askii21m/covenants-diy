//! Opcode-by-opcode tapscript execution, with the stack captured after each
//! step. This is the part that makes a covenant legible: you watch the
//! template hash get pushed, compared, and enforced.

use std::collections::HashMap;

use bitcoin::consensus::deserialize;
use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash};
use bitcoin::{
    absolute, transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use covenants_core::enforce::Ruleset;
use covenants_interp::{Deployments, Exec, ExecCtx, Options, TxTemplate};
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
    }
}

#[derive(Debug, Clone, Deserialize, Tsify)]
pub struct PrevoutSpec {
    pub value: u64,
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
        Some(hex) => {
            deserialize(&hex_bytes(hex, "tx")?).map_err(|e| format!("tx: {e}"))?
        }
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
                value: Amount::from_sat(p.value),
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
    let mut internal_key = internal_key;
    let full_witness_size = match &req.control_block {
        Some(cb) => {
            let cb = ControlBlock::decode(&hex_bytes(cb, "control_block")?)
                .map_err(|e| format!("control_block: {e}"))?;
            if internal_key.is_none() {
                internal_key = Some(cb.internal_key);
            }
            let mut w = Witness::new();
            for item in &stack {
                w.push(item);
            }
            w.push(script.as_bytes());
            w.push(cb.serialize());
            Some(w.size())
        }
        None => None,
    };

    let leaf = TapLeafHash::from_script(&script, LeafVersion::TapScript);
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
            Some((success, error, final_stack)) => {
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
