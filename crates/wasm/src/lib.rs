//! wasm bindings: one stateless function per computing node. The graph
//! lives in the frontend; nothing here holds state between calls.
//!
//! Every entry point takes and returns a `Ts<T>`, a JsValue that knows its
//! TypeScript type, so malformed input from JavaScript throws rather than
//! panics.

use std::collections::BTreeMap;
use std::str::FromStr;

use bitcoin::consensus::encode::{deserialize, serialize_hex};
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin::secp256k1::ffi::CPtr;
use bitcoin::secp256k1::{Secp256k1, XOnlyPublicKey};
use bitcoin::taproot::{LeafVersion, TapLeafHash};
use bitcoin::{
    absolute, transaction, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxOut, Witness,
};
use covenants_core::enforce::{self, EnforcementReport, Ruleset};
use covenants_core::{ctv, source, taproot};
use serde::{Deserialize, Serialize};
use tsify::{Ts, Tsify};
use wasm_bindgen::prelude::*;

mod asm;
mod debug;
mod js;

pub use debug::{DebugRequest, DebugTrace};

#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

fn err<E: std::fmt::Display>(context: &str) -> impl Fn(E) -> JsError + '_ {
    move |e| JsError::new(&format!("{context}: {e}"))
}

fn hex(s: &str, what: &str) -> Result<Vec<u8>, JsError> {
    Vec::<u8>::from_hex(s.trim()).map_err(|e| JsError::new(&format!("{what}: invalid hex: {e}")))
}

fn parse_network(s: &str) -> Result<Network, JsError> {
    Network::from_str(s).map_err(err("network"))
}

// ---------------------------------------------------------------------------
// Template: a transaction without prevouts or witnesses. What a covenant
// commits to.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize, Tsify)]
pub struct TemplateInput {
    pub sequence: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize, Tsify)]
pub struct TemplateOutput {
    /// Satoshis.
    pub value: u64,
    /// scriptPubKey hex.
    pub script_pubkey: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, Tsify)]
pub struct TemplateRequest {
    #[serde(default = "two")]
    pub version: i32,
    #[serde(default)]
    pub locktime: u32,
    #[serde(default, deserialize_with = "crate::js::vec_or_empty")]
    pub inputs: Vec<TemplateInput>,
    #[serde(default, deserialize_with = "crate::js::vec_or_empty")]
    pub outputs: Vec<TemplateOutput>,
}
fn two() -> i32 {
    2
}

#[derive(Serialize, Tsify)]
pub struct TemplateView {
    /// The transaction with null prevouts and empty witnesses, hex. Feed
    /// this to `realize` with the real prevouts.
    pub template: String,
    /// BIP-119 template hash per input.
    pub ctv: Vec<String>,
    /// Weight with empty witnesses, so a lower bound.
    pub base_weight: usize,
}

fn build_template(req: &TemplateRequest) -> Result<Transaction, JsError> {
    let mut output = Vec::with_capacity(req.outputs.len());
    for (i, o) in req.outputs.iter().enumerate() {
        output.push(TxOut {
            value: Amount::from_sat(o.value),
            script_pubkey: ScriptBuf::from(hex(
                &o.script_pubkey,
                &format!("output {i} scriptPubKey"),
            )?),
        });
    }
    Ok(Transaction {
        version: transaction::Version(req.version),
        lock_time: absolute::LockTime::from_consensus(req.locktime),
        input: req
            .inputs
            .iter()
            .map(|i| TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence(i.sequence),
                witness: Witness::new(),
            })
            .collect(),
        output,
    })
}

#[wasm_bindgen]
pub fn template(req: Ts<TemplateRequest>) -> Result<Ts<TemplateView>, JsError> {
    let req = req.to_rust().map_err(err("request"))?;
    if req.inputs.is_empty() {
        return Err(JsError::new("a template needs at least one input"));
    }
    if req.outputs.is_empty() {
        return Err(JsError::new("a template needs at least one output"));
    }
    let tx = build_template(&req)?;
    let ctv = (0..tx.input.len() as u32)
        .map(|i| ctv::default_template_hash(&tx, i).to_lower_hex_string())
        .collect();
    TemplateView {
        template: serialize_hex(&tx),
        ctv,
        base_weight: tx.weight().to_wu() as usize,
    }
    .into_ts()
    .map_err(err("response"))
}

/// BIP-119 template hash of any raw transaction, for hashes built elsewhere.
#[wasm_bindgen]
pub fn template_hash(tx_hex: &str, input_index: u32) -> Result<String, JsError> {
    let tx: Transaction = deserialize(&hex(tx_hex, "tx")?).map_err(err("tx"))?;
    if input_index as usize >= tx.input.len() {
        return Err(JsError::new(&format!(
            "input {input_index} does not exist; the transaction has {} inputs",
            tx.input.len()
        )));
    }
    Ok(ctv::default_template_hash(&tx, input_index).to_lower_hex_string())
}

// ---------------------------------------------------------------------------
// Transaction: a template bound to prevouts and witnesses.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Tsify)]
pub struct RealizeRequest {
    /// Template hex from `template`.
    pub template: String,
    /// `"txid:vout"` per input; an empty string leaves that prevout null.
    #[serde(default, deserialize_with = "crate::js::vec_or_empty")]
    pub prevouts: Vec<String>,
    /// Witness stack per input, bottom first, hex items.
    #[serde(default, deserialize_with = "crate::js::vec_or_empty")]
    pub witnesses: Vec<Vec<String>>,
    /// Value of each prevout in satoshis, when known, for the fee.
    #[serde(default, deserialize_with = "crate::js::vec_or_empty")]
    pub prevout_values: Vec<Option<u64>>,
}

#[derive(Serialize, Tsify)]
pub struct TransactionView {
    pub hex: String,
    pub txid: String,
    pub wtxid: String,
    /// `"txid:vout"` per output, for wiring into a child's prevout.
    pub outpoints: Vec<String>,
    pub weight: usize,
    pub vsize: usize,
    /// Inputs minus outputs, when every prevout value is known.
    pub fee: Option<i64>,
    /// True when every prevout is bound and every input has a witness.
    pub complete: bool,
}

#[wasm_bindgen]
pub fn realize(req: Ts<RealizeRequest>) -> Result<Ts<TransactionView>, JsError> {
    let req = req.to_rust().map_err(err("request"))?;
    let mut tx: Transaction =
        deserialize(&hex(&req.template, "template")?).map_err(err("template"))?;
    let mut complete = true;
    for (i, input) in tx.input.iter_mut().enumerate() {
        match req
            .prevouts
            .get(i)
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
        {
            Some(s) => {
                input.previous_output = OutPoint::from_str(s)
                    .map_err(|e| JsError::new(&format!("prevout {i}: {e}")))?;
            }
            None => complete = false,
        }
        match req.witnesses.get(i) {
            Some(items) if !items.is_empty() => {
                let mut w = Witness::new();
                for (k, item) in items.iter().enumerate() {
                    w.push(hex(item, &format!("witness {i} item {k}"))?);
                }
                input.witness = w;
            }
            _ => complete = false,
        }
    }
    let fee = if req.prevout_values.len() == tx.input.len()
        && req.prevout_values.iter().all(|v| v.is_some())
    {
        let in_sum: i64 = req.prevout_values.iter().map(|v| v.unwrap() as i64).sum();
        let out_sum: i64 = tx.output.iter().map(|o| o.value.to_sat() as i64).sum();
        Some(in_sum - out_sum)
    } else {
        None
    };
    let txid = tx.compute_txid();
    TransactionView {
        hex: serialize_hex(&tx),
        txid: txid.to_string(),
        wtxid: tx.compute_wtxid().to_string(),
        outpoints: (0..tx.output.len())
            .map(|v| format!("{txid}:{v}"))
            .collect(),
        weight: tx.weight().to_wu() as usize,
        vsize: tx.vsize(),
        fee,
        complete,
    }
    .into_ts()
    .map_err(err("response"))
}

#[derive(Serialize, Tsify)]
pub struct ParsedInput {
    pub prevout: String,
    pub sequence: u32,
    pub script_sig: String,
    pub witness: Vec<String>,
}

#[derive(Serialize, Tsify)]
pub struct ParsedTx {
    pub version: i32,
    pub locktime: u32,
    pub inputs: Vec<ParsedInput>,
    pub outputs: Vec<TemplateOutput>,
    pub txid: String,
    pub weight: usize,
    pub vsize: usize,
}

#[wasm_bindgen]
pub fn parse_tx(tx_hex: &str) -> Result<Ts<ParsedTx>, JsError> {
    let tx: Transaction = deserialize(&hex(tx_hex, "tx")?).map_err(err("tx"))?;
    ParsedTx {
        version: tx.version.0,
        locktime: tx.lock_time.to_consensus_u32(),
        inputs: tx
            .input
            .iter()
            .map(|i| ParsedInput {
                prevout: i.previous_output.to_string(),
                sequence: i.sequence.0,
                script_sig: i.script_sig.to_hex_string(),
                witness: i.witness.iter().map(|w| w.to_lower_hex_string()).collect(),
            })
            .collect(),
        outputs: tx
            .output
            .iter()
            .map(|o| TemplateOutput {
                value: o.value.to_sat(),
                script_pubkey: o.script_pubkey.to_hex_string(),
            })
            .collect(),
        txid: tx.compute_txid().to_string(),
        weight: tx.weight().to_wu() as usize,
        vsize: tx.vsize(),
    }
    .into_ts()
    .map_err(err("response"))
}

// ---------------------------------------------------------------------------
// Tapscript: source with @refs to script bytes.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Tsify)]
pub struct AssembleRequest {
    pub source: String,
    /// Values wired into `@name` references, hex. A plain object on the JS
    /// side; tsify would type a map as `Map`, which serde_wasm_bindgen
    /// does not read by default.
    #[serde(default)]
    #[tsify(type = "Record<string, string>")]
    pub bindings: BTreeMap<String, String>,
    #[serde(default)]
    pub ruleset: Ruleset,
}

#[derive(Serialize, Tsify)]
pub struct SourcePosition {
    pub line: usize,
    pub word: usize,
    pub message: String,
}

#[derive(Serialize, Tsify)]
pub struct AssembleView {
    /// Every `@name` in the source, in order of first appearance. Present
    /// even when assembly fails, so the node can expose its ports.
    pub refs: Vec<String>,
    pub script: Option<String>,
    pub asm: Option<String>,
    pub leaf_hash: Option<String>,
    pub enforcement: Option<EnforcementReport>,
    pub error: Option<SourcePosition>,
}

#[wasm_bindgen]
pub fn assemble(req: Ts<AssembleRequest>) -> Result<Ts<AssembleView>, JsError> {
    let req = req.to_rust().map_err(err("request"))?;
    let refs = match source::refs(&req.source) {
        Ok(r) => r,
        Err(e) => {
            return AssembleView {
                refs: vec![],
                script: None,
                asm: None,
                leaf_hash: None,
                enforcement: None,
                error: Some(SourcePosition {
                    line: e.line,
                    word: e.word,
                    message: e.message,
                }),
            }
            .into_ts()
            .map_err(err("response"));
        }
    };
    let mut bindings = BTreeMap::new();
    for (k, v) in &req.bindings {
        bindings.insert(k.clone(), hex(v, &format!("@{k}"))?);
    }
    let view = match source::assemble(&req.source, &bindings) {
        Ok(a) => AssembleView {
            refs,
            asm: Some(asm::render(&a.script)),
            leaf_hash: Some(
                TapLeafHash::from_script(&a.script, LeafVersion::TapScript).to_string(),
            ),
            enforcement: Some(enforce::classify(&a.script, &req.ruleset)),
            script: Some(a.script.to_hex_string()),
            error: None,
        },
        Err(e) => AssembleView {
            refs,
            script: None,
            asm: None,
            leaf_hash: None,
            enforcement: None,
            error: Some(SourcePosition {
                line: e.line,
                word: e.word,
                message: e.message,
            }),
        },
    };
    view.into_ts().map_err(err("response"))
}

/// Script hex to covenant-aware assembly.
#[wasm_bindgen]
pub fn disassemble(script_hex: &str) -> Result<String, JsError> {
    Ok(asm::render(
        ScriptBuf::from(hex(script_hex, "script")?).as_script(),
    ))
}

#[wasm_bindgen]
pub fn classify(script_hex: &str, ruleset: Ts<Ruleset>) -> Result<Ts<EnforcementReport>, JsError> {
    let ruleset = ruleset.to_rust().map_err(err("ruleset"))?;
    enforce::classify(
        ScriptBuf::from(hex(script_hex, "script")?).as_script(),
        &ruleset,
    )
    .into_ts()
    .map_err(err("response"))
}

#[wasm_bindgen]
pub fn tapleaf_hash(script_hex: &str) -> Result<String, JsError> {
    let s = ScriptBuf::from(hex(script_hex, "script")?);
    Ok(TapLeafHash::from_script(&s, LeafVersion::TapScript).to_string())
}

// ---------------------------------------------------------------------------
// Taproot output.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Tsify)]
pub struct TaprootRequest {
    pub network: String,
    /// x-only hex; absent selects the NUMS point.
    #[serde(default)]
    #[tsify(optional, type = "string")]
    pub internal_key: Option<String>,
    /// Leaf scripts, hex.
    #[serde(default, deserialize_with = "crate::js::vec_or_empty")]
    pub leaves: Vec<String>,
}

#[derive(Serialize, Tsify)]
pub struct TaprootView {
    pub internal_key: String,
    pub output_key: String,
    pub merkle_root: Option<String>,
    pub address: String,
    pub script_pubkey: String,
    pub leaf_hashes: Vec<String>,
    pub control_blocks: Vec<String>,
}

#[wasm_bindgen]
pub fn taproot_output(req: Ts<TaprootRequest>) -> Result<Ts<TaprootView>, JsError> {
    let req = req.to_rust().map_err(err("request"))?;
    let network = parse_network(&req.network)?;
    let internal_key = match &req.internal_key {
        Some(k) if !k.trim().is_empty() => Some(
            XOnlyPublicKey::from_slice(&hex(k, "internal key")?).map_err(err("internal key"))?,
        ),
        _ => None,
    };
    let mut leaves = Vec::with_capacity(req.leaves.len());
    for (i, l) in req.leaves.iter().enumerate() {
        leaves.push(ScriptBuf::from(hex(l, &format!("leaf {i}"))?));
    }
    let secp = Secp256k1::verification_only();
    let t = taproot::build(&secp, network, internal_key, &leaves).map_err(|e| {
        JsError::new(match e {
            taproot::TaprootError::Tree => "leaves: duplicate script, or too many for one tree",
            taproot::TaprootError::Finalize => "could not finalize the taptree",
        })
    })?;
    TaprootView {
        internal_key: t.internal_key.to_string(),
        output_key: t.spend_info.output_key().to_x_only_public_key().to_string(),
        merkle_root: t.spend_info.merkle_root().map(|r| r.to_string()),
        address: t.address.to_string(),
        script_pubkey: t.script_pubkey.to_hex_string(),
        leaf_hashes: t.leaf_hashes.iter().map(|h| h.to_string()).collect(),
        control_blocks: t
            .control_blocks
            .iter()
            .map(|c| c.serialize().to_lower_hex_string())
            .collect(),
    }
    .into_ts()
    .map_err(err("response"))
}

#[wasm_bindgen]
pub fn nums_key() -> String {
    taproot::nums_internal_key().to_string()
}

// ---------------------------------------------------------------------------
// Execute: the debugger.
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub fn execute(req: Ts<DebugRequest>) -> Result<Ts<DebugTrace>, JsError> {
    let req = req.to_rust().map_err(err("request"))?;
    debug::trace(req)
        .map_err(|e| JsError::new(&e))?
        .into_ts()
        .map_err(err("response"))
}

// ---------------------------------------------------------------------------
// Byte primitives.
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub fn sha256(data_hex: &str) -> Result<String, JsError> {
    Ok(sha256::Hash::hash(&hex(data_hex, "data")?)
        .to_byte_array()
        .to_lower_hex_string())
}

#[wasm_bindgen]
pub fn tagged_hash(tag: &str, data_hex: &str) -> Result<String, JsError> {
    let t = sha256::Hash::hash(tag.as_bytes());
    let mut e = sha256::Hash::engine();
    e.input(t.as_byte_array());
    e.input(t.as_byte_array());
    e.input(&hex(data_hex, "data")?);
    Ok(sha256::Hash::from_engine(e)
        .to_byte_array()
        .to_lower_hex_string())
}

// ---------------------------------------------------------------------------
// Keys and signatures. Secrets are plain 32-byte hex: this is a sandbox
// for signet and regtest, and a key a user can see is a key they can
// reason about.
// ---------------------------------------------------------------------------

fn secret(hex_str: &str) -> Result<bitcoin::secp256k1::Keypair, JsError> {
    let bytes = hex(hex_str, "secret")?;
    let sk = bitcoin::secp256k1::SecretKey::from_slice(&bytes).map_err(err("secret"))?;
    Ok(bitcoin::secp256k1::Keypair::from_secret_key(
        &Secp256k1::new(),
        &sk,
    ))
}

/// The BIP-340 x-only public key for a secret.
#[wasm_bindgen]
pub fn pubkey(secret_hex: &str) -> Result<String, JsError> {
    let (xonly, _) = secret(secret_hex)?.x_only_public_key();
    Ok(xonly.to_string())
}

/// A BIP-340 signature, deterministic (no aux randomness), so the same
/// inputs give the same signature. The message may be any length: a
/// sighash is 32 bytes, but BIP-348 does not pre-hash what CSFS checks,
/// and libsecp256k1 signs variable-length messages through sign_custom.
#[wasm_bindgen]
pub fn sign_schnorr(secret_hex: &str, message_hex: &str) -> Result<String, JsError> {
    let kp = secret(secret_hex)?;
    let msg = hex(message_hex, "message")?;
    let secp = Secp256k1::new();
    let mut sig = [0u8; 64];
    // SAFETY: sig is 64 bytes as the call requires, msg is a live slice
    // whose length is passed alongside it (null when empty, as the C API
    // requires), and extra_params is the library's own default.
    let ok = unsafe {
        let extra = bitcoin::secp256k1::ffi::SchnorrSigExtraParams::new(None, std::ptr::null());
        bitcoin::secp256k1::ffi::secp256k1_schnorrsig_sign_custom(
            secp.ctx().as_ptr(),
            sig.as_mut_ptr(),
            if msg.is_empty() {
                std::ptr::null()
            } else {
                msg.as_ptr()
            },
            msg.len(),
            kp.as_c_ptr(),
            &extra,
        )
    };
    if ok != 1 {
        return Err(JsError::new("signature: libsecp256k1 refused to sign"));
    }
    Ok(sig.to_lower_hex_string())
}

/// BIP-340 verification over a message of any length, matching what the
/// interpreter does for CSFS. Accepts a 64-byte signature, or 65 with a
/// trailing sighash byte, which is ignored here.
#[wasm_bindgen]
pub fn verify_schnorr(
    pubkey_hex: &str,
    message_hex: &str,
    signature_hex: &str,
) -> Result<bool, JsError> {
    let pk = XOnlyPublicKey::from_str(pubkey_hex.trim()).map_err(err("pubkey"))?;
    let msg = hex(message_hex, "message")?;
    let mut sig = hex(signature_hex, "signature")?;
    if sig.len() == 65 {
        sig.pop();
    }
    if sig.len() != 64 {
        return Err(JsError::new(
            "signature: must be 64 bytes, or 65 with a hash type byte",
        ));
    }
    // SAFETY: sig is checked to be 64 bytes, msg is a live slice whose
    // length is passed alongside it, null when empty as the C API requires.
    Ok(unsafe {
        bitcoin::secp256k1::ffi::secp256k1_schnorrsig_verify(
            bitcoin::secp256k1::ffi::secp256k1_context_no_precomp,
            sig.as_ptr(),
            if msg.is_empty() {
                std::ptr::null()
            } else {
                msg.as_ptr()
            },
            msg.len(),
            pk.as_c_ptr(),
        ) == 1
    })
}

#[derive(Debug, Clone, Deserialize, Tsify)]
pub struct SighashRequest {
    /// Spending transaction hex.
    pub tx: String,
    pub input_index: u32,
    /// The outputs being spent, one per input, in input order. Modes that
    /// commit to fewer (ANYONECANPAY, ANYPREVOUT) only need the signed
    /// input's; ANYPREVOUTANYSCRIPT needs none.
    #[serde(default, deserialize_with = "crate::js::vec_or_empty")]
    #[tsify(optional)]
    pub prevouts: Vec<debug::PrevoutSpec>,
    /// BIP-341 hash type byte, with BIP-118's 0x40 and 0xc0 modes.
    pub hash_type: u8,
    /// The tapscript being satisfied, hex. Committed unless the mode is
    /// ANYPREVOUTANYSCRIPT.
    pub leaf_script: String,
}

#[derive(Debug, Clone, Serialize, Tsify)]
pub struct SighashView {
    /// The bytes the digest is the tagged hash of. A script that rebuilds
    /// its own signature message with OP_CAT is rebuilding exactly these.
    pub preimage: String,
    /// The 32-byte digest a BIP-340 signature is made over.
    pub sighash: String,
    pub hash_type: u8,
    /// 0x00 for a BIP-342 key, 0x01 for a BIP-118 key; the sighash commits
    /// to it, so a signature for one never verifies under the other.
    pub key_version: u8,
    pub tapleaf_hash: String,
}

/// The script-path sighash for one input of a transaction. The key version
/// follows the hash type: any BIP-118 mode means a BIP-118 key.
#[wasm_bindgen]
pub fn sighash(req: Ts<SighashRequest>) -> Result<Ts<SighashView>, JsError> {
    use covenants_core::sighash::{script_spend_sighash, KeyVersion, Prevouts};
    let req = req.to_rust().map_err(err("request"))?;
    let tx: Transaction = deserialize(&hex(&req.tx, "tx")?).map_err(err("tx"))?;
    let idx = req.input_index as usize;
    if idx >= tx.input.len() {
        return Err(JsError::new(&format!(
            "input_index {idx} out of range for {} inputs",
            tx.input.len()
        )));
    }
    let prevouts: Vec<TxOut> = req
        .prevouts
        .iter()
        .map(|p| {
            Ok(TxOut {
                value: Amount::from_sat(p.value),
                script_pubkey: ScriptBuf::from(hex(&p.script_pubkey, "prevout script")?),
            })
        })
        .collect::<Result<_, JsError>>()?;
    let key_version = if req.hash_type & 0x40 != 0 {
        KeyVersion::Bip118
    } else {
        KeyVersion::V0
    };
    let leaf = ScriptBuf::from(hex(&req.leaf_script, "leaf_script")?);
    let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
    // One prevout given for a single-input transaction, or one for this
    // input under a mode that only commits to it, is the common case.
    let prev = if prevouts.len() == tx.input.len() {
        Prevouts::All(&prevouts)
    } else if prevouts.len() == 1 {
        Prevouts::One(idx, &prevouts[0])
    } else if prevouts.is_empty() {
        Prevouts::None
    } else {
        return Err(JsError::new(&format!(
            "{} prevouts for {} inputs",
            prevouts.len(),
            tx.input.len()
        )));
    };
    let digest = script_spend_sighash(
        &tx,
        idx,
        prev,
        req.hash_type,
        key_version,
        leaf_hash,
        u32::MAX,
        None,
    )
    .map_err(|e| JsError::new(&format!("sighash: {e:?}")))?;
    let preimage = covenants_core::sighash::script_spend_preimage(
        &tx,
        idx,
        prev,
        req.hash_type,
        key_version,
        leaf_hash,
        u32::MAX,
        None,
    )
    .map_err(|e| JsError::new(&format!("sighash: {e:?}")))?;
    SighashView {
        preimage: preimage.to_lower_hex_string(),
        sighash: digest.to_lower_hex_string(),
        hash_type: req.hash_type,
        key_version: if key_version == KeyVersion::Bip118 {
            1
        } else {
            0
        },
        tapleaf_hash: leaf_hash.to_byte_array().to_lower_hex_string(),
    }
    .into_ts()
    .map_err(err("response"))
}

// ---------------------------------------------------------------------------
// The opcode catalog. Every entry is checked against the same parser the
// assembler uses, so the editor can never offer a word that fails to
// assemble, and each carries what a tapscript author actually needs to
// know: whether it works here at all.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Tsify)]
pub struct OpcodeCatalog {
    pub opcodes: Vec<OpcodeInfo>,
}

#[derive(Debug, Clone, Serialize, Tsify)]
pub struct OpcodeInfo {
    pub name: String,
    /// Shorter spelling the assembler also accepts, where one exists.
    pub alias: Option<String>,
    pub byte: u8,
    pub category: String,
    /// How this opcode behaves in a tapscript:
    /// `ok` plain consensus; `covenant` needs the named deployment;
    /// `success` is OP_SUCCESSx, which makes the whole script pass;
    /// `disallowed` fails the script outright; `legacy` is pre-taproot only.
    pub status: String,
    /// Deployment this opcode belongs to, for `covenant` entries.
    pub deployment: Option<String>,
}

fn entry(
    name: &str,
    alias: Option<&str>,
    category: &str,
    status: &str,
    deployment: Option<&str>,
) -> Option<OpcodeInfo> {
    let op = covenants_core::parse_opcode(name).ok()?;
    Some(OpcodeInfo {
        name: name.to_string(),
        alias: alias.map(|s| s.to_string()),
        byte: op.to_u8(),
        category: category.to_string(),
        status: status.to_string(),
        deployment: deployment.map(|s| s.to_string()),
    })
}

/// Every opcode worth writing in a tapscript, in the order the editor
/// should offer them. The 75 OP_PUSHBYTES_n and the OP_RETURN_n spellings
/// are left out: they are how a script decodes, not how one is written.
#[wasm_bindgen]
pub fn opcodes() -> Result<Ts<OpcodeCatalog>, JsError> {
    use std::iter::once;
    let mut out: Vec<OpcodeInfo> = Vec::new();
    let mut add = |name: &str, alias: Option<&str>, cat: &str, status: &str, dep: Option<&str>| {
        if let Some(e) = entry(name, alias, cat, status, dep) {
            out.push(e);
        }
    };

    for n in once("OP_0")
        .chain((1..=16).map(|_| ""))
        .enumerate()
        .map(|(i, s)| {
            if i == 0 {
                s.to_string()
            } else {
                format!("OP_{i}")
            }
        })
    {
        add(&n, None, "constants", "ok", None);
    }
    add(
        "OP_1NEGATE",
        Some("OP_PUSHNUM_NEG1"),
        "constants",
        "ok",
        None,
    );

    for (name, alias) in [
        ("OP_TOALTSTACK", None),
        ("OP_FROMALTSTACK", None),
        ("OP_2DROP", None),
        ("OP_2DUP", None),
        ("OP_3DUP", None),
        ("OP_2OVER", None),
        ("OP_2ROT", None),
        ("OP_2SWAP", None),
        ("OP_IFDUP", None),
        ("OP_DEPTH", None),
        ("OP_DROP", None),
        ("OP_DUP", None),
        ("OP_NIP", None),
        ("OP_OVER", None),
        ("OP_PICK", None),
        ("OP_ROLL", None),
        ("OP_ROT", None),
        ("OP_SWAP", None),
        ("OP_TUCK", None),
    ] {
        add(name, alias, "stack", "ok", None);
    }

    for name in [
        "OP_IF",
        "OP_NOTIF",
        "OP_ELSE",
        "OP_ENDIF",
        "OP_VERIFY",
        "OP_RETURN",
    ] {
        add(name, None, "flow", "ok", None);
    }

    add("OP_SIZE", None, "splice", "ok", None);
    add("OP_EQUAL", None, "compare", "ok", None);
    add("OP_EQUALVERIFY", None, "compare", "ok", None);

    for name in [
        "OP_1ADD",
        "OP_1SUB",
        "OP_NEGATE",
        "OP_ABS",
        "OP_NOT",
        "OP_0NOTEQUAL",
        "OP_ADD",
        "OP_SUB",
        "OP_BOOLAND",
        "OP_BOOLOR",
        "OP_NUMEQUAL",
        "OP_NUMEQUALVERIFY",
        "OP_NUMNOTEQUAL",
        "OP_LESSTHAN",
        "OP_GREATERTHAN",
        "OP_LESSTHANOREQUAL",
        "OP_GREATERTHANOREQUAL",
        "OP_MIN",
        "OP_MAX",
        "OP_WITHIN",
    ] {
        add(name, None, "arithmetic", "ok", None);
    }

    for name in [
        "OP_RIPEMD160",
        "OP_SHA1",
        "OP_SHA256",
        "OP_HASH160",
        "OP_HASH256",
        "OP_CODESEPARATOR",
    ] {
        add(name, None, "crypto", "ok", None);
    }
    add("OP_CHECKSIG", None, "crypto", "ok", None);
    add("OP_CHECKSIGVERIFY", None, "crypto", "ok", None);
    add("OP_CHECKSIGADD", None, "crypto", "ok", None);

    add(
        "OP_CHECKLOCKTIMEVERIFY",
        Some("OP_CLTV"),
        "locktime",
        "ok",
        None,
    );
    add(
        "OP_CHECKSEQUENCEVERIFY",
        Some("OP_CSV"),
        "locktime",
        "ok",
        None,
    );

    add(
        "OP_CHECKTEMPLATEVERIFY",
        Some("OP_CTV"),
        "covenants",
        "covenant",
        Some("ctv"),
    );
    add(
        "OP_CHECKSIGFROMSTACK",
        Some("OP_CSFS"),
        "covenants",
        "covenant",
        Some("csfs"),
    );
    add("OP_CAT", None, "covenants", "covenant", Some("cat"));
    add(
        "OP_TEMPLATEHASH",
        Some("OP_TH"),
        "covenants",
        "covenant",
        Some("templatehash"),
    );
    add(
        "OP_INTERNALKEY",
        None,
        "covenants",
        "covenant",
        Some("internalkey"),
    );
    add(
        "OP_PAIRCOMMIT",
        Some("OP_PC"),
        "covenants",
        "covenant",
        Some("paircommit"),
    );
    add("OP_TXHASH", None, "covenants", "covenant", Some("txhash"));
    add(
        "OP_CHECKCONTRACTVERIFY",
        Some("OP_CCV"),
        "covenants",
        "covenant",
        Some("ccv"),
    );

    // Disabled before taproot, OP_SUCCESSx inside a tapscript: writing one
    // makes the whole script pass, which is never what an author means.
    for name in [
        "OP_SUBSTR",
        "OP_LEFT",
        "OP_RIGHT",
        "OP_INVERT",
        "OP_AND",
        "OP_OR",
        "OP_XOR",
        "OP_2MUL",
        "OP_2DIV",
        "OP_MUL",
        "OP_DIV",
        "OP_MOD",
        "OP_LSHIFT",
        "OP_RSHIFT",
    ] {
        add(name, None, "op_success", "success", None);
    }

    // Rejected by BIP-342 rather than made a no-op.
    add("OP_CHECKMULTISIG", None, "legacy", "disallowed", None);
    add("OP_CHECKMULTISIGVERIFY", None, "legacy", "disallowed", None);

    for name in [
        "OP_NOP", "OP_NOP1", "OP_NOP5", "OP_NOP6", "OP_NOP7", "OP_NOP8", "OP_NOP9", "OP_NOP10",
    ] {
        add(name, None, "nop", "ok", None);
    }

    OpcodeCatalog { opcodes: out }
        .into_ts()
        .map_err(err("response"))
}

// ---------------------------------------------------------------------------
// BIP-446 template hash.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Tsify)]
pub struct TemplateHashRequest {
    /// Spending transaction hex.
    pub tx: String,
    pub input_index: u32,
    /// Taproot annex, hex, including its 0x50 prefix. Committed when present.
    #[serde(default)]
    #[tsify(optional, type = "string")]
    pub annex: Option<String>,
}

/// The BIP-446 template hash for one input. It commits to no prevout, no
/// scriptPubKey and no amount, so a signature over it binds the shape of
/// the transaction rather than the coin it spends.
#[wasm_bindgen]
pub fn template_hash_446(req: Ts<TemplateHashRequest>) -> Result<String, JsError> {
    let req = req.to_rust().map_err(err("request"))?;
    let tx: Transaction = deserialize(&hex(&req.tx, "tx")?).map_err(err("tx"))?;
    let annex = match &req.annex {
        Some(a) => Some(hex(a, "annex")?),
        None => None,
    };
    let h = covenants_core::templatehash::template_hash(
        &tx,
        req.input_index as usize,
        annex.as_deref(),
    )
    .map_err(|e| JsError::new(&format!("template hash: {e:?}")))?;
    Ok(h.to_lower_hex_string())
}
