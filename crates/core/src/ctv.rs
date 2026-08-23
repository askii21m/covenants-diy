use bitcoin::consensus::Encodable;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::opcodes::all::OP_NOP4;
use bitcoin::script::Builder;
use bitcoin::{ScriptBuf, Transaction};

/// `<hash> OP_CHECKTEMPLATEVERIFY`.
pub fn ctv_script(hash: &[u8; 32]) -> ScriptBuf {
    Builder::new()
        .push_slice(hash)
        .push_opcode(OP_NOP4)
        .into_script()
}

/// DefaultCheckTemplateVerifyHash per BIP-119. All hashes are single SHA256;
/// the scriptSig hash is committed only when at least one input has a
/// non-empty scriptSig.
pub fn default_template_hash(tx: &Transaction, input_index: u32) -> [u8; 32] {
    let mut buf = Vec::with_capacity(128);
    buf.extend_from_slice(&tx.version.0.to_le_bytes());
    buf.extend_from_slice(&tx.lock_time.to_consensus_u32().to_le_bytes());

    if tx.input.iter().any(|i| !i.script_sig.is_empty()) {
        let mut ss = Vec::new();
        for i in &tx.input {
            i.script_sig.consensus_encode(&mut ss).expect("vec write");
        }
        buf.extend_from_slice(sha256::Hash::hash(&ss).as_byte_array());
    }

    buf.extend_from_slice(&(tx.input.len() as u32).to_le_bytes());

    let mut seqs = Vec::with_capacity(4 * tx.input.len());
    for i in &tx.input {
        seqs.extend_from_slice(&i.sequence.0.to_le_bytes());
    }
    buf.extend_from_slice(sha256::Hash::hash(&seqs).as_byte_array());

    buf.extend_from_slice(&(tx.output.len() as u32).to_le_bytes());

    let mut outs = Vec::new();
    for o in &tx.output {
        o.consensus_encode(&mut outs).expect("vec write");
    }
    buf.extend_from_slice(sha256::Hash::hash(&outs).as_byte_array());

    buf.extend_from_slice(&input_index.to_le_bytes());

    sha256::Hash::hash(&buf).to_byte_array()
}
