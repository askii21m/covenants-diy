//! BIP-446 OP_TEMPLATEHASH.
//!
//! A template hash commits to the transaction spending an output, without
//! committing to what is being spent: no prevouts, no scriptPubKeys, no
//! amounts. That omission is the point. It keeps the hash out of a cycle
//! when the hash is committed inside the output it constrains, and it is
//! what makes a signature over the hash rebindable onto a later state.
//!
//! Where BIP-119 differs: CTV verifies against a hash on the stack and is
//! defined for legacy script too; OP_TEMPLATEHASH pushes and is tapscript
//! only, so it composes. CTV commits to input scriptSigs, which a taproot
//! spend has none of; OP_TEMPLATEHASH commits to the annex, which CTV does
//! not.

use bitcoin::consensus::encode::VarInt;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::Transaction;

/// BIP-340 tagged hash.
fn tagged(tag: &str, data: &[u8]) -> [u8; 32] {
    let t = sha256::Hash::hash(tag.as_bytes());
    let mut e = sha256::Hash::engine();
    e.input(t.as_byte_array());
    e.input(t.as_byte_array());
    e.input(data);
    sha256::Hash::from_engine(e).to_byte_array()
}

fn sha256_of(f: impl FnOnce(&mut sha256::HashEngine)) -> [u8; 32] {
    let mut e = sha256::Hash::engine();
    f(&mut e);
    sha256::Hash::from_engine(e).to_byte_array()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemplateHashError {
    InputIndexOutOfBounds,
}

/// The BIP-446 template hash for one input of a transaction.
///
/// The preimage is, in order: nVersion, nLockTime, sha_sequences,
/// sha_outputs, annex_present, input_index, and sha_annex when an annex is
/// present. Four-byte values are little-endian.
pub fn template_hash(
    tx: &Transaction,
    input_index: usize,
    annex: Option<&[u8]>,
) -> Result<[u8; 32], TemplateHashError> {
    if input_index >= tx.input.len() {
        return Err(TemplateHashError::InputIndexOutOfBounds);
    }
    let mut msg = Vec::with_capacity(109);
    msg.extend_from_slice(&tx.version.0.to_le_bytes());
    msg.extend_from_slice(&tx.lock_time.to_consensus_u32().to_le_bytes());
    // sha_sequences and sha_outputs are BIP-341's, unchanged, so a node
    // already computing them for signature validation reuses them here.
    msg.extend_from_slice(&sha256_of(|e| {
        for i in &tx.input {
            e.input(&i.sequence.0.to_le_bytes());
        }
    }));
    msg.extend_from_slice(&sha256_of(|e| {
        for o in &tx.output {
            o.consensus_encode(e).expect("engine write");
        }
    }));
    msg.push(annex.is_some() as u8);
    msg.extend_from_slice(&(input_index as u32).to_le_bytes());
    if let Some(annex) = annex {
        msg.extend_from_slice(&sha256_of(|e| {
            VarInt::from(annex.len()).consensus_encode(e).expect("engine write");
            e.input(annex);
        }));
    }
    Ok(tagged("TemplateHash", &msg))
}
