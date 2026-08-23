use bitcoin::consensus::encode::VarInt;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::taproot::TapLeafHash;
use bitcoin::{TapSighash, Transaction, TxOut};

pub const SIGHASH_DEFAULT: u8 = 0x00;
pub const SIGHASH_ALL: u8 = 0x01;
pub const SIGHASH_NONE: u8 = 0x02;
pub const SIGHASH_SINGLE: u8 = 0x03;
pub const SIGHASH_ANYONECANPAY: u8 = 0x80;
pub const SIGHASH_ANYPREVOUT: u8 = 0x40;
pub const SIGHASH_ANYPREVOUTANYSCRIPT: u8 = 0xc0;

/// key_version byte committed in the sighash extension. 0x00 for BIP-342
/// keys, 0x01 for BIP-118 keys; the split prevents signature reuse across
/// the two key types under the same private key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyVersion {
    V0,
    Bip118,
}

impl KeyVersion {
    fn to_u8(self) -> u8 {
        match self {
            KeyVersion::V0 => 0x00,
            KeyVersion::Bip118 => 0x01,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prevouts<'a> {
    All(&'a [TxOut]),
    One(usize, &'a TxOut),
    None,
}

impl<'a> Prevouts<'a> {
    fn get(&self, input_index: usize) -> Result<&'a TxOut, SighashError> {
        match self {
            Prevouts::All(all) => all.get(input_index).ok_or(SighashError::MissingPrevouts),
            Prevouts::One(i, out) if *i == input_index => Ok(out),
            _ => Err(SighashError::MissingPrevouts),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SighashError {
    InvalidHashType(u8),
    SingleWithoutCorrespondingOutput,
    InputIndexOutOfBounds,
    /// The prevout data required by this hash_type mode was not supplied.
    MissingPrevouts,
}

pub fn is_valid_hash_type(hash_type: u8, key_version: KeyVersion) -> bool {
    match hash_type {
        0x00..=0x03 | 0x81..=0x83 => true,
        0x41..=0x43 | 0xc1..=0xc3 => key_version == KeyVersion::Bip118,
        _ => false,
    }
}

fn sha256_concat(mut f: impl FnMut(&mut sha256::HashEngine)) -> [u8; 32] {
    let mut e = sha256::Hash::engine();
    f(&mut e);
    sha256::Hash::from_engine(e).to_byte_array()
}

/// Taproot script-path sighash per BIP-341/342 (key_version 0x00) and
/// BIP-118 (key_version 0x01). ext_flag is always 1: this computes the
/// script-spend digest, never the key-path digest.
pub fn script_spend_sighash(
    tx: &Transaction,
    input_index: usize,
    prevouts: Prevouts,
    hash_type: u8,
    key_version: KeyVersion,
    tapleaf_hash: TapLeafHash,
    codesep_pos: u32,
    annex: Option<&[u8]>,
) -> Result<[u8; 32], SighashError> {
    let msg = script_spend_preimage(
        tx, input_index, prevouts, hash_type, key_version, tapleaf_hash, codesep_pos, annex,
    )?;
    let mut engine = TapSighash::engine();
    engine.input(&msg);
    Ok(TapSighash::from_engine(engine).to_byte_array())
}

/// The bytes the sighash is the tagged hash of, without the epoch-0x00 that
/// the TapSighash tag prepends. A script rebuilding its own signature
/// message with OP_CAT needs exactly these, which is the only reason this
/// is public.
#[allow(clippy::too_many_arguments)]
pub fn script_spend_preimage(
    tx: &Transaction,
    input_index: usize,
    prevouts: Prevouts,
    hash_type: u8,
    key_version: KeyVersion,
    tapleaf_hash: TapLeafHash,
    codesep_pos: u32,
    annex: Option<&[u8]>,
) -> Result<Vec<u8>, SighashError> {
    if !is_valid_hash_type(hash_type, key_version) {
        return Err(SighashError::InvalidHashType(hash_type));
    }
    if input_index >= tx.input.len() {
        return Err(SighashError::InputIndexOutOfBounds);
    }

    let output_type = hash_type & 0x03;
    let input_mode = hash_type & 0xc0;
    let anyonecanpay = hash_type & SIGHASH_ANYONECANPAY != 0;

    let mut msg = Vec::with_capacity(256);
    msg.push(0x00);
    msg.push(hash_type);
    msg.extend_from_slice(&tx.version.0.to_le_bytes());
    msg.extend_from_slice(&tx.lock_time.to_consensus_u32().to_le_bytes());

    if !anyonecanpay && input_mode == 0x00 {
        let all = match prevouts {
            Prevouts::All(all) if all.len() == tx.input.len() => all,
            _ => return Err(SighashError::MissingPrevouts),
        };
        msg.extend_from_slice(&sha256_concat(|e| {
            for i in &tx.input {
                i.previous_output.consensus_encode(e).expect("engine write");
            }
        }));
        msg.extend_from_slice(&sha256_concat(|e| {
            for p in all {
                e.input(&p.value.to_sat().to_le_bytes());
            }
        }));
        msg.extend_from_slice(&sha256_concat(|e| {
            for p in all {
                p.script_pubkey.consensus_encode(e).expect("engine write");
            }
        }));
        msg.extend_from_slice(&sha256_concat(|e| {
            for i in &tx.input {
                e.input(&i.sequence.0.to_le_bytes());
            }
        }));
    }

    if output_type != SIGHASH_NONE && output_type != SIGHASH_SINGLE {
        msg.extend_from_slice(&sha256_concat(|e| {
            for o in &tx.output {
                o.consensus_encode(e).expect("engine write");
            }
        }));
    }

    let spend_type: u8 = 2 + annex.is_some() as u8;
    msg.push(spend_type);

    let txin = &tx.input[input_index];
    match input_mode {
        0x00 => {
            msg.extend_from_slice(&(input_index as u32).to_le_bytes());
        }
        0x80 => {
            let prevout = prevouts.get(input_index)?;
            txin.previous_output
                .consensus_encode(&mut msg)
                .expect("vec write");
            msg.extend_from_slice(&prevout.value.to_sat().to_le_bytes());
            prevout
                .script_pubkey
                .consensus_encode(&mut msg)
                .expect("vec write");
            msg.extend_from_slice(&txin.sequence.0.to_le_bytes());
        }
        0x40 => {
            let prevout = prevouts.get(input_index)?;
            msg.extend_from_slice(&prevout.value.to_sat().to_le_bytes());
            prevout
                .script_pubkey
                .consensus_encode(&mut msg)
                .expect("vec write");
            msg.extend_from_slice(&txin.sequence.0.to_le_bytes());
        }
        0xc0 => {
            msg.extend_from_slice(&txin.sequence.0.to_le_bytes());
        }
        _ => unreachable!(),
    }

    if let Some(annex) = annex {
        msg.extend_from_slice(&sha256_concat(|e| {
            VarInt::from(annex.len()).consensus_encode(e).expect("engine write");
            e.input(annex);
        }));
    }

    if output_type == SIGHASH_SINGLE {
        let out = tx
            .output
            .get(input_index)
            .ok_or(SighashError::SingleWithoutCorrespondingOutput)?;
        msg.extend_from_slice(&sha256_concat(|e| {
            out.consensus_encode(e).expect("engine write");
        }));
    }

    if input_mode != SIGHASH_ANYPREVOUTANYSCRIPT {
        msg.extend_from_slice(&tapleaf_hash.to_byte_array());
    }
    msg.push(key_version.to_u8());
    msg.extend_from_slice(&codesep_pos.to_le_bytes());
    Ok(msg)
}
