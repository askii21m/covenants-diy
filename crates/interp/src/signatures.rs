use bitcoin::secp256k1::ffi::CPtr;
use bitcoin::secp256k1::{self, PublicKey, XOnlyPublicKey};
use bitcoin::sighash::{Annex, EcdsaSighashType, Prevouts, TapSighashType};

use covenants_core::sighash as core_sighash;

use crate::*;

lazy_static::lazy_static! {
    static ref SECP: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
}

/// BIP-340 verification over a message of arbitrary length. The safe rust
/// API only takes 32-byte digests; libsecp256k1 itself is variable-length,
/// which BIP-348 requires since the CSFS message is not pre-hashed.
fn verify_schnorr_varlen(sig: &[u8; 64], msg: &[u8], pk: &XOnlyPublicKey) -> bool {
    unsafe {
        secp256k1::ffi::secp256k1_schnorrsig_verify(
            secp256k1::ffi::secp256k1_context_no_precomp,
            sig.as_ptr(),
            if msg.is_empty() {
                core::ptr::null()
            } else {
                msg.as_ptr()
            },
            msg.len(),
            pk.as_c_ptr(),
        ) == 1
    }
}

impl Exec {
    pub fn check_sig_ecdsa(&mut self, sig: &[u8], pk: &[u8], script_code: &[u8]) -> bool {
        let pk = match PublicKey::from_slice(pk) {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        if sig.is_empty() {
            return false;
        }

        let hashtype = *sig.last().unwrap();
        let sig = match secp256k1::ecdsa::Signature::from_der(&sig[0..sig.len() - 1]) {
            Ok(s) => s,
            Err(_) => return false,
        };

        let sighash = if self.ctx == ExecCtx::SegwitV0 {
            self.sighashcache
                .p2wsh_signature_hash(
                    self.tx.input_idx,
                    Script::from_bytes(script_code),
                    self.tx.prevouts[self.tx.input_idx].value,
                    //TODO(stevenroose) this might not actually emulate consensus behavior
                    EcdsaSighashType::from_consensus(hashtype as u32),
                )
                .expect("only happens on prevout index out of bounds")
                .into()
        } else if self.ctx == ExecCtx::Legacy {
            self.sighashcache
                .legacy_signature_hash(
                    self.tx.input_idx,
                    Script::from_bytes(script_code),
                    hashtype as u32,
                )
                .expect("TODO(stevenroose) seems to only happen if prevout index out of bound")
                .into()
        } else {
            unreachable!();
        };

        SECP.verify_ecdsa(&sighash, &sig, &pk).is_ok()
    }

    /// [pk] should be passed as 32-bytes.
    pub fn check_sig_schnorr(&mut self, sig: &[u8], pk: &[u8]) -> Result<(), ExecError> {
        assert_eq!(pk.len(), 32);

        if sig.len() != 64 && sig.len() != 65 {
            return Err(ExecError::SchnorrSigSize);
        }

        let pk = XOnlyPublicKey::from_slice(pk).map_err(|_| ExecError::SchnorrSig)?;
        let (sig, hashtype) = if sig.len() == 65 {
            let b = *sig.last().unwrap();
            let sig = secp256k1::schnorr::Signature::from_slice(&sig[0..sig.len() - 1])
                .map_err(|_| ExecError::SchnorrSig)?;

            if b == TapSighashType::Default as u8 {
                return Err(ExecError::SchnorrSigHashtype);
            }
            let sht =
                TapSighashType::from_consensus_u8(b).map_err(|_| ExecError::SchnorrSigHashtype)?;
            (sig, sht)
        } else {
            let sig = secp256k1::schnorr::Signature::from_slice(sig)
                .map_err(|_| ExecError::SchnorrSig)?;
            (sig, TapSighashType::Default)
        };

        let (leaf_hash, annex) = self.tx.taproot_annex_scriptleaf.as_ref().unwrap();
        let sighash = self
            .sighashcache
            .taproot_signature_hash(
                self.tx.input_idx,
                &Prevouts::All(&self.tx.prevouts),
                annex
                    .as_ref()
                    .map(|a| Annex::new(a).expect("we checked annex prefix before")),
                Some((*leaf_hash, self.last_codeseparator_pos.unwrap_or(u32::MAX))),
                hashtype,
            )
            .expect("TODO(stevenroose) seems to only happen if prevout index out of bound");

        if SECP.verify_schnorr(&sig, &sighash.into(), &pk) != Ok(()) {
            return Err(ExecError::SchnorrSig);
        }

        Ok(())
    }

    /// BIP-118 signature verification for 0x01-type public keys.
    pub fn check_sig_schnorr_apo(&mut self, sig: &[u8], pk: &[u8]) -> Result<(), ExecError> {
        debug_assert!(pk[0] == 0x01 && (pk.len() == 1 || pk.len() == 33));

        let xonly = if pk.len() == 1 {
            self.tx
                .internal_key
                .ok_or(ExecError::Bip118InternalKeyMissing)?
        } else {
            XOnlyPublicKey::from_slice(&pk[1..]).map_err(|_| ExecError::SchnorrSig)?
        };

        let (sig64, hash_type) = match sig.len() {
            64 => (&sig[..64], 0x00u8),
            65 => {
                let ht = sig[64];
                if ht == 0x00
                    || !core_sighash::is_valid_hash_type(ht, core_sighash::KeyVersion::Bip118)
                {
                    return Err(ExecError::SchnorrSigHashtype);
                }
                (&sig[..64], ht)
            }
            _ => return Err(ExecError::SchnorrSigSize),
        };

        let (leaf_hash, annex) = self.tx.taproot_annex_scriptleaf.as_ref().unwrap();
        let digest = core_sighash::script_spend_sighash(
            &self.tx.tx,
            self.tx.input_idx,
            core_sighash::Prevouts::All(&self.tx.prevouts),
            hash_type,
            core_sighash::KeyVersion::Bip118,
            *leaf_hash,
            self.last_codeseparator_pos.unwrap_or(u32::MAX),
            annex.as_deref(),
        )
        .map_err(|_| ExecError::SchnorrSigHashtype)?;

        let sig = secp256k1::schnorr::Signature::from_slice(sig64)
            .map_err(|_| ExecError::SchnorrSig)?;
        let msg = secp256k1::Message::from_digest(digest);
        if SECP.verify_schnorr(&sig, &msg, &xonly).is_err() {
            return Err(ExecError::SchnorrSig);
        }
        Ok(())
    }

    /// BIP-348 verification: BIP-340 over the raw message.
    pub fn check_csfs_schnorr(&mut self, sig: &[u8], msg: &[u8], pk: &[u8]) -> Result<(), ExecError> {
        debug_assert_eq!(pk.len(), 32);
        if sig.len() != 64 {
            return Err(ExecError::SchnorrSigSize);
        }
        let pk = XOnlyPublicKey::from_slice(pk).map_err(|_| ExecError::SchnorrSig)?;
        let sig: &[u8; 64] = sig.try_into().expect("length checked");
        if !verify_schnorr_varlen(sig, msg, &pk) {
            return Err(ExecError::SchnorrSig);
        }
        Ok(())
    }
}
