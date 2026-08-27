//! BIP-443 OP_CHECKCONTRACTVERIFY.
//!
//! A contract is a taproot output whose internal key carries data: take a
//! naked key, tweak it by the data the contract holds, then taptweak that
//! by a script tree. The opcode checks that some input or output of the
//! spending transaction is exactly that output, which is what lets a script
//! say "the coin must move to this same program, with this new state".
//!
//! Two tweaks, and they are not the same construction. The data tweak is a
//! plain SHA-256 over the key and the data; the tree tweak is BIP-341's
//! tagged TapTweak. Committing to the same 32 bytes through one or the
//! other gives different keys.
//!
//! Where BIP-119 differs: CTV commits to a whole transaction template, so
//! the next transaction is fixed when the coin is created. A contract fixes
//! only the shape of the program the coin moves into, so the state can be
//! chosen at spend time and still be constrained.

use std::sync::OnceLock;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Scalar, Secp256k1, VerifyOnly, XOnlyPublicKey};
use bitcoin::taproot::{TapNodeHash, TapTweakHash};
use bitcoin::ScriptBuf;

/// Check an input's script; no amount check.
pub const CCV_MODE_CHECK_INPUT: i64 = -1;
/// Check an output's script, and carry this input's residual amount into it.
pub const CCV_MODE_CHECK_OUTPUT: i64 = 0;
/// Check an output's script and leave amounts alone.
pub const CCV_MODE_CHECK_OUTPUT_IGNORE_AMOUNT: i64 = 1;
/// Check an output's script, taking its amount out of the residual.
pub const CCV_MODE_CHECK_OUTPUT_DEDUCT_AMOUNT: i64 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CcvMode {
    CheckInput,
    CheckOutput,
    CheckOutputIgnoreAmount,
    CheckOutputDeductAmount,
}

impl CcvMode {
    /// A mode outside the defined range is left for a future deployment to
    /// give meaning to, and succeeds the script outright rather than
    /// failing, so this returns None for it.
    pub fn from_i64(v: i64) -> Option<CcvMode> {
        match v {
            CCV_MODE_CHECK_INPUT => Some(CcvMode::CheckInput),
            CCV_MODE_CHECK_OUTPUT => Some(CcvMode::CheckOutput),
            CCV_MODE_CHECK_OUTPUT_IGNORE_AMOUNT => Some(CcvMode::CheckOutputIgnoreAmount),
            CCV_MODE_CHECK_OUTPUT_DEDUCT_AMOUNT => Some(CcvMode::CheckOutputDeductAmount),
            _ => None,
        }
    }

    pub fn targets_input(self) -> bool {
        self == CcvMode::CheckInput
    }
}

/// The only way this arithmetic fails. Parameter shapes are rejected before
/// they reach here, by the interpreter that reads them off the stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CcvError {
    /// A tweak landed outside the group order, or the tweaked point is the
    /// point at infinity. Both are unreachable for honestly chosen data.
    Tweak,
}

fn secp() -> &'static Secp256k1<VerifyOnly> {
    static S: OnceLock<Secp256k1<VerifyOnly>> = OnceLock::new();
    S.get_or_init(Secp256k1::verification_only)
}

/// The BIP-443 data tweak: a plain SHA-256 over the key and the data, added
/// to the key as a scalar. Deliberately not a tagged hash, and not the same
/// as taptweaking by the same bytes.
pub fn tweak_embed_data(naked: &XOnlyPublicKey, data: &[u8]) -> Result<XOnlyPublicKey, CcvError> {
    if data.is_empty() {
        return Ok(*naked);
    }
    let mut preimage = Vec::with_capacity(32 + data.len());
    preimage.extend_from_slice(&naked.serialize());
    preimage.extend_from_slice(data);
    let t = sha256::Hash::hash(&preimage).to_byte_array();
    let scalar = Scalar::from_be_bytes(t).map_err(|_| CcvError::Tweak)?;
    let (key, _parity) = naked
        .add_tweak(secp(), &scalar)
        .map_err(|_| CcvError::Tweak)?;
    Ok(key)
}

/// The scriptPubKey the opcode requires at the target: the naked key,
/// tweaked by the data, then taptweaked by the tree when one is given.
pub fn expected_script_pubkey(
    naked: &XOnlyPublicKey,
    data: &[u8],
    taptree: Option<[u8; 32]>,
) -> Result<ScriptBuf, CcvError> {
    let internal = tweak_embed_data(naked, data)?;
    let output_key = match taptree {
        Some(root) => {
            // rust-bitcoin's tap_tweak panics on a tweak out of range rather
            // than returning, and the root here is an arbitrary push from a
            // script, so the same arithmetic is done with the error kept.
            let t =
                TapTweakHash::from_key_and_tweak(internal, Some(TapNodeHash::assume_hidden(root)));
            let scalar = Scalar::from_be_bytes(t.to_byte_array()).map_err(|_| CcvError::Tweak)?;
            let (key, _parity) = internal
                .add_tweak(secp(), &scalar)
                .map_err(|_| CcvError::Tweak)?;
            key
        }
        None => internal,
    };
    let mut spk = Vec::with_capacity(34);
    spk.push(0x51);
    spk.push(0x20);
    spk.extend_from_slice(&output_key.serialize());
    Ok(ScriptBuf::from(spk))
}

#[cfg(test)]
mod tests {
    use super::*;
    // The differential check below compares this module's own tweak against
    // rust-bitcoin's, which is the point of keeping both.
    use bitcoin::key::TapTweak;
    use std::str::FromStr;

    /// Private key 7, so the vectors are reproducible from the model.
    fn key() -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&{
            let mut b = [0u8; 32];
            b[31] = 7;
            b
        })
        .unwrap();
        sk.x_only_public_key(&secp).0
    }

    fn nums() -> XOnlyPublicKey {
        crate::taproot::nums_internal_key()
    }

    fn spk_hex(naked: &XOnlyPublicKey, data: &[u8], tree: Option<[u8; 32]>) -> String {
        use bitcoin::hex::DisplayHex;
        expected_script_pubkey(naked, data, tree)
            .unwrap()
            .as_bytes()
            .to_lower_hex_string()
    }

    fn tree(byte: u8) -> Option<[u8; 32]> {
        Some([byte; 32])
    }

    /// Generated from the spec's pseudocode by an independent model, since
    /// BIP-443 publishes no vectors of its own.
    #[test]
    fn matches_the_independent_model() {
        assert_eq!(
            spk_hex(&key(), b"", None),
            "51205cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc"
        );
        assert_eq!(
            spk_hex(&key(), b"hello", None),
            "5120607a22a263458e92d1d83b1cb64359fced43c0d0434fbf2effaa31e976433d0f"
        );
        assert_eq!(
            spk_hex(&key(), b"", tree(0x11)),
            "512090f2e067ba033147c0d22c7aafc997a4199a01bf2235b0894c32c56abd444e18"
        );
        assert_eq!(
            spk_hex(&key(), b"world", tree(0x22)),
            "51209a707c41596840c1f887aeb546a92172be987ade46bf428e35228c2aa9edf926"
        );
        assert_eq!(
            spk_hex(&nums(), b"state", None),
            "512031f42326f6dcf54ab5c140c9ebe67ceccf8678b1bdd0cf90adb917c9a828b798"
        );
        assert_eq!(
            spk_hex(&nums(), b"state", tree(0x33)),
            "51202e309f81803064572ca365872039257595b8bec3d933ee57e9f78865fea1f53a"
        );
        let long: Vec<u8> = (0u8..80).collect();
        assert_eq!(
            spk_hex(&key(), &long, tree(0x44)),
            "5120b09393aaf15b84e880e8373295827d09a5488b3a50f54aa27ca7581e30fe2c8f"
        );
        assert_eq!(
            spk_hex(&key(), b"\x01", None),
            "51202ec3fc05c42162f81509fbe59f3c75ca99f608b6b77bf80a236a81334cd9bb6c"
        );
    }

    /// The taptweak half is BIP-341's, so rust-bitcoin computes it too.
    /// Agreeing with it anchors the point arithmetic the data tweak also
    /// relies on.
    #[test]
    fn taptweak_agrees_with_rust_bitcoin() {
        let secp = Secp256k1::new();
        let k = key();
        let root = TapNodeHash::assume_hidden([0x11; 32]);
        let (theirs, _) = k.tap_tweak(&secp, Some(root));
        let mine = expected_script_pubkey(&k, b"", tree(0x11)).unwrap();
        let mut want = vec![0x51, 0x20];
        want.extend_from_slice(&theirs.to_x_only_public_key().serialize());
        assert_eq!(mine.as_bytes(), &want[..]);
    }

    /// The two tweaks are different constructions, so committing to the
    /// same 32 bytes through each must not land on the same key.
    #[test]
    fn the_data_tweak_is_not_the_taptweak() {
        let k = key();
        let bytes = [0x5a; 32];
        let data_side = expected_script_pubkey(&k, &bytes, None).unwrap();
        let tree_side = expected_script_pubkey(&k, b"", Some(bytes)).unwrap();
        assert_ne!(data_side, tree_side);
    }

    #[test]
    fn empty_data_leaves_the_key_alone() {
        let k = key();
        assert_eq!(tweak_embed_data(&k, b"").unwrap(), k);
        assert_ne!(tweak_embed_data(&k, b"x").unwrap(), k);
    }

    /// Data is committed to whole: one byte different is a different key.
    #[test]
    fn every_byte_of_the_data_is_committed() {
        let k = key();
        let a = expected_script_pubkey(&k, b"state-1", None).unwrap();
        let b = expected_script_pubkey(&k, b"state-2", None).unwrap();
        assert_ne!(a, b);
    }

    /// The naked key is part of the tweak preimage, so two keys carrying
    /// the same data stay distinct.
    #[test]
    fn the_naked_key_is_in_the_preimage() {
        let a = expected_script_pubkey(&key(), b"same", None).unwrap();
        let b = expected_script_pubkey(&nums(), b"same", None).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn the_result_is_a_p2tr_script() {
        let spk = expected_script_pubkey(&key(), b"anything", None).unwrap();
        let b = spk.as_bytes();
        assert_eq!(b.len(), 34);
        assert_eq!(b[0], 0x51);
        assert_eq!(b[1], 0x20);
        assert!(spk.is_p2tr());
    }

    #[test]
    fn modes_decode_and_the_rest_are_left_open() {
        assert_eq!(CcvMode::from_i64(-1), Some(CcvMode::CheckInput));
        assert_eq!(CcvMode::from_i64(0), Some(CcvMode::CheckOutput));
        assert_eq!(CcvMode::from_i64(1), Some(CcvMode::CheckOutputIgnoreAmount));
        assert_eq!(CcvMode::from_i64(2), Some(CcvMode::CheckOutputDeductAmount));
        for undefined in [-2i64, 3, 100, i64::MIN, i64::MAX] {
            assert_eq!(CcvMode::from_i64(undefined), None);
        }
        assert!(CcvMode::CheckInput.targets_input());
        assert!(!CcvMode::CheckOutput.targets_input());
    }

    #[test]
    fn the_nums_key_is_the_one_bip341_defines() {
        assert_eq!(
            nums(),
            XOnlyPublicKey::from_str(
                "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
            )
            .unwrap()
        );
    }
}
