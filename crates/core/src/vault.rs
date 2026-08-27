//! BIP-345 OP_VAULT and OP_VAULT_RECOVER.
//!
//! A vault is a taproot output with two leaves: one that recovers the coin
//! to a scriptPubKey fixed when the vault was made, and one that starts a
//! withdrawal. OP_VAULT spends the second into an output whose taptree is
//! the same tree with that one leaf rewritten, which is how a delay and a
//! destination chosen at spend time get locked in without having been known
//! when the coin was received. OP_VAULT_RECOVER spends either leaf's coin
//! to the recovery scriptPubKey, and stays available for as long as the
//! withdrawal is still waiting out its delay.
//!
//! Where BIP-119 differs: CTV fixes the whole next transaction when the coin
//! is created, so a vault built from CTV alone has to precommit every amount
//! it might ever withdraw. OP_VAULT fixes only the shape of the leaf, so the
//! destination is chosen at trigger time and the recovery path survives the
//! rewrite.
//!
//! This opcode and BIP-443's OP_CHECKCONTRACTVERIFY both claim
//! OP_SUCCESS187, so the two cannot be deployed together.

use bitcoin::hashes::Hash;
use bitcoin::opcodes::all::{OP_PUSHBYTES_0, OP_PUSHNUM_NEG1};
use bitcoin::opcodes::Opcode;
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::secp256k1::{Scalar, Secp256k1, VerifyOnly, XOnlyPublicKey};
use bitcoin::taproot::{ControlBlock, TapLeafHash, TapNodeHash, TapTweakHash};
use bitcoin::{Script, ScriptBuf};
use std::sync::OnceLock;

use crate::tagged::{compact_size, tagged};

/// BIP-342 validation weight OP_VAULT costs. The check does an EC
/// multiplication plus hashing over the control block, which the BIP prices
/// at roughly twice a Schnorr verification less the part a node could cache.
pub const VAULT_VALIDATION_WEIGHT: i64 = 60;

/// The largest satoshi value a CScriptNum can carry here. BIP-345 reads
/// `revault-amount` at 7 bytes so the whole money supply fits.
pub const VAULT_MAX_AMOUNT_SIZE: usize = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultError {
    /// A tweak landed outside the group order, or the tweaked point is the
    /// point at infinity. Both are unreachable for honestly chosen keys.
    Tweak,
    /// A leaf-update item longer than a script push can carry.
    ItemTooLarge,
    /// The control block is not a well-formed one.
    ControlBlock,
}

fn secp() -> &'static Secp256k1<VerifyOnly> {
    static S: OnceLock<Secp256k1<VerifyOnly>> = OnceLock::new();
    S.get_or_init(Secp256k1::verification_only)
}

/// `tagged_hash("VaultRecoverySPK", CompactSize(len(spk)) || spk)`. The
/// length prefix is what stops two different scriptPubKeys whose bytes
/// happen to run together from hashing alike.
pub fn recovery_spk_hash(spk: &Script) -> [u8; 32] {
    let mut data = compact_size(spk.len());
    data.extend_from_slice(spk.as_bytes());
    tagged("VaultRecoverySPK", &data)
}

/// One leaf-update item, pushed the way the spec's reference does it: the
/// short forms for small numbers, a data push otherwise. Getting this wrong
/// is invisible until a spend-delay small enough to reach OP_1..OP_16 makes
/// every taptree comparison miss.
fn push_item(builder: Builder, item: &[u8]) -> Result<Builder, VaultError> {
    if item.is_empty() {
        return Ok(builder.push_opcode(OP_PUSHBYTES_0));
    }
    if item.len() == 1 {
        match item[0] {
            n @ 1..=16 => return Ok(builder.push_opcode(Opcode::from(0x50 + n))),
            0x81 => return Ok(builder.push_opcode(OP_PUSHNUM_NEG1)),
            _ => {}
        }
    }
    let bytes = PushBytesBuf::try_from(item.to_vec()).map_err(|_| VaultError::ItemTooLarge)?;
    Ok(builder.push_slice(bytes))
}

/// The leaf that replaces the executing one: the items pushed in order,
/// then the body appended whole. `items` runs deepest-stack-first, which is
/// the order the pushes appear in the finished script.
pub fn leaf_update_script(items: &[Vec<u8>], body: &[u8]) -> Result<ScriptBuf, VaultError> {
    let mut builder = Builder::new();
    for item in items {
        builder = push_item(builder, item)?;
    }
    let mut out = builder.into_script().to_bytes();
    out.extend_from_slice(body);
    Ok(ScriptBuf::from(out))
}

/// The x-only key a trigger output must carry: the spent input's tree with
/// the executing leaf swapped for `new_leaf`, then taptweaked.
///
/// The control block supplies the merkle path and the internal key, so the
/// rest of the tree is carried over without ever being named. The parity of
/// the result is not returned because BIP-345 lets it vary.
pub fn expected_trigger_output_key(
    control_block: &[u8],
    new_leaf: &Script,
) -> Result<XOnlyPublicKey, VaultError> {
    let cb = ControlBlock::decode(control_block).map_err(|_| VaultError::ControlBlock)?;
    let leaf = TapLeafHash::from_script(new_leaf, cb.leaf_version);
    let mut node = TapNodeHash::from(leaf);
    for step in cb.merkle_branch.as_slice() {
        node = TapNodeHash::from_node_hashes(node, *step);
    }
    // rust-bitcoin's tap_tweak panics on a tweak out of range rather than
    // returning, and the leaf here is built from arbitrary stack items.
    let t = TapTweakHash::from_key_and_tweak(cb.internal_key, Some(node));
    let scalar = Scalar::from_be_bytes(t.to_byte_array()).map_err(|_| VaultError::Tweak)?;
    let (key, _parity) = cb
        .internal_key
        .add_tweak(secp(), &scalar)
        .map_err(|_| VaultError::Tweak)?;
    Ok(key)
}

/// The scriptPubKey shape a trigger output must have. BIP-345 requires a
/// version 1 witness program; the caller checks the key inside it.
pub fn p2tr_script_pubkey(key: &XOnlyPublicKey) -> ScriptBuf {
    let mut spk = Vec::with_capacity(34);
    spk.push(0x51);
    spk.push(0x20);
    spk.extend_from_slice(&key.serialize());
    ScriptBuf::from(spk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hex::DisplayHex;
    use bitcoin::taproot::{LeafVersion, TaprootBuilder};

    fn hex(b: &[u8]) -> String {
        b.to_lower_hex_string()
    }

    fn key() -> XOnlyPublicKey {
        crate::taproot::nums_internal_key()
    }

    fn leaf(tag: u8) -> ScriptBuf {
        ScriptBuf::from(vec![0x51, 0x01, tag])
    }

    /// The spec's own worked example: a vault leaf carrying a spend delay
    /// and a push count of 2 becomes `<ctv-hash> <delay> OP_CSV OP_DROP
    /// OP_CTV`. The delay is small enough to take the OP_N short form,
    /// which is exactly the case a raw data push would get wrong.
    #[test]
    fn the_worked_example_from_the_bip() {
        let ctv_hash = vec![0xabu8; 32];
        let delay = vec![10u8];
        let body = vec![0xb2, 0x75, 0xb3];
        let script = leaf_update_script(&[ctv_hash.clone(), delay], &body).unwrap();
        let mut want = vec![0x20];
        want.extend_from_slice(&ctv_hash);
        want.push(0x5a);
        want.extend_from_slice(&body);
        assert_eq!(script.as_bytes(), &want[..]);
    }

    /// The short forms the reference's PushAll uses. A one-byte item in
    /// 1..=16 is OP_N, 0x81 is OP_1NEGATE, and empty is OP_0.
    #[test]
    fn small_items_take_the_short_push_forms() {
        let cases: [(&[u8], &[u8]); 7] = [
            (&[], &[0x00]),
            (&[1], &[0x51]),
            (&[16], &[0x60]),
            (&[0x81], &[0x4f]),
            (&[17], &[0x01, 0x11]),
            (&[0], &[0x01, 0x00]),
            (&[0x80], &[0x01, 0x80]),
        ];
        for (item, want) in cases {
            let got = leaf_update_script(&[item.to_vec()], &[]).unwrap();
            assert_eq!(got.as_bytes(), want, "item {}", hex(item));
        }
    }

    /// Zero and negative zero are distinct stack items and must not collapse
    /// onto the same push.
    #[test]
    fn zero_is_not_the_empty_item() {
        let empty = leaf_update_script(&[vec![]], &[]).unwrap();
        let zero = leaf_update_script(&[vec![0u8]], &[]).unwrap();
        assert_ne!(empty.as_bytes(), zero.as_bytes());
    }

    #[test]
    fn items_appear_in_the_order_given_and_the_body_last() {
        let s = leaf_update_script(&[vec![1], vec![2], vec![3]], &[0xac]).unwrap();
        assert_eq!(s.as_bytes(), &[0x51, 0x52, 0x53, 0xac]);
    }

    #[test]
    fn no_items_leaves_the_body_alone() {
        let s = leaf_update_script(&[], &[0xb2, 0x75]).unwrap();
        assert_eq!(s.as_bytes(), &[0xb2, 0x75]);
    }

    /// Substituting a leaf must land on the same output key as building the
    /// whole tree again with that leaf in place. Folding the control block
    /// of the old leaf is the only thing the opcode gets to do, so this is
    /// the property the opcode rests on.
    #[test]
    fn substitution_agrees_with_a_tree_rebuilt_around_it() {
        let secp = Secp256k1::new();
        let (old, new, b, c) = (leaf(1), leaf(9), leaf(2), leaf(3));

        let before = TaprootBuilder::new()
            .add_leaf(1, old.clone())
            .unwrap()
            .add_leaf(2, b.clone())
            .unwrap()
            .add_leaf(2, c.clone())
            .unwrap()
            .finalize(&secp, key())
            .unwrap();
        let after = TaprootBuilder::new()
            .add_leaf(1, new.clone())
            .unwrap()
            .add_leaf(2, b)
            .unwrap()
            .add_leaf(2, c)
            .unwrap()
            .finalize(&secp, key())
            .unwrap();

        let cb = before
            .control_block(&(old, LeafVersion::TapScript))
            .unwrap()
            .serialize();
        assert_eq!(
            expected_trigger_output_key(&cb, &new).unwrap(),
            after.output_key().to_x_only_public_key()
        );
    }

    /// A one-leaf tree has an empty merkle path, so the leaf is the root.
    #[test]
    fn a_single_leaf_tree_substitutes_too() {
        let secp = Secp256k1::new();
        let (old, new) = (leaf(1), leaf(2));
        let before = TaprootBuilder::new()
            .add_leaf(0, old.clone())
            .unwrap()
            .finalize(&secp, key())
            .unwrap();
        let after = TaprootBuilder::new()
            .add_leaf(0, new.clone())
            .unwrap()
            .finalize(&secp, key())
            .unwrap();
        let cb = before
            .control_block(&(old, LeafVersion::TapScript))
            .unwrap()
            .serialize();
        assert_eq!(
            expected_trigger_output_key(&cb, &new).unwrap(),
            after.output_key().to_x_only_public_key()
        );
    }

    /// Substituting the leaf that is already there changes nothing, which
    /// pins the fold against an off-by-one in the merkle path.
    #[test]
    fn substituting_a_leaf_for_itself_is_the_same_tree() {
        let secp = Secp256k1::new();
        let (a, b) = (leaf(1), leaf(2));
        let tree = TaprootBuilder::new()
            .add_leaf(1, a.clone())
            .unwrap()
            .add_leaf(1, b)
            .unwrap()
            .finalize(&secp, key())
            .unwrap();
        let cb = tree
            .control_block(&(a.clone(), LeafVersion::TapScript))
            .unwrap()
            .serialize();
        assert_eq!(
            expected_trigger_output_key(&cb, &a).unwrap(),
            tree.output_key().to_x_only_public_key()
        );
    }

    #[test]
    fn a_malformed_control_block_is_rejected() {
        for bad in [vec![], vec![0xc0; 32], vec![0xc0; 34], vec![0xc0; 66]] {
            assert_eq!(
                expected_trigger_output_key(&bad, &leaf(1)),
                Err(VaultError::ControlBlock),
                "len {}",
                bad.len()
            );
        }
    }

    /// The recovery hash covers the length as well as the bytes, so a
    /// scriptPubKey is not confusable with a longer one starting the same.
    #[test]
    fn the_recovery_hash_commits_to_the_length() {
        let a = recovery_spk_hash(Script::from_bytes(&[0x51, 0x02, 0xaa, 0xbb]));
        let b = recovery_spk_hash(Script::from_bytes(&[0x51, 0x02, 0xaa]));
        assert_ne!(a, b);
    }

    /// Derived from the BIP's own definition of the tag and preimage, since
    /// BIP-345 ships no vectors of its own.
    #[test]
    fn the_recovery_hash_matches_the_independent_model() {
        let spk = p2tr_script_pubkey(&key());
        assert_eq!(
            hex(&recovery_spk_hash(&spk)),
            "5a8f0816cb7b59a21f592e1c18c835e8d7cbf7db58efa579f341cbc62d459a22"
        );
    }

    #[test]
    fn the_trigger_script_pubkey_is_a_p2tr() {
        let spk = p2tr_script_pubkey(&key());
        assert_eq!(spk.len(), 34);
        assert!(spk.is_p2tr());
    }
}
