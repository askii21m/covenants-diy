//! Taproot output assembly: internal key plus leaf scripts to address,
//! scriptPubKey, output key, merkle root, and a control block per leaf.
//! All of it is rust-bitcoin's TaprootBuilder; this is the one place that
//! decides how leaves are arranged.

use std::str::FromStr;

use bitcoin::secp256k1::{Secp256k1, Verification, XOnlyPublicKey};
use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash, TaprootBuilder, TaprootSpendInfo};
use bitcoin::{Address, Network, ScriptBuf};

/// The BIP-341 nothing-up-my-sleeve point; outputs using it have no key path.
pub fn nums_internal_key() -> XOnlyPublicKey {
    XOnlyPublicKey::from_str("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
        .expect("constant")
}

#[derive(Debug, Clone)]
pub struct TaprootOutput {
    pub internal_key: XOnlyPublicKey,
    pub spend_info: TaprootSpendInfo,
    pub script_pubkey: ScriptBuf,
    pub address: Address,
    pub leaf_hashes: Vec<TapLeafHash>,
    pub control_blocks: Vec<ControlBlock>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaprootError {
    /// More leaves than a taptree can hold, or a duplicate script.
    Tree,
    Finalize,
}

/// Leaves are arranged by the huffman constructor with equal weights, which
/// yields the shallowest tree. A duplicate script is rejected rather than
/// deduplicated, because its control block would be ambiguous.
/// Depths for a balanced tree over `n` leaves, shallowest first, which is
/// also depth-first order.
///
/// Deliberately a function of the leaf count alone. Building by Huffman
/// weight instead ties the shape to the leaf hashes, because equal weights
/// leave the heap to break ties on the node hash. BIP-345 rewrites one leaf
/// and requires every other leaf's merkle path to survive it, so a shape
/// that moves when a leaf's bytes change turns a correctly built vault into
/// a trigger mismatch.
fn balanced_depths(n: usize) -> Vec<u8> {
    if n <= 1 {
        return vec![0; n];
    }
    let mut height = 0u32;
    while (1usize << height) < n {
        height += 1;
    }
    let shallow = (1usize << height) - n;
    (0..n)
        .map(|i| if i < shallow { height - 1 } else { height } as u8)
        .collect()
}

pub fn build<C: Verification>(
    secp: &Secp256k1<C>,
    network: Network,
    internal_key: Option<XOnlyPublicKey>,
    leaves: &[ScriptBuf],
) -> Result<TaprootOutput, TaprootError> {
    let internal_key = internal_key.unwrap_or_else(nums_internal_key);
    for (i, a) in leaves.iter().enumerate() {
        if leaves[..i].contains(a) {
            return Err(TaprootError::Tree);
        }
    }
    let spend_info = if leaves.is_empty() {
        TaprootBuilder::new()
            .finalize(secp, internal_key)
            .map_err(|_| TaprootError::Finalize)?
    } else {
        let mut builder = TaprootBuilder::new();
        for (script, depth) in leaves.iter().zip(balanced_depths(leaves.len())) {
            builder = builder
                .add_leaf(depth, script.clone())
                .map_err(|_| TaprootError::Tree)?;
        }
        builder
            .finalize(secp, internal_key)
            .map_err(|_| TaprootError::Finalize)?
    };
    let leaf_hashes = leaves
        .iter()
        .map(|s| TapLeafHash::from_script(s, LeafVersion::TapScript))
        .collect();
    let control_blocks = leaves
        .iter()
        .map(|s| {
            spend_info
                .control_block(&(s.clone(), LeafVersion::TapScript))
                .ok_or(TaprootError::Tree)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(TaprootOutput {
        internal_key,
        script_pubkey: ScriptBuf::new_p2tr_tweaked(spend_info.output_key()),
        address: Address::p2tr_tweaked(spend_info.output_key(), network),
        spend_info,
        leaf_hashes,
        control_blocks,
    })
}

#[cfg(test)]
mod tests {
    /// BIP-345 rewrites one leaf and folds every other leaf's control block
    /// up the tree unchanged, so the shape must not depend on leaf content.
    /// A Huffman build with equal weights broke this for three leaves: one
    /// arbitrary sibling in twelve moved the path and rejected a correct
    /// vault.
    #[test]
    fn substituting_a_leaf_leaves_every_other_path_alone() {
        let secp = Secp256k1::new();
        for n in 2..=8usize {
            for swap in 0..n {
                let before: Vec<ScriptBuf> = (0..n)
                    .map(|i| ScriptBuf::from(vec![0x51, 0x01, i as u8]))
                    .collect();
                let mut after = before.clone();
                after[swap] = ScriptBuf::from(vec![0x51, 0x01, 0x90 | swap as u8]);
                let b = build(&secp, Network::Signet, None, &before).unwrap();
                let a = build(&secp, Network::Signet, None, &after).unwrap();
                for other in (0..n).filter(|i| *i != swap) {
                    assert_eq!(
                        b.control_blocks[other].merkle_branch.as_slice().len(),
                        a.control_blocks[other].merkle_branch.as_slice().len(),
                        "n={n} swap={swap} other={other}: path length moved"
                    );
                }
                assert_eq!(
                    b.control_blocks[swap].merkle_branch.as_slice(),
                    a.control_blocks[swap].merkle_branch.as_slice(),
                    "n={n} swap={swap}: the rewritten leaf's own path moved"
                );
            }
        }
    }

    #[test]
    fn balanced_depths_form_a_whole_tree() {
        for n in 1..=17usize {
            let d = balanced_depths(n);
            assert_eq!(d.len(), n);
            let kraft: f64 = d.iter().map(|x| 0.5f64.powi(i32::from(*x))).sum();
            assert!(
                (kraft - 1.0).abs() < 1e-9,
                "n={n} depths={d:?} kraft={kraft}"
            );
        }
    }

    use super::*;
    use bitcoin::hashes::Hash;

    #[test]
    fn every_control_block_commits_to_the_output_key() {
        let secp = Secp256k1::new();
        let leaves: Vec<ScriptBuf> = (1u8..=3).map(|b| ScriptBuf::from(vec![0x50 + b])).collect();
        let t = build(&secp, Network::Signet, None, &leaves).unwrap();
        assert!(t.address.to_string().starts_with("tb1p"));
        assert_eq!(t.control_blocks.len(), 3);
        for (s, cb) in leaves.iter().zip(&t.control_blocks) {
            assert!(cb.verify_taproot_commitment(
                &secp,
                t.spend_info.output_key().to_x_only_public_key(),
                s
            ));
        }
        assert_eq!(
            t.leaf_hashes[0],
            TapLeafHash::from_script(&leaves[0], LeafVersion::TapScript)
        );
        assert!(t.spend_info.merkle_root().is_some());
        assert_ne!(
            t.spend_info.merkle_root().unwrap().to_byte_array(),
            [0u8; 32]
        );
    }

    #[test]
    fn no_leaves_is_key_path_only() {
        let secp = Secp256k1::new();
        let t = build(&secp, Network::Signet, None, &[]).unwrap();
        assert!(t.spend_info.merkle_root().is_none());
        assert!(t.control_blocks.is_empty());
    }

    #[test]
    fn duplicate_leaf_is_rejected() {
        let secp = Secp256k1::new();
        let s = ScriptBuf::from(vec![0x51]);
        assert_eq!(
            build(&secp, Network::Signet, None, &[s.clone(), s]).unwrap_err(),
            TaprootError::Tree
        );
    }
}
