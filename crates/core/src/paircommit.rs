//! BIP-442 OP_PAIRCOMMIT.
//!
//! Commits to two stack elements at once. Each is prefixed with its own
//! length, so the pair (`ab`, ``) and the pair (`a`, `b`) commit to
//! different values; concatenating them first would not.
//!
//! LNHANCE carries it alongside CTV and CSFS so a script can bind two
//! values, a state number and a balance say, into one 32-byte commitment
//! without spending the opcodes that taking them apart again would cost.

use crate::tagged::{compact_size, tagged};

/// `hash_PairCommit(compact_size(len(x1)) || x1 || compact_size(len(x2)) || x2)`,
/// where x2 is the top of the stack.
pub fn pair_commit(x1: &[u8], x2: &[u8]) -> [u8; 32] {
    let mut data = compact_size(x1.len());
    data.extend_from_slice(x1);
    data.extend_from_slice(&compact_size(x2.len()));
    data.extend_from_slice(x2);
    tagged("PairCommit", &data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: [u8; 32]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    // Derived from the BIP text, which ships no vectors of its own.
    #[test]
    fn bip442_vectors() {
        assert_eq!(
            hex(pair_commit(b"", b"")),
            "4a9eb31bc6573906336dd486295c1720aa513dbc7d866bc4367c0de08921829e"
        );
        assert_eq!(
            hex(pair_commit(&[0x01], &[0x02])),
            "7b755eeb15ba472552dd012a322190deec809545e8db397c17604fe23cc13f02"
        );
        assert_eq!(
            hex(pair_commit(&[0xde; 32], &[0xad; 32])),
            "000e9776b76b177d4b9a2abc1341610cf537bd9a89a5c2a43d25f3b20bdf68c3"
        );
    }

    #[test]
    fn the_order_of_the_pair_matters() {
        assert_ne!(pair_commit(&[0x01], &[0x02]), pair_commit(&[0x02], &[0x01]));
        assert_eq!(
            hex(pair_commit(&[0x01], b"")),
            "851d4d9f81b6a091ace6544d69cd2db0caaeea18569d120ce5d7bec2405018c9"
        );
        assert_eq!(
            hex(pair_commit(b"", &[0x01])),
            "f88048b9f72a9bde7f9439683a141adb888a861d6253bb9ac170f7de0e77b4b3"
        );
    }

    /// The length prefixes are what stop (`ab`, ``) and (`a`, `b`) colliding.
    #[test]
    fn a_prefix_keeps_the_halves_apart() {
        assert_ne!(
            pair_commit(&[0x01, 0x02], b""),
            pair_commit(&[0x01], &[0x02])
        );
    }

    /// 252 takes one byte, 253 takes three. Both sides of that edge, and the
    /// 520-byte element cap where the three-byte form is always used.
    #[test]
    fn compact_size_edges() {
        assert_eq!(compact_size(0), vec![0x00]);
        assert_eq!(compact_size(252), vec![0xfc]);
        assert_eq!(compact_size(253), vec![0xfd, 0xfd, 0x00]);
        assert_eq!(compact_size(520), vec![0xfd, 0x08, 0x02]);
        assert_eq!(
            hex(pair_commit(&[0u8; 252], &[0x00])),
            "80da8a294dc841a71385d4b9a33f3779a2b1931186c141c740675ad17be460d2"
        );
        assert_eq!(
            hex(pair_commit(&[0u8; 253], &[0x00])),
            "0cd05bc7d679263e43f091b480570debf5d1170795044e3c7db28e0be25566e4"
        );
        assert_eq!(
            hex(pair_commit(&[0u8; 520], &[0u8; 520])),
            "681db552e70ece38cac0446fc8b7f681b411395a6588c7743de4f1bea853291e"
        );
    }
}
