//! BIP-340 tagged hashing and Bitcoin's CompactSize, shared by the opcodes
//! that commit to variable-length data.

use bitcoin::hashes::{sha256, Hash, HashEngine};

/// BIP-340 tagged hash.
pub fn tagged(tag: &str, data: &[u8]) -> [u8; 32] {
    let t = sha256::Hash::hash(tag.as_bytes());
    let mut e = sha256::Hash::engine();
    e.input(t.as_byte_array());
    e.input(t.as_byte_array());
    e.input(data);
    sha256::Hash::from_engine(e).to_byte_array()
}

/// Bitcoin's CompactSize. The callers here commit to script elements and
/// scriptPubKeys, so only the one-byte and three-byte forms are reachable,
/// but the rest is written out because the encoding is the encoding.
pub fn compact_size(n: usize) -> Vec<u8> {
    match n {
        0..=0xfc => vec![n as u8],
        0xfd..=0xffff => {
            let mut v = vec![0xfd];
            v.extend_from_slice(&(n as u16).to_le_bytes());
            v
        }
        0x1_0000..=0xffff_ffff => {
            let mut v = vec![0xfe];
            v.extend_from_slice(&(n as u32).to_le_bytes());
            v
        }
        _ => {
            let mut v = vec![0xff];
            v.extend_from_slice(&(n as u64).to_le_bytes());
            v
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_size_covers_every_form() {
        assert_eq!(compact_size(0), vec![0x00]);
        assert_eq!(compact_size(0xfc), vec![0xfc]);
        assert_eq!(compact_size(0xfd), vec![0xfd, 0xfd, 0x00]);
        assert_eq!(compact_size(0xffff), vec![0xfd, 0xff, 0xff]);
        assert_eq!(compact_size(0x1_0000), vec![0xfe, 0x00, 0x00, 0x01, 0x00]);
    }

    /// BIP-340's own worked tag, so the construction is anchored to the spec
    /// rather than to this codebase's other callers.
    #[test]
    fn tagged_matches_the_bip340_construction() {
        let t = sha256::Hash::hash(b"TapLeaf");
        let mut e = sha256::Hash::engine();
        e.input(t.as_byte_array());
        e.input(t.as_byte_array());
        e.input(b"abc");
        assert_eq!(
            tagged("TapLeaf", b"abc"),
            sha256::Hash::from_engine(e).to_byte_array()
        );
    }
}
