use bitcoin::hashes::Hash;
use bitcoin::sighash::{Annex, Prevouts as RbPrevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, TapLeafHash};
use bitcoin::{
    absolute, transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
};
use covenants_core::sighash::{script_spend_sighash, KeyVersion, Prevouts, SighashError};

fn fixture(n_in: usize, n_out: usize) -> (Transaction, Vec<TxOut>) {
    let mut inputs = Vec::new();
    let mut prevouts = Vec::new();
    for i in 0..n_in {
        let mut txid = [0u8; 32];
        txid[0] = i as u8 + 1;
        txid[31] = 0xaa;
        inputs.push(TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array(txid),
                vout: i as u32,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence(0xfffffffd - i as u32),
            witness: Witness::new(),
        });
        let mut spk = vec![0x51, 0x20];
        spk.extend(std::iter::repeat(i as u8 + 0x30).take(32));
        prevouts.push(TxOut {
            value: Amount::from_sat(100_000 + i as u64 * 7),
            script_pubkey: ScriptBuf::from(spk),
        });
    }
    let mut outputs = Vec::new();
    for o in 0..n_out {
        let mut spk = vec![0x51, 0x20];
        spk.extend(std::iter::repeat(o as u8 + 0x60).take(32));
        outputs.push(TxOut {
            value: Amount::from_sat(50_000 + o as u64 * 11),
            script_pubkey: ScriptBuf::from(spk),
        });
    }
    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::from_consensus(500_000),
        input: inputs,
        output: outputs,
    };
    (tx, prevouts)
}

fn leaf() -> TapLeafHash {
    let script = ScriptBuf::from(vec![0x51]);
    TapLeafHash::from_script(&script, LeafVersion::TapScript)
}

#[test]
fn differential_against_rust_bitcoin() {
    let shapes = [(1usize, 1usize), (3, 2), (2, 3)];
    let hash_types = [0x00u8, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83];
    let annexes: [Option<Vec<u8>>; 2] = [None, Some(vec![0x50, 0xde, 0xad])];
    let codeseps = [u32::MAX, 7];

    let mut compared = 0usize;
    for (n_in, n_out) in shapes {
        let (tx, prevouts) = fixture(n_in, n_out);
        let mut cache = SighashCache::new(&tx);
        for input_index in 0..n_in {
            for &ht in &hash_types {
                for annex in &annexes {
                    for &codesep in &codeseps {
                        let ours = script_spend_sighash(
                            &tx,
                            input_index,
                            Prevouts::All(&prevouts),
                            ht,
                            KeyVersion::V0,
                            leaf(),
                            codesep,
                            annex.as_deref(),
                        );
                        let theirs = cache.taproot_signature_hash(
                            input_index,
                            &RbPrevouts::All(&prevouts),
                            annex.as_deref().map(|a| Annex::new(a).unwrap()),
                            Some((leaf(), codesep)),
                            TapSighashType::from_consensus_u8(ht).unwrap(),
                        );
                        if ht & 0x03 == 0x03 && input_index >= n_out {
                            assert_eq!(
                                ours,
                                Err(SighashError::SingleWithoutCorrespondingOutput)
                            );
                            assert!(theirs.is_err());
                        } else {
                            assert_eq!(
                                ours.unwrap(),
                                theirs.unwrap().to_byte_array(),
                                "ht {ht:#x} idx {input_index} annex {} codesep {codesep}",
                                annex.is_some(),
                            );
                            compared += 1;
                        }
                    }
                }
            }
        }
    }
    assert!(compared > 100, "only {compared} digests compared");
}

#[test]
fn anyonecanpay_accepts_single_prevout() {
    let (tx, prevouts) = fixture(2, 2);
    let all = script_spend_sighash(
        &tx,
        1,
        Prevouts::All(&prevouts),
        0x81,
        KeyVersion::V0,
        leaf(),
        u32::MAX,
        None,
    )
    .unwrap();
    let one = script_spend_sighash(
        &tx,
        1,
        Prevouts::One(1, &prevouts[1]),
        0x81,
        KeyVersion::V0,
        leaf(),
        u32::MAX,
        None,
    )
    .unwrap();
    assert_eq!(all, one);
}

#[test]
fn apo_ignores_outpoint() {
    let (mut tx, prevouts) = fixture(2, 2);
    let base = script_spend_sighash(
        &tx,
        0,
        Prevouts::One(0, &prevouts[0]),
        0x41,
        KeyVersion::Bip118,
        leaf(),
        u32::MAX,
        None,
    )
    .unwrap();

    tx.input[0].previous_output.vout = 99;
    let mut txid = [0x7f; 32];
    txid[5] = 1;
    tx.input[0].previous_output.txid = Txid::from_byte_array(txid);
    let rebound = script_spend_sighash(
        &tx,
        0,
        Prevouts::One(0, &prevouts[0]),
        0x41,
        KeyVersion::Bip118,
        leaf(),
        u32::MAX,
        None,
    )
    .unwrap();
    assert_eq!(base, rebound);

    let normal_base = script_spend_sighash(
        &tx,
        0,
        Prevouts::All(&prevouts),
        0x01,
        KeyVersion::Bip118,
        leaf(),
        u32::MAX,
        None,
    )
    .unwrap();
    tx.input[0].previous_output.vout = 3;
    let normal_rebound = script_spend_sighash(
        &tx,
        0,
        Prevouts::All(&prevouts),
        0x01,
        KeyVersion::Bip118,
        leaf(),
        u32::MAX,
        None,
    )
    .unwrap();
    assert_ne!(normal_base, normal_rebound);
}

#[test]
fn apo_commits_to_amount_and_script_apoas_does_not() {
    let (tx, prevouts) = fixture(1, 1);
    let mut fat_prevout = prevouts[0].clone();
    fat_prevout.value = Amount::from_sat(999_999);

    let apo_a = script_spend_sighash(
        &tx, 0, Prevouts::One(0, &prevouts[0]), 0x41, KeyVersion::Bip118, leaf(), u32::MAX, None,
    )
    .unwrap();
    let apo_b = script_spend_sighash(
        &tx, 0, Prevouts::One(0, &fat_prevout), 0x41, KeyVersion::Bip118, leaf(), u32::MAX, None,
    )
    .unwrap();
    assert_ne!(apo_a, apo_b);

    let apoas_a = script_spend_sighash(
        &tx, 0, Prevouts::None, 0xc1, KeyVersion::Bip118, leaf(), u32::MAX, None,
    )
    .unwrap();
    let other_leaf = TapLeafHash::from_script(&ScriptBuf::from(vec![0x52]), LeafVersion::TapScript);
    let apoas_b = script_spend_sighash(
        &tx, 0, Prevouts::None, 0xc1, KeyVersion::Bip118, other_leaf, u32::MAX, None,
    )
    .unwrap();
    assert_eq!(apoas_a, apoas_b);

    let apo_leaf_a = script_spend_sighash(
        &tx, 0, Prevouts::One(0, &prevouts[0]), 0x41, KeyVersion::Bip118, leaf(), u32::MAX, None,
    )
    .unwrap();
    let apo_leaf_b = script_spend_sighash(
        &tx, 0, Prevouts::One(0, &prevouts[0]), 0x41, KeyVersion::Bip118, other_leaf, u32::MAX, None,
    )
    .unwrap();
    assert_ne!(apo_leaf_a, apo_leaf_b);
}

#[test]
fn apoas_still_commits_to_codesep_and_sequence() {
    let (mut tx, _) = fixture(1, 1);
    let a = script_spend_sighash(
        &tx, 0, Prevouts::None, 0xc1, KeyVersion::Bip118, leaf(), u32::MAX, None,
    )
    .unwrap();
    let b = script_spend_sighash(
        &tx, 0, Prevouts::None, 0xc1, KeyVersion::Bip118, leaf(), 12, None,
    )
    .unwrap();
    assert_ne!(a, b);

    tx.input[0].sequence = Sequence(0x1234);
    let c = script_spend_sighash(
        &tx, 0, Prevouts::None, 0xc1, KeyVersion::Bip118, leaf(), u32::MAX, None,
    )
    .unwrap();
    assert_ne!(a, c);
}

#[test]
fn key_version_separates_digests() {
    let (tx, prevouts) = fixture(1, 1);
    let v0 = script_spend_sighash(
        &tx, 0, Prevouts::All(&prevouts), 0x01, KeyVersion::V0, leaf(), u32::MAX, None,
    )
    .unwrap();
    let v118 = script_spend_sighash(
        &tx, 0, Prevouts::All(&prevouts), 0x01, KeyVersion::Bip118, leaf(), u32::MAX, None,
    )
    .unwrap();
    assert_ne!(v0, v118);
}

#[test]
fn hash_type_validity() {
    let (tx, prevouts) = fixture(1, 1);
    for ht in [0x40u8, 0xc0, 0x04, 0x80, 0x44, 0xff] {
        let r = script_spend_sighash(
            &tx, 0, Prevouts::All(&prevouts), ht, KeyVersion::Bip118, leaf(), u32::MAX, None,
        );
        assert_eq!(r, Err(SighashError::InvalidHashType(ht)), "ht {ht:#x}");
    }
    for ht in [0x41u8, 0x42, 0x43, 0xc1, 0xc2, 0xc3] {
        let r = script_spend_sighash(
            &tx, 0, Prevouts::All(&prevouts), ht, KeyVersion::V0, leaf(), u32::MAX, None,
        );
        assert_eq!(r, Err(SighashError::InvalidHashType(ht)), "ht {ht:#x}");
    }
    let apo_single = script_spend_sighash(
        &tx, 0, Prevouts::All(&prevouts), 0x43, KeyVersion::Bip118, leaf(), u32::MAX, None,
    );
    assert!(apo_single.is_ok());
}
