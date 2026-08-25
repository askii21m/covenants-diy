//! BIP-346 test vectors, as published with the BIP's reference
//! implementation.
//!
//! The fixture spends four inputs with deliberately malformed witnesses,
//! which is what makes it worth running: input 1 carries a one-byte
//! control block behind an annex, so the control block is committed but
//! the leaf script behind it is not.

use bitcoin::consensus::deserialize;
use bitcoin::hex::FromHex;
use bitcoin::{Transaction, TxOut};
use covenants_core::txhash::{tx_hash, CurrentInput};
use serde_json::Value;

#[test]
fn bip346_txhash_vectors() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/bip346-txhash.json"
    );
    let data = std::fs::read_to_string(path).unwrap();
    let groups: Vec<Value> = serde_json::from_str(&data).unwrap();

    let mut cases = 0usize;
    for group in &groups {
        let tx: Transaction =
            deserialize(&Vec::<u8>::from_hex(group["tx"].as_str().unwrap()).unwrap())
                .expect("vector tx must parse");
        let prevouts: Vec<TxOut> = group["prevs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| {
                deserialize(&Vec::<u8>::from_hex(p.as_str().unwrap()).unwrap())
                    .expect("vector prevout must parse")
            })
            .collect();

        for v in group["vectors"].as_array().unwrap() {
            let id = v["id"].as_str().unwrap();
            let txfs = Vec::<u8>::from_hex(v["txfs"].as_str().unwrap()).unwrap();
            let input_index = v["input"].as_u64().unwrap() as usize;
            let current = CurrentInput {
                last_codeseparator_pos: v["codeseparator"].as_u64().map(|p| p as u32),
                ..Default::default()
            };

            let got = tx_hash(&txfs, &tx, &prevouts, input_index, &current)
                .unwrap_or_else(|e| panic!("{id}: {e:?}"));
            let want = v["txhash"].as_str().unwrap();
            assert_eq!(
                bitcoin::hex::DisplayHex::to_lower_hex_string(&got[..]),
                want,
                "{id} (txfs {})",
                v["txfs"].as_str().unwrap()
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 150, "expected the published vector count");
}
