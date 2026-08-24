use bitcoin::consensus::deserialize;
use bitcoin::hex::FromHex;
use bitcoin::Transaction;
use covenants_core::ctv::default_template_hash;
use serde_json::Value;

#[test]
fn bip119_ctvhash_vectors() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../spec/vectors/ctvhash.json"
    );
    let data = std::fs::read_to_string(path).unwrap();
    let entries: Vec<Value> = serde_json::from_str(&data).unwrap();

    let mut cases = 0usize;
    for e in &entries {
        let (Some(hex_tx), Some(idxs), Some(results)) = (
            e.get("hex_tx").and_then(Value::as_str),
            e.get("spend_index").and_then(Value::as_array),
            e.get("result").and_then(Value::as_array),
        ) else {
            continue;
        };
        let Ok(tx_bytes) = Vec::<u8>::from_hex(hex_tx) else {
            continue;
        };
        let tx: Transaction = deserialize(&tx_bytes).expect("vector tx must parse");
        for (i, idx) in idxs.iter().enumerate() {
            let idx = u32::try_from(idx.as_u64().unwrap()).unwrap();
            let want = Vec::<u8>::from_hex(results[i].as_str().unwrap()).unwrap();
            let got = default_template_hash(&tx, idx);
            assert_eq!(
                got.as_slice(),
                want.as_slice(),
                "spend_index {idx} of {hex_tx}"
            );
            cases += 1;
        }
    }
    assert!(cases >= 100, "only {cases} vector cases ran");
}
