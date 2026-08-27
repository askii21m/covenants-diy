//! The official BIP-446 test vectors, run end to end: each case is a real
//! transaction validated against the real spent outputs, with the script
//! and control block taken from the witness exactly as a node would.

use bitcoin::consensus::deserialize;
use bitcoin::hex::FromHex;
use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash};
use bitcoin::{ScriptBuf, Transaction, TxOut};
use covenants_interp::{Deployments, Exec, ExecCtx, Options, TxTemplate};
use serde_json::Value;

/// The BIP-341 annex is the last witness element when there is more than
/// one and it starts with 0x50.
fn split_witness(items: &[Vec<u8>]) -> (Vec<Vec<u8>>, Option<Vec<u8>>) {
    let mut items = items.to_vec();
    let annex = if items.len() >= 2
        && items
            .last()
            .map(|l| l.first() == Some(&0x50))
            .unwrap_or(false)
    {
        items.pop()
    } else {
        None
    };
    (items, annex)
}

fn run_case(case: &Value) -> Result<bool, String> {
    let tx_hex = case["spending_tx"].as_str().ok_or("no spending_tx")?;
    let tx: Transaction = deserialize(&Vec::<u8>::from_hex(tx_hex).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let input_index = case["input_index"].as_u64().ok_or("no input_index")? as usize;
    let prevouts: Vec<TxOut> = case["spent_outputs"]
        .as_array()
        .ok_or("no spent_outputs")?
        .iter()
        .map(|v| {
            let bytes = Vec::<u8>::from_hex(v.as_str().unwrap()).unwrap();
            deserialize::<TxOut>(&bytes).unwrap()
        })
        .collect();

    let witness: Vec<Vec<u8>> = tx.input[input_index]
        .witness
        .iter()
        .map(|b| b.to_vec())
        .collect();
    let (mut stack, annex) = split_witness(&witness);
    // Script path: [inputs..., script, control block].
    let control = stack.pop().ok_or("no control block")?;
    let script = ScriptBuf::from(stack.pop().ok_or("no script")?);
    let cb = ControlBlock::decode(&control).map_err(|e| e.to_string())?;
    let leaf = TapLeafHash::from_script(&script, LeafVersion::TapScript);

    let input_amount = prevouts.first().map(|p| p.value.to_sat());
    let mut exec = Exec::new(
        ExecCtx::Tapscript,
        Options {
            deployments: Deployments::default(),
            ..Default::default()
        },
        TxTemplate {
            tx,
            prevouts,
            input_idx: input_index,
            taproot_annex_scriptleaf: Some((leaf, annex)),
            internal_key: Some(cb.internal_key),
            full_witness_size: None,
            control_block: None,
            ccv_state: None,
            taptree_root: None,
            input_amount,
        },
        script,
        stack,
    )
    .map_err(|e| format!("{e:?}"))?;

    loop {
        if let Err(res) = exec.exec_next() {
            return Ok(res.success);
        }
    }
}

#[test]
fn bip446_basics_vectors() {
    let raw = include_str!("../../core/tests/vectors/bip446-basics.json");
    let cases: Vec<Value> = serde_json::from_str(raw).expect("vectors parse");
    assert!(
        cases.len() >= 19,
        "expected the published vector set, got {}",
        cases.len()
    );

    let mut failures = Vec::new();
    for (i, case) in cases.iter().enumerate() {
        let want = case["valid"].as_bool().expect("valid flag");
        let comment = case["comment"].as_str().unwrap_or("");
        match run_case(case) {
            Ok(got) if got == want => {}
            Ok(got) => failures.push(format!("#{i} `{comment}`: got success={got}, want {want}")),
            // A case that should fail may fail before execution starts;
            // one that should pass may not.
            Err(e) if !want => {
                let _ = e;
            }
            Err(e) => failures.push(format!("#{i} `{comment}`: {e}")),
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} vectors failed:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
}

/// The exhaustive suite, built on Bitcoin Core's taproot test framework.
/// Each case carries a witness that should succeed and usually one that
/// should fail; the witness is substituted into the named input, exactly
/// as the framework does.
fn run_asset(case: &Value, which: &str) -> Option<Result<bool, String>> {
    let spec = case.get(which)?;
    // Each case names the flags it runs under. Without TEMPLATEHASH, 0xce
    // is still OP_SUCCESS206 and the script passes without running, which
    // is what the `discouraged_template` cases check.
    let flags = case["flags"].as_str().unwrap_or("");
    let deployments = Deployments {
        ctv: false,
        csfs: false,
        cat: false,
        apo: false,
        templatehash: flags.split(',').any(|f| f == "TEMPLATEHASH"),
        internalkey: false,
        paircommit: false,
        txhash: false,
        ccv: false,
    };
    let tx_hex = case["tx"].as_str()?;
    let mut tx: Transaction = deserialize(&Vec::<u8>::from_hex(tx_hex).ok()?).ok()?;
    let index = case["index"].as_u64()? as usize;
    let prevouts: Vec<TxOut> = case["prevouts"]
        .as_array()?
        .iter()
        .map(|v| deserialize::<TxOut>(&Vec::<u8>::from_hex(v.as_str().unwrap()).unwrap()).unwrap())
        .collect();

    // A non-empty scriptSig means this is not a bare taproot spend, which
    // is the only shape this harness runs.
    if spec
        .get("scriptSig")
        .and_then(|s| s.as_str())
        .map(|s| !s.is_empty())
        .unwrap_or(false)
    {
        return None;
    }
    let witness: Vec<Vec<u8>> = spec
        .get("witness")?
        .as_array()?
        .iter()
        .map(|v| Vec::<u8>::from_hex(v.as_str().unwrap()).unwrap())
        .collect();
    let (mut stack, annex) = split_witness(&witness);
    // Key-path spends have nothing for a script interpreter to run.
    if stack.len() < 2 {
        return None;
    }
    let control = stack.pop()?;
    let script = ScriptBuf::from(stack.pop()?);
    let cb = ControlBlock::decode(&control).ok()?;
    if cb.leaf_version != LeafVersion::TapScript {
        return None;
    }
    let leaf = TapLeafHash::from_script(&script, LeafVersion::TapScript);
    tx.input[index].witness = bitcoin::Witness::from_slice(&witness);

    let input_amount = prevouts.first().map(|p| p.value.to_sat());
    let exec = Exec::new(
        ExecCtx::Tapscript,
        Options {
            deployments,
            ..Default::default()
        },
        TxTemplate {
            tx,
            prevouts,
            input_idx: index,
            taproot_annex_scriptleaf: Some((leaf, annex)),
            internal_key: Some(cb.internal_key),
            full_witness_size: None,
            control_block: None,
            ccv_state: None,
            taptree_root: None,
            input_amount,
        },
        script,
        stack,
    );
    let mut exec = match exec {
        Ok(e) => e,
        Err(e) => return Some(Err(format!("{e:?}"))),
    };
    loop {
        if let Err(res) = exec.exec_next() {
            return Some(Ok(res.success));
        }
    }
}

#[test]
fn bip446_script_assets_vectors() {
    let raw = include_str!("../../core/tests/vectors/bip446-assets.json");
    let cases: Vec<Value> = serde_json::from_str(raw).expect("vectors parse");
    assert!(
        cases.len() > 300,
        "expected the published suite, got {}",
        cases.len()
    );

    let (mut ran, mut failures) = (0usize, Vec::new());
    for (i, case) in cases.iter().enumerate() {
        let comment = case["comment"].as_str().unwrap_or("");
        for (which, want) in [("success", true), ("failure", false)] {
            let Some(result) = run_asset(case, which) else {
                continue;
            };
            ran += 1;
            match result {
                Ok(got) if got == want => {}
                // A case meant to fail may be rejected before execution.
                Err(_) if !want => {}
                Ok(got) => failures.push(format!(
                    "#{i} {which} `{comment}`: success={got}, want {want}"
                )),
                Err(e) => failures.push(format!("#{i} {which} `{comment}`: {e}")),
            }
        }
    }
    println!(
        "ran {ran} taproot script-path cases from {} vectors",
        cases.len()
    );
    assert!(ran > 400, "harness skipped too much: only ran {ran}");
    assert!(
        failures.is_empty(),
        "{} failed:\n{}",
        failures.len(),
        failures
            .iter()
            .take(20)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}
