use bitcoin::hashes::Hash;
use bitcoin::hex::FromHex;
use bitcoin::opcodes::all::{
    OP_CAT, OP_CHECKSIG, OP_CODESEPARATOR, OP_DROP, OP_NOP4, OP_PUSHNUM_1, OP_RETURN_204,
};
use bitcoin::script::Builder;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, XOnlyPublicKey};
use bitcoin::taproot::{LeafVersion, TapLeafHash};
use bitcoin::{
    absolute, transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
};
use covenants_core::ctv::default_template_hash;
use covenants_core::sighash::{script_spend_sighash, KeyVersion, Prevouts};
use covenants_interp::{
    Deployments, Error, Exec, ExecCtx, ExecError, ExecutionResult, Options, TxTemplate,
};

fn fixture(n_in: usize, n_out: usize) -> (Transaction, Vec<TxOut>) {
    let mut inputs = Vec::new();
    let mut prevouts = Vec::new();
    for i in 0..n_in {
        let mut txid = [0u8; 32];
        txid[0] = i as u8 + 1;
        inputs.push(TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array(txid),
                vout: i as u32,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence(0xfffffffd),
            witness: Witness::new(),
        });
        let mut spk = vec![0x51, 0x20];
        spk.extend(std::iter::repeat(i as u8 + 0x30).take(32));
        prevouts.push(TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::from(spk),
        });
    }
    let mut outputs = Vec::new();
    for o in 0..n_out {
        let mut spk = vec![0x51, 0x20];
        spk.extend(std::iter::repeat(o as u8 + 0x60).take(32));
        outputs.push(TxOut {
            value: Amount::from_sat(90_000),
            script_pubkey: ScriptBuf::from(spk),
        });
    }
    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::from_consensus(0),
        input: inputs,
        output: outputs,
    };
    (tx, prevouts)
}

fn run_tapscript_with(
    script: ScriptBuf,
    witness: Vec<Vec<u8>>,
    tx: Transaction,
    prevouts: Vec<TxOut>,
    deployments: Deployments,
    internal_key: Option<XOnlyPublicKey>,
) -> Result<ExecutionResult, Error> {
    let leaf = TapLeafHash::from_script(&script, LeafVersion::TapScript);
    let mut exec = Exec::new(
        ExecCtx::Tapscript,
        Options {
            deployments,
            ..Default::default()
        },
        TxTemplate {
            tx,
            prevouts,
            input_idx: 0,
            taproot_annex_scriptleaf: Some((leaf, None)),
            internal_key,
            full_witness_size: None,
        },
        script,
        witness,
    )?;
    while exec.exec_next().is_ok() {}
    Ok(exec.result().unwrap().clone())
}

fn run_tapscript(
    script: ScriptBuf,
    witness: Vec<Vec<u8>>,
    tx: Transaction,
    prevouts: Vec<TxOut>,
) -> Result<ExecutionResult, Error> {
    run_tapscript_with(script, witness, tx, prevouts, Deployments::default(), None)
}

fn keypair() -> (Secp256k1<bitcoin::secp256k1::All>, Keypair, XOnlyPublicKey) {
    let secp = Secp256k1::new();
    let kp = Keypair::from_seckey_slice(&secp, &[7u8; 32]).unwrap();
    let (xonly, _) = kp.x_only_public_key();
    (secp, kp, xonly)
}

#[test]
fn ctv_matching_hash_succeeds() {
    let (tx, prevouts) = fixture(1, 1);
    let hash = default_template_hash(&tx, 0);
    let script = Builder::new()
        .push_slice(hash)
        .push_opcode(OP_NOP4)
        .into_script();
    let res = run_tapscript(script, vec![], tx, prevouts).unwrap();
    assert!(res.success, "{:?}", res.error);
}

#[test]
fn ctv_wrong_hash_fails() {
    let (tx, prevouts) = fixture(1, 1);
    let mut hash = default_template_hash(&tx, 0);
    hash[0] ^= 1;
    let script = Builder::new()
        .push_slice(hash)
        .push_opcode(OP_NOP4)
        .into_script();
    let res = run_tapscript(script, vec![], tx, prevouts).unwrap();
    assert_eq!(res.error, Some(ExecError::TemplateMismatch));
}

#[test]
fn ctv_non_32_byte_arg_is_nop() {
    let (tx, prevouts) = fixture(1, 1);
    let script = Builder::new()
        .push_slice([1u8; 31])
        .push_opcode(OP_NOP4)
        .into_script();
    let res = run_tapscript(script, vec![], tx, prevouts).unwrap();
    assert!(res.success, "{:?}", res.error);
}

#[test]
fn ctv_disabled_is_plain_nop() {
    let (tx, prevouts) = fixture(1, 1);
    let script = Builder::new()
        .push_slice([0xee; 32])
        .push_opcode(OP_NOP4)
        .into_script();
    let deployments = Deployments {
        ctv: false,
        ..Default::default()
    };
    let res = run_tapscript_with(script, vec![], tx, prevouts, deployments, None).unwrap();
    assert!(res.success, "{:?}", res.error);
}

#[test]
fn csfs_valid_signature() {
    let (secp, kp, xonly) = keypair();
    let msg = [0x42u8; 32];
    let sig = secp.sign_schnorr_no_aux_rand(&Message::from_digest(msg), &kp);
    let (tx, prevouts) = fixture(1, 1);
    let script = Builder::new()
        .push_slice(xonly.serialize())
        .push_opcode(OP_RETURN_204)
        .into_script();
    let res = run_tapscript(
        script,
        vec![sig.as_ref().to_vec(), msg.to_vec()],
        tx,
        prevouts,
    )
    .unwrap();
    assert!(res.success, "{:?}", res.error);
    assert_eq!(res.final_stack.get(0), vec![1]);
}

#[test]
fn csfs_invalid_signature_fails() {
    let (secp, kp, xonly) = keypair();
    let msg = [0x42u8; 32];
    let sig = secp.sign_schnorr_no_aux_rand(&Message::from_digest(msg), &kp);
    let mut sig = sig.as_ref().to_vec();
    sig[10] ^= 1;
    let (tx, prevouts) = fixture(1, 1);
    let script = Builder::new()
        .push_slice(xonly.serialize())
        .push_opcode(OP_RETURN_204)
        .into_script();
    let res = run_tapscript(script, vec![sig, msg.to_vec()], tx, prevouts).unwrap();
    assert_eq!(res.error, Some(ExecError::SchnorrSig));
}

#[test]
fn csfs_empty_signature_pushes_false() {
    let (_, _, xonly) = keypair();
    let (tx, prevouts) = fixture(1, 1);
    let script = Builder::new()
        .push_slice(xonly.serialize())
        .push_opcode(OP_RETURN_204)
        .into_script();
    let res = run_tapscript(script, vec![vec![], vec![0x42; 32]], tx, prevouts).unwrap();
    assert!(!res.success);
    assert_eq!(res.error, None);
    assert_eq!(res.final_stack.get(0), Vec::<u8>::new());
}

#[test]
fn csfs_unknown_key_type_succeeds() {
    let (tx, prevouts) = fixture(1, 1);
    let script = Builder::new()
        .push_slice([9u8; 31])
        .push_opcode(OP_RETURN_204)
        .into_script();
    let res = run_tapscript(script, vec![vec![0xde; 64], vec![0xad; 5]], tx, prevouts).unwrap();
    assert!(res.success, "{:?}", res.error);
    assert_eq!(res.final_stack.get(0), vec![1]);
}

#[test]
fn csfs_empty_pubkey_fails() {
    let (tx, prevouts) = fixture(1, 1);
    let script = Builder::new()
        .push_slice([])
        .push_opcode(OP_RETURN_204)
        .into_script();
    let res = run_tapscript(script, vec![vec![0xde; 64], vec![0xad; 5]], tx, prevouts).unwrap();
    assert_eq!(res.error, Some(ExecError::PubkeyType));
}

#[test]
fn csfs_bip340_vectors_including_varlen_messages() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../spec/vectors/test-vectors.csv"
    );
    let data = std::fs::read_to_string(path).unwrap();
    let mut cases = 0usize;
    let mut varlen = 0usize;
    for line in data.lines().skip(1) {
        let cols: Vec<&str> = line.split(',').collect();
        if cols.len() < 7 {
            continue;
        }
        let (pk_hex, msg_hex, sig_hex, expect) = (cols[2], cols[4], cols[5], cols[6]);
        let Ok(pk) = Vec::<u8>::from_hex(pk_hex) else {
            continue;
        };
        let Ok(msg) = Vec::<u8>::from_hex(msg_hex) else {
            continue;
        };
        let Ok(sig) = Vec::<u8>::from_hex(sig_hex) else {
            continue;
        };
        if pk.len() != 32 {
            continue;
        }
        let pk32: [u8; 32] = pk.try_into().unwrap();
        let (tx, prevouts) = fixture(1, 1);
        let script = Builder::new()
            .push_slice(pk32)
            .push_opcode(OP_RETURN_204)
            .into_script();
        let res = run_tapscript(script, vec![sig, msg.clone()], tx, prevouts).unwrap();
        if expect == "TRUE" {
            assert!(res.success, "vector line should verify: {line}");
        } else {
            assert!(res.error.is_some(), "vector line should fail: {line}");
        }
        cases += 1;
        if msg.len() != 32 {
            varlen += 1;
        }
    }
    assert!(cases >= 15, "only {cases} vector cases ran");
    assert!(varlen >= 4, "only {varlen} variable-length cases ran");
}

#[test]
fn op_success_makes_script_pass() {
    let (tx, prevouts) = fixture(1, 1);
    let res = run_tapscript(ScriptBuf::from(vec![0x50u8]), vec![], tx, prevouts).unwrap();
    assert!(res.success);
}

#[test]
fn op_success_beats_truncated_tail() {
    let (tx, prevouts) = fixture(1, 1);
    let res = run_tapscript(ScriptBuf::from(vec![0x50u8, 0x4c]), vec![], tx, prevouts).unwrap();
    assert!(res.success);
}

#[test]
fn truncated_push_without_op_success_fails() {
    let (tx, prevouts) = fixture(1, 1);
    let res = run_tapscript(ScriptBuf::from(vec![0x4cu8]), vec![], tx, prevouts);
    assert!(matches!(res, Err(Error::InvalidScript(_))));
}

#[test]
fn csfs_opcode_is_op_success_when_undeployed() {
    let (tx, prevouts) = fixture(1, 1);
    let deployments = Deployments {
        csfs: false,
        ..Default::default()
    };
    let res = run_tapscript_with(
        ScriptBuf::from(vec![0xccu8]),
        vec![],
        tx.clone(),
        prevouts.clone(),
        deployments,
        None,
    )
    .unwrap();
    assert!(res.success);

    let res = run_tapscript(ScriptBuf::from(vec![0xccu8]), vec![], tx, prevouts).unwrap();
    assert_eq!(res.error, Some(ExecError::InvalidStackOperation));
}

#[test]
fn cat_opcode_is_op_success_when_undeployed() {
    let (tx, prevouts) = fixture(1, 1);
    let deployments = Deployments {
        cat: false,
        ..Default::default()
    };
    let res = run_tapscript_with(
        ScriptBuf::from(vec![0x7eu8]),
        vec![],
        tx,
        prevouts,
        deployments,
        None,
    )
    .unwrap();
    assert!(res.success);
}

#[test]
fn cat_concatenates_in_stack_order() {
    let (tx, prevouts) = fixture(1, 1);
    let script = Builder::new().push_opcode(OP_CAT).into_script();
    let res = run_tapscript(script, vec![vec![1], vec![2]], tx, prevouts).unwrap();
    assert!(res.success, "{:?}", res.error);
    assert_eq!(res.final_stack.get(0), vec![1, 2]);
}

#[test]
fn cat_result_over_520_bytes_fails() {
    let (tx, prevouts) = fixture(1, 1);
    let script = Builder::new().push_opcode(OP_CAT).into_script();
    let res = run_tapscript(script, vec![vec![1; 300], vec![2; 300]], tx, prevouts).unwrap();
    assert_eq!(res.error, Some(ExecError::PushSize));
}

fn apo_script_33(xonly: &XOnlyPublicKey) -> ScriptBuf {
    let mut key = vec![0x01u8];
    key.extend_from_slice(&xonly.serialize());
    let key: [u8; 33] = key.try_into().unwrap();
    Builder::new()
        .push_slice(key)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

#[test]
fn apo_signature_rebinds_to_other_outpoint() {
    let (secp, kp, xonly) = keypair();
    let (mut tx, prevouts) = fixture(1, 1);
    let script = apo_script_33(&xonly);
    let leaf = TapLeafHash::from_script(&script, LeafVersion::TapScript);

    let digest = script_spend_sighash(
        &tx,
        0,
        Prevouts::All(&prevouts),
        0x41,
        KeyVersion::Bip118,
        leaf,
        u32::MAX,
        None,
    )
    .unwrap();
    let mut sig = secp
        .sign_schnorr_no_aux_rand(&Message::from_digest(digest), &kp)
        .as_ref()
        .to_vec();
    sig.push(0x41);

    let res = run_tapscript(
        script.clone(),
        vec![sig.clone()],
        tx.clone(),
        prevouts.clone(),
    )
    .unwrap();
    assert!(res.success, "{:?}", res.error);

    tx.input[0].previous_output = OutPoint {
        txid: Txid::from_byte_array([0x99; 32]),
        vout: 7,
    };
    let res = run_tapscript(script, vec![sig], tx, prevouts).unwrap();
    assert!(res.success, "rebound spend should verify: {:?}", res.error);
}

#[test]
fn apo_sighash_all_does_not_rebind() {
    let (secp, kp, xonly) = keypair();
    let (mut tx, prevouts) = fixture(1, 1);
    let script = apo_script_33(&xonly);
    let leaf = TapLeafHash::from_script(&script, LeafVersion::TapScript);

    let digest = script_spend_sighash(
        &tx,
        0,
        Prevouts::All(&prevouts),
        0x01,
        KeyVersion::Bip118,
        leaf,
        u32::MAX,
        None,
    )
    .unwrap();
    let mut sig = secp
        .sign_schnorr_no_aux_rand(&Message::from_digest(digest), &kp)
        .as_ref()
        .to_vec();
    sig.push(0x01);

    tx.input[0].previous_output = OutPoint {
        txid: Txid::from_byte_array([0x99; 32]),
        vout: 7,
    };
    let res = run_tapscript(script, vec![sig], tx, prevouts).unwrap();
    assert_eq!(res.error, Some(ExecError::SchnorrSig));
}

#[test]
fn apo_one_byte_key_uses_internal_key() {
    let (secp, kp, xonly) = keypair();
    let (tx, prevouts) = fixture(1, 1);
    let script = Builder::new()
        .push_opcode(OP_PUSHNUM_1)
        .push_opcode(OP_CHECKSIG)
        .into_script();
    let leaf = TapLeafHash::from_script(&script, LeafVersion::TapScript);

    let digest = script_spend_sighash(
        &tx,
        0,
        Prevouts::All(&prevouts),
        0xc1,
        KeyVersion::Bip118,
        leaf,
        u32::MAX,
        None,
    )
    .unwrap();
    let mut sig = secp
        .sign_schnorr_no_aux_rand(&Message::from_digest(digest), &kp)
        .as_ref()
        .to_vec();
    sig.push(0xc1);

    let res = run_tapscript_with(
        script.clone(),
        vec![sig.clone()],
        tx.clone(),
        prevouts.clone(),
        Deployments::default(),
        Some(xonly),
    )
    .unwrap();
    assert!(res.success, "{:?}", res.error);

    let res = run_tapscript_with(
        script,
        vec![sig],
        tx,
        prevouts,
        Deployments::default(),
        None,
    )
    .unwrap();
    assert_eq!(res.error, Some(ExecError::Bip118InternalKeyMissing));
}

#[test]
fn apo_disabled_treats_key_as_unknown_type() {
    let (_, _, xonly) = keypair();
    let (tx, prevouts) = fixture(1, 1);
    let script = apo_script_33(&xonly);
    let deployments = Deployments {
        apo: false,
        ..Default::default()
    };

    let res = run_tapscript_with(
        script.clone(),
        vec![vec![0xaa; 64]],
        tx.clone(),
        prevouts.clone(),
        deployments,
        None,
    )
    .unwrap();
    assert!(res.success, "{:?}", res.error);

    let res = run_tapscript_with(script, vec![vec![]], tx, prevouts, deployments, None).unwrap();
    assert!(!res.success);
    assert_eq!(res.error, None);
}

#[test]
fn checksig_unknown_key_type_empty_sig_pushes_false() {
    let (tx, prevouts) = fixture(1, 1);
    let script = Builder::new()
        .push_slice([9u8; 31])
        .push_opcode(OP_CHECKSIG)
        .into_script();
    let res = run_tapscript(script, vec![vec![]], tx, prevouts).unwrap();
    assert!(!res.success);
    assert_eq!(res.error, None);
}

#[test]
fn codeseparator_position_counts_opcodes_not_bytes() {
    let (secp, kp, xonly) = keypair();
    let (tx, prevouts) = fixture(1, 1);
    let script = Builder::new()
        .push_slice([0xab; 10])
        .push_opcode(OP_DROP)
        .push_opcode(OP_CODESEPARATOR)
        .push_slice(xonly.serialize())
        .push_opcode(OP_CHECKSIG)
        .into_script();
    let leaf = TapLeafHash::from_script(&script, LeafVersion::TapScript);

    let digest = script_spend_sighash(
        &tx,
        0,
        Prevouts::All(&prevouts),
        0x00,
        KeyVersion::V0,
        leaf,
        2,
        None,
    )
    .unwrap();
    let sig = secp
        .sign_schnorr_no_aux_rand(&Message::from_digest(digest), &kp)
        .as_ref()
        .to_vec();

    let res = run_tapscript(script, vec![sig], tx, prevouts).unwrap();
    assert!(res.success, "{:?}", res.error);
}
