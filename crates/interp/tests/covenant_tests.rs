use bitcoin::hashes::Hash;
use bitcoin::hex::FromHex;
use bitcoin::opcodes::all::OP_RETURN_189 as OP_TXHASH;
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
        spk.extend(std::iter::repeat_n(i as u8 + 0x30, 32));
        prevouts.push(TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::from(spk),
        });
    }
    let mut outputs = Vec::new();
    for o in 0..n_out {
        let mut spk = vec![0x51, 0x20];
        spk.extend(std::iter::repeat_n(o as u8 + 0x60, 32));
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
            control_block: None,
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

// --- BIP-442 OP_PAIRCOMMIT ---------------------------------------------------

const OP_PAIRCOMMIT: bitcoin::opcodes::Opcode = bitcoin::opcodes::all::OP_RETURN_205;

#[test]
fn paircommit_pushes_the_commitment() {
    let (tx, prevouts) = fixture(1, 1);
    let x1 = [0xdeu8; 32];
    let x2 = [0xadu8; 32];
    let want = covenants_core::paircommit::pair_commit(&x1, &x2);
    let script = Builder::new()
        .push_slice(x1)
        .push_slice(x2)
        .push_opcode(OP_PAIRCOMMIT)
        .push_slice(want)
        .push_opcode(bitcoin::opcodes::all::OP_EQUAL)
        .into_script();
    let res = run_tapscript(script, vec![], tx, prevouts).unwrap();
    assert!(res.success, "{:?}", res.error);
}

#[test]
fn paircommit_is_order_sensitive() {
    let (tx, prevouts) = fixture(1, 1);
    let x1 = [0x01u8; 32];
    let x2 = [0x02u8; 32];
    // The commitment for the pair the other way round must not satisfy this.
    let swapped = covenants_core::paircommit::pair_commit(&x2, &x1);
    let script = Builder::new()
        .push_slice(x1)
        .push_slice(x2)
        .push_opcode(OP_PAIRCOMMIT)
        .push_slice(swapped)
        .push_opcode(bitcoin::opcodes::all::OP_EQUAL)
        .into_script();
    let res = run_tapscript(script, vec![], tx, prevouts).unwrap();
    assert!(!res.success);
}

#[test]
fn paircommit_needs_two_elements() {
    let (tx, prevouts) = fixture(1, 1);
    let script = Builder::new()
        .push_slice([0x01u8; 32])
        .push_opcode(OP_PAIRCOMMIT)
        .into_script();
    let res = run_tapscript(script, vec![], tx, prevouts).unwrap();
    assert_eq!(res.error, Some(ExecError::InvalidStackOperation));
}

/// 0xcd is an OP_SUCCESSx, so with the deployment off the whole script
/// passes rather than the opcode being skipped.
#[test]
fn paircommit_disabled_is_op_success() {
    let (tx, prevouts) = fixture(1, 1);
    let deployments = Deployments {
        paircommit: false,
        txhash: false,
        ..Deployments::default()
    };
    let script = Builder::new()
        .push_opcode(OP_PAIRCOMMIT)
        .push_opcode(bitcoin::opcodes::all::OP_RETURN)
        .into_script();
    let res = run_tapscript_with(script, vec![], tx, prevouts, deployments, None).unwrap();
    assert!(res.success, "an inactive OP_SUCCESSx passes the script");
}

/// The empty selector is the default template, which is what makes
/// OP_TXHASH a generalisation of CTV rather than a parallel mechanism.
#[test]
fn txhash_pushes_the_hash_for_the_empty_selector() {
    let (tx, prevouts) = fixture(1, 1);
    let script = ScriptBuf::from(vec![0x51]);
    let want = covenants_core::txhash::tx_hash(
        &[],
        &tx,
        &prevouts,
        0,
        &covenants_core::txhash::CurrentInput {
            leaf: Some((0xc0, &script)),
            ..Default::default()
        },
    )
    .unwrap();
    let script = Builder::new()
        .push_slice([])
        .push_opcode(OP_TXHASH)
        .push_slice(want)
        .push_opcode(bitcoin::opcodes::all::OP_EQUAL)
        .into_script();
    let res = run_tapscript(script, vec![], tx, prevouts).unwrap();
    assert!(res.success, "{:?}", res.error);
}

/// Two selectors naming different fields have to give different hashes,
/// or the selector would not be doing anything.
#[test]
fn txhash_separates_selectors() {
    let (tx, prevouts) = fixture(1, 1);
    let script = Builder::new()
        .push_slice([0x01u8, 0x00])
        .push_opcode(OP_TXHASH)
        .push_slice([0x02u8, 0x00])
        .push_opcode(OP_TXHASH)
        .push_opcode(bitcoin::opcodes::all::OP_EQUAL)
        .push_opcode(bitcoin::opcodes::all::OP_NOT)
        .into_script();
    let res = run_tapscript(script, vec![], tx, prevouts).unwrap();
    assert!(res.success, "{:?}", res.error);
}

/// The spent script is the leaf being executed, so a script that commits
/// to it commits to itself. Two different leaves must not agree.
#[test]
fn txhash_commits_to_the_executing_leaf() {
    let (tx, prevouts) = fixture(1, 1);
    let selector = [
        covenants_core::txhash::TXFS_CURRENT_INPUT_SPENTSCRIPT,
        0x00u8,
    ];
    let mut hashes = Vec::new();
    for filler in [OP_DROP, OP_CODESEPARATOR] {
        let script = Builder::new()
            .push_slice(selector)
            .push_opcode(OP_TXHASH)
            .push_opcode(OP_PUSHNUM_1)
            .push_opcode(filler)
            .into_script();
        let res = run_tapscript(script, vec![], tx.clone(), prevouts.clone()).unwrap();
        // iter_str runs bottom to top, and the hash is what is left on top.
        hashes.push(res.final_stack.iter_str().next_back().unwrap().to_vec());
    }
    assert_ne!(
        hashes[0], hashes[1],
        "two different leaves produced the same spent-script commitment"
    );
}

/// BIP-346 charges 25 weight per hash. The budget comes from the witness
/// size, so a script with no witness to pay for them runs out.
#[test]
fn txhash_is_charged_against_the_validation_budget() {
    let (tx, prevouts) = fixture(1, 1);
    let mut b = Builder::new();
    for _ in 0..4 {
        b = b
            .push_slice([0x01u8, 0x00])
            .push_opcode(OP_TXHASH)
            .push_opcode(OP_DROP);
    }
    let script = b.push_opcode(OP_PUSHNUM_1).into_script();
    let res = run_tapscript(script, vec![], tx, prevouts).unwrap();
    assert_eq!(
        res.error,
        Some(ExecError::TapscriptValidationWeight),
        "four hashes on a 50-weight budget must exhaust it"
    );
}

/// An invalid selector fails the script rather than pushing something.
#[test]
fn txhash_rejects_an_invalid_selector() {
    let (tx, prevouts) = fixture(1, 1);
    // Leading 9 inputs, of one.
    let script = Builder::new()
        .push_slice([0x01u8, 0x02, 0x09, 0x00])
        .push_opcode(OP_TXHASH)
        .into_script();
    let res = run_tapscript(script, vec![], tx, prevouts).unwrap();
    assert_eq!(
        res.error,
        Some(ExecError::TxFieldSelector(
            covenants_core::txhash::TxHashError::SelectionOutOfBounds
        ))
    );
}

/// Inactive, 0xbd is OP_SUCCESS189: the script passes without running.
#[test]
fn txhash_inactive_is_op_success() {
    let (tx, prevouts) = fixture(1, 1);
    let deployments = Deployments {
        txhash: false,
        ..Default::default()
    };
    let script = Builder::new()
        .push_opcode(OP_TXHASH)
        .push_opcode(bitcoin::opcodes::all::OP_RETURN)
        .into_script();
    let res = run_tapscript_with(script, vec![], tx, prevouts, deployments, None).unwrap();
    assert!(res.success, "an inactive OP_TXHASH passes the script");
}

/// The guard against the bug this opcode shipped with: BIP-342 scans for
/// OP_SUCCESSx before executing anything, and an active deployment has to
/// be carved out of that scan. Without the carve-out this script passes
/// without running, so a script that should fail reports success.
#[test]
fn an_active_txhash_does_not_pass_the_script_by_itself() {
    let (tx, prevouts) = fixture(1, 1);
    let script = Builder::new()
        .push_slice([0x01u8, 0x00])
        .push_opcode(OP_TXHASH)
        .push_opcode(OP_DROP)
        .push_opcode(bitcoin::opcodes::OP_0)
        .into_script();
    let res = run_tapscript(script, vec![], tx, prevouts).unwrap();
    assert!(
        !res.success,
        "an active OP_TXHASH passed a script ending in OP_0, so the pre-scan \
         treated it as OP_SUCCESSx instead of executing it"
    );
}
