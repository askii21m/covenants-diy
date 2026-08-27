//! BIP-345 OP_VAULT and OP_VAULT_RECOVER.
//!
//! The vault is built here the way the BIP builds one: a two-leaf taptree
//! whose recovery leaf names a scriptPubKey by its hash, and whose trigger
//! leaf is rewritten into a timelocked spend when a withdrawal starts. The
//! expected trigger output is always computed by building the second tree
//! with rust-bitcoin rather than by the same code the opcode uses, so a
//! shared mistake in the fold cannot make a test agree with itself.

use bitcoin::absolute::LockTime;
use bitcoin::secp256k1::{Secp256k1, XOnlyPublicKey};
use bitcoin::taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo};
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use covenants_interp::{
    Deployments, Error, Exec, ExecCtx, ExecError, ExecutionResult, Options, TxTemplate,
    VaultTxState,
};

const VAULT: u8 = 0xbb;
const VAULT_RECOVER: u8 = 0xbc;
/// `OP_CHECKSEQUENCEVERIFY OP_DROP OP_CHECKTEMPLATEVERIFY`, the BIP's own
/// example of a leaf-update body.
const BODY: [u8; 3] = [0xb2, 0x75, 0xb3];
const DELAY: u8 = 10;
const VAULT_VALUE: u64 = 100_000;

fn nums() -> XOnlyPublicKey {
    covenants_core::taproot::nums_internal_key()
}

/// Minimal CScriptNum encoding, written out rather than borrowed so the
/// tests do not encode their numbers with the code under test.
fn num(n: i64) -> Vec<u8> {
    if n == 0 {
        return vec![];
    }
    let neg = n < 0;
    let mut v = Vec::new();
    let mut a = n.unsigned_abs();
    while a > 0 {
        v.push((a & 0xff) as u8);
        a >>= 8;
    }
    if v.last().unwrap() & 0x80 != 0 {
        v.push(if neg { 0x80 } else { 0x00 });
    } else if neg {
        *v.last_mut().unwrap() |= 0x80;
    }
    v
}

fn recovery_leaf(spk_hash: &[u8; 32]) -> ScriptBuf {
    let mut s = vec![0x20];
    s.extend_from_slice(spk_hash);
    s.push(VAULT_RECOVER);
    ScriptBuf::from(s)
}

/// `<spend-delay> 2 <body> OP_VAULT`. The delay is small enough to take the
/// OP_N short form, which is the case a plain data push would get wrong.
fn trigger_leaf() -> ScriptBuf {
    let mut s = vec![0x50 + DELAY, 0x52, BODY.len() as u8];
    s.extend_from_slice(&BODY);
    s.push(VAULT);
    ScriptBuf::from(s)
}

/// The leaf the trigger leaf is rewritten into, spelled out byte by byte.
fn rewritten_leaf(ctv_hash: &[u8; 32]) -> ScriptBuf {
    let mut s = vec![0x20];
    s.extend_from_slice(ctv_hash);
    s.push(0x50 + DELAY);
    s.extend_from_slice(&BODY);
    ScriptBuf::from(s)
}

fn tree(a: ScriptBuf, b: ScriptBuf) -> TaprootSpendInfo {
    TaprootBuilder::new()
        .add_leaf(1, a)
        .unwrap()
        .add_leaf(1, b)
        .unwrap()
        .finalize(&Secp256k1::new(), nums())
        .unwrap()
}

fn spk_of(info: &TaprootSpendInfo) -> ScriptBuf {
    ScriptBuf::new_p2tr_tweaked(info.output_key())
}

fn control_block(info: &TaprootSpendInfo, leaf: &ScriptBuf) -> Vec<u8> {
    info.control_block(&(leaf.clone(), LeafVersion::TapScript))
        .unwrap()
        .serialize()
}

fn spend_tx(outputs: Vec<TxOut>, n_inputs: usize) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: (0..n_inputs)
            .map(|i| TxIn {
                previous_output: OutPoint::new(
                    bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array(
                        [i as u8 + 1; 32],
                    )),
                    0,
                ),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            })
            .collect(),
        output: outputs,
    }
}

fn out(spk: &ScriptBuf, sats: u64) -> TxOut {
    TxOut {
        value: Amount::from_sat(sats),
        script_pubkey: spk.clone(),
    }
}

struct Spend {
    script: ScriptBuf,
    witness: Vec<Vec<u8>>,
    control_block: Vec<u8>,
    tx: Transaction,
    prevouts: Vec<TxOut>,
    input_idx: usize,
    carried: Option<VaultTxState>,
    deployments: Deployments,
    witness_size: Option<usize>,
}

fn deployments() -> Deployments {
    Deployments {
        vault: true,
        ccv: false,
        ..Default::default()
    }
}

fn run(s: Spend) -> Result<(ExecutionResult, VaultTxState), Error> {
    let leaf = bitcoin::taproot::TapLeafHash::from_script(&s.script, LeafVersion::TapScript);
    let input_amount = s.prevouts.get(s.input_idx).map(|p| p.value.to_sat());
    let mut exec = Exec::new(
        ExecCtx::Tapscript,
        Options {
            deployments: s.deployments,
            ..Default::default()
        },
        TxTemplate {
            tx: s.tx,
            prevouts: s.prevouts,
            input_idx: s.input_idx,
            taproot_annex_scriptleaf: Some((leaf, None)),
            internal_key: Some(nums()),
            full_witness_size: s.witness_size,
            control_block: Some(s.control_block),
            ccv_state: None,
            vault_state: s.carried,
            taptree_root: None,
            input_amount,
        },
        s.script,
        s.witness,
    )?;
    while exec.exec_next().is_ok() {}
    let state = exec.vault_state();
    Ok((exec.result().unwrap().clone(), state))
}

/// A vault, the transaction that triggers a withdrawal from it, and the
/// pieces a test needs to poke at either one.
struct Vault {
    info: TaprootSpendInfo,
    spk: ScriptBuf,
    recovery_spk: ScriptBuf,
    recovery_hash: [u8; 32],
    ctv_hash: [u8; 32],
    triggered: TaprootSpendInfo,
}

fn vault() -> Vault {
    // Any scriptPubKey will do; the vault only ever sees its hash.
    let recovery_spk = ScriptBuf::new_p2tr_tweaked(
        tree(ScriptBuf::from(vec![0x51]), ScriptBuf::from(vec![0x52])).output_key(),
    );
    let recovery_hash = covenants_core::vault::recovery_spk_hash(&recovery_spk);
    let ctv_hash = [0xcd; 32];
    let recover = recovery_leaf(&recovery_hash);
    let info = tree(recover.clone(), trigger_leaf());
    let triggered = tree(recover, rewritten_leaf(&ctv_hash));
    Vault {
        spk: spk_of(&info),
        recovery_spk,
        recovery_hash,
        ctv_hash,
        info,
        triggered,
    }
}

/// Witness for a trigger, bottom to top.
fn trigger_witness(
    v: &Vault,
    trigger_idx: i64,
    revault_idx: i64,
    revault_amount: i64,
) -> Vec<Vec<u8>> {
    vec![
        num(revault_amount),
        num(revault_idx),
        num(trigger_idx),
        v.ctv_hash.to_vec(),
    ]
}

fn trigger_spend(v: &Vault, outputs: Vec<TxOut>, witness: Vec<Vec<u8>>) -> Spend {
    Spend {
        script: trigger_leaf(),
        witness,
        control_block: control_block(&v.info, &trigger_leaf()),
        tx: spend_tx(outputs, 1),
        prevouts: vec![out(&v.spk, VAULT_VALUE)],
        input_idx: 0,
        carried: None,
        deployments: deployments(),
        witness_size: None,
    }
}

#[test]
fn a_trigger_rewrites_the_leaf_and_carries_the_value() {
    let v = vault();
    let trigger_spk = spk_of(&v.triggered);
    let (res, state) = run(trigger_spend(
        &v,
        vec![out(&trigger_spk, VAULT_VALUE)],
        trigger_witness(&v, 0, -1, 0),
    ))
    .unwrap();
    assert!(res.success, "{:?}", res.error);
    assert_eq!(state.output_min_amount, vec![VAULT_VALUE]);
}

/// The whole point of the design: rewriting the trigger leaf leaves the
/// recovery leaf exactly where it was, so the withdrawal stays interruptible.
#[test]
fn the_recovery_leaf_survives_the_rewrite() {
    let v = vault();
    let recover = recovery_leaf(&v.recovery_hash);
    let (res, _) = run(Spend {
        script: recover.clone(),
        witness: vec![num(0)],
        control_block: control_block(&v.triggered, &recover),
        tx: spend_tx(vec![out(&v.recovery_spk, VAULT_VALUE)], 1),
        prevouts: vec![out(&spk_of(&v.triggered), VAULT_VALUE)],
        input_idx: 0,
        carried: None,
        deployments: deployments(),
        witness_size: None,
    })
    .unwrap();
    assert!(res.success, "{:?}", res.error);
}

#[test]
fn a_partial_revault_pays_the_rest_back_into_the_vault() {
    let v = vault();
    let trigger_spk = spk_of(&v.triggered);
    let (res, state) = run(trigger_spend(
        &v,
        vec![out(&trigger_spk, 40_000), out(&v.spk, 60_000)],
        trigger_witness(&v, 0, 1, 60_000),
    ))
    .unwrap();
    assert!(res.success, "{:?}", res.error);
    assert_eq!(state.output_min_amount, vec![40_000, 60_000]);
}

#[test]
fn a_revault_must_pay_the_vault_it_came_from() {
    let v = vault();
    let trigger_spk = spk_of(&v.triggered);
    let (res, _) = run(trigger_spend(
        &v,
        vec![out(&trigger_spk, 40_000), out(&v.recovery_spk, 60_000)],
        trigger_witness(&v, 0, 1, 60_000),
    ))
    .unwrap();
    assert_eq!(res.error, Some(ExecError::VaultRevault));
}

#[test]
fn the_trigger_output_must_carry_the_rewritten_leaf() {
    let v = vault();
    let wrong = tree(recovery_leaf(&v.recovery_hash), rewritten_leaf(&[0xee; 32]));
    let (res, _) = run(trigger_spend(
        &v,
        vec![out(&spk_of(&wrong), VAULT_VALUE)],
        trigger_witness(&v, 0, -1, 0),
    ))
    .unwrap();
    assert_eq!(res.error, Some(ExecError::VaultTriggerMismatch));
}

#[test]
fn the_trigger_output_must_be_a_taproot_output() {
    let v = vault();
    let (res, _) = run(trigger_spend(
        &v,
        vec![out(&ScriptBuf::from(vec![0x00, 0x14, 0x11]), VAULT_VALUE)],
        trigger_witness(&v, 0, -1, 0),
    ))
    .unwrap();
    assert_eq!(res.error, Some(ExecError::VaultTriggerType));
}

#[test]
fn the_trigger_output_must_hold_what_the_input_was_worth() {
    let v = vault();
    let trigger_spk = spk_of(&v.triggered);
    let (res, _) = run(trigger_spend(
        &v,
        vec![out(&trigger_spk, VAULT_VALUE - 1)],
        trigger_witness(&v, 0, -1, 0),
    ))
    .unwrap();
    assert_eq!(res.error, Some(ExecError::VaultAmount));
}

/// Only -1 says there is no revault. Any other negative would let the
/// witness be padded while the spend waits without changing what it means.
#[test]
fn a_negative_revault_index_other_than_minus_one_is_rejected() {
    let v = vault();
    let trigger_spk = spk_of(&v.triggered);
    for idx in [-2i64, -3, -100] {
        let (res, _) = run(trigger_spend(
            &v,
            vec![out(&trigger_spk, VAULT_VALUE)],
            trigger_witness(&v, 0, idx, 0),
        ))
        .unwrap();
        assert_eq!(res.error, Some(ExecError::VaultParameter), "idx {idx}");
    }
}

#[test]
fn a_revault_amount_and_a_revault_output_must_agree() {
    let v = vault();
    let trigger_spk = spk_of(&v.triggered);
    // An amount with no output to put it in.
    let (res, _) = run(trigger_spend(
        &v,
        vec![out(&trigger_spk, VAULT_VALUE)],
        trigger_witness(&v, 0, -1, 10_000),
    ))
    .unwrap();
    assert_eq!(res.error, Some(ExecError::VaultParameter));

    // An output with nothing to put in it.
    let (res, _) = run(trigger_spend(
        &v,
        vec![out(&trigger_spk, 40_000), out(&v.spk, 60_000)],
        trigger_witness(&v, 0, 1, 0),
    ))
    .unwrap();
    assert_eq!(res.error, Some(ExecError::VaultParameter));
}

#[test]
fn a_revault_cannot_exceed_what_the_input_holds() {
    let v = vault();
    let trigger_spk = spk_of(&v.triggered);
    let (res, _) = run(trigger_spend(
        &v,
        vec![out(&trigger_spk, 40_000), out(&v.spk, VAULT_VALUE + 1)],
        trigger_witness(&v, 0, 1, (VAULT_VALUE + 1) as i64),
    ))
    .unwrap();
    assert_eq!(res.error, Some(ExecError::VaultRevault));
}

#[test]
fn an_index_past_the_end_of_the_outputs_is_rejected() {
    let v = vault();
    let trigger_spk = spk_of(&v.triggered);
    let (res, _) = run(trigger_spend(
        &v,
        vec![out(&trigger_spk, VAULT_VALUE)],
        trigger_witness(&v, 7, -1, 0),
    ))
    .unwrap();
    assert_eq!(res.error, Some(ExecError::VaultIndexOutOfBounds));
}

#[test]
fn a_recovery_pays_the_script_pubkey_the_vault_committed_to() {
    let v = vault();
    let recover = recovery_leaf(&v.recovery_hash);
    let (res, state) = run(Spend {
        script: recover.clone(),
        witness: vec![num(0)],
        control_block: control_block(&v.info, &recover),
        tx: spend_tx(vec![out(&v.recovery_spk, VAULT_VALUE)], 1),
        prevouts: vec![out(&v.spk, VAULT_VALUE)],
        input_idx: 0,
        carried: None,
        deployments: deployments(),
        witness_size: None,
    })
    .unwrap();
    assert!(res.success, "{:?}", res.error);
    assert_eq!(state.output_min_amount, vec![VAULT_VALUE]);
}

#[test]
fn a_recovery_to_another_script_pubkey_is_rejected() {
    let v = vault();
    let recover = recovery_leaf(&v.recovery_hash);
    let (res, _) = run(Spend {
        script: recover.clone(),
        witness: vec![num(0)],
        control_block: control_block(&v.info, &recover),
        tx: spend_tx(vec![out(&v.spk, VAULT_VALUE)], 1),
        prevouts: vec![out(&v.spk, VAULT_VALUE)],
        input_idx: 0,
        carried: None,
        deployments: deployments(),
        witness_size: None,
    })
    .unwrap();
    assert_eq!(res.error, Some(ExecError::VaultRecoveryMismatch));
}

#[test]
fn a_recovery_must_carry_the_whole_input() {
    let v = vault();
    let recover = recovery_leaf(&v.recovery_hash);
    let (res, _) = run(Spend {
        script: recover.clone(),
        witness: vec![num(0)],
        control_block: control_block(&v.info, &recover),
        tx: spend_tx(vec![out(&v.recovery_spk, VAULT_VALUE - 1)], 1),
        prevouts: vec![out(&v.spk, VAULT_VALUE)],
        input_idx: 0,
        carried: None,
        deployments: deployments(),
        witness_size: None,
    })
    .unwrap();
    assert_eq!(res.error, Some(ExecError::VaultAmount));
}

/// BIP-345's deferred checks sum every input paying into an output before
/// the amount is judged, which is what lets two vaults recover together.
/// Threading the state one input at a time has to reach the same verdict.
#[test]
fn two_inputs_recovering_together_are_summed() {
    let v = vault();
    let recover = recovery_leaf(&v.recovery_hash);
    let tx = spend_tx(vec![out(&v.recovery_spk, VAULT_VALUE * 2)], 2);
    let prevouts = vec![out(&v.spk, VAULT_VALUE), out(&v.spk, VAULT_VALUE)];

    let mut carried = None;
    for input_idx in 0..2 {
        let (res, state) = run(Spend {
            script: recover.clone(),
            witness: vec![num(0)],
            control_block: control_block(&v.info, &recover),
            tx: tx.clone(),
            prevouts: prevouts.clone(),
            input_idx,
            carried: carried.clone(),
            deployments: deployments(),
            witness_size: None,
        })
        .unwrap();
        assert!(res.success, "input {input_idx}: {:?}", res.error);
        carried = Some(state);
    }
    assert_eq!(carried.unwrap().output_min_amount, vec![VAULT_VALUE * 2]);
}

/// The same two inputs paying into an output that only covers one of them.
/// The first input passes on its own, so only the threaded state catches it.
#[test]
fn two_inputs_cannot_be_paid_by_one_input_worth_of_output() {
    let v = vault();
    let recover = recovery_leaf(&v.recovery_hash);
    let tx = spend_tx(vec![out(&v.recovery_spk, VAULT_VALUE)], 2);
    let prevouts = vec![out(&v.spk, VAULT_VALUE), out(&v.spk, VAULT_VALUE)];

    let (first, state) = run(Spend {
        script: recover.clone(),
        witness: vec![num(0)],
        control_block: control_block(&v.info, &recover),
        tx: tx.clone(),
        prevouts: prevouts.clone(),
        input_idx: 0,
        carried: None,
        deployments: deployments(),
        witness_size: None,
    })
    .unwrap();
    assert!(first.success, "{:?}", first.error);

    let (second, _) = run(Spend {
        script: recover.clone(),
        witness: vec![num(0)],
        control_block: control_block(&v.info, &recover),
        tx,
        prevouts,
        input_idx: 1,
        carried: Some(state),
        deployments: deployments(),
        witness_size: None,
    })
    .unwrap();
    assert_eq!(second.error, Some(ExecError::VaultAmount));
}

/// The pre-scan must carve an active OP_VAULT out of the OP_SUCCESSx set.
/// Miss it and every test above passes for the wrong reason, because the
/// script would succeed before the opcode ever ran.
#[test]
fn an_active_vault_does_not_pass_the_script_by_itself() {
    let v = vault();
    let (res, _) = run(trigger_spend(
        &v,
        vec![out(&spk_of(&v.info), VAULT_VALUE)],
        trigger_witness(&v, 0, -1, 0),
    ))
    .unwrap();
    assert!(!res.success);
    assert_eq!(res.error, Some(ExecError::VaultTriggerMismatch));
}

#[test]
fn an_active_vault_recover_does_not_pass_the_script_by_itself() {
    let v = vault();
    let recover = recovery_leaf(&[0x00; 32]);
    let (res, _) = run(Spend {
        script: recover.clone(),
        witness: vec![num(0)],
        control_block: control_block(&v.info, &recovery_leaf(&v.recovery_hash)),
        tx: spend_tx(vec![out(&v.recovery_spk, VAULT_VALUE)], 1),
        prevouts: vec![out(&v.spk, VAULT_VALUE)],
        input_idx: 0,
        carried: None,
        deployments: deployments(),
        witness_size: None,
    })
    .unwrap();
    assert!(!res.success);
    assert_eq!(res.error, Some(ExecError::VaultRecoveryMismatch));
}

/// With the deployment off the byte is OP_SUCCESS187 again, and the script
/// passes without the opcode meaning anything.
#[test]
fn an_inactive_vault_is_still_op_success() {
    let v = vault();
    let (res, _) = run(Spend {
        deployments: Deployments {
            vault: false,
            ccv: false,
            ..Default::default()
        },
        ..trigger_spend(
            &v,
            vec![out(&spk_of(&v.info), VAULT_VALUE)],
            trigger_witness(&v, 0, -1, 0),
        )
    })
    .unwrap();
    assert!(res.success, "{:?}", res.error);
}

/// BIP-345 and BIP-443 both claim 0xbb, so a run with both on would have to
/// guess which opcode it is.
#[test]
fn vault_and_checkcontractverify_cannot_both_be_on() {
    let v = vault();
    let err = run(Spend {
        deployments: Deployments {
            vault: true,
            ccv: true,
            ..Default::default()
        },
        ..trigger_spend(
            &v,
            vec![out(&spk_of(&v.triggered), VAULT_VALUE)],
            trigger_witness(&v, 0, -1, 0),
        )
    })
    .unwrap_err();
    assert!(
        matches!(err, Error::Other(m) if m.contains("0xbb")),
        "{err:?}"
    );
}

/// The rewrite costs 60 of the BIP-342 validation budget, which starts at
/// 50 plus the witness size. The boundary is what pins the charge: one byte
/// of witness either side of it decides the spend.
#[test]
fn the_trigger_is_charged_against_the_validation_budget() {
    let v = vault();
    let trigger_spk = spk_of(&v.triggered);
    let outputs = vec![out(&trigger_spk, VAULT_VALUE)];

    let (res, _) = run(Spend {
        witness_size: Some(9),
        ..trigger_spend(&v, outputs.clone(), trigger_witness(&v, 0, -1, 0))
    })
    .unwrap();
    assert_eq!(
        res.error,
        Some(ExecError::TapscriptValidationWeight),
        "59 of budget cannot pay a charge of 60"
    );

    let (res, _) = run(Spend {
        witness_size: Some(10),
        ..trigger_spend(&v, outputs, trigger_witness(&v, 0, -1, 0))
    })
    .unwrap();
    assert!(res.success, "60 of budget pays it exactly: {:?}", res.error);
}

/// A node proves the control block commits to the coin before any script
/// runs, so "the taptree of the currently evaluated input" is a fact by the
/// time the opcode reads it. Nothing here does that for us, and the merkle
/// path is what the rewrite is folded up, so a control block from another
/// tree would have the opcode check the output against that other tree.
#[test]
fn a_control_block_from_another_tree_is_rejected() {
    let v = vault();
    let other = tree(ScriptBuf::from(vec![0x51, 0x51]), trigger_leaf());
    let after = tree(
        ScriptBuf::from(vec![0x51, 0x51]),
        rewritten_leaf(&v.ctv_hash),
    );
    let (res, _) = run(Spend {
        control_block: control_block(&other, &trigger_leaf()),
        tx: spend_tx(vec![out(&spk_of(&after), VAULT_VALUE)], 1),
        ..trigger_spend(&v, vec![], trigger_witness(&v, 0, -1, 0))
    })
    .unwrap();
    assert_eq!(res.error, Some(ExecError::VaultControlBlockMismatch));
}

/// The prevouts a caller supplies may be placeholders, so the rewrite rule
/// says so rather than tying itself to an empty script that any unspendable
/// output would match.
#[test]
fn a_missing_input_script_pubkey_is_refused_rather_than_assumed() {
    let v = vault();
    let (res, _) = run(Spend {
        prevouts: vec![out(&ScriptBuf::new(), VAULT_VALUE)],
        ..trigger_spend(
            &v,
            vec![out(&spk_of(&v.triggered), VAULT_VALUE)],
            trigger_witness(&v, 0, -1, 0),
        )
    })
    .unwrap();
    assert_eq!(res.error, Some(ExecError::VaultPrevoutMissing));
}

/// The state is handed to the next input even when this one fails, so a
/// credit from an input that never validated must not appear in it.
#[test]
fn a_failed_credit_leaves_the_carried_state_alone() {
    let v = vault();
    let trigger_spk = spk_of(&v.triggered);
    let (res, state) = run(trigger_spend(
        &v,
        vec![out(&trigger_spk, 40_000), out(&v.spk, 10)],
        trigger_witness(&v, 0, 1, 60_000),
    ))
    .unwrap();
    assert_eq!(res.error, Some(ExecError::VaultAmount));
    assert_eq!(state.output_min_amount, vec![0, 0]);
}
