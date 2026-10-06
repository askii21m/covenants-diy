//! Operand bounds that used to stop the interpreter rather than the script:
//! a PICK or ROLL index equal to the pool size, and a five-byte CSV operand
//! above u32::MAX. Bitcoin Core fails the script in both cases, and a tool
//! that steps through scripts has to report the same failure, not vanish.

use bitcoin::hashes::Hash;
use bitcoin::opcodes::all::{
    OP_CSV, OP_DROP, OP_EQUALVERIFY, OP_PICK, OP_PUSHNUM_1, OP_PUSHNUM_2, OP_PUSHNUM_3, OP_ROLL,
};
use bitcoin::script::Builder;
use bitcoin::taproot::{LeafVersion, TapLeafHash};
use bitcoin::{
    absolute, transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
};
use covenants_interp::{Exec, ExecCtx, ExecError, ExecutionResult, Options, TxTemplate};

/// A one-input tapscript spend whose input carries the given nSequence.
fn run(script: ScriptBuf, sequence: u32) -> ExecutionResult {
    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::all_zeros(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence(sequence),
            witness: Witness::new(),
        }],
        output: vec![],
    };
    let prevouts = vec![TxOut {
        value: Amount::from_sat(1_000),
        script_pubkey: ScriptBuf::new(),
    }];
    let leaf = TapLeafHash::from_script(&script, LeafVersion::TapScript);
    let mut exec = Exec::new(
        ExecCtx::Tapscript,
        Options::default(),
        TxTemplate {
            tx,
            prevouts,
            input_idx: 0,
            taproot_annex_scriptleaf: Some((leaf, None)),
            internal_key: None,
            full_witness_size: None,
            control_block: None,
            taptree_root: None,
            ccv_state: None,
            vault_state: None,
            input_amount: None,
        },
        script,
        vec![],
    )
    .unwrap();
    while exec.exec_next().is_ok() {}
    exec.result().unwrap().clone()
}

/// The selector is not one of the items it indexes, so with `1 1` the pool
/// holds one item and index 1 is out of range.
#[test]
fn pick_and_roll_reject_an_index_equal_to_the_pool_size() {
    for op in [OP_PICK, OP_ROLL] {
        let script = Builder::new()
            .push_opcode(OP_PUSHNUM_1)
            .push_opcode(OP_PUSHNUM_1)
            .push_opcode(op)
            .into_script();
        let res = run(script, 0xffff_fffd);
        assert!(!res.success, "{op:?} must fail the script");
        assert_eq!(res.error, Some(ExecError::InvalidStackOperation), "{op:?}");
    }
}

/// `2 3 1 PICK` copies the 2 from the bottom; `2 3 1 ROLL` moves it.
#[test]
fn pick_and_roll_reach_the_bottom_of_the_pool() {
    let picked = Builder::new()
        .push_opcode(OP_PUSHNUM_2)
        .push_opcode(OP_PUSHNUM_3)
        .push_opcode(OP_PUSHNUM_1)
        .push_opcode(OP_PICK)
        .push_opcode(OP_PUSHNUM_2)
        .push_opcode(OP_EQUALVERIFY)
        .push_opcode(OP_DROP)
        .into_script();
    assert!(run(picked, 0xffff_fffd).success);

    let rolled = Builder::new()
        .push_opcode(OP_PUSHNUM_2)
        .push_opcode(OP_PUSHNUM_3)
        .push_opcode(OP_PUSHNUM_1)
        .push_opcode(OP_ROLL)
        .push_opcode(OP_PUSHNUM_2)
        .push_opcode(OP_EQUALVERIFY)
        .into_script();
    assert!(run(rolled, 0xffff_fffd).success);
}

/// 2^32 + 5 is a legal five-byte operand. BIP-68 reads only its type flag
/// and low sixteen bits, so it asks for five blocks: met by an input at
/// sequence 5, refused by one at 4.
#[test]
fn csv_reads_a_five_byte_operand_through_the_lock_time_mask() {
    let csv = || {
        Builder::new()
            .push_int((1i64 << 32) + 5)
            .push_opcode(OP_CSV)
            .into_script()
    };
    assert!(run(csv(), 5).success);
    let res = run(csv(), 4);
    assert!(!res.success);
    assert_eq!(res.error, Some(ExecError::UnsatisfiedLocktime));
}
