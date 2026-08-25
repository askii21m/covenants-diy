//! BIP-346 OP_TXHASH.
//!
//! A TxHash commits to a caller-chosen subset of the spending transaction.
//! The subset is named by a TxFieldSelector, a short byte string popped off
//! the stack, and the result is a plain SHA-256 over the selected fields in
//! a fixed order.
//!
//! Where BIP-119 differs: CTV commits to one fixed field set and compares
//! against a hash already on the stack. OP_TXHASH pushes, and the field set
//! is chosen per call, so the empty selector reproduces CTV's coverage
//! while other selectors reproduce every BIP-341 and BIP-118 sighash mode.
//! Paired with OP_CHECKSIGFROMSTACK it is a signature hash the script
//! itself defines.
//!
//! Selectors are malleable: several encodings can name the same fields, so
//! a script that cares should set TXFS_CONTROL and commit to the selector
//! it used.

use bitcoin::consensus::encode::VarInt;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::{Script, Transaction, TxOut, Witness};

// First selector byte: global fields.
pub const TXFS_VERSION: u8 = 1 << 0;
pub const TXFS_LOCKTIME: u8 = 1 << 1;
pub const TXFS_CURRENT_INPUT_IDX: u8 = 1 << 2;
pub const TXFS_CURRENT_INPUT_CONTROL_BLOCK: u8 = 1 << 3;
pub const TXFS_CURRENT_INPUT_SPENTSCRIPT: u8 = 1 << 4;
pub const TXFS_CURRENT_INPUT_LAST_CODESEPARATOR_POS: u8 = 1 << 5;
pub const TXFS_CURRENT_INPUT_TAPROOT_ANNEX: u8 = 1 << 6;
/// Commit to the selector itself. Set this unless malleability is wanted.
pub const TXFS_CONTROL: u8 = 1 << 7;

// Second selector byte: which fields of the selected inputs and outputs.
pub const TXFS_INPUTS_PREVOUTS: u8 = 1 << 0;
pub const TXFS_INPUTS_SEQUENCES: u8 = 1 << 1;
pub const TXFS_INPUTS_SCRIPTSIGS: u8 = 1 << 2;
pub const TXFS_INPUTS_PREV_SCRIPTPUBKEYS: u8 = 1 << 3;
pub const TXFS_INPUTS_PREV_VALUES: u8 = 1 << 4;
pub const TXFS_INPUTS_TAPROOT_ANNEXES: u8 = 1 << 5;
pub const TXFS_OUTPUTS_SCRIPTPUBKEYS: u8 = 1 << 6;
pub const TXFS_OUTPUTS_VALUES: u8 = 1 << 7;

pub const TXFS_INPUTS_ALL: u8 = TXFS_INPUTS_PREVOUTS
    | TXFS_INPUTS_SEQUENCES
    | TXFS_INPUTS_SCRIPTSIGS
    | TXFS_INPUTS_PREV_SCRIPTPUBKEYS
    | TXFS_INPUTS_PREV_VALUES
    | TXFS_INPUTS_TAPROOT_ANNEXES;
pub const TXFS_OUTPUTS_ALL: u8 = TXFS_OUTPUTS_SCRIPTPUBKEYS | TXFS_OUTPUTS_VALUES;

// Third and fourth selector bytes: which inputs, then which outputs.
pub const TXFS_INOUT_NUMBER: u8 = 1 << 7;
pub const TXFS_INOUT_SELECTION_NONE: u8 = 0x00;
pub const TXFS_INOUT_SELECTION_CURRENT: u8 = 0x40;
pub const TXFS_INOUT_SELECTION_ALL: u8 = 0x3f;
pub const TXFS_INOUT_SELECTION_MODE: u8 = 1 << 6;
pub const TXFS_INOUT_LEADING_SIZE: u8 = 1 << 5;
pub const TXFS_INOUT_INDIVIDUAL_MODE: u8 = 1 << 5;
pub const TXFS_INOUT_SELECTION_MASK: u8 = 0xff ^ (1 << 7) ^ (1 << 6) ^ (1 << 5);

/// What the empty selector expands to: everything except what is being
/// spent, which is what keeps a hash committed inside its own output out
/// of a cycle.
pub const TXFS_SPECIAL_TEMPLATE: [u8; 4] = [
    TXFS_VERSION | TXFS_LOCKTIME | TXFS_CURRENT_INPUT_IDX,
    TXFS_INPUTS_SEQUENCES | TXFS_INPUTS_SCRIPTSIGS | TXFS_OUTPUTS_ALL,
    TXFS_INOUT_NUMBER | TXFS_INOUT_SELECTION_ALL,
    TXFS_INOUT_NUMBER | TXFS_INOUT_SELECTION_ALL,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxHashError {
    InputIndexOutOfBounds,
    PrevoutsMismatch,
    /// 0b10 is not assigned in the one-byte notation.
    InvalidShortSelection,
    /// A selector byte was promised by a mode but the string ended.
    SelectorTruncated,
    /// Bytes remain after both selections were read.
    SelectorTrailingBytes,
    /// A leading count or explicit index names an input or output the
    /// transaction does not have.
    SelectionOutOfBounds,
    /// Explicit indices have to ascend, so one selector names one field set.
    SelectionNotAscending,
    /// The current input's output was selected but there is no output at
    /// that index.
    CurrentIndexExceedsOutputs,
    /// Control block or spent script selected on a non-taproot input.
    NotTaproot,
}

/// Everything about the input being spent that is not in the transaction
/// itself. A `None` field falls back to the input's witness, so a complete
/// signed transaction hashes per the BIP while a tool that holds these
/// out of band can pass them directly.
#[derive(Debug, Clone, Copy, Default)]
pub struct CurrentInput<'a> {
    pub control_block: Option<&'a [u8]>,
    /// Leaf version and the script being executed.
    pub leaf: Option<(u8, &'a Script)>,
    pub annex: Option<&'a [u8]>,
    /// Position of the last OP_CODESEPARATOR executed, 0xffffffff if none.
    pub last_codeseparator_pos: Option<u32>,
}

fn sha256_of(f: impl FnOnce(&mut sha256::HashEngine)) -> [u8; 32] {
    let mut e = sha256::Hash::engine();
    f(&mut e);
    sha256::Hash::from_engine(e).to_byte_array()
}

fn sha256_empty() -> [u8; 32] {
    sha256::Hash::hash(&[]).to_byte_array()
}

fn is_p2tr(spk: &Script) -> bool {
    let b = spk.as_bytes();
    b.len() == 34 && b[0] == 0x51 && b[1] == 0x20
}

/// The annex is the last witness element when there is more than one and
/// it starts with 0x50.
fn witness_annex(w: &Witness) -> Option<&[u8]> {
    if w.len() >= 2 {
        let last = w.last()?;
        if last.first() == Some(&0x50) {
            return Some(last);
        }
    }
    None
}

fn witness_without_annex(w: &Witness) -> usize {
    w.len() - usize::from(witness_annex(w).is_some())
}

fn witness_control_block(w: &Witness) -> Option<&[u8]> {
    let n = witness_without_annex(w);
    if n >= 2 {
        w.nth(n - 1)
    } else {
        None
    }
}

/// A leaf script is only exposed behind a well-formed control block: one
/// byte of leaf version and parity, a 32-byte internal key, then a 32-byte
/// merkle step per level. Without that the witness is not a script spend
/// and there is nothing to commit to.
fn witness_leaf(w: &Witness) -> Option<(u8, &[u8])> {
    let n = witness_without_annex(w);
    if n < 2 {
        return None;
    }
    let cb = w.nth(n - 1)?;
    if cb.len() < 33 || (cb.len() - 33) % 32 != 0 {
        return None;
    }
    Some((cb[0] & 0xfe, w.nth(n - 2)?))
}

/// Read the low 7 bits as a two's-complement signed integer.
fn read_i7(v: u8) -> i32 {
    let m = (v & 0x7f) as i32;
    if m & 0x40 == 0 {
        m
    } else {
        m - 0x80
    }
}

/// Read the low 15 bits as a two's-complement signed integer.
fn read_i15(v: u16) -> i32 {
    let m = (v & 0x7fff) as i32;
    if m & 0x4000 == 0 {
        m
    } else {
        m - 0x8000
    }
}

/// Expand the one-byte notation into the four-byte form it stands for.
fn convert_short(txfs: u8) -> Result<[u8; 4], TxHashError> {
    let mut base = TXFS_VERSION | TXFS_LOCKTIME | TXFS_CONTROL | TXFS_CURRENT_INPUT_TAPROOT_ANNEX;
    let mut inout = TXFS_OUTPUTS_ALL | TXFS_INPUTS_SEQUENCES | TXFS_INPUTS_SCRIPTSIGS;

    let selection = |bits: u8| match bits {
        0b00 => Ok(TXFS_INOUT_SELECTION_NONE),
        0b01 => Ok(TXFS_INOUT_SELECTION_CURRENT),
        0b11 => Ok(TXFS_INOUT_SELECTION_ALL),
        _ => Err(TxHashError::InvalidShortSelection),
    };
    let inputs = selection(txfs & 0b11)?;
    let outputs = selection((txfs & 0b1100) >> 2)?;

    if txfs & 0b0001_0000 != 0 {
        inout |= TXFS_INPUTS_PREVOUTS;
    }
    if txfs & 0b0010_0000 != 0 {
        inout |= TXFS_INPUTS_PREV_SCRIPTPUBKEYS | TXFS_INPUTS_PREV_VALUES;
    }
    if txfs & 0b0100_0000 != 0 {
        base |= TXFS_CURRENT_INPUT_CONTROL_BLOCK
            | TXFS_CURRENT_INPUT_SPENTSCRIPT
            | TXFS_CURRENT_INPUT_LAST_CODESEPARATOR_POS;
    }
    if txfs & 0b1000_0000 != 0 {
        base |= TXFS_CURRENT_INPUT_IDX;
    }
    Ok([base, inout, inputs, outputs])
}

/// Read one in/output selection, returning the selected indices and
/// whether the count of them is committed to.
fn parse_selection(
    first: u8,
    bytes: &mut impl Iterator<Item = u8>,
    nb_items: usize,
    current_input_idx: u32,
) -> Result<(Vec<usize>, bool), TxHashError> {
    let commit_number = first & TXFS_INOUT_NUMBER != 0;
    let selection = first & !TXFS_INOUT_NUMBER;

    let selected = if selection == TXFS_INOUT_SELECTION_NONE {
        Vec::new()
    } else if selection == TXFS_INOUT_SELECTION_ALL {
        (0..nb_items).collect()
    } else if selection == TXFS_INOUT_SELECTION_CURRENT {
        // Reachable for outputs: an input always exists at its own index.
        if current_input_idx as usize >= nb_items {
            return Err(TxHashError::CurrentIndexExceedsOutputs);
        }
        vec![current_input_idx as usize]
    } else if selection & TXFS_INOUT_SELECTION_MODE == 0 {
        let count = if selection & TXFS_INOUT_LEADING_SIZE == 0 {
            (selection & TXFS_INOUT_SELECTION_MASK) as usize
        } else {
            let next = bytes.next().ok_or(TxHashError::SelectorTruncated)?;
            (((selection & TXFS_INOUT_SELECTION_MASK) as usize) << 8) + next as usize
        };
        if count > nb_items {
            return Err(TxHashError::SelectionOutOfBounds);
        }
        (0..count).collect()
    } else {
        let absolute = selection & TXFS_INOUT_INDIVIDUAL_MODE == 0;
        let count = (selection & TXFS_INOUT_SELECTION_MASK) as usize;
        let mut selected = Vec::with_capacity(count);
        for _ in 0..count {
            let first = bytes.next().ok_or(TxHashError::SelectorTruncated)?;
            let single_byte = first & 0x80 == 0;
            // Two-byte form: the low 7 bits of this byte are the high bits
            // of the number. BIP-346's reference implementation masks with
            // 0x80 here instead, which discards those 7 bits and adds a
            // constant 0x8000; that puts every absolute two-byte index past
            // 32767 and so always out of bounds. Its own vectors never
            // reach this branch, so they do not distinguish the two.
            let number = if single_byte {
                first as u16
            } else {
                let next = bytes.next().ok_or(TxHashError::SelectorTruncated)?;
                (((first & 0x7f) as u16) << 8) + next as u16
            };

            let idx = if absolute {
                number as i64
            } else {
                let rel = if single_byte {
                    read_i7(number as u8)
                } else {
                    read_i15(number)
                };
                current_input_idx as i64 + rel as i64
            };
            if idx < 0 || idx as usize >= nb_items {
                return Err(TxHashError::SelectionOutOfBounds);
            }
            let idx = idx as usize;
            if let Some(last) = selected.last() {
                if idx <= *last {
                    return Err(TxHashError::SelectionNotAscending);
                }
            }
            selected.push(idx);
        }
        selected
    };
    Ok((selected, commit_number))
}

/// The BIP-346 TxHash of `tx` at `input_index` under `txfs`.
///
/// An empty selector means the default template; a one-byte selector is
/// the short notation; anything longer is the full form.
pub fn tx_hash(
    txfs: &[u8],
    tx: &Transaction,
    prevouts: &[TxOut],
    input_index: usize,
    current: &CurrentInput,
) -> Result<[u8; 32], TxHashError> {
    if input_index >= tx.input.len() {
        return Err(TxHashError::InputIndexOutOfBounds);
    }
    if prevouts.len() != tx.input.len() {
        return Err(TxHashError::PrevoutsMismatch);
    }
    let current_input_idx = input_index as u32;

    let expanded;
    let txfs: &[u8] = match txfs.len() {
        0 => &TXFS_SPECIAL_TEMPLATE,
        1 => {
            expanded = convert_short(txfs[0])?;
            &expanded
        }
        _ => txfs,
    };

    let mut e = sha256::Hash::engine();
    if txfs[0] & TXFS_CONTROL != 0 {
        e.input(txfs);
    }

    let mut bytes = txfs.iter().copied();
    let global = bytes.next().expect("selector is never empty here");

    if global & TXFS_VERSION != 0 {
        e.input(&tx.version.0.to_le_bytes());
    }
    if global & TXFS_LOCKTIME != 0 {
        e.input(&tx.lock_time.to_consensus_u32().to_le_bytes());
    }
    if global & TXFS_CURRENT_INPUT_IDX != 0 {
        e.input(&current_input_idx.to_le_bytes());
    }

    let prevout = &prevouts[input_index];
    let input = &tx.input[input_index];

    if global & TXFS_CURRENT_INPUT_CONTROL_BLOCK != 0 {
        if !is_p2tr(&prevout.script_pubkey) {
            return Err(TxHashError::NotTaproot);
        }
        match current
            .control_block
            .or_else(|| witness_control_block(&input.witness))
        {
            Some(cb) => e.input(sha256::Hash::hash(cb).as_byte_array()),
            None => e.input(&sha256_empty()),
        }
    }

    if global & TXFS_CURRENT_INPUT_SPENTSCRIPT != 0 {
        if !is_p2tr(&prevout.script_pubkey) {
            return Err(TxHashError::NotTaproot);
        }
        let leaf = current
            .leaf
            .map(|(v, s)| (v, s.as_bytes()))
            .or_else(|| witness_leaf(&input.witness));
        match leaf {
            Some((version, script)) => e.input(&sha256_of(|e| {
                e.input(&[version]);
                VarInt::from(script.len())
                    .consensus_encode(e)
                    .expect("engine write");
                e.input(script);
            })),
            None => e.input(&sha256_empty()),
        }
    }

    if global & TXFS_CURRENT_INPUT_LAST_CODESEPARATOR_POS != 0 {
        e.input(
            &current
                .last_codeseparator_pos
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
    }

    if global & TXFS_CURRENT_INPUT_TAPROOT_ANNEX != 0 {
        match current.annex.or_else(|| witness_annex(&input.witness)) {
            Some(annex) => e.input(sha256::Hash::hash(annex).as_byte_array()),
            None => e.input(&sha256_empty()),
        }
    }

    let fields = bytes.next().unwrap_or(0x00);

    let (inputs, commit_nb_inputs) = match bytes.next() {
        Some(first) => parse_selection(first, &mut bytes, tx.input.len(), current_input_idx)?,
        None => (Vec::new(), false),
    };

    if commit_nb_inputs {
        e.input(&(tx.input.len() as u32).to_le_bytes());
    }
    if !inputs.is_empty() {
        if fields & TXFS_INPUTS_PREVOUTS != 0 {
            e.input(&sha256_of(|e| {
                for i in &inputs {
                    tx.input[*i]
                        .previous_output
                        .consensus_encode(e)
                        .expect("engine write");
                }
            }));
        }
        if fields & TXFS_INPUTS_SEQUENCES != 0 {
            e.input(&sha256_of(|e| {
                for i in &inputs {
                    e.input(&tx.input[*i].sequence.0.to_le_bytes());
                }
            }));
        }
        if fields & TXFS_INPUTS_SCRIPTSIGS != 0 {
            e.input(&sha256_of(|e| {
                for i in &inputs {
                    e.input(sha256::Hash::hash(tx.input[*i].script_sig.as_bytes()).as_byte_array());
                }
            }));
        }
        if fields & TXFS_INPUTS_PREV_SCRIPTPUBKEYS != 0 {
            e.input(&sha256_of(|e| {
                for i in &inputs {
                    e.input(
                        sha256::Hash::hash(prevouts[*i].script_pubkey.as_bytes()).as_byte_array(),
                    );
                }
            }));
        }
        if fields & TXFS_INPUTS_PREV_VALUES != 0 {
            e.input(&sha256_of(|e| {
                for i in &inputs {
                    e.input(&prevouts[*i].value.to_sat().to_le_bytes());
                }
            }));
        }
        if fields & TXFS_INPUTS_TAPROOT_ANNEXES != 0 {
            e.input(&sha256_of(|e| {
                for i in &inputs {
                    let annex = if is_p2tr(&prevouts[*i].script_pubkey) {
                        witness_annex(&tx.input[*i].witness)
                    } else {
                        None
                    };
                    match annex {
                        Some(a) => e.input(sha256::Hash::hash(a).as_byte_array()),
                        None => e.input(&sha256_empty()),
                    }
                }
            }));
        }
    }

    let (outputs, commit_nb_outputs) = match bytes.next() {
        Some(first) => parse_selection(first, &mut bytes, tx.output.len(), current_input_idx)?,
        None => (Vec::new(), false),
    };

    if commit_nb_outputs {
        e.input(&(tx.output.len() as u32).to_le_bytes());
    }
    if !outputs.is_empty() {
        if fields & TXFS_OUTPUTS_SCRIPTPUBKEYS != 0 {
            e.input(&sha256_of(|e| {
                for i in &outputs {
                    e.input(
                        sha256::Hash::hash(tx.output[*i].script_pubkey.as_bytes()).as_byte_array(),
                    );
                }
            }));
        }
        if fields & TXFS_OUTPUTS_VALUES != 0 {
            e.input(&sha256_of(|e| {
                for i in &outputs {
                    e.input(&tx.output[*i].value.to_sat().to_le_bytes());
                }
            }));
        }
    }

    if bytes.next().is_some() {
        return Err(TxHashError::SelectorTrailingBytes);
    }
    Ok(sha256::Hash::from_engine(e).to_byte_array())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hex::FromHex;
    use bitcoin::{Amount, ScriptBuf};

    fn empty_tx(inputs: usize, outputs: usize) -> (Transaction, Vec<TxOut>) {
        use bitcoin::{absolute, transaction, OutPoint, Sequence, TxIn};
        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: (0..inputs)
                .map(|_| TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            output: (0..outputs)
                .map(|_| TxOut {
                    value: Amount::from_sat(1000),
                    script_pubkey: ScriptBuf::new(),
                })
                .collect(),
        };
        let prevouts = (0..inputs)
            .map(|_| TxOut {
                value: Amount::from_sat(2000),
                script_pubkey: ScriptBuf::from(
                    Vec::<u8>::from_hex(&format!("5120{}", "22".repeat(32))).unwrap(),
                ),
            })
            .collect();
        (tx, prevouts)
    }

    #[test]
    fn empty_selector_is_the_template() {
        let (tx, prevouts) = empty_tx(1, 1);
        let a = tx_hash(&[], &tx, &prevouts, 0, &CurrentInput::default()).unwrap();
        let b = tx_hash(
            &TXFS_SPECIAL_TEMPLATE,
            &tx,
            &prevouts,
            0,
            &CurrentInput::default(),
        )
        .unwrap();
        assert_eq!(a, b);
    }

    /// The template deliberately omits what is being spent, so changing a
    /// prevout script or amount cannot move the hash. That is what keeps a
    /// hash committed inside its own output out of a cycle.
    #[test]
    fn template_ignores_what_is_being_spent() {
        let (tx, mut prevouts) = empty_tx(1, 1);
        let before = tx_hash(&[], &tx, &prevouts, 0, &CurrentInput::default()).unwrap();
        prevouts[0].value = Amount::from_sat(999_999);
        prevouts[0].script_pubkey =
            ScriptBuf::from(Vec::<u8>::from_hex(&format!("5120{}", "77".repeat(32))).unwrap());
        let after = tx_hash(&[], &tx, &prevouts, 0, &CurrentInput::default()).unwrap();
        assert_eq!(before, after);
    }

    #[test]
    fn outputs_are_committed() {
        let (mut tx, prevouts) = empty_tx(1, 1);
        let before = tx_hash(&[], &tx, &prevouts, 0, &CurrentInput::default()).unwrap();
        tx.output[0].value = Amount::from_sat(1);
        let after = tx_hash(&[], &tx, &prevouts, 0, &CurrentInput::default()).unwrap();
        assert_ne!(before, after);
    }

    /// TXFS_CONTROL exists because distinct selectors can name the same
    /// fields. With it set the selector is in the preimage, so two
    /// spellings of one selection give different hashes.
    #[test]
    fn control_bit_commits_to_the_selector() {
        let (tx, prevouts) = empty_tx(1, 1);
        let without = tx_hash(&[0x03, 0x00], &tx, &prevouts, 0, &CurrentInput::default()).unwrap();
        let with = tx_hash(
            &[0x03 | TXFS_CONTROL, 0x00],
            &tx,
            &prevouts,
            0,
            &CurrentInput::default(),
        )
        .unwrap();
        assert_ne!(without, with);
    }

    #[test]
    fn short_notation_rejects_the_unassigned_selection() {
        let (tx, prevouts) = empty_tx(1, 1);
        // 0b10 is unassigned for inputs and for outputs.
        for byte in [0b0000_0010u8, 0b0000_1000u8] {
            assert_eq!(
                tx_hash(&[byte], &tx, &prevouts, 0, &CurrentInput::default()),
                Err(TxHashError::InvalidShortSelection)
            );
        }
    }

    #[test]
    fn selecting_the_current_output_needs_one_to_exist() {
        let (tx, prevouts) = empty_tx(2, 1);
        // Input 1 exists, output 1 does not.
        let txfs = [
            TXFS_VERSION,
            TXFS_OUTPUTS_ALL,
            0x00,
            TXFS_INOUT_SELECTION_CURRENT,
        ];
        assert_eq!(
            tx_hash(&txfs, &tx, &prevouts, 1, &CurrentInput::default()),
            Err(TxHashError::CurrentIndexExceedsOutputs)
        );
        assert!(tx_hash(&txfs, &tx, &prevouts, 0, &CurrentInput::default()).is_ok());
    }

    #[test]
    fn explicit_indices_have_to_ascend() {
        let (tx, prevouts) = empty_tx(3, 3);
        let ascending = [
            TXFS_VERSION,
            TXFS_INPUTS_SEQUENCES,
            TXFS_INOUT_SELECTION_MODE | 0x02,
            0x00,
            0x01,
            0x00,
        ];
        assert!(tx_hash(&ascending, &tx, &prevouts, 0, &CurrentInput::default()).is_ok());
        let descending = [
            TXFS_VERSION,
            TXFS_INPUTS_SEQUENCES,
            TXFS_INOUT_SELECTION_MODE | 0x02,
            0x01,
            0x00,
            0x00,
        ];
        assert_eq!(
            tx_hash(&descending, &tx, &prevouts, 0, &CurrentInput::default()),
            Err(TxHashError::SelectionNotAscending)
        );
    }

    #[test]
    fn out_of_range_selections_are_rejected() {
        let (tx, prevouts) = empty_tx(2, 2);
        // Leading 5 of 2 inputs.
        let leading = [TXFS_VERSION, TXFS_INPUTS_SEQUENCES, 0x05, 0x00];
        assert_eq!(
            tx_hash(&leading, &tx, &prevouts, 0, &CurrentInput::default()),
            Err(TxHashError::SelectionOutOfBounds)
        );
        // Absolute index 9 of 2 inputs.
        let absolute = [
            TXFS_VERSION,
            TXFS_INPUTS_SEQUENCES,
            TXFS_INOUT_SELECTION_MODE | 0x01,
            0x09,
            0x00,
        ];
        assert_eq!(
            tx_hash(&absolute, &tx, &prevouts, 0, &CurrentInput::default()),
            Err(TxHashError::SelectionOutOfBounds)
        );
    }

    /// A relative index below zero names no input, and must not wrap.
    #[test]
    fn relative_indices_do_not_wrap_below_zero() {
        let (tx, prevouts) = empty_tx(3, 3);
        let back_one = [
            TXFS_VERSION,
            TXFS_INPUTS_SEQUENCES,
            TXFS_INOUT_SELECTION_MODE | TXFS_INOUT_INDIVIDUAL_MODE | 0x01,
            0x7f, // -1
            0x00,
        ];
        assert_eq!(
            tx_hash(&back_one, &tx, &prevouts, 0, &CurrentInput::default()),
            Err(TxHashError::SelectionOutOfBounds)
        );
        assert!(tx_hash(&back_one, &tx, &prevouts, 1, &CurrentInput::default()).is_ok());
    }

    #[test]
    fn trailing_selector_bytes_are_rejected() {
        let (tx, prevouts) = empty_tx(1, 1);
        assert_eq!(
            tx_hash(
                &[TXFS_VERSION, 0x00, 0x00, 0x00, 0xff],
                &tx,
                &prevouts,
                0,
                &CurrentInput::default()
            ),
            Err(TxHashError::SelectorTrailingBytes)
        );
    }

    #[test]
    fn a_truncated_selector_is_rejected() {
        let (tx, prevouts) = empty_tx(2, 2);
        // Individual mode promising one index byte that never arrives.
        let truncated = [
            TXFS_VERSION,
            TXFS_INPUTS_SEQUENCES,
            TXFS_INOUT_SELECTION_MODE | 0x01,
        ];
        assert_eq!(
            tx_hash(&truncated, &tx, &prevouts, 0, &CurrentInput::default()),
            Err(TxHashError::SelectorTruncated)
        );
    }

    #[test]
    fn current_input_context_overrides_an_absent_witness() {
        let (tx, prevouts) = empty_tx(1, 1);
        let script = ScriptBuf::from(vec![0x51]);
        let txfs = [TXFS_CURRENT_INPUT_SPENTSCRIPT, 0x00];
        let without = tx_hash(&txfs, &tx, &prevouts, 0, &CurrentInput::default()).unwrap();
        let with = tx_hash(
            &txfs,
            &tx,
            &prevouts,
            0,
            &CurrentInput {
                leaf: Some((0xc0, &script)),
                ..Default::default()
            },
        )
        .unwrap();
        assert_ne!(without, with);
    }

    #[test]
    fn spent_script_needs_a_taproot_prevout() {
        let (tx, mut prevouts) = empty_tx(1, 1);
        prevouts[0].script_pubkey = ScriptBuf::new();
        for bit in [
            TXFS_CURRENT_INPUT_SPENTSCRIPT,
            TXFS_CURRENT_INPUT_CONTROL_BLOCK,
        ] {
            assert_eq!(
                tx_hash(&[bit, 0x00], &tx, &prevouts, 0, &CurrentInput::default()),
                Err(TxHashError::NotTaproot)
            );
        }
    }

    #[test]
    fn prevouts_have_to_cover_every_input() {
        let (tx, _) = empty_tx(2, 1);
        let (_, one) = empty_tx(1, 1);
        assert_eq!(
            tx_hash(&[], &tx, &one, 0, &CurrentInput::default()),
            Err(TxHashError::PrevoutsMismatch)
        );
    }

    #[test]
    fn input_index_is_bounds_checked() {
        let (tx, prevouts) = empty_tx(1, 1);
        assert_eq!(
            tx_hash(&[], &tx, &prevouts, 4, &CurrentInput::default()),
            Err(TxHashError::InputIndexOutOfBounds)
        );
    }

    #[test]
    fn signed_index_helpers_round_trip() {
        assert_eq!(read_i7(0x00), 0);
        assert_eq!(read_i7(0x3f), 63);
        assert_eq!(read_i7(0x40), -64);
        assert_eq!(read_i7(0x7f), -1);
        assert_eq!(read_i15(0x0000), 0);
        assert_eq!(read_i15(0x3fff), 16383);
        assert_eq!(read_i15(0x4000), -16384);
        assert_eq!(read_i15(0x7fff), -1);
    }
}
