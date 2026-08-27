use bitcoin::blockdata::script;

/// Error of a script execution.
///
/// Equivalent to Bitcoin Core's `ScriptError_t`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecError {
    DisabledOpcode,
    OpCodeseparator,
    BadOpcode,
    OpCount,
    PushSize,
    MinimalData,
    InvalidStackOperation,
    NegativeLocktime,
    UnsatisfiedLocktime,
    UnbalancedConditional,
    TapscriptMinimalIf,
    Verify,
    OpReturn,
    EqualVerify,
    NumEqualVerify,
    CheckSigVerify,
    TapscriptValidationWeight,
    PubkeyType,
    SchnorrSigSize,
    SchnorrSigHashtype,
    SchnorrSig,
    TapscriptCheckMultiSig,
    PubkeyCount,
    StackSize,
    WitnessPubkeyType,
    /// BIP-119: 32-byte argument does not match the transaction's template hash.
    TemplateMismatch,
    /// BIP-118: the 1-byte 0x01 key refers to the taproot internal key, which
    /// was not provided in the TxTemplate.
    Bip118InternalKeyMissing,
    /// BIP-446: the input being spent is not in the transaction.
    TemplateHashInputIndex,
    /// BIP-349: OP_INTERNALKEY with no taproot internal key provided.
    InternalKeyMissing,
    /// BIP-346: the TxFieldSelector does not name a valid set of fields.
    TxFieldSelector(covenants_core::txhash::TxHashError),
    /// BIP-443: a CHECKCONTRACTVERIFY parameter is not one of the shapes
    /// the opcode accepts.
    CcvParameter,
    /// BIP-443: the index names an input or output the transaction has not got.
    CcvIndexOutOfBounds,
    /// BIP-443: the target's scriptPubKey is not the contract the script names.
    CcvMismatch,
    /// BIP-443: an amount rule was reached without knowing what the input is
    /// worth, so the rule cannot be evaluated. Passing it would report a
    /// covenant as enforced when nothing was checked.
    CcvAmountUnknown,
    /// BIP-443: the amount rules for the target output were broken, either by
    /// two incompatible checks on it or by an output that takes more than the
    /// input has left.
    CcvAmount,
    /// BIP-443: a taptree of -1 needs the current input's tree, which was not
    /// provided in the TxTemplate.
    CcvTaptreeMissing,
    /// BIP-443: a naked key of -1 needs the taproot internal key, which was
    /// not provided in the TxTemplate.
    CcvInternalKeyMissing,
    /// BIP-443: the key or a tweak of it is not a usable point.
    CcvKey(covenants_core::ccv::CcvError),

    // new ones for us
    ScriptIntNumericOverflow,
    Debug,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Exec(ExecError),
    InvalidScript(script::Error),
    Other(&'static str),
}
