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
