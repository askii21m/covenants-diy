// What each opcode does, in one line, for the completion list and the
// hover. The catalog itself (names, bytes, whether the opcode works in a
// tapscript at all) comes from the engine, which checks every entry against
// the same parser the assembler uses; this file is only the prose. A test
// asserts every catalog entry has an entry here.

export const DESCRIPTIONS: Record<string, string> = {
  // constants
  OP_0: "Push an empty byte string, which reads as false and as the number zero.",
  OP_1: "Push the number 1. Also written OP_TRUE.",
  OP_2: "Push the number 2.", OP_3: "Push the number 3.", OP_4: "Push the number 4.",
  OP_5: "Push the number 5.", OP_6: "Push the number 6.", OP_7: "Push the number 7.",
  OP_8: "Push the number 8.", OP_9: "Push the number 9.", OP_10: "Push the number 10.",
  OP_11: "Push the number 11.", OP_12: "Push the number 12.", OP_13: "Push the number 13.",
  OP_14: "Push the number 14.", OP_15: "Push the number 15.", OP_16: "Push the number 16.",
  OP_1NEGATE: "Push the number -1.",

  // stack
  OP_TOALTSTACK: "Move the top item to the altstack.",
  OP_FROMALTSTACK: "Move the top altstack item back.",
  OP_2DROP: "Drop the top two items.",
  OP_2DUP: "Copy the top two items.",
  OP_3DUP: "Copy the top three items.",
  OP_2OVER: "Copy the two items below the top two.",
  OP_2ROT: "Move the fifth and sixth items to the top.",
  OP_2SWAP: "Swap the top two pairs.",
  OP_IFDUP: "Copy the top item, but only if it is true.",
  OP_DEPTH: "Push how many items are on the stack.",
  OP_DROP: "Drop the top item.",
  OP_DUP: "Copy the top item.",
  OP_NIP: "Drop the second item.",
  OP_OVER: "Copy the second item to the top.",
  OP_PICK: "Copy the nth item to the top, n from the stack.",
  OP_ROLL: "Move the nth item to the top, n from the stack.",
  OP_ROT: "Move the third item to the top.",
  OP_SWAP: "Swap the top two items.",
  OP_TUCK: "Copy the top item to below the second.",

  // flow
  OP_IF: "Run the branch if the top item is true. In a tapscript the condition must be exactly an empty string or 0x01.",
  OP_NOTIF: "Run the branch if the top item is false. Same minimal-condition rule as OP_IF.",
  OP_ELSE: "The other branch.",
  OP_ENDIF: "Close the branch.",
  OP_VERIFY: "Fail the script unless the top item is true, and drop it.",
  OP_RETURN: "Fail the script immediately.",

  // splice and compare
  OP_SIZE: "Push the length of the top item, without removing it.",
  OP_EQUAL: "Push whether the top two items are byte-identical.",
  OP_EQUALVERIFY: "Fail unless the top two items are byte-identical.",

  // arithmetic
  OP_1ADD: "Add one.", OP_1SUB: "Subtract one.", OP_NEGATE: "Flip the sign.", OP_ABS: "Absolute value.",
  OP_NOT: "Push whether the top item is zero.",
  OP_0NOTEQUAL: "Push whether the top item is not zero.",
  OP_ADD: "Add the top two numbers.", OP_SUB: "Subtract the top from the second.",
  OP_BOOLAND: "Push whether both are non-zero.", OP_BOOLOR: "Push whether either is non-zero.",
  OP_NUMEQUAL: "Push whether the two numbers are equal.",
  OP_NUMEQUALVERIFY: "Fail unless the two numbers are equal.",
  OP_NUMNOTEQUAL: "Push whether the two numbers differ.",
  OP_LESSTHAN: "Push whether the second is less than the top.",
  OP_GREATERTHAN: "Push whether the second is greater than the top.",
  OP_LESSTHANOREQUAL: "Push whether the second is at most the top.",
  OP_GREATERTHANOREQUAL: "Push whether the second is at least the top.",
  OP_MIN: "Push the smaller of the two.", OP_MAX: "Push the larger of the two.",
  OP_WITHIN: "Push whether a number is within a half-open range.",

  // crypto
  OP_RIPEMD160: "RIPEMD-160 of the top item.",
  OP_SHA1: "SHA-1 of the top item. Broken; do not commit to anything with it.",
  OP_SHA256: "SHA-256 of the top item.",
  OP_HASH160: "RIPEMD-160 of the SHA-256 of the top item.",
  OP_HASH256: "SHA-256 applied twice to the top item.",
  OP_CODESEPARATOR: "Record this position, which the next signature commits to.",
  OP_CHECKSIG: "Verify a BIP-340 signature over this input's sighash, against the key on the stack. An empty signature pushes false rather than failing.",
  OP_CHECKSIGVERIFY: "OP_CHECKSIG then OP_VERIFY: fails rather than pushing false.",
  OP_CHECKSIGADD: "Verify a signature and add one to a running count. Taproot's replacement for OP_CHECKMULTISIG.",

  // locktime
  OP_CHECKLOCKTIMEVERIFY: "Fail unless the transaction's locktime is at least the top item. BIP-65.",
  OP_CHECKSEQUENCEVERIFY: "Fail unless this input's sequence encodes at least the relative delay on the stack. BIP-112.",

  // covenants
  OP_CHECKTEMPLATEVERIFY: "Fail unless the spending transaction matches the 32-byte template hash on the stack. Commits to version, locktime, sequences, outputs and input count, but not to what is being spent. BIP-119.",
  OP_CHECKSIGFROMSTACK: "Verify a signature over a message taken from the stack rather than over the transaction. Stack: signature, message, key. The message is not hashed first. BIP-348.",
  OP_CAT: "Concatenate the top two items, second-from-top first. Limited to 520 bytes. BIP-347.",
  OP_TEMPLATEHASH: "Push a hash of the spending transaction: version, locktime, all sequences, all outputs, the annex, and this input's index. It does not commit to which coins are being spent, which is what keeps it out of a cycle when the hash sits in the output it constrains, and what makes a signature over it rebindable. BIP-446.",
  OP_INTERNALKEY: "Push the taproot internal key of the output being spent, so a leaf can name the key it was built from without repeating it. BIP-349.",

  // op_success
  OP_SUBSTR: "Disabled before taproot.", OP_LEFT: "Disabled before taproot.", OP_RIGHT: "Disabled before taproot.",
  OP_INVERT: "Disabled before taproot.", OP_AND: "Disabled before taproot.", OP_OR: "Disabled before taproot.",
  OP_XOR: "Disabled before taproot.", OP_2MUL: "Disabled before taproot.", OP_2DIV: "Disabled before taproot.",
  OP_MUL: "Disabled before taproot.", OP_DIV: "Disabled before taproot.", OP_MOD: "Disabled before taproot.",
  OP_LSHIFT: "Disabled before taproot.", OP_RSHIFT: "Disabled before taproot.",

  // legacy
  OP_CHECKMULTISIG: "Rejected outright in a tapscript. Use OP_CHECKSIGADD.",
  OP_CHECKMULTISIGVERIFY: "Rejected outright in a tapscript. Use OP_CHECKSIGADD.",

  // nops
  OP_NOP: "Does nothing.",
  OP_NOP1: "Does nothing. Reserved for a future soft fork.",
  OP_NOP5: "Does nothing. Reserved for a future soft fork.",
  OP_NOP6: "Does nothing. Reserved for a future soft fork.",
  OP_NOP7: "Does nothing. Reserved for a future soft fork.",
  OP_NOP8: "Does nothing. Reserved for a future soft fork.",
  OP_NOP9: "Does nothing. Reserved for a future soft fork.",
  OP_NOP10: "Does nothing. Reserved for a future soft fork.",
};

/** What a status means for someone writing this script, in one line. */
export const STATUS_NOTE: Record<string, string> = {
  success: "OP_SUCCESSx in a tapscript: the whole script passes, unconditionally, without running.",
  disallowed: "Not allowed in a tapscript: the script fails when it is reached.",
  covenant: "Needs its deployment to be active. Without it, see the enforcement line below.",
};
