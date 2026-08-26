//! Disassembly that knows the covenant opcodes. rust-bitcoin renders the
//! soft-fork opcodes by their pre-deployment names (`OP_NOP4`,
//! `OP_RETURN_204`), which is the opposite of useful in a covenant tool.

use bitcoin::hex::DisplayHex;
use bitcoin::opcodes::all::{
    OP_NOP4, OP_RETURN_187, OP_RETURN_189, OP_RETURN_203, OP_RETURN_204, OP_RETURN_205,
    OP_RETURN_206,
};
use bitcoin::opcodes::Opcode;
use bitcoin::script::Instruction;
use bitcoin::Script;

pub fn op_name(op: Opcode) -> String {
    match op {
        OP_NOP4 => "OP_CHECKTEMPLATEVERIFY".to_string(),
        OP_RETURN_204 => "OP_CHECKSIGFROMSTACK".to_string(),
        OP_RETURN_206 => "OP_TEMPLATEHASH".to_string(),
        OP_RETURN_203 => "OP_INTERNALKEY".to_string(),
        OP_RETURN_205 => "OP_PAIRCOMMIT".to_string(),
        OP_RETURN_189 => "OP_TXHASH".to_string(),
        OP_RETURN_187 => "OP_CHECKCONTRACTVERIFY".to_string(),
        other => other.to_string(),
    }
}

/// Byte offset and rendered text for each decoded instruction. A decode
/// failure ends the list with an `<invalid>` marker rather than erroring:
/// the debugger still wants to show what came before it.
pub fn instructions(script: &Script) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for item in script.instruction_indices() {
        match item {
            Ok((pos, Instruction::PushBytes(b))) => {
                let text = if b.as_bytes().is_empty() {
                    "OP_0".to_string()
                } else {
                    format!("<{}>", b.as_bytes().to_lower_hex_string())
                };
                out.push((pos, text));
            }
            Ok((pos, Instruction::Op(op))) => out.push((pos, op_name(op))),
            Err(_) => {
                let pos = out
                    .last()
                    .map(|(p, _): &(usize, String)| *p + 1)
                    .unwrap_or(0);
                out.push((pos, "<invalid>".to_string()));
                break;
            }
        }
    }
    out
}

pub fn render(script: &Script) -> String {
    instructions(script)
        .into_iter()
        .map(|(_, t)| t)
        .collect::<Vec<_>>()
        .join(" ")
}
