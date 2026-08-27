//! Disassembly that knows the covenant opcodes. rust-bitcoin renders the
//! soft-fork opcodes by their pre-deployment names (`OP_NOP4`,
//! `OP_RETURN_204`), which is the opposite of useful in a covenant tool.

use bitcoin::hex::DisplayHex;
use bitcoin::opcodes::all::{
    OP_NOP4, OP_PUSHNUM_1, OP_PUSHNUM_16, OP_PUSHNUM_NEG1, OP_RETURN_187, OP_RETURN_189,
    OP_RETURN_203, OP_RETURN_204, OP_RETURN_205, OP_RETURN_206,
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
        // rust-bitcoin spells these OP_PUSHNUM_n; every reference and this
        // assembler call them OP_n, and rendering a name the assembler does
        // not take means the disassembly panel cannot be pasted back.
        other if (OP_PUSHNUM_1.to_u8()..=OP_PUSHNUM_16.to_u8()).contains(&other.to_u8()) => {
            format!("OP_{}", other.to_u8() - OP_PUSHNUM_1.to_u8() + 1)
        }
        OP_PUSHNUM_NEG1 => "OP_1NEGATE".to_string(),
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

#[cfg(test)]
mod tests {
    use super::render;
    use bitcoin::hex::{DisplayHex, FromHex};
    use bitcoin::ScriptBuf;
    use covenants_core::FromAsm;

    fn asm_to_hex(src: &str) -> String {
        ScriptBuf::from_asm(src)
            .unwrap()
            .as_bytes()
            .to_lower_hex_string()
    }

    /// Disassembly that does not assemble back to the same bytes is a lie
    /// told in the one panel a reader trusts most. A number push renders as
    /// its bytes, so reading those bytes back as a number moved them: the
    /// 144 in a relative timelock came back as nine thousand.
    #[test]
    fn disassembly_assembles_back_to_the_same_bytes() {
        for src in [
            "144 OP_CHECKSEQUENCEVERIFY",
            "1 2 OP_ADD",
            "<deadbeef> OP_SHA256",
            "16 OP_DROP",
            "OP_0 OP_1 OP_EQUAL",
            "1000 OP_DROP",
            "<0100> OP_DROP",
        ] {
            let once = asm_to_hex(src);
            let script = ScriptBuf::from(Vec::<u8>::from_hex(&once).unwrap());
            let rendered = render(&script);
            let twice = ScriptBuf::from_asm(&rendered)
                .unwrap_or_else(|e| panic!("{src} -> {once} -> {rendered:?} did not parse: {e:?}"))
                .as_bytes()
                .to_lower_hex_string();
            assert_eq!(once, twice, "{src} did not survive a round trip");
        }
    }

    /// A bracketed word is bytes, never a number, so these differ.
    #[test]
    fn brackets_mean_bytes() {
        assert_eq!(asm_to_hex("<9000>"), "029000");
        assert_eq!(asm_to_hex("144"), "029000");
        assert_eq!(asm_to_hex("<0100>"), "020100");
        assert_ne!(asm_to_hex("<0100>"), asm_to_hex("100"));
    }

    /// Odd-length hex names no whole bytes, so it is rejected rather than
    /// quietly read as a number.
    #[test]
    fn a_bracketed_word_must_be_whole_bytes() {
        assert!(ScriptBuf::from_asm("<0>").is_err());
        assert!(ScriptBuf::from_asm("<abc>").is_err());
    }
}
