//! Implements the ASM parser for [`ScriptBuf`].

use std::str::FromStr;

use bitcoin::{
    hex,
    opcodes::{self, all::*},
    script::{Builder, PushBytes},
    Opcode, ScriptBuf,
};

use crate::parse_opcode;

/// Trait that something can be parsed from ASM.
pub trait FromAsm: Sized {
    /// Parses `Self` from ASM.
    fn from_asm(asm: &str) -> Result<Self, FromAsmError>;
}

impl FromAsm for ScriptBuf {
    fn from_asm(asm: &str) -> Result<Self, FromAsmError> {
        from_asm_with_spans(asm).map(|(script, _)| script)
    }
}

/// Where an instruction came from: its byte offset in the script, and the
/// first and last words that produced it. A push opcode and its bytes are
/// two words for one instruction, and they need not share a line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AsmSpan {
    pub offset: usize,
    pub first: (usize, usize),
    pub last: (usize, usize),
}

/// Parses ASM and keeps where each instruction came from, so a trace's
/// byte offsets can be put back on the words that produced them.
pub fn from_asm_with_spans(asm: &str) -> Result<(ScriptBuf, Vec<AsmSpan>), FromAsmError> {
    let mut buf = Vec::with_capacity(65);
    let mut builder = Builder::new();
    let mut spans = Vec::new();
    let mut words = iter_words(asm);
    while let Some((pos, mut word)) = words.next() {
        // Every push appends, so the builder's length before one is that
        // instruction's offset. The builder's only folding path, push_verify,
        // is never taken here.
        let offset = builder.len();
        let mut last = pos;
        // The formatter prints OP_PUSHBYTES_0 as OP_0.
        if word == "OP_0" {
            builder = builder.push_opcode(OP_PUSHBYTES_0);
            spans.push(AsmSpan {
                offset,
                first: pos,
                last,
            });
            continue;
        }
        if let Ok(op) = parse_opcode(word) {
            // check for push opcodes
            if op.to_u8() <= OP_PUSHDATA4.to_u8() {
                let (next, push) = words
                    .next()
                    .ok_or(err(pos, FromAsmErrorKind::UnexpectedEOF))?;
                last = next;
                if !try_parse_raw_hex(push, &mut buf) {
                    return Err(err(next, FromAsmErrorKind::InvalidHex));
                }
                // The builder cannot emit a non-minimal length prefix, so a
                // non-minimal push can be rejected but never produced.
                let expected_push_op = match buf.len() {
                    n if n < opcodes::all::OP_PUSHDATA1.to_u8() as usize => Opcode::from(n as u8),
                    n if n < 0x100 => opcodes::all::OP_PUSHDATA1,
                    n if n < 0x10000 => opcodes::all::OP_PUSHDATA2,
                    n if (n as u64) < 0x1_0000_0000 => opcodes::all::OP_PUSHDATA4,
                    _ => return Err(err(next, FromAsmErrorKind::PushExceedsMaxSize)),
                };
                if op != expected_push_op {
                    return Err(err(pos, FromAsmErrorKind::NonMinimalBytePush));
                }
                let push = <&PushBytes>::try_from(&buf[..])
                    .map_err(|_| err(next, FromAsmErrorKind::PushExceedsMaxSize))?;
                builder = builder.push_slice(push);
            } else {
                builder = builder.push_opcode(op);
            }
            spans.push(AsmSpan {
                offset,
                first: pos,
                last,
            });
            continue;
        }
        // Anything the opcode table does not name is a number or a push.
        // Angle brackets say "these bytes", so a bracketed word is hex and
        // never a number: the disassembler writes every push that way, and
        // reading <9000> as nine thousand meant its own output assembled
        // back to different bytes.
        let bracketed = word.starts_with('<') && word.ends_with('>');
        if bracketed {
            word = &word[1..word.len() - 1];
        }
        if !bracketed {
            if let Ok(i) = i64::from_str(word) {
                builder = builder.push_int(i);
                spans.push(AsmSpan {
                    offset,
                    first: pos,
                    last,
                });
                continue;
            }
        }
        // Hex, with or without a 0x prefix.
        if word.starts_with("0x") {
            word = &word[2..];
        }
        if try_parse_raw_hex(word, &mut buf) {
            let push = <&PushBytes>::try_from(&buf[..])
                .map_err(|_| err(pos, FromAsmErrorKind::PushExceedsMaxSize))?;
            builder = builder.push_slice(push);
            spans.push(AsmSpan {
                offset,
                first: pos,
                last,
            });
        } else {
            return Err(err(pos, FromAsmErrorKind::UnknownInstruction));
        }
    }
    Ok((builder.into_script(), spans))
}

/// Try to parse raw hex bytes and push them into the buffer.
fn try_parse_raw_hex(hex: &str, buf: &mut Vec<u8>) -> bool {
    buf.clear();
    let iter = match hex::HexToBytesIter::new(hex) {
        Ok(i) => i,
        Err(_) => return false,
    };
    for item in iter {
        let item = match item {
            Ok(i) => i,
            Err(_) => return false,
        };
        buf.push(item);
    }
    true
}
/// Create an iterator over instruction words and their position in the file.
fn iter_words(asm: &str) -> impl Iterator<Item = ((usize, usize), &str)> {
    asm.lines().enumerate().flat_map(|(line_idx, line)| {
        let content = line.split("#").next().unwrap().split("//").next().unwrap();
        content
            .split_whitespace()
            .enumerate()
            .map(move |(word_idx, word)| ((line_idx, word_idx), word))
    })
}

fn err(position: (usize, usize), kind: FromAsmErrorKind) -> FromAsmError {
    FromAsmError { position, kind }
}

/// The different kinds of [`FromAsmError`] that can occur.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FromAsmErrorKind {
    /// ASM ended unexpectedly.
    UnexpectedEOF,
    /// We were not able to interpret the instruction.
    UnknownInstruction,
    /// Invalid hexadecimal bytes.
    InvalidHex,
    /// Byte push exceeding the maximum size.
    PushExceedsMaxSize,
    /// ASM contains a byte push with non-minimal size prefix.
    ///
    /// This is not necessarily invalid, but we can't construct such pushes.
    NonMinimalBytePush,
}
/// Error from parsing Script ASM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FromAsmError {
    /// The position of the instruction that caused the error.
    ///
    /// The value is (line, word) with word incremented after
    /// every chunk of whitespace.
    pub position: (usize, usize),
    /// The kind of error that occurred.
    pub kind: FromAsmErrorKind,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spans_start_where_their_instruction_does() {
        let (script, spans) =
            from_asm_with_spans("OP_DUP OP_PUSHBYTES_2 abcd 5 <ff> OP_0").unwrap();
        // OP_DUP | 02 ab cd | OP_5 | 01 ff | OP_0
        assert_eq!(script.len(), 8);
        let got: Vec<_> = spans
            .iter()
            .map(|s| (s.offset, s.first.1, s.last.1))
            .collect();
        assert_eq!(
            got,
            vec![(0, 0, 0), (1, 1, 2), (4, 3, 3), (5, 4, 4), (7, 5, 5)]
        );
    }

    #[test]
    fn a_push_may_end_on_another_line() {
        let (_, spans) = from_asm_with_spans("OP_PUSHBYTES_1\nff").unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].first, (0, 0));
        assert_eq!(spans[0].last, (1, 0));
    }
}
