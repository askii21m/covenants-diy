//! Tapscript source: assembly text plus references. `@name` stands for a
//! value computed elsewhere and wired into the node that owns the script.
//! A reference is a wire, so the set of references in the text is the set
//! of input ports the node exposes.
//!
//! Tokenising is deliberately simple: whitespace-separated words, `#` to
//! end of line is a comment. Anything that is not a reference is handed to
//! the assembler verbatim.

use std::collections::BTreeMap;
use std::fmt;

use bitcoin::hex::DisplayHex;
use bitcoin::ScriptBuf;
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;

use crate::asm::from_asm_with_spans;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    Word(String),
    Ref(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceError {
    /// Zero-based line and word, the assembler's convention.
    pub line: usize,
    pub word: usize,
    pub message: String,
}

impl fmt::Display for SourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "line {} word {}: {}",
            self.line + 1,
            self.word + 1,
            self.message
        )
    }
}

fn valid_ref_name(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

pub fn tokenize(source: &str) -> Result<Vec<(usize, usize, Token)>, SourceError> {
    let mut out = Vec::new();
    for (line_no, line) in source.lines().enumerate() {
        let content = line.split('#').next().unwrap_or("");
        for (word_no, word) in content.split_whitespace().enumerate() {
            let token = if let Some(name) = word.strip_prefix('@') {
                if !valid_ref_name(name) {
                    return Err(SourceError {
                        line: line_no,
                        word: word_no,
                        message: format!(
                            "`{word}` is not a valid reference; use letters, digits and underscores"
                        ),
                    });
                }
                Token::Ref(name.to_string())
            } else {
                Token::Word(word.to_string())
            };
            out.push((line_no, word_no, token));
        }
    }
    Ok(out)
}

/// Reference names in order of first appearance.
pub fn refs(source: &str) -> Result<Vec<String>, SourceError> {
    let mut names: Vec<String> = Vec::new();
    for (_, _, tok) in tokenize(source)? {
        if let Token::Ref(n) = tok {
            if !names.contains(&n) {
                names.push(n);
            }
        }
    }
    Ok(names)
}

/// Where an instruction in the assembled script came from in the source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(Tsify))]
pub struct Span {
    /// Byte offset of the instruction in the script.
    pub offset: usize,
    pub line: usize,
    pub word: usize,
    /// A push opcode and its bytes are one instruction from two words, and
    /// the author may have put them on different lines.
    pub end_line: usize,
    pub end_word: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assembled {
    pub script: ScriptBuf,
    /// What each reference resolved to, in order of first appearance.
    pub resolved: Vec<(String, Vec<u8>)>,
    /// One per instruction, in script order.
    pub spans: Vec<Span>,
}

/// What the assembler's failure means, said the way the editor should show
/// it: the debug spelling of the error kind is not prose.
fn explain(kind: &crate::asm::FromAsmErrorKind) -> String {
    use crate::asm::FromAsmErrorKind::*;
    match kind {
        UnknownInstruction => "not an opcode, a number, or hex".to_string(),
        UnexpectedEOF => "this push has no bytes after it".to_string(),
        InvalidHex => "not valid hex".to_string(),
        PushExceedsMaxSize => "a push cannot be longer than 520 bytes".to_string(),
        NonMinimalBytePush => "this push names the wrong length for its bytes".to_string(),
    }
}

/// Assembles source with every reference bound. An unbound reference is an
/// error at its position, so the editor can underline it.
pub fn assemble(
    source: &str,
    bindings: &BTreeMap<String, Vec<u8>>,
) -> Result<Assembled, SourceError> {
    let mut asm = String::new();
    let mut resolved: Vec<(String, Vec<u8>)> = Vec::new();
    // The assembler is handed one flat line, so the position it reports is
    // an index into that line and means nothing to whoever wrote the
    // script. This records where each emitted word came from, so an error
    // can be put back on the line and word the author is looking at.
    let mut origin: Vec<(usize, usize)> = Vec::new();
    for (line, word, tok) in tokenize(source)? {
        origin.push((line, word));
        match tok {
            Token::Word(w) => {
                asm.push_str(&w);
                asm.push(' ');
            }
            Token::Ref(name) => {
                let bytes = bindings.get(&name).ok_or_else(|| SourceError {
                    line,
                    word,
                    message: format!("nothing is wired into @{name}"),
                })?;
                asm.push_str(&bytes.to_lower_hex_string());
                asm.push(' ');
                if !resolved.iter().any(|(n, _)| n == &name) {
                    resolved.push((name, bytes.clone()));
                }
            }
        }
    }
    let (script, raw) = from_asm_with_spans(&asm).map_err(|e| {
        // Everything is on line 0 of the flattened asm, so its word index
        // is the index into what we emitted. Past the end means the script
        // ran out of words, which belongs on the last one.
        let (line, word) = origin
            .get(e.position.1)
            .or_else(|| origin.last())
            .copied()
            .unwrap_or((0, 0));
        SourceError {
            line,
            word,
            message: explain(&e.kind),
        }
    })?;
    // The assembler saw one line, so its word indices are indices into
    // `origin`, the same lookup the error path above makes.
    let at = |w: usize| origin.get(w).copied().unwrap_or((0, 0));
    let spans = raw
        .iter()
        .map(|s| {
            let (line, word) = at(s.first.1);
            let (end_line, end_word) = at(s.last.1);
            Span {
                offset: s.offset,
                line,
                word,
                end_line,
                end_word,
            }
        })
        .collect();
    Ok(Assembled {
        script,
        resolved,
        spans,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refs_in_order_of_first_appearance() {
        let r = refs("@b OP_DUP @a # @c in a comment\n@b OP_CTV").unwrap();
        assert_eq!(r, vec!["b", "a"]);
    }

    #[test]
    fn assembles_with_bindings() {
        let mut b = BTreeMap::new();
        b.insert("hash".to_string(), vec![0xaa; 32]);
        let a = assemble("144 OP_CSV OP_DROP @hash OP_CHECKTEMPLATEVERIFY", &b).unwrap();
        assert_eq!(a.script.len(), 2 + 1 + 1 + 1 + 33 + 1);
        assert_eq!(a.resolved, vec![("hash".to_string(), vec![0xaa; 32])]);
    }

    #[test]
    fn unbound_ref_points_at_the_word() {
        let e = assemble("OP_DUP\nOP_DROP @nope OP_CTV", &BTreeMap::new()).unwrap_err();
        assert_eq!((e.line, e.word), (1, 1));
        assert!(e.message.contains("@nope"));
    }

    #[test]
    fn bad_ref_name_is_rejected() {
        let e = tokenize("@1abc").unwrap_err();
        assert!(e.message.contains("not a valid reference"));
    }

    #[test]
    fn assembler_errors_keep_position() {
        let e = assemble("OP_DUP OP_NOTANOPCODE", &BTreeMap::new()).unwrap_err();
        assert_eq!((e.line, e.word), (0, 1));
        // Prose, not the debug spelling of the error kind: this message is
        // shown to whoever is writing the script.
        assert_eq!(e.message, "not an opcode, a number, or hex");
        let e = assemble("OP_PUSHBYTES_2 zz", &BTreeMap::new()).unwrap_err();
        assert_eq!(e.message, "not valid hex");
    }

    /// The assembler sees one flat line; the author sees their own. An
    /// error has to come back to where they actually typed it.
    #[test]
    fn assembler_errors_land_on_the_source_line() {
        // Comments and earlier lines do not shift the position.
        let src = "# a comment that is not code\n# nor is this\nOP_SHA256 OP_SWAP\nOP_DUP OP_NOPE OP_DROP";
        let e = assemble(src, &BTreeMap::new()).unwrap_err();
        assert_eq!((e.line, e.word), (3, 1));

        // A reference expands to a long hex push but still counts as one word.
        let mut b = BTreeMap::new();
        b.insert("x".to_string(), vec![0u8; 32]);
        let e = assemble("@x OP_CTV\nOP_NOPE", &b).unwrap_err();
        assert_eq!((e.line, e.word), (1, 0));
    }

    #[test]
    fn spans_map_back_to_the_author_s_lines() {
        let mut b = BTreeMap::new();
        b.insert("a".to_string(), vec![0xab]);
        let a = assemble("@a OP_DUP\n  OP_PUSHBYTES_1 # c\n01", &b).unwrap();
        let got: Vec<_> = a
            .spans
            .iter()
            .map(|s| (s.offset, s.line, s.word, s.end_line, s.end_word))
            .collect();
        // <ab> | OP_DUP | 01 01, the last from two words on two lines
        assert_eq!(got, vec![(0, 0, 0, 0, 0), (2, 0, 1, 0, 1), (3, 1, 0, 2, 0)]);
    }
}
