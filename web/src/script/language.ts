// Tapscript as a CodeMirror language. A stream tokenizer is enough: the
// grammar is one token per word, and the interesting part is which words
// are opcodes, which are references to wired values, and which are pushes.

import { StreamLanguage, HighlightStyle, syntaxHighlighting } from "@codemirror/language";
import { tags as t } from "@lezer/highlight";
import { wasm } from "../engine";
import { DESCRIPTIONS, STATUS_NOTE } from "./opcodes";

export interface Opcode {
  name: string; alias?: string | null; byte: number;
  category: string; status: string; deployment?: string | null;
  description: string;
}

let cached: Opcode[] | null = null;
/** The engine's catalog, with this file's prose attached. */
export function catalog(): Opcode[] {
  if (cached) return cached;
  try {
    cached = wasm.opcodes().opcodes.map((o) => ({ ...o, description: DESCRIPTIONS[o.name] ?? "" }));
  } catch { cached = []; }
  return cached;
}
export function statusNote(status: string): string | undefined { return STATUS_NOTE[status]; }

let names: Map<string, Opcode> | null = null;
/** Every spelling the assembler accepts, mapped to its opcode. */
export function byName(): Map<string, Opcode> {
  if (names) return names;
  names = new Map();
  for (const o of catalog()) {
    names.set(o.name, o);
    if (o.alias) names.set(o.alias, o);
    // The assembler also takes the name without its OP_ prefix.
    if (o.name.startsWith("OP_")) names.set(o.name.slice(3), o);
  }
  return names;
}

const WORD = /[A-Za-z0-9_]/;

export const tapscript = StreamLanguage.define<{ }>({
  name: "tapscript",
  token(stream) {
    if (stream.eatSpace()) return null;
    if (stream.peek() === "#") { stream.skipToEnd(); return "comment"; }
    if (stream.peek() === "@") {
      stream.next();
      while (stream.peek() && WORD.test(stream.peek()!)) stream.next();
      return "variableName";
    }
    if (stream.peek() === "<") { stream.next(); while (stream.peek() && stream.peek() !== ">") stream.next(); stream.next(); return "string"; }
    let word = "";
    while (stream.peek() && WORD.test(stream.peek()!)) word += stream.next();
    if (!word) { stream.next(); return null; }
    const op = byName().get(word);
    if (op) {
      if (op.status === "success" || op.status === "disallowed") return "invalid";
      if (op.status === "covenant") return "keyword";
      return "operator";
    }
    if (/^-?\d+$/.test(word)) return "number";
    if (/^(0x)?[0-9a-fA-F]+$/.test(word) && word.length > 1) return "string";
    return "invalid";
  },
  languageData: { commentTokens: { line: "#" } },
});

/** Colours drawn from the app's palette rather than a stock theme. */
export const highlightStyle = HighlightStyle.define([
  { tag: t.comment, color: "var(--t3)", fontStyle: "italic" },
  { tag: t.operator, color: "var(--sy-op)" },
  { tag: t.keyword, color: "var(--sy-cov)", fontWeight: "600" },
  { tag: t.variableName, color: "var(--sy-ref)" },
  { tag: t.number, color: "var(--sy-num)" },
  { tag: t.string, color: "var(--sy-hex)" },
  { tag: t.invalid, color: "var(--sy-bad)", textDecoration: "underline wavy" },
]);

export const highlighting = syntaxHighlighting(highlightStyle);
