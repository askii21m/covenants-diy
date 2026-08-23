// Completion for tapscript: the opcodes the engine says exist, and the
// @names this particular node has ports for. Both carry enough detail to
// answer the question that made you open the list.

import type { CompletionContext, CompletionResult, Completion } from "@codemirror/autocomplete";
import { catalog, statusNote, type Opcode } from "./language";

/** The values wired into this node, by reference name. */
export interface Refs { name: string; value?: string }

function info(o: Opcode): (() => Node) {
  return () => {
    const wrap = document.createElement("div");
    wrap.className = "cm-doc";
    const head = document.createElement("div");
    head.className = "cm-doc-head";
    head.textContent = `${o.name}  0x${o.byte.toString(16).padStart(2, "0")}`;
    wrap.appendChild(head);
    if (o.description) {
      const p = document.createElement("p");
      p.textContent = o.description;
      wrap.appendChild(p);
    }
    const note = statusNote(o.status);
    if (note) {
      const w = document.createElement("p");
      w.className = o.status === "covenant" ? "cm-doc-note" : "cm-doc-warn";
      w.textContent = note;
      wrap.appendChild(w);
    }
    if (o.alias) {
      const a = document.createElement("p");
      a.className = "cm-doc-note";
      a.textContent = `Also ${o.alias}, and ${o.name.replace(/^OP_/, "")}.`;
      wrap.appendChild(a);
    }
    return wrap;
  };
}

/** Opcodes rank by how likely they are to be what someone means here:
 *  covenant opcodes first, then ordinary ones, then the traps. */
function boost(o: Opcode): number {
  if (o.status === "covenant") return 2;
  if (o.status === "success" || o.status === "disallowed") return -99;
  if (o.category === "nop") return -50;
  return 0;
}

let options: Completion[] | null = null;
function opcodeOptions(): Completion[] {
  if (options) return options;
  options = catalog().map((o) => ({
    label: o.name,
    detail: o.status === "covenant" ? String(o.deployment).toUpperCase()
      : o.status === "success" ? "OP_SUCCESS"
      : o.status === "disallowed" ? "not in tapscript"
      : o.category,
    type: o.status === "covenant" ? "keyword" : o.status === "ok" ? "function" : "constant",
    info: info(o),
    boost: boost(o),
  }));
  return options;
}

/** Completions for a tapscript, given the node's reference ports. */
export function completions(refs: () => Refs[]) {
  return (ctx: CompletionContext): CompletionResult | null => {
    // Inside a comment, nothing is worth offering.
    const line = ctx.state.doc.lineAt(ctx.pos);
    const before = line.text.slice(0, ctx.pos - line.from);
    if (before.includes("#")) return null;

    const ref = ctx.matchBefore(/@[\w]*/);
    if (ref) {
      const list = refs();
      return {
        from: ref.from,
        options: list.map((r) => ({
          label: `@${r.name}`,
          detail: r.value ? `${r.value.slice(0, 16)}${r.value.length > 16 ? "…" : ""}` : "not wired",
          type: "variable",
          info: r.value ? `Wired in: ${r.value}` : "This port exists but nothing is wired into it yet.",
        })),
        validFor: /^@[\w]*$/,
      };
    }

    const word = ctx.matchBefore(/[A-Za-z_][\w]*/);
    if (!word && !ctx.explicit) return null;
    return {
      from: word ? word.from : ctx.pos,
      options: opcodeOptions(),
      validFor: /^[A-Za-z_][\w]*$/,
    };
  };
}
