// What the editor knows that a generic one cannot: which @names have a
// value wired into them, and what an opcode under the pointer means.

import { StateEffect, StateField, RangeSetBuilder } from "@codemirror/state";
import { EditorView, Decoration, hoverTooltip, type Tooltip } from "@codemirror/view";
import { byName, statusNote } from "./language";
import type { Refs } from "./complete";

/** The node's reference ports, pushed in whenever a wire changes. */
export const setRefs = StateEffect.define<Refs[]>();
export const refsField = StateField.define<Refs[]>({
  create: () => [],
  update(value, tr) {
    for (const e of tr.effects) if (e.is(setRefs)) return e.value;
    return value;
  },
});

const unbound = Decoration.mark({ class: "cm-ref-unbound" });
const bound = Decoration.mark({ class: "cm-ref-bound" });

/** Colour each @name by whether anything is wired into it. An unbound
 *  reference is not a syntax error, it is a wire you have not run yet, and
 *  the difference is the thing worth seeing. */
export const refMarks = EditorView.decorations.compute(["doc", refsField], (state) => {
  const refs = state.field(refsField);
  const known = new Map(refs.map((r) => [r.name, Boolean(r.value)]));
  const builder = new RangeSetBuilder<Decoration>();
  const text = state.doc.toString();
  const re = /@[A-Za-z_]\w*/g;
  let m: RegExpExecArray | null;
  // Skip anything after a # on its line.
  const commentAt = (i: number) => {
    const start = text.lastIndexOf("\n", i - 1) + 1;
    const hash = text.slice(start, i).indexOf("#");
    return hash !== -1;
  };
  while ((m = re.exec(text))) {
    if (commentAt(m.index)) continue;
    const name = m[0].slice(1);
    if (!known.has(name)) continue;
    builder.add(m.index, m.index + m[0].length, known.get(name) ? bound : unbound);
  }
  return builder.finish();
});

function panel(title: string, body: string, note?: string, noteClass = "cm-doc-note"): HTMLElement {
  const wrap = document.createElement("div");
  wrap.className = "cm-doc";
  const head = document.createElement("div");
  head.className = "cm-doc-head";
  head.textContent = title;
  wrap.appendChild(head);
  if (body) {
    const p = document.createElement("p");
    p.textContent = body;
    wrap.appendChild(p);
  }
  if (note) {
    const n = document.createElement("p");
    n.className = noteClass;
    n.textContent = note;
    wrap.appendChild(n);
  }
  return wrap;
}

/** Hovering a word says what it is: an opcode's meaning, or what a
 *  reference currently carries. */
export const hover = hoverTooltip(
  (view, pos): Tooltip | null => {
    const line = view.state.doc.lineAt(pos);
    const offset = pos - line.from;
    if (line.text.slice(0, offset).includes("#")) return null;

    const isWord = (c: string) => /[A-Za-z0-9_@]/.test(c);
    let from = offset,
      to = offset;
    while (from > 0 && isWord(line.text[from - 1])) from--;
    while (to < line.text.length && isWord(line.text[to])) to++;
    const word = line.text.slice(from, to);
    if (!word) return null;

    if (word.startsWith("@")) {
      const name = word.slice(1);
      const r = view.state.field(refsField).find((x) => x.name === name);
      const body = r
        ? r.value
          ? `Carries ${r.value}`
          : "This port exists, but nothing is wired into it yet."
        : "A new reference. Wiring appears as a port on this node once the script assembles.";
      return { pos: line.from + from, end: line.from + to, above: true, create: () => ({ dom: panel(word, body) }) };
    }

    const op = byName().get(word);
    if (!op) return null;
    const note = statusNote(op.status);
    return {
      pos: line.from + from,
      end: line.from + to,
      above: true,
      create: () => ({
        dom: panel(
          `${op.name}  0x${op.byte.toString(16).padStart(2, "0")}`,
          op.description,
          note,
          op.status === "covenant" ? "cm-doc-note" : "cm-doc-warn",
        ),
      }),
    };
  },
  { hideOnChange: true },
);
