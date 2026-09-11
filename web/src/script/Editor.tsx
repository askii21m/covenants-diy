// The script editor. CodeMirror does the editing; this wires it to the
// store on the same contract every other field uses: debounced as you
// type, committed on blur before whatever took the focus acts, and a
// pending edit landed before the document changes under it.

import { useEffect, useRef } from "react";
import { EditorState, Compartment } from "@codemirror/state";
import {
  EditorView,
  keymap,
  lineNumbers,
  highlightActiveLine,
  highlightActiveLineGutter,
  drawSelection,
  rectangularSelection,
  crosshairCursor,
  placeholder as cmPlaceholder,
  tooltips,
} from "@codemirror/view";
import { defaultKeymap, history, historyKeymap, indentWithTab, toggleComment } from "@codemirror/commands";
import { autocompletion, completionKeymap, closeBrackets, closeBracketsKeymap } from "@codemirror/autocomplete";
import { linter, lintGutter, type Diagnostic } from "@codemirror/lint";
import { bracketMatching } from "@codemirror/language";
import { tapscript, highlighting } from "./language";
import { completions, type Refs } from "./complete";
import { refsField, refMarks, hover, setRefs, setStep, stepField, stepMarks, type StepMark } from "./marks";
import { useStore, registerPendingEdit } from "../store";

function tooltipHost(): HTMLElement {
  let el = document.getElementById("cm-tips");
  if (!el) {
    el = document.createElement("div");
    el.id = "cm-tips";
    // Full width, no height: fixed elements are out of flow so this adds no
    // scroll extent, but a zero-width host would be the containing block for
    // any tooltip that is not itself fixed, collapsing it onto its longest
    // word.
    el.style.cssText = "position:fixed;top:0;left:0;width:100vw;height:0;overflow:visible";
    document.body.appendChild(el);
  }
  return el;
}

export interface ScriptError {
  line: number;
  word: number;
  message: string;
}

/** The character range of a word, so a mark sits under the word rather
 *  than the whole line. */
export function wordRange(doc: string, line: number, word: number): { from: number; to: number } {
  const lines = doc.split("\n");
  const text = lines[line] ?? "";
  let at = 0;
  for (let i = 0; i < line && i < lines.length; i++) at += lines[i].length + 1;
  // A position arrives one render behind the text it describes, so deleting
  // the last line leaves one past the end of the shorter document, which
  // CodeMirror rejects outright.
  const clamp = (n: number) => Math.max(0, Math.min(n, doc.length));
  // Words are whitespace-separated; comments do not count.
  const code = text.split("#")[0];
  const re = /\S+/g;
  let m: RegExpExecArray | null,
    n = 0;
  while ((m = re.exec(code))) {
    if (n === word) return { from: clamp(at + m.index), to: clamp(at + m.index + m[0].length) };
    n++;
  }
  return { from: clamp(at), to: clamp(at + text.length) };
}

const errorRange = (doc: string, err: ScriptError) => wordRange(doc, err.line, err.word);

export function Editor({
  id,
  source,
  error,
  refs,
  readOnly = false,
  mark = null,
}: {
  id: string;
  source: string;
  error?: ScriptError;
  refs: Refs[];
  /** Fixed for the life of the editor: a viewer never becomes an editor. */
  readOnly?: boolean;
  mark?: StepMark | null;
}) {
  const host = useRef<HTMLDivElement>(null);
  const view = useRef<EditorView | null>(null);
  const lintC = useRef(new Compartment());
  // Read through refs so the CodeMirror extensions, built once, always see
  // current values rather than the ones from the render that made them.
  const live = useRef({ id, refs, error });
  live.current = { id, refs, error };

  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const pendingText = useRef<string | null>(null);
  const pendingId = useRef<string>(id);

  useEffect(() => {
    const commit = (v: string, nodeId: string) => {
      if (useStore.getState().nodes.some((n) => n.id === nodeId)) useStore.getState().setField(nodeId, "source", v);
    };
    const schedule = (v: string, nodeId: string) => {
      clearTimeout(timer.current);
      pendingText.current = v;
      pendingId.current = nodeId;
      const doc = useStore.getState().active;
      timer.current = setTimeout(() => {
        pendingText.current = null;
        if (useStore.getState().active === doc) commit(v, nodeId);
      }, 150);
    };
    const flush = () => {
      if (pendingText.current == null) return;
      clearTimeout(timer.current);
      const v = pendingText.current;
      pendingText.current = null;
      commit(v, pendingId.current);
    };
    const unregister = readOnly ? () => {} : registerPendingEdit(flush);

    // Reading needs the language, the marks and the hover. Editing adds
    // history, completion and the commit path; a viewer has none of these,
    // so nothing in it can ever reach the store.
    const editing = readOnly
      ? [EditorState.readOnly.of(true), EditorView.editable.of(false)]
      : [
          highlightActiveLineGutter(),
          highlightActiveLine(),
          history(),
          rectangularSelection(),
          crosshairCursor(),
          bracketMatching(),
          closeBrackets(),
          autocompletion({
            override: [completions(() => live.current.refs)],
            activateOnTyping: true,
            icons: false,
            maxRenderedOptions: 40,
          }),
          cmPlaceholder("A tapscript. Type OP_ for the opcodes, @ for a wired value."),
          keymap.of([
            { key: "Mod-/", run: toggleComment },
            ...closeBracketsKeymap,
            ...completionKeymap,
            ...historyKeymap,
            indentWithTab,
            ...defaultKeymap,
          ]),
          EditorView.updateListener.of((u) => {
            if (u.docChanged) schedule(u.state.doc.toString(), live.current.id);
          }),
          EditorView.domEventHandlers({
            blur: () => {
              flush();
              return false;
            },
          }),
        ];
    const state = EditorState.create({
      doc: source,
      extensions: [
        // Completion and hover panels are put outside the editor, positioned
        // fixed: inside it they are clipped by the panel that holds it, which
        // cut the documentation in half. The host is fixed and of no height,
        // because in normal flow the container CodeMirror mounts gains a
        // viewport of height and the whole page becomes scrollable by
        // exactly one screen.
        tooltips({ parent: tooltipHost(), position: "fixed" }),
        lineNumbers(),
        drawSelection(),
        tapscript,
        highlighting,
        refsField,
        refMarks,
        stepField,
        stepMarks,
        hover,
        lintGutter(),
        lintC.current.of(linter(() => [])),
        ...editing,
        EditorView.lineWrapping,
        EditorView.theme({
          "&": { height: "100%", fontSize: "13px" },
          ".cm-scroller": { fontFamily: "var(--mono)", lineHeight: "1.55" },
          "&.cm-focused": { outline: "none" },
        }),
      ],
    });
    const v = new EditorView({ state, parent: host.current! });
    v.dispatch({ effects: setRefs.of(live.current.refs) });
    view.current = v;
    return () => {
      unregister();
      flush();
      v.destroy();
      view.current = null;
    };
    // Built once. Document swaps are handled below, so the editor keeps its
    // history and selection while a node is being edited.
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // A different node, or an outside change (undo, a loaded example), is
  // pushed into the editor. What the user typed is never overwritten:
  // `source` only differs from the buffer when the change came from away.
  useEffect(() => {
    const v = view.current;
    if (!v) return;
    if (v.state.doc.toString() === source) return;
    v.dispatch({
      changes: { from: 0, to: v.state.doc.length, insert: source },
      selection: { anchor: Math.min(v.state.selection.main.anchor, source.length) },
    });
  }, [id, source]);

  // Which @names have a value wired into them, for the marks and the hover.
  const refKey = refs.map((r) => `${r.name}=${r.value ?? ""}`).join("\u0000");
  useEffect(() => {
    view.current?.dispatch({ effects: setRefs.of(live.current.refs) });
  }, [refKey]);

  // The assembler's error, as a diagnostic under the exact word.
  useEffect(() => {
    const v = view.current;
    if (!v) return;
    const make = (): Diagnostic[] => {
      const err = live.current.error;
      if (!err) return [];
      const doc = v.state.doc.toString();
      const { from, to } = errorRange(doc, err);
      return [{ from, to: Math.max(to, from + 1), severity: "error", message: err.message }];
    };
    v.dispatch({ effects: lintC.current.reconfigure(linter(make, { delay: 0 })) });
  }, [error?.line, error?.word, error?.message, source]);

  // The step under the trace's cursor, as a mark on the word that ran,
  // brought into view because a script can outgrow the pane. Keyed on the
  // three values rather than the object, which is rebuilt every render.
  const from = mark?.from,
    to = mark?.to,
    failed = mark?.failed ?? false;
  useEffect(() => {
    const v = view.current;
    if (!v) return;
    v.dispatch({
      effects:
        from == null || to == null
          ? [setStep.of(null)]
          : [setStep.of({ from, to, failed }), EditorView.scrollIntoView(from, { y: "center" })],
    });
  }, [from, to, failed, source]);

  return <div className="cm-host" ref={host} />;
}
