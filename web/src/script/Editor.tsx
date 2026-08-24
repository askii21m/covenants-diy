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
import { refsField, refMarks, hover, setRefs } from "./marks";
import { useStore, registerPendingEdit } from "../store";

export interface ScriptError {
  line: number;
  word: number;
  message: string;
}

/** The character range of the word the assembler pointed at, so the
 *  squiggle sits under the word rather than the whole line. */
function errorRange(doc: string, err: ScriptError): { from: number; to: number } {
  const lines = doc.split("\n");
  const line = lines[err.line] ?? "";
  let at = 0;
  for (let i = 0; i < err.line; i++) at += lines[i].length + 1;
  // Words are whitespace-separated; comments do not count.
  const code = line.split("#")[0];
  const re = /\S+/g;
  let m: RegExpExecArray | null,
    n = 0;
  while ((m = re.exec(code))) {
    if (n === err.word) return { from: at + m.index, to: at + m.index + m[0].length };
    n++;
  }
  return { from: at, to: at + line.length };
}

export function Editor({ id, source, error, refs }: { id: string; source: string; error?: ScriptError; refs: Refs[] }) {
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
    const unregister = registerPendingEdit(flush);

    const state = EditorState.create({
      doc: source,
      extensions: [
        // Completion and hover panels are put on the body, positioned
        // fixed: inside the editor they are clipped by the panel that
        // holds it, which cut the documentation in half.
        tooltips({ parent: document.body, position: "fixed" }),
        lineNumbers(),
        highlightActiveLineGutter(),
        highlightActiveLine(),
        history(),
        drawSelection(),
        rectangularSelection(),
        crosshairCursor(),
        bracketMatching(),
        closeBrackets(),
        tapscript,
        highlighting,
        refsField,
        refMarks,
        hover,
        autocompletion({
          override: [completions(() => live.current.refs)],
          activateOnTyping: true,
          icons: false,
          maxRenderedOptions: 40,
        }),
        lintGutter(),
        lintC.current.of(linter(() => [])),
        cmPlaceholder("A tapscript. Type OP_ for the opcodes, @ for a wired value."),
        keymap.of([
          { key: "Mod-/", run: toggleComment },
          ...closeBracketsKeymap,
          ...completionKeymap,
          ...historyKeymap,
          indentWithTab,
          ...defaultKeymap,
        ]),
        EditorView.lineWrapping,
        EditorView.updateListener.of((u) => {
          if (u.docChanged) schedule(u.state.doc.toString(), live.current.id);
        }),
        EditorView.domEventHandlers({
          blur: () => {
            flush();
            return false;
          },
        }),
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

  return <div className="cm-host" ref={host} />;
}
