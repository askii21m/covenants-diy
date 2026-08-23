// A name that edits in place: double-click (or a parent's F2) turns the
// text into an input sized to its content; Enter or blur commits, Escape
// reverts. Never a browser prompt.
import { useEffect, useRef, useState } from "react";
import { registerPendingEdit } from "../store";

export function InlineName({ value, editing, onStart, onCommit, className, placeholder }: {
  value: string; editing: boolean; onStart: () => void; onCommit: (v: string | null) => void; className?: string; placeholder?: string;
}) {
  const [draft, setDraft] = useState(value);
  const ref = useRef<HTMLInputElement>(null);
  // The draft is a pending edit: closing the page or the document mid-rename
  // commits it rather than dropping it, the same as a field or a script.
  const live = useRef({ draft, value, onCommit });
  live.current = { draft, value, onCommit };
  useEffect(() => { if (editing) { setDraft(value); requestAnimationFrame(() => { ref.current?.focus(); ref.current?.select(); }); } }, [editing, value]);
  useEffect(() => {
    if (!editing) return;
    return registerPendingEdit(() => {
      const { draft, value, onCommit } = live.current;
      const v = draft.trim();
      if (v && v !== value) onCommit(v);
    });
  }, [editing]);
  if (!editing) {
    return <span className={className} title="double-click to rename" onDoubleClick={(e) => { e.stopPropagation(); onStart(); }}>{value || <span className="ph">{placeholder}</span>}</span>;
  }
  return (
    <input ref={ref} className={`${className ?? ""} inline-edit nodrag nopan`} value={draft} size={Math.min(20, Math.max(4, draft.length + 1))}
      onChange={(e) => setDraft(e.target.value)}
      onKeyDown={(e) => { e.stopPropagation(); if (e.key === "Enter") onCommit(draft.trim()); if (e.key === "Escape") onCommit(null); }}
      onBlur={() => onCommit(draft.trim())}
      onMouseDown={(e) => e.stopPropagation()} onDoubleClick={(e) => e.stopPropagation()} />
  );
}
