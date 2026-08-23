import { useState } from "react";
import { CATEGORIES, KINDS } from "../registry";
import { useStore } from "../store";

export function Library() {
  const [q, setQ] = useState("");
  const placing = useStore((s) => s.placing);
  const setPlacing = useStore((s) => s.setPlacing);
  // Clicking attaches the node to the cursor; the next click on the canvas
  // places it. Dragging drops it where it lands.
  const place = (kind: string) => setPlacing(placing === kind ? null : kind);
  const kinds = Object.values(KINDS).filter((k) => !q || k.label.toLowerCase().includes(q.toLowerCase()) || k.description.toLowerCase().includes(q.toLowerCase()));
  return (
    <aside className="lib">
      <input className="search" placeholder="Search nodes" value={q} onChange={(e) => setQ(e.target.value)}
        onKeyDown={(e) => { if (e.key === "Enter" && kinds[0]) place(kinds[0].kind); }} />
      {CATEGORIES.map((c) => {
        const items = kinds.filter((k) => k.category === c);
        if (!items.length) return null;
        return (
          <div key={c}>
            <div className="cat">{c}</div>
            {items.map((k) => (
              <button className={`it ${placing === k.kind ? "placing" : ""}`} key={k.kind} title={k.description} onClick={() => place(k.kind)}
                draggable onDragStart={(e) => { e.dataTransfer.setData("application/covenants-kind", k.kind); e.dataTransfer.effectAllowed = "move"; }}>
                {k.label}
              </button>
            ))}
          </div>
        );
      })}
    </aside>
  );
}
