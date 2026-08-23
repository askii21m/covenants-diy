// One component renders every kind. The registry says which ports a node
// has; this draws a row per port with a handle, a real input where the
// user can type, the wired value when a wire has arrived, and the current
// value on every output.

import { memo, useEffect, useRef, useState } from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";
import { KINDS, type Port, type Value } from "../registry";
import { useStore, registerPendingEdit, reachableFrom, type FlowNode } from "../store";
import { highlight } from "../highlight";
import { InlineName } from "./InlineName";
import { scriptBlock } from "../script/wrap";

const short = (v: Value | undefined, n = 18): string => {
  if (v == null || v === "") return "";
  if (Array.isArray(v)) return `${v.length} item${v.length === 1 ? "" : "s"}`;
  const s = String(v);
  return s.length > n + 1 ? `${s.slice(0, n)}…` : s;
};
const sats = (v: Value | undefined) => {
  const n = Number(v);
  return Number.isFinite(n) ? n.toLocaleString("en-US").replace(/,/g, " ") : String(v ?? "");
};

/** A field that commits as you type, debounced, and follows external
 *  changes (a loaded example, an undo) when it is not focused. A pending
 *  edit is committed on blur, so it lands before anything the click that
 *  took focus away does (switching documents, say), and a timer that
 *  outlives its document is dropped rather than written into the next. */
function Field({ port, value, onChange }: { port: Port; value: unknown; onChange: (v: unknown) => void }) {
  const [draft, setDraft] = useState("");
  const [focused, setFocused] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const pending = useRef<string | null>(null);
  const shown = (v: unknown) => (v == null ? "" : port.field === "number" && port.label.includes("sat") && Number.isFinite(Number(v)) ? sats(v as Value) : String(v));
  const parse = (v: string) => (port.field === "number" ? Number(v.replace(/[\s,_]/g, "")) : v.trim());
  useEffect(() => { if (!focused) setDraft(shown(value)); }, [value, focused]);
  useEffect(() => () => clearTimeout(timer.current), []);
  const commit = (v: string) => {
    clearTimeout(timer.current);
    pending.current = v;
    const doc = useStore.getState().active;
    timer.current = setTimeout(() => { pending.current = null; if (useStore.getState().active === doc) onChange(parse(v)); }, 180);
  };
  const flush = () => {
    if (pending.current == null) return;
    clearTimeout(timer.current);
    const v = pending.current; pending.current = null;
    onChange(parse(v));
  };
  // Also flushed by anything that closes or switches a document, or saves.
  const flushRef = useRef(flush); flushRef.current = flush;
  useEffect(() => registerPendingEdit(() => flushRef.current()), []);
  return (
    <input className={`f nodrag nopan ${port.field === "number" ? "n" : ""}`} value={draft}
      placeholder={port.field === "hex" ? "hex" : port.field === "number" ? "0" : ""}
      type={port.field === "number" ? "number" : undefined}
      min={port.min} max={port.max} step={port.field === "number" ? 1 : undefined}
      title={port.field === "number" && (port.min != null || port.max != null) ? `${port.min?.toLocaleString("en-US") ?? "any"} to ${port.max?.toLocaleString("en-US") ?? "any"}` : undefined}
      inputMode={port.field === "number" ? "numeric" : undefined} spellCheck={false}
      onChange={(e) => { setDraft(e.target.value); commit(e.target.value); }}
      onFocus={() => setFocused(true)} onBlur={() => { flush(); setFocused(false); }}
      onMouseDown={(e) => e.stopPropagation()} onKeyDown={(e) => { if (e.key === "Enter") (e.target as HTMLInputElement).blur(); }}
      aria-label={port.label} />
  );
}

function CovNodeImpl({ id, data, selected }: NodeProps<FlowNode>) {
  const kind = KINDS[data.kind as string];
  const computed = useStore((s) => s.computed[id]);
  const edges = useStore((s) => s.edges);
  const allComputed = useStore((s) => s.computed);
  const setField = useStore((s) => s.setField);
  if (!kind) return <div className="cov err">unknown node</div>;

  const inputs = kind.inputs(data);
  const outputs = kind.outputs(data);
  const wiredValue = (port: string): Value | undefined => {
    const e = edges.find((e) => e.target === id && e.targetHandle === port);
    return e ? allComputed[e.source]?.outputs[e.sourceHandle ?? "value"] : undefined;
  };
  const status = computed?.status ?? "ok";
  const counts: Array<[string, string, number]> = [];
  if ("nIn" in data) counts.push(["nIn", "input", 1]);
  if ("nOut" in data) counts.push(["nOut", "output", 1]);
  if ("nLeaves" in data) counts.push(["nLeaves", "leaf", 1]);
  if ("nItems" in data) counts.push(["nItems", "item", 0]);
  if ("nParts" in data) counts.push(["nParts", "part", 2]);
  const refsBound: Record<string, string> = {};
  for (const p of inputs) if (p.id.startsWith("ref_")) { const v = wiredValue(p.id); if (v != null) refsBound[p.id.slice(4)] = String(v); }

  const collapsed = Boolean(data.collapsed);
  const renaming = useStore((s) => s.renaming === id);
  const setRenaming = useStore((s) => s.setRenaming);
  const setPinMenu = useStore((s) => s.setPinMenu);
  // While a wire is being dragged, the pins it cannot land on step back so
  // the ones it can are the only bright things on the canvas.
  const connecting = useStore((s) => s.connecting);
  const dim = (p: Port, side: "source" | "target") => (connecting && !reachableFrom(connecting, id, p, side) ? " off" : "");
  const breakWires = useStore((s) => s.breakWires);
  // React Flow starts a wire on mousedown; the alt guard sits on both the
  // pointer and the mouse event so it does not rely on a cancelled
  // pointerdown suppressing the compat mousedown.
  const alt = (handleId: string) => (e: React.PointerEvent | React.MouseEvent) => { if (e.altKey && e.button === 0) { e.preventDefault(); e.stopPropagation(); breakWires(id, handleId); } };
  const pinProps = (handleId: string, side: "source" | "target") => ({
    onContextMenu: (e: React.MouseEvent) => { e.preventDefault(); e.stopPropagation(); setPinMenu({ nodeId: id, handleId, side, x: e.clientX, y: e.clientY }); },
    onPointerDownCapture: alt(handleId), onMouseDownCapture: alt(handleId),
  });

  return (
    <div className={`cov k-${kind.category.toLowerCase()} ${selected ? "on" : ""} st-${status} ${collapsed ? "collapsed" : ""}`}>
      <div className="hd">
        <button className="chev nodrag" title={collapsed ? "expand" : "collapse"} onClick={(e) => { e.stopPropagation(); setField(id, "collapsed", !collapsed); }}>{collapsed ? "▸" : "▾"}</button>
        <span className="k">{kind.label}</span>
        <InlineName className="n" value={String(data.name ?? "")} placeholder={kind.label.toLowerCase()} editing={renaming}
          onStart={() => setRenaming(id)} onCommit={(v) => { if (v != null && v !== "") setField(id, "name", v); setRenaming(null); }} />
        <span className={`d ${status}`} title={computed?.message ?? ""} />
      </div>
      {collapsed && (
        <div className="stubs">
          {inputs.filter((p) => !p.wide).map((p) => <Handle key={p.id} type="target" position={Position.Left} id={p.id} className={`p t-${p.type}${dim(p, "target")}`} title={`${p.label} · ${p.type}`} {...pinProps(p.id, "target")} />)}
          {outputs.map((p) => <Handle key={p.id} type="source" position={Position.Right} id={p.id} className={`p t-${p.type}${dim(p, "source")}`} title={`${p.label} · ${p.type}`} {...pinProps(p.id, "source")} />)}
        </div>
      )}
      <div className="bd" hidden={collapsed}>
        {inputs.map((p) => p.wide ? (
          <div className="r wide" key={p.id}>
            {/* The preview is clamped; fade the edge so a reader can see
                the script carries on past it. */}
            <pre className={`src ${scriptBlock(String(data[p.id] ?? "")).clipped ? "clipped" : ""}`}>{highlight(String(data[p.id] ?? ""), undefined, refsBound)}</pre>
          </div>
        ) : (
          <div className="r in" key={p.id}>
            <Handle type="target" position={Position.Left} id={p.id} className={`p t-${p.type}${dim(p, "target")}`}
              title={`${p.label} · ${p.type}${wiredValue(p.id) !== undefined ? " · alt-click to disconnect" : ""}`} {...pinProps(p.id, "target")} />
            <span className="l">{p.label}</span>
            {(() => {
              const w = wiredValue(p.id);
              if (w !== undefined) return <span className="f wired" title={Array.isArray(w) ? w.join("\n") : String(w)}>{p.label.includes("sat") ? sats(w) : short(w, 16)}</span>;
              if (!p.field) return <span className="f empty" title="wire a value in">not wired</span>;
              if (p.field === "select") return (
                <select className="f sel nodrag nopan" value={String(data[p.id] ?? p.options?.[0] ?? "")} aria-label={p.label}
                  onChange={(e) => setField(id, p.id, e.target.value)} onMouseDown={(e) => e.stopPropagation()}>
                  {(p.options ?? []).map((o) => <option key={o} value={o}>{o}</option>)}
                </select>
              );
              return <Field port={p} value={data[p.id]} onChange={(v) => setField(id, p.id, v)} />;
            })()}
          </div>
        ))}
        {outputs.length > 0 && inputs.length > 0 && <div className="sep" />}
        {outputs.map((p) => {
          const v = computed?.outputs[p.id];
          const text = v == null ? "" : Array.isArray(v) ? v.join("\n") : String(v);
          return (
            <div className="r out" key={p.id}>
              <span className="l">{p.label}</span>
              <span className={`v ${v == null ? "none" : ""}`} title={text ? `${text}\n\nclick to copy` : "no value yet"}
                onClick={(e) => { e.stopPropagation(); if (text) navigator.clipboard?.writeText(text); }}>
                {v == null ? "none" : p.label.includes("sat") ? sats(v) : short(v)}
              </span>
              <Handle type="source" position={Position.Right} id={p.id} className={`p t-${p.type}${dim(p, "source")}`} title={`${p.label} · ${p.type}`} {...pinProps(p.id, "source")} />
            </div>
          );
        })}
      </div>
      <div className="ft" hidden={collapsed}>
        {counts.map(([key, label, min]) => (
          <span className="cnt" key={key}>
            <button className="nodrag" title={`remove ${label}`} onClick={(e) => { e.stopPropagation(); setField(id, key, Math.max(min, Number(data[key]) - 1)); }}>-</button>
            <span>{String(data[key])} {label}{Number(data[key]) === 1 ? "" : "s"}</span>
            <button className="nodrag" title={`add ${label}`} onClick={(e) => { e.stopPropagation(); setField(id, key, Number(data[key]) + 1); }}>+</button>
          </span>
        ))}
        {computed?.message && <span className={`msg ${status}`}>{computed.message}</span>}
      </div>
    </div>
  );
}

export const CovNode = memo(CovNodeImpl);
