// The detail panel: the selected node's content. A Tapscript gets the
// editor beside its derived values, an Execute gets the trace, a Template
// or Transaction gets its decoded structure, anything else its outputs.

import { Fragment, useRef } from "react";
import { KINDS, type Value } from "../registry";
import { useStore, portValue } from "../store";
import { Editor } from "../script/Editor";
import { wasm, flagsOf } from "../engine";
import type { DebugTrace, ParsedTx, AssembleView } from "../../pkg/covenants.js";
import { COMMENT_COLORS } from "../nodes/CommentNode";

/** The draggable seam between the panel's two halves. */
export function Split() {
  const setSplitRatio = useStore((s) => s.setSplitRatio);
  const dragging = useRef(false);
  return (
    <div
      className="vdiv"
      role="separator"
      aria-orientation="vertical"
      title="drag to resize"
      onPointerDown={(e) => {
        dragging.current = true;
        (e.target as HTMLElement).setPointerCapture(e.pointerId);
      }}
      onPointerMove={(e) => {
        if (!dragging.current) return;
        const box = (e.currentTarget as HTMLElement).parentElement!.getBoundingClientRect();
        setSplitRatio((e.clientX - box.left) / box.width);
      }}
      onPointerUp={(e) => {
        dragging.current = false;
        (e.target as HTMLElement).releasePointerCapture(e.pointerId);
      }}
      onDoubleClick={() => setSplitRatio(0.56)}
    />
  );
}

const short = (s: string, n = 16) => (s.length > n + 1 ? `${s.slice(0, n)}…` : s);
const sats = (n: number) => n.toLocaleString("en-US").replace(/,/g, " ");

export function Detail() {
  const selected = useStore((s) => s.selected);
  const node = useStore((s) => s.nodes.find((n) => n.id === selected));
  const computed = useStore((s) => (selected ? s.computed[selected] : undefined));
  const kind = node ? KINDS[node.data.kind as string] : undefined;
  if (!node || !kind)
    return (
      <div className="detail">
        <div className="empty">Select a node. Its script, trace, or decoded value appears here.</div>
      </div>
    );
  return (
    <div className="detail">
      <div className="ph">
        <span className="k">{kind.label}</span>
        <b>{String(node.data.name)}</b>
        <span className="desc">{kind.description}</span>
        {computed?.message && <span className={`pill ${computed.status ?? "ok"}`}>{computed.message}</span>}
      </div>
      {node.data.kind === "tapscript" ? (
        <ScriptEditor
          id={node.id}
          source={String(node.data.source ?? "")}
          view={computed?.extra as AssembleView | undefined}
        />
      ) : node.data.kind === "execute" ? (
        <Trace trace={computed?.extra as DebugTrace | undefined} />
      ) : node.data.kind === "template" || node.data.kind === "transaction" ? (
        <TxDetail hex={String(computed?.outputs[node.data.kind === "template" ? "template" : "hex"] ?? "")} />
      ) : node.data.kind === "comment" ? (
        <CommentDetail id={node.id} data={node.data} />
      ) : (
        <Outputs id={node.id} />
      )}
    </div>
  );
}

// --- script editor ----------------------------------------------------------

function ScriptEditor({ id, source, view }: { id: string; source: string; view?: AssembleView }) {
  const edges = useStore((s) => s.edges);
  const ratio = useStore((s) => s.splitRatio);
  const nodes = useStore((s) => s.nodes);
  const computed = useStore((s) => s.computed);
  const bound: Record<string, string> = {};
  for (const r of view?.refs ?? []) {
    const v = portValue(id, `ref_${r}`);
    if (v != null) bound[r] = String(v);
  }
  const err = view?.error ? { line: view.error.line, word: view.error.word, message: view.error.message } : undefined;

  // Where this script goes: which taproot outputs hold it, which executions run it.
  const consumers = edges
    .filter((e) => e.source === id && e.sourceHandle === "script")
    .map((e) => {
      const n = nodes.find((n) => n.id === e.target);
      return n ? { node: n, port: e.targetHandle ?? "", result: computed[n.id] } : null;
    })
    .filter(Boolean) as {
    node: { id: string; data: Record<string, unknown> };
    port: string;
    result?: { message?: string; status?: string };
  }[];
  const underNone = view?.script
    ? (() => {
        try {
          return wasm.classify(view.script, flagsOf("none"));
        } catch {
          return null;
        }
      })()
    : null;

  return (
    <div className="two" style={{ ["--split" as string]: `${(ratio * 100).toFixed(2)}%` }}>
      <div className="ed">
        <div className="edwrap">
          <Editor
            id={id}
            source={source}
            error={err}
            refs={(view?.refs ?? []).map((r) => ({ name: r, value: bound[r] }))}
          />
        </div>
        <div className={`st ${err ? "err" : ""}`}>
          {err ? (
            <span>
              line {err.line + 1}, word {err.word + 1}: {err.message}
            </span>
          ) : (
            <>
              <span>
                <b>{view?.script ? `${view.script.length / 2} B` : "none"}</b>
              </span>
              {view?.enforcement && (
                <span className={view.enforcement.status === "enforced" ? "ok" : "warn"}>
                  {view.enforcement.status}
                  {view.enforcement.inactive.length ? ` · ${view.enforcement.inactive.join(", ")} inactive` : ""}
                </span>
              )}
              {(view?.refs ?? []).map((r) => (
                <span key={r} className={bound[r] ? "ref" : "ref unbound"} title={bound[r] ?? "nothing wired"}>
                  @{r}
                  {bound[r] ? ` = ${short(bound[r], 10)}` : " · not wired"}
                </span>
              ))}
              <span className="hint">
                <kbd>⌃Space</kbd> for opcodes, <kbd>@</kbd> for a wired value, <kbd>⌘/</kbd> comments
              </span>
            </>
          )}
        </div>
      </div>
      <Split />
      <dl className="kv side">
        <dt>script</dt>
        <dd
          className="copy"
          title="click to copy"
          onClick={() => view?.script && navigator.clipboard?.writeText(view.script)}
        >
          {view?.script ?? "none"}
        </dd>
        <dt>disassembly</dt>
        <dd>{view?.asm ?? "none"}</dd>
        <dt>leaf hash</dt>
        <dd>{view?.leaf_hash ?? "none"}</dd>
        {consumers.map((c, i) => (
          <Fragment key={i}>
            <dt>
              {c.node.data.kind === "taproot" ? "in taptree" : c.node.data.kind === "execute" ? "run by" : "feeds"}
            </dt>
            <dd className="a">
              {String(c.node.data.name)} · {c.port}
              {c.result?.message ? ` · ${c.result.message}` : ""}
            </dd>
          </Fragment>
        ))}
        {view?.enforcement && (
          <>
            <dt>under this ruleset</dt>
            <dd className={view.enforcement.status === "enforced" ? "a" : "w"}>
              {view.enforcement.status}
              {view.enforcement.inactive.length ? ` · ${view.enforcement.inactive.join(", ")} inactive` : ""}
            </dd>
          </>
        )}
        {underNone && (
          <>
            <dt>under none</dt>
            <dd className={underNone.status === "enforced" ? "a" : "w"}>
              {underNone.status}
              {underNone.inactive.length ? ` · ${underNone.inactive.join(", ")} would be inactive` : ""}
            </dd>
          </>
        )}
      </dl>
    </div>
  );
}

// --- trace ----------------------------------------------------------------

function Trace({ trace }: { trace?: DebugTrace }) {
  if (!trace) return <div className="empty">Wire a script and a transaction to run.</div>;
  return (
    <div className="trace">
      <table className="steps">
        <thead>
          <tr>
            <th className="n"></th>
            <th className="op">opcode</th>
            <th>stack after</th>
            <th className="w">budget</th>
          </tr>
        </thead>
        <tbody>
          {trace.steps.map((s) => (
            <tr key={s.index} className={s.error ? "fail" : ""}>
              <td className="n">{s.index}</td>
              <td className="op">
                {s.op.startsWith("OP_") ? <span className="mn">{s.op}</span> : short(s.op.replace(/[<>]/g, ""), 22)}
              </td>
              <td>
                <div className="cellstack">
                  {s.stack.length === 0 && !s.error && <span className="none">empty</span>}
                  {s.stack.map((it, i) => (
                    <span className="it" key={i} title={it}>
                      {it.length > 18 ? short(it, 14) : it || "0"}
                    </span>
                  ))}
                  {s.error && <span className="it err">{s.error}</span>}
                </div>
              </td>
              <td className="w">{s.validation_weight}</td>
            </tr>
          ))}
          {trace.steps.length === 0 && (
            <tr>
              <td colSpan={4} className="none">
                {trace.error ?? "no steps"}
              </td>
            </tr>
          )}
        </tbody>
      </table>
      <div className="st">
        <span className={trace.success ? "ok" : "err"}>
          {trace.success ? "accepted" : `rejected${trace.error ? `: ${trace.error}` : ""}`}
        </span>
        <span title={trace.unpriced_ops > 0 ? "an opcode ran whose weight no BIP has settled" : undefined}>
          budget {trace.validation_weight_start} → {trace.validation_weight_remaining}
          {trace.unpriced_ops > 0 ? " at least" : ""}
        </span>
        <span>final stack [{trace.final_stack.map((x) => short(x, 10)).join(", ")}]</span>
      </div>
    </div>
  );
}

// --- transaction ------------------------------------------------------------

function TxDetail({ hex }: { hex: string }) {
  const ratio = useStore((s) => s.splitRatio);
  let parsed: ParsedTx | null = null;
  try {
    if (hex) parsed = wasm.parse_tx(hex);
  } catch {
    parsed = null;
  }
  if (!parsed) return <div className="empty">No transaction yet.</div>;
  return (
    <div className="two" style={{ ["--split" as string]: `${(ratio * 100).toFixed(2)}%` }}>
      <dl className="kv">
        <dt>txid</dt>
        <dd>{parsed.txid}</dd>
        <dt>version · locktime</dt>
        <dd>
          {parsed.version} · {parsed.locktime}
        </dd>
        <dt>weight</dt>
        <dd>
          {parsed.weight} wu · {parsed.vsize} vB
        </dd>
        {parsed.inputs.map((i, k) => (
          <Fragment key={`i${k}`}>
            <dt>input {k}</dt>
            <dd>
              {i.prevout} · sequence {i.sequence.toString(16)}
              {i.witness.length ? ` · witness ${i.witness.length} items` : " · no witness"}
            </dd>
          </Fragment>
        ))}
        {parsed.outputs.map((o, k) => (
          <Fragment key={`o${k}`}>
            <dt>output {k}</dt>
            <dd>
              {sats(o.value)} sat → {o.script_pubkey}
            </dd>
          </Fragment>
        ))}
      </dl>
      <Split />
      <div className="hexbox" title="click to copy" onClick={() => navigator.clipboard?.writeText(hex)}>
        {hex}
      </div>
    </div>
  );
}

// --- generic outputs ---------------------------------------------------------

function Outputs({ id }: { id: string }) {
  const node = useStore((s) => s.nodes.find((n) => n.id === id));
  const computed = useStore((s) => s.computed[id]);
  const kind = node ? KINDS[node.data.kind as string] : undefined;
  if (!node || !kind) return null;
  return (
    <dl className="kv">
      {kind.outputs(node.data).map((p) => {
        const v: Value | undefined = computed?.outputs[p.id];
        const text = v == null ? "none" : Array.isArray(v) ? v.join("\n") : String(v);
        return (
          <Fragment key={p.id}>
            <dt>{p.label}</dt>
            <dd
              className="copy"
              title="click to copy"
              onClick={() => v != null && navigator.clipboard?.writeText(text)}
            >
              {text}
            </dd>
          </Fragment>
        );
      })}
    </dl>
  );
}

// --- comment ----------------------------------------------------------------
// The Details panel a comment gets in Unreal: title, colour, move mode.

function CommentDetail({ id, data }: { id: string; data: Record<string, unknown> }) {
  const setField = useStore((s) => s.setField);
  return (
    <div className="cm-detail">
      <label className="cm-row">
        <span>Title</span>
        <input
          className="cm-input"
          value={String(data.name ?? "")}
          placeholder="Comment"
          onChange={(e) => setField(id, "name", e.target.value)}
        />
      </label>
      <div className="cm-row">
        <span>Comment color</span>
        <div className="swatches" role="radiogroup" aria-label="comment colour">
          {COMMENT_COLORS.map((k) => (
            <button
              key={k}
              role="radio"
              aria-checked={data.color === k}
              className={`swatch cm-c-${k} ${data.color === k ? "on" : ""}`}
              title={k}
              onClick={() => setField(id, "color", k)}
            />
          ))}
        </div>
      </div>
      <label className="cm-row">
        <span>Move mode</span>
        <select
          className="cm-input"
          value={data.moveContents === false ? "comment" : "group"}
          onChange={(e) => setField(id, "moveContents", e.target.value === "group")}
        >
          <option value="group">Group movement: nodes inside move with it</option>
          <option value="comment">Comment only</option>
        </select>
      </label>
      <div className="cm-help">
        Created with <kbd>C</kbd> around a selection, or an empty one at the cursor. <kbd>F2</kbd> or double-click the
        title to rename. Resize from any edge. Below 60% zoom the title grows into a bubble.
      </div>
    </div>
  );
}
