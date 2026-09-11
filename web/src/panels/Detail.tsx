// The detail panel: the selected node's content. A Tapscript gets the
// editor beside its derived values, an Execute gets the trace, a Template
// or Transaction gets its decoded structure, anything else its outputs.

import { Fragment, useEffect, useRef, useState, type KeyboardEvent } from "react";
import { KINDS, type Value } from "../registry";
import { useStore, portValue, feeder } from "../store";
import { Editor, wordRange } from "../script/Editor";
import type { Refs } from "../script/complete";
import type { StepMark } from "../script/marks";
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
        <Debugger id={node.id} trace={computed?.extra as DebugTrace | undefined} />
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

/** A script's @names with what is wired into each, for the editor's marks. */
function refsOf(id: string, view?: AssembleView): Refs[] {
  return (view?.refs ?? []).map((r) => {
    const v = portValue(id, `ref_${r}`);
    return { name: r, value: v == null ? undefined : String(v) };
  });
}

function ScriptEditor({ id, source, view }: { id: string; source: string; view?: AssembleView }) {
  const edges = useStore((s) => s.edges);
  const ratio = useStore((s) => s.splitRatio);
  const nodes = useStore((s) => s.nodes);
  const computed = useStore((s) => s.computed);
  const refs = refsOf(id, view);
  const bound: Record<string, string> = {};
  for (const r of refs) if (r.value != null) bound[r.name] = r.value;
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
          <Editor id={id} source={source} error={err} refs={refs} />
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

function Trace({
  trace,
  at,
  pick,
  onKey,
}: {
  trace?: DebugTrace;
  at: number | null;
  pick: (i: number) => void;
  onKey: (e: KeyboardEvent<HTMLDivElement>) => void;
}) {
  const row = useRef<HTMLTableRowElement>(null);
  useEffect(() => {
    row.current?.scrollIntoView({ block: "nearest" });
  }, [at]);
  if (!trace) return <div className="empty">Wire a script and a transaction to run.</div>;
  return (
    <div className="trace" tabIndex={0} onKeyDown={onKey}>
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
            <tr
              key={s.index}
              ref={s.index === at ? row : undefined}
              className={`${s.error ? "fail" : ""} ${s.index === at ? "cur" : ""}`.trim()}
              onClick={() => pick(s.index)}
            >
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
        {trace.steps.length > 0 && (
          <span className="hint">
            <kbd>↑</kbd> <kbd>↓</kbd> step
          </span>
        )}
      </div>
    </div>
  );
}

/** The trace beside the script that produced it, stepped together. The row
 *  under the cursor and the word that ran are one instruction, joined by
 *  the byte offset the assembler recorded for every word it emitted. */
function Debugger({ id, trace }: { id: string; trace?: DebugTrace }) {
  const nodes = useStore((s) => s.nodes);
  const edges = useStore((s) => s.edges);
  const computed = useStore((s) => s.computed);
  const ratio = useStore((s) => s.splitRatio);
  const leaf = feeder(id, "script", nodes, edges);
  const view = leaf?.data.kind === "tapscript" ? (computed[leaf.id]?.extra as AssembleView | undefined) : undefined;
  const source = leaf ? String(leaf.data.source ?? "") : "";
  const steps = trace?.steps ?? [];
  const failing = steps.findIndex((s) => s.error);

  // The cursor opens on the failing step, since that is the question a
  // rejected script asks, and on nothing otherwise, so a trace that passes
  // reads exactly as it did before it could be stepped.
  const [cur, setCur] = useState<number | null>(failing >= 0 ? failing : null);
  useEffect(() => {
    setCur(failing >= 0 ? failing : null);
  }, [id, failing]);
  const at = cur == null || steps.length === 0 ? null : Math.min(cur, steps.length - 1);

  const step = at == null ? undefined : steps[at];
  const span = step && view?.spans.find((s) => s.offset === step.position);
  const mark: StepMark | null = span
    ? {
        from: wordRange(source, span.line, span.word).from,
        to: wordRange(source, span.end_line, span.end_word).to,
        failed: Boolean(step?.error),
      }
    : null;

  const onKey = (e: KeyboardEvent<HTMLDivElement>) => {
    const k = e.key;
    const steps_ = steps.length;
    if (steps_ === 0) return;
    if (k === "Escape") {
      e.preventDefault();
      e.stopPropagation();
      setCur(null);
      // Nothing here answers to the keys any more, so hand them back. The
      // canvas ignores them while the panel holds the focus, and a second
      // Escape now reaches it and clears the selection.
      e.currentTarget.blur();
      return;
    }
    if (!["ArrowDown", "ArrowUp", "Home", "End"].includes(k)) return;
    // The canvas listens on the window for Home and the rest. A key the
    // trace has used must not also reframe the graph.
    e.preventDefault();
    e.stopPropagation();
    // Held down, keys can arrive faster than a render, so each one moves
    // from the step the one before it landed on rather than from the step
    // this render was built with.
    setCur((prev) => {
      const last = steps_ - 1;
      const now = prev == null ? null : Math.min(prev, last);
      if (k === "ArrowDown") return now == null ? 0 : Math.min(now + 1, last);
      if (k === "ArrowUp") return now == null ? last : Math.max(now - 1, 0);
      if (k === "Home") return 0;
      if (k === "End") return last;
      return null;
    });
  };

  const table = <Trace trace={trace} at={at} pick={setCur} onKey={onKey} />;
  if (!leaf || !view) return table;
  return (
    <div className="two" style={{ ["--split" as string]: `${(ratio * 100).toFixed(2)}%` }}>
      {table}
      <Split />
      <div className="ed">
        <div className="edwrap">
          <Editor id={leaf.id} source={source} readOnly refs={refsOf(leaf.id, view)} mark={mark} />
        </div>
        <div className="st">
          <span>
            <b>{String(leaf.data.name)}</b>
          </span>
          {step && span ? (
            <span>
              step {at! + 1} of {steps.length} · line {span.line + 1}
            </span>
          ) : (
            <span>{steps.length ? `${steps.length} steps` : "not run"}</span>
          )}
        </div>
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
