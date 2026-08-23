// Graph state and evaluation. React Flow owns nodes and edges; this store
// owns them too, plus the computed values, an undo stack, and autosave.
// Every structural change re-evaluates the whole graph in topological
// order, which is cheap at the sizes a covenant construction reaches.

import { create } from "zustand";
import {
  applyNodeChanges, applyEdgeChanges, addEdge,
  type Node, type Edge, type NodeChange, type EdgeChange, type Connection,
} from "@xyflow/react";
import {
  KINDS, portsCompatible, findPort, firstCompatibleInput, firstCompatibleOutput, outOfRange,
  type NodeFields, type Computed, type Value, type PortType, type Port,
} from "./registry";
import { RULESETS, NETWORKS, type Network } from "./engine";

export type FlowNode = Node<NodeFields>;
export interface Flow { nodes: FlowNode[]; edges: Edge[]; network: Network; ruleset: string }
type Snapshot = Pick<Flow, "nodes" | "edges">;

export interface Viewport { x: number; y: number; zoom: number }
/** An open document: a flow, its name, the view it was left at, and its own
 *  undo history. The active document's content also lives at the top level
 *  of the store, which is what the canvas and panels bind to. */
export interface Doc extends Flow { id: string; name: string; view: Viewport | null; past: Snapshot[]; future: Snapshot[] }

const SESSION_KEY = "covenants.session";
const LAYOUT_KEY = "covenants.layout";

/** How the panels were last sized. Kept apart from the session: it is how
 *  the window is arranged, not what is in it. */
interface Layout { panelHeight: number; splitRatio: number; showMinimap: boolean }
export function savedLayout(): Layout {
  const fallback = { panelHeight: 280, splitRatio: 0.56, showMinimap: true };
  try {
    const raw = localStorage.getItem(LAYOUT_KEY);
    if (!raw) return fallback;
    const l = JSON.parse(raw) as Partial<Layout>;
    return {
      panelHeight: Number.isFinite(l.panelHeight) ? Math.max(120, Math.min(720, l.panelHeight!)) : fallback.panelHeight,
      splitRatio: Number.isFinite(l.splitRatio) ? Math.max(0.2, Math.min(0.85, l.splitRatio!)) : fallback.splitRatio,
      showMinimap: typeof l.showMinimap === "boolean" ? l.showMinimap : fallback.showMinimap,
    };
  } catch { return fallback; }
}
function saveLayout(l: Layout) {
  try { localStorage.setItem(LAYOUT_KEY, JSON.stringify(l)); } catch { /* unavailable */ }
}
type SessionDoc = Omit<Doc, "past" | "future">;
interface Session { v: 2; active: string; docs: SessionDoc[]; closed?: SessionDoc[] }

/** A flow as it arrives from a file or storage, reduced to what the editor
 *  can render: nodes with a string id (first one wins), a finite position,
 *  and data naming a known kind, filled out with that kind's defaults;
 *  edges between kept nodes; a known network and ruleset; a string name.
 *  Null when there is no node list at all. React Flow's own fields
 *  (measured, dragging, selected) are not carried. */
export function sanitizeFlow(raw: unknown): (Partial<Flow> & { name?: string }) | null {
  if (!raw || typeof raw !== "object") return null;
  const r = raw as Record<string, unknown>;
  if (!Array.isArray(r.nodes)) return null;
  const nodes: FlowNode[] = [];
  const seen = new Set<string>();
  for (const n of r.nodes) {
    if (!n || typeof n !== "object") continue;
    const o = n as Record<string, unknown>;
    const pos = o.position as Record<string, unknown> | undefined;
    const data = o.data as Record<string, unknown> | undefined;
    if (typeof o.id !== "string" || seen.has(o.id) || !pos || typeof pos !== "object") continue;
    const x = Number(pos.x), y = Number(pos.y);
    if (!Number.isFinite(x) || !Number.isFinite(y)) continue;
    if (!data || typeof data !== "object" || typeof data.kind !== "string" || !Object.hasOwn(KINDS, data.kind)) continue;
    const kind = data.kind;
    seen.add(o.id);
    nodes.push({
      id: o.id, type: kind === "reroute" ? "reroute" : kind === "comment" ? "comment" : "cov",
      position: { x, y }, data: { ...KINDS[kind].defaults(), ...data, kind },
      ...(kind === "comment" ? { zIndex: -1 } : {}),
    });
  }
  const edges: Edge[] = [];
  const edgeIds = new Set<string>();
  const endpoints = new Set<string>();
  for (const e of Array.isArray(r.edges) ? r.edges : []) {
    if (!e || typeof e !== "object") continue;
    const o = e as Record<string, unknown>;
    if (typeof o.source !== "string" || typeof o.target !== "string" || !seen.has(o.source) || !seen.has(o.target)) continue;
    const sh = typeof o.sourceHandle === "string" ? o.sourceHandle : null, th = typeof o.targetHandle === "string" ? o.targetHandle : null;
    // By endpoints as well as by id: ids are reminted per document, so two
    // differently-named wires between the same pins would collide later.
    const pins = `${o.source}.${sh}->${o.target}.${th}`;
    if (endpoints.has(pins)) continue;
    endpoints.add(pins);
    const id = typeof o.id === "string" && o.id ? o.id : `e_${pins}`;
    if (edgeIds.has(id)) continue;
    edgeIds.add(id);
    edges.push({ id, source: o.source, sourceHandle: sh, target: o.target, targetHandle: th });
  }
  const network = (NETWORKS as readonly string[]).includes(String(r.network)) ? (r.network as Network) : undefined;
  const ruleset = typeof r.ruleset === "string" && Object.hasOwn(RULESETS, r.ruleset) ? r.ruleset : undefined;
  const name = typeof r.name === "string" ? r.name : undefined;
  // A file that had nodes but none the editor understands is a failure, not
  // an empty document; an empty file is legitimately empty.
  if (!nodes.length && (r.nodes as unknown[]).length) return null;
  return { nodes, edges, network, ruleset, name };
}

function sessionDoc(raw: unknown, fallbackName: string): SessionDoc | null {
  const flow = sanitizeFlow(raw);
  if (!flow) return null;
  const r = raw as Record<string, unknown>;
  const v = r.view as Record<string, unknown> | null | undefined;
  const view = v && typeof v === "object" && [v.x, v.y, v.zoom].every((n) => Number.isFinite(Number(n))) && Number(v.zoom) > 0
    ? { x: Number(v.x), y: Number(v.y), zoom: Number(v.zoom) } : null;
  return {
    id: typeof r.id === "string" && r.id ? r.id : nextId("doc"),
    name: typeof r.name === "string" && r.name ? r.name : fallbackName,
    nodes: flow.nodes ?? [], edges: flow.edges ?? [], network: flow.network ?? "signet", ruleset: flow.ruleset ?? "letter", view,
  };
}

/** The saved session: every open document and which one was in front,
 *  each document sanitized so a malformed entry is dropped rather than
 *  crashing every boot. Session data the app cannot read (a failed parse,
 *  a version it does not know) is copied to a backup key before anything
 *  can overwrite it. A single-slot save from before documents existed
 *  becomes one document. */
export function savedSession(): Session | null {
  let raw: string | null = null;
  try {
    raw = localStorage.getItem(SESSION_KEY);
    if (raw) {
      const s = JSON.parse(raw) as Partial<Session>;
      if (s && s.v === 2 && Array.isArray(s.docs)) {
        const stored = s.docs;
        const docs = stored.map((d, i) => sessionDoc(d, `untitled ${i + 1}`)).filter((d): d is SessionDoc => d !== null);
        const closed = (Array.isArray(s.closed) ? s.closed : []).map((d) => sessionDoc(d, "untitled")).filter((d): d is SessionDoc => d !== null);
        // Anything sanitizing threw away is kept in a backup: the autosave
        // is about to overwrite the original with the reduced version.
        const nodeCount = (d: unknown) => (Array.isArray((d as { nodes?: unknown[] })?.nodes) ? (d as { nodes: unknown[] }).nodes.length : 0);
        const lost = docs.length !== stored.length || docs.some((d, i) => nodeCount(stored[i]) !== d.nodes.length);
        if (lost) backup(raw);
        if (!docs.length) return null;
        // Ids minted by the old counter could repeat; the first keeps it.
        const ids = new Set<string>();
        for (const d of docs) { if (ids.has(d.id)) d.id = nextId("doc"); ids.add(d.id); }
        return { v: 2, active: typeof s.active === "string" && ids.has(s.active) ? s.active : docs[0].id, docs, closed };
      }
      backup(raw);
      return null;
    }
    return null;
  } catch {
    backup(raw);
    return null;
  }
}

/** Keep a copy of session data the app is about to replace with less,
 *  without overwriting a copy already kept: a repeated ?fresh=1 or a second
 *  failed parse must not bury the first, real one. */
export function backup(raw: string | null) {
  try { if (raw && localStorage.getItem(`${SESSION_KEY}.bak`) === null) localStorage.setItem(`${SESSION_KEY}.bak`, raw); } catch { /* unavailable */ }
}

/** The stored session as written, for ?fresh=1 to preserve. */
export function rawSession(): string | null {
  try { return localStorage.getItem(SESSION_KEY); } catch { return null; }
}
const UNDO_DEPTH = 100;

interface State extends Flow {
  computed: Record<string, Computed>;
  selected: string | null;
  panelHeight: number;
  /** Fraction of the detail panel given to the left half, 0.2 to 0.85. */
  splitRatio: number;
  showMinimap: boolean;
  past: Snapshot[];
  future: Snapshot[];
  clipboard: Snapshot | null;
  /** A node kind attached to the cursor, waiting for a click to place. */
  placing: string | null;
  /** Wire a dragged node would splice into if dropped now. */
  spliceEdge: string | null;
  /** Node whose name is being edited in place. */
  renaming: string | null;
  /** The pin a wire is being dragged from, while the drag lasts. Every
   *  node reads it to dim the pins this wire could not land on. */
  connecting: Pending | null;
  /** A pin that was right-clicked, for the canvas to put a menu on. */
  pinMenu: { nodeId: string; handleId: string; side: "source" | "target"; x: number; y: number } | null;

  /** Every open document, the active one's entry refreshed by stash(). */
  docs: Doc[];
  active: string;
  /** Recently closed documents, newest first, for reopening. */
  closed: Doc[];
  /** Where the active document's canvas is. */
  view: Viewport | null;
  /** Set when the last autosave was refused by storage; cleared by the next success. */
  saveError: boolean;

  onNodesChange: (c: NodeChange<FlowNode>[]) => void;
  onEdgesChange: (c: EdgeChange[]) => void;
  onConnect: (c: Connection) => void;
  setField: (id: string, key: string, value: unknown) => void;
  addNode: (kind: string, position: { x: number; y: number }) => string;
  removeSelected: () => void;
  setNetwork: (n: Network) => void;
  setRuleset: (r: string) => void;
  select: (id: string | null) => void;
  setPanelHeight: (h: number) => void;
  toggleMinimap: () => void;
  setSplitRatio: (r: number) => void;
  undo: () => void;
  redo: () => void;

  setPlacing: (kind: string | null) => void;
  setSpliceEdge: (id: string | null) => void;
  setRenaming: (id: string | null) => void;
  setPinMenu: (m: State["pinMenu"]) => void;
  setConnecting: (p: Pending | null) => void;
  /** Remove every wire on a node, or on one of its pins. */
  breakWires: (nodeId: string, handleId?: string) => void;

  newDoc: (name: string, flow?: Partial<Flow>) => string;
  switchDoc: (id: string) => void;
  closeDoc: (id: string) => void;
  reopenClosed: () => void;
  renameDoc: (id: string, name: string) => void;
  setView: (v: Viewport) => void;
  /** Replace every document with a saved session. */
  restoreSession: (s: Session) => void;
  /** Add a node at a position and, given a pending pin, wire it up. */
  addNodeAt: (kind: string, position: { x: number; y: number }, pending?: Pending) => string;
  /** Replace an edge with edge→node→edge. */
  spliceNode: (nodeId: string, edgeId: string) => void;
  insertReroute: (edgeId: string, position: { x: number; y: number }) => void;
  disconnectInput: (nodeId: string, handleId: string) => void;
  removeEdge: (id: string) => void;
  reconnect: (oldEdge: Edge, c: Connection) => void;
  selectAll: () => void;
  deselectAll: () => void;
  copy: () => void;
  paste: (at?: { x: number; y: number }) => void;
  duplicate: () => void;
  moveNodes: (ids: string[], dx: number, dy: number) => void;
  commentAroundSelection: (at?: { x: number; y: number }) => string | null;
  setNodeSize: (id: string, width: number, height: number) => void;
}

/** Editors holding a keystroke that has not been committed yet. Their
 *  writes are debounced and they commit on blur, but a document can be
 *  closed or switched before any blur happens (middle-click acts on
 *  mousedown), and a page can be hidden mid-word. Anything that changes
 *  which document is live, or writes the session, lands these first. */
const pendingEdits = new Set<() => void>();
export function registerPendingEdit(flush: () => void): () => void {
  pendingEdits.add(flush);
  return () => { pendingEdits.delete(flush); };
}
export function flushPendingEdits() { for (const f of [...pendingEdits]) f(); }

/** The pin a wire was dragged from, when an add-menu opens on drop. */
export interface Pending { nodeId: string; handleId: string; handleType: "source" | "target" }

/** Ids carry 48 random bits, so two documents, two browser tabs, or two
 *  sessions never mint the same one. A counter restarting on every load
 *  can repeat a restored document's id, and stash() then writes the live
 *  content into both of them. */
export const nextId = (kind: string) => {
  const b = new Uint8Array(6);
  crypto.getRandomValues(b);
  return `${kind}_${Array.from(b, (x) => x.toString(36).padStart(2, "0")).join("")}`;
};

/** The same flow with every node id minted afresh and every edge pointed
 *  at the new ids. Two documents opened from one example or one file
 *  would otherwise share ids, and anything keyed by id (a debounced edit,
 *  React Flow's component instances) could cross between them. */
export function remapIds<T extends Partial<Flow>>(flow: T): T {
  const map = new Map<string, string>();
  const nodes = (flow.nodes ?? []).map((n) => { const id = nextId(String(n.data?.kind ?? "node")); map.set(n.id, id); return { ...n, id }; });
  const edges = (flow.edges ?? []).map((e) => {
    const source = map.get(e.source) ?? e.source, target = map.get(e.target) ?? e.target;
    return { ...e, id: `e_${source}.${e.sourceHandle}->${target}.${e.targetHandle}`, source, target };
  });
  return { ...flow, nodes, edges };
}

/** Evaluate every node. Wired inputs come from upstream outputs; a missing
 *  upstream (cycle, or a failed node) leaves the port undefined. */
export function evaluate(nodes: FlowNode[], edges: Edge[], network: Network, ruleset: string): Record<string, Computed> {
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const incoming = new Map<string, Edge[]>();
  const indeg = new Map<string, number>();
  for (const n of nodes) indeg.set(n.id, 0);
  for (const e of edges) {
    if (!byId.has(e.source) || !byId.has(e.target)) continue;
    incoming.set(e.target, [...(incoming.get(e.target) ?? []), e]);
    indeg.set(e.target, (indeg.get(e.target) ?? 0) + 1);
  }
  const order: string[] = [];
  const queue = nodes.filter((n) => indeg.get(n.id) === 0).map((n) => n.id);
  while (queue.length) {
    const id = queue.shift()!;
    order.push(id);
    for (const e of edges) {
      if (e.source !== id || !byId.has(e.target)) continue;
      const d = (indeg.get(e.target) ?? 1) - 1;
      indeg.set(e.target, d);
      if (d === 0) queue.push(e.target);
    }
  }
  const ctx = { network, ruleset: RULESETS[ruleset]?.flags ?? RULESETS.letter.flags };
  const out: Record<string, Computed> = {};
  for (const id of order) {
    const n = byId.get(id)!;
    const kind = KINDS[n.data.kind as string];
    if (!kind) { out[id] = { outputs: {}, status: "error", message: `unknown node kind ${String(n.data.kind)}` }; continue; }
    const wired: Record<string, Value> = {};
    for (const e of incoming.get(id) ?? []) {
      const v = out[e.source]?.outputs[e.sourceHandle ?? "value"];
      if (v !== undefined && e.targetHandle) wired[e.targetHandle] = v;
    }
    // Every numeric field is checked against the range its port declares
    // before the node runs. Doing it here rather than in each compute means
    // a node cannot forget, and a value that arrived over a wire is held to
    // the same range as one that was typed.
    const bad = outOfRange(n.data, wired, kind.inputs(n.data));
    if (bad) { out[id] = { outputs: {}, status: "error", message: bad }; continue; }
    try { out[id] = kind.compute(n.data, wired, ctx); }
    catch (e) { out[id] = { outputs: {}, status: "error", message: String(e) }; }
  }
  for (const n of nodes) if (!out[n.id]) out[n.id] = { outputs: {}, status: "error", message: "part of a cycle" };
  return out;
}

/** Drop wires into ports that no longer exist after a field change. */
function pruneEdges(nodes: FlowNode[], edges: Edge[]): Edge[] {
  const byId = new Map(nodes.map((n) => [n.id, n]));
  return edges.filter((e) => {
    const t = byId.get(e.target), s = byId.get(e.source);
    if (!t || !s) return false;
    const tin = KINDS[t.data.kind as string]?.inputs(t.data).some((p) => p.id === e.targetHandle);
    const sout = KINDS[s.data.kind as string]?.outputs(s.data).some((p) => p.id === e.sourceHandle);
    return Boolean(tin && sout);
  });
}

export const useStore = create<State>((set, get) => {
  const recompute = (partial: Partial<State> = {}) => {
    const s = { ...get(), ...partial };
    set({ ...partial, computed: evaluate(s.nodes, s.edges, s.network, s.ruleset) });
  };
  /** A structural change: snapshot for undo, then recompute. */
  const commit = (partial: Partial<State>) => {
    const { nodes, edges, past } = get();
    set({ past: [...past.slice(-(UNDO_DEPTH - 1)), { nodes, edges }], future: [] });
    recompute(partial);
  };
  /** The document list with the live document written back into its entry. */
  const stash = (): Doc[] => {
    const s = get();
    return s.docs.map((d) => d.id === s.active
      ? { ...d, nodes: s.nodes, edges: s.edges, network: s.network, ruleset: s.ruleset, view: s.view, past: s.past, future: s.future }
      : d);
  };
  /** Make a document the live one. Transient editor state does not carry over. */
  const activate = (d: Doc, docs: Doc[]) => {
    // The selection pointer resets, so the per-node flags must too, or the
    // canvas paints a selection the store denies.
    const nodes = d.nodes.map((n) => (n.selected ? { ...n, selected: false } : n));
    const edges = d.edges.map((e) => (e.selected ? { ...e, selected: false } : e));
    set({
      docs, active: d.id, nodes, edges, network: d.network, ruleset: d.ruleset, view: d.view, past: d.past, future: d.future,
      selected: null, renaming: null, placing: null, spliceEdge: null, pinMenu: null, connecting: null,
      computed: evaluate(nodes, edges, d.network, d.ruleset),
    });
  };
  const uniqueName = (name: string, docs: Doc[]) => {
    const taken = new Set(docs.map((d) => d.name));
    if (!taken.has(name)) return name;
    for (let i = 2; ; i++) if (!taken.has(`${name} ${i}`)) return `${name} ${i}`;
  };
  const makeDoc = (name: string, raw: Partial<Flow> | undefined, docs: Doc[]): Doc => {
    const clean = raw ? sanitizeFlow(raw) : null;
    const flow = clean ? remapIds(clean) : null;
    return {
      id: nextId("doc"), name: uniqueName(name, docs),
      nodes: flow?.nodes ?? [], edges: flow?.edges ?? [],
      network: flow?.network ?? get().network, ruleset: flow?.ruleset ?? get().ruleset,
      view: null, past: [], future: [],
    };
  };
  return {
    nodes: [], edges: [], computed: {},
    network: "signet", ruleset: "letter", selected: null, panelHeight: savedLayout().panelHeight, splitRatio: savedLayout().splitRatio, showMinimap: savedLayout().showMinimap,
    past: [], future: [], clipboard: null, placing: null, spliceEdge: null, renaming: null, pinMenu: null, connecting: null,
    docs: [], active: "", closed: [], view: null, saveError: false,

    setPinMenu: (pinMenu) => set({ pinMenu }),
    setConnecting: (connecting) => set({ connecting }),
    breakWires: (nodeId, handleId) => {
      const edges = get().edges.filter((e) => handleId === undefined
        ? e.source !== nodeId && e.target !== nodeId
        : !((e.source === nodeId && e.sourceHandle === handleId) || (e.target === nodeId && e.targetHandle === handleId)));
      if (edges.length !== get().edges.length) commit({ edges });
    },

    newDoc: (name, flow) => {
      flushPendingEdits();
      const docs = stash();
      const d = makeDoc(name, flow, docs);
      activate(d, [...docs, d]);
      return d.id;
    },
    switchDoc: (id) => {
      if (id === get().active) return;
      flushPendingEdits();
      const docs = stash();
      const d = docs.find((x) => x.id === id);
      if (d) activate(d, docs);
    },
    closeDoc: (id) => {
      flushPendingEdits();
      const docs = stash();
      const i = docs.findIndex((d) => d.id === id);
      if (i < 0) return;
      const rest = docs.filter((d) => d.id !== id);
      // Only a document with something in it is worth offering back.
      const closed = docs[i].nodes.length ? [docs[i], ...get().closed].slice(0, 8) : get().closed;
      if (id !== get().active) { set({ docs: rest, closed }); return; }
      if (!rest.length) { const d = makeDoc("untitled", undefined, []); activate(d, [d]); set({ closed }); return; }
      activate(rest[Math.min(i, rest.length - 1)], rest);
      set({ closed });
    },
    reopenClosed: () => {
      flushPendingEdits();
      const [d, ...closed] = get().closed;
      if (!d) return;
      const docs = stash();
      const back = { ...d, name: uniqueName(d.name, docs) };
      activate(back, [...docs, back]);
      set({ closed });
    },
    renameDoc: (id, name) => set({ docs: stash().map((d) => (d.id === id ? { ...d, name } : d)) }),
    setView: (view) => set({ view }),
    restoreSession: (sess) => {
      const docs: Doc[] = sess.docs.map((d) => ({ ...d, past: [], future: [] }));
      const d = docs.find((x) => x.id === sess.active) ?? docs[0];
      if (d) activate(d, docs);
      set({ closed: (sess.closed ?? []).map((d) => ({ ...d, past: [], future: [] })) });
    },

    onNodesChange: (changes) => {
      const nodes = applyNodeChanges(changes, get().nodes);
      if (changes.some((c) => c.type === "remove")) commit({ nodes }); else set({ nodes });
      const sel = changes.find((c) => c.type === "select" && c.selected);
      if (sel && sel.type === "select") set({ selected: sel.id });
    },
    onEdgesChange: (changes) => {
      const edges = applyEdgeChanges(changes, get().edges);
      if (changes.some((c) => c.type === "remove")) commit({ edges }); else set({ edges });
    },
    onConnect: (c) => {
      // One wire per input port: a new connection replaces the old one.
      const edges = get().edges.filter((e) => !(e.target === c.target && e.targetHandle === c.targetHandle));
      commit({ edges: addEdge({ ...c, id: `e_${c.source}.${c.sourceHandle}->${c.target}.${c.targetHandle}` }, edges) });
    },
    setField: (id, key, value) => {
      const nodes = get().nodes.map((n) => (n.id === id ? { ...n, data: { ...n.data, [key]: value } } : n));
      commit({ nodes, edges: pruneEdges(nodes, get().edges) });
    },
    addNode: (kind, position) => {
      const id = nextId(kind);
      // defaults() does not know its own kind; the node must carry it.
      const data = { ...KINDS[kind].defaults(), kind };
      commit({ nodes: [...get().nodes.map((n) => ({ ...n, selected: false })), { id, type: "cov", position, data, selected: true }], selected: id });
      return id;
    },
    removeSelected: () => {
      const ids = new Set(get().nodes.filter((n) => n.selected).map((n) => n.id));
      const selEdges = new Set(get().edges.filter((e) => e.selected).map((e) => e.id));
      if (!ids.size && !selEdges.size) return;
      commit({
        nodes: get().nodes.filter((n) => !ids.has(n.id)),
        edges: get().edges.filter((e) => !ids.has(e.source) && !ids.has(e.target) && !selEdges.has(e.id)),
        selected: get().selected && ids.has(get().selected!) ? null : get().selected,
      });
    },
    setNetwork: (network) => recompute({ network }),
    setRuleset: (ruleset) => recompute({ ruleset }),
    select: (selected) => set({ selected, nodes: get().nodes.map((n) => n.selected === (n.id === selected) ? n : { ...n, selected: n.id === selected }) }),
    setPanelHeight: (h) => { const panelHeight = Math.max(120, Math.min(720, h)); set({ panelHeight }); saveLayout({ panelHeight, splitRatio: get().splitRatio, showMinimap: get().showMinimap }); },
    setSplitRatio: (r) => { const splitRatio = Math.max(0.2, Math.min(0.85, r)); set({ splitRatio }); saveLayout({ panelHeight: get().panelHeight, splitRatio, showMinimap: get().showMinimap }); },
    toggleMinimap: () => { const showMinimap = !get().showMinimap; set({ showMinimap }); saveLayout({ panelHeight: get().panelHeight, splitRatio: get().splitRatio, showMinimap }); },
    undo: () => {
      const { past, future, nodes, edges } = get();
      const prev = past[past.length - 1];
      if (!prev) return;
      set({ past: past.slice(0, -1), future: [{ nodes, edges }, ...future].slice(0, UNDO_DEPTH) });
      recompute({ nodes: prev.nodes, edges: prev.edges });
    },
    redo: () => {
      const { past, future, nodes, edges } = get();
      const next = future[0];
      if (!next) return;
      set({ future: future.slice(1), past: [...past, { nodes, edges }] });
      recompute({ nodes: next.nodes, edges: next.edges });
    },

    setPlacing: (placing) => set({ placing }),
    setSpliceEdge: (spliceEdge) => { if (get().spliceEdge !== spliceEdge) set({ spliceEdge }); },
    setRenaming: (renaming) => set({ renaming }),

    addNodeAt: (kind, position, pending) => {
      const id = nextId(kind);
      const data = { ...KINDS[kind].defaults(), kind };
      const nodes = [...get().nodes.map((n) => ({ ...n, selected: false })), { id, type: "cov", position, data, selected: true } as FlowNode];
      let edges = get().edges;
      if (pending) {
        const from = get().nodes.find((n) => n.id === pending.nodeId);
        const fromPort = from && findPort(from.data, pending.handleType, pending.handleId);
        if (from && fromPort) {
          if (pending.handleType === "source") {
            const to = firstCompatibleInput(data, fromPort);
            if (to) edges = [...edges.filter((e) => !(e.target === id && e.targetHandle === to.id)),
              { id: `e_${from.id}.${fromPort.id}->${id}.${to.id}`, source: from.id, sourceHandle: fromPort.id, target: id, targetHandle: to.id }];
          } else {
            const out = firstCompatibleOutput(data, fromPort);
            if (out) edges = [...edges.filter((e) => !(e.target === from.id && e.targetHandle === fromPort.id)),
              { id: `e_${id}.${out.id}->${from.id}.${fromPort.id}`, source: id, sourceHandle: out.id, target: from.id, targetHandle: fromPort.id }];
          }
        }
      }
      commit({ nodes, edges, selected: id, placing: null });
      return id;
    },

    spliceNode: (nodeId, edgeId) => {
      const node = get().nodes.find((n) => n.id === nodeId);
      const edge = get().edges.find((e) => e.id === edgeId);
      if (!node || !edge) return;
      const src = get().nodes.find((n) => n.id === edge.source);
      const srcPort = src && findPort(src.data, "source", edge.sourceHandle ?? "");
      if (!srcPort) return;
      const into = firstCompatibleInput(node.data, srcPort);
      const tgt = get().nodes.find((n) => n.id === edge.target);
      const tgtPort = tgt && findPort(tgt.data, "target", edge.targetHandle ?? "");
      const outOf = tgtPort && firstCompatibleOutput(node.data, tgtPort);
      if (!into || !outOf) return;
      const edges = get().edges.filter((e) => e.id !== edgeId && !(e.target === nodeId && e.targetHandle === into.id));
      edges.push({ id: `e_${edge.source}.${edge.sourceHandle}->${nodeId}.${into.id}`, source: edge.source, sourceHandle: edge.sourceHandle, target: nodeId, targetHandle: into.id });
      edges.push({ id: `e_${nodeId}.${outOf.id}->${edge.target}.${edge.targetHandle}`, source: nodeId, sourceHandle: outOf.id, target: edge.target, targetHandle: edge.targetHandle });
      commit({ edges, spliceEdge: null });
    },

    insertReroute: (edgeId, position) => {
      const edge = get().edges.find((e) => e.id === edgeId);
      if (!edge) return;
      const id = nextId("reroute");
      // The dot lands under the cursor, on the grid: the ring is 32px.
      const node: FlowNode = { id, type: "reroute", position: { x: Math.round((position.x - 16) / 16) * 16, y: Math.round((position.y - 16) / 16) * 16 }, data: { ...KINDS.reroute.defaults(), kind: "reroute" } };
      const edges = get().edges.filter((e) => e.id !== edgeId);
      edges.push({ id: `e_${edge.source}.${edge.sourceHandle}->${id}.in`, source: edge.source, sourceHandle: edge.sourceHandle, target: id, targetHandle: "in" });
      edges.push({ id: `e_${id}.out->${edge.target}.${edge.targetHandle}`, source: id, sourceHandle: "out", target: edge.target, targetHandle: edge.targetHandle });
      commit({ nodes: [...get().nodes, node], edges });
    },

    disconnectInput: (nodeId, handleId) => {
      const edges = get().edges.filter((e) => !(e.target === nodeId && e.targetHandle === handleId));
      if (edges.length !== get().edges.length) commit({ edges });
    },
    removeEdge: (id) => commit({ edges: get().edges.filter((e) => e.id !== id) }),
    reconnect: (oldEdge, c) => {
      if (!c.source || !c.target) return;
      const edges = get().edges.filter((e) => e.id !== oldEdge.id && !(e.target === c.target && e.targetHandle === c.targetHandle));
      commit({ edges: addEdge({ ...c, id: `e_${c.source}.${c.sourceHandle}->${c.target}.${c.targetHandle}` }, edges) });
    },

    selectAll: () => set({ nodes: get().nodes.map((n) => ({ ...n, selected: true })) }),
    deselectAll: () => set({ nodes: get().nodes.map((n) => (n.selected ? { ...n, selected: false } : n)), edges: get().edges.map((e) => (e.selected ? { ...e, selected: false } : e)), selected: null }),

    copy: () => {
      const nodes = get().nodes.filter((n) => n.selected);
      if (!nodes.length) return;
      const ids = new Set(nodes.map((n) => n.id));
      const edges = get().edges.filter((e) => ids.has(e.source) && ids.has(e.target));
      set({ clipboard: { nodes: structuredClone(nodes), edges: structuredClone(edges) } });
    },
    paste: (at) => {
      const clip = get().clipboard;
      if (!clip?.nodes.length) return;
      const minX = Math.min(...clip.nodes.map((n) => n.position.x)), minY = Math.min(...clip.nodes.map((n) => n.position.y));
      const dx = at ? at.x - minX : 40, dy = at ? at.y - minY : 40;
      const map = new Map(clip.nodes.map((n) => [n.id, nextId(String(n.data.kind))]));
      const nodes = clip.nodes.map((n) => ({ ...structuredClone(n), id: map.get(n.id)!, position: { x: n.position.x + dx, y: n.position.y + dy }, selected: true }));
      const edges = clip.edges.map((e) => ({ ...e, id: `e_${map.get(e.source)}.${e.sourceHandle}->${map.get(e.target)}.${e.targetHandle}`, source: map.get(e.source)!, target: map.get(e.target)!, selected: false }));
      commit({ nodes: [...get().nodes.map((n) => ({ ...n, selected: false })), ...nodes], edges: [...get().edges, ...edges], selected: nodes[0].id });
    },
    duplicate: () => { get().copy(); get().paste(); },

    moveNodes: (ids, dx, dy) => {
      if (!ids.length || (dx === 0 && dy === 0)) return;
      const set_ = new Set(ids);
      set({ nodes: get().nodes.map((n) => (set_.has(n.id) ? { ...n, position: { x: n.position.x + dx, y: n.position.y + dy } } : n)) });
    },

    commentAroundSelection: (at) => {
      const sel = get().nodes.filter((n) => n.selected && n.data.kind !== "comment");
      if (!sel.length) {
        // Unreal: with nothing selected, a small empty box near the cursor.
        if (!at) return null;
        const id = nextId("comment");
        const node: FlowNode = { id, type: "comment", position: { x: at.x, y: at.y }, data: { ...KINDS.comment.defaults(), kind: "comment" }, zIndex: -1 };
        commit({ nodes: [node, ...get().nodes.map((n) => ({ ...n, selected: false }))], selected: id, renaming: id });
        return id;
      }
      const pad = 24, head = 36;
      const x0 = Math.min(...sel.map((n) => n.position.x)) - pad;
      const y0 = Math.min(...sel.map((n) => n.position.y)) - pad - head;
      const x1 = Math.max(...sel.map((n) => n.position.x + (n.measured?.width ?? 288))) + pad;
      const y1 = Math.max(...sel.map((n) => n.position.y + (n.measured?.height ?? 200))) + pad;
      const id = nextId("comment");
      const node: FlowNode = { id, type: "cov", position: { x: x0, y: y0 }, data: { ...KINDS.comment.defaults(), kind: "comment", width: x1 - x0, height: y1 - y0 }, zIndex: -1 };
      commit({ nodes: [node, ...get().nodes.map((n) => ({ ...n, selected: false }))], selected: id, renaming: id });
      return id;
    },
    setNodeSize: (id, width, height) => set({ nodes: get().nodes.map((n) => (n.id === id ? { ...n, data: { ...n.data, width, height } } : n)) }),
  };
});

/** True when a wire from `source.handle` may land on `target.handle`. */
export function isValidConnection(c: { source: string | null; sourceHandle?: string | null; target: string | null; targetHandle?: string | null }): boolean {
  if (!c.source || !c.target || c.source === c.target) return false;
  const s = useStore.getState();
  const sn = s.nodes.find((n) => n.id === c.source), tn = s.nodes.find((n) => n.id === c.target);
  if (!sn || !tn) return false;
  const sp = findPort(sn.data, "source", c.sourceHandle ?? ""), tp = findPort(tn.data, "target", c.targetHandle ?? "");
  if (!sp || !tp) return false;
  return portsCompatible(sp, tp);
}

/** Whether the pin being dragged could land on this one. Used to dim the
 *  pins it could not, so the reachable ones stand out while dragging. */
export function reachableFrom(connecting: Pending | null, nodeId: string, port: Port, side: "source" | "target"): boolean {
  if (!connecting) return true;
  // The pin the wire is coming out of stays lit: it is where you are.
  if (connecting.nodeId === nodeId && connecting.handleId === port.id && connecting.handleType === side) return true;
  if (connecting.handleType === side) return false;          // both ends the same way round
  const s = useStore.getState();
  const from = s.nodes.find((n) => n.id === connecting.nodeId);
  if (!from) return true;
  if (from.id === nodeId) return false;                      // a node cannot feed itself
  const fromPort = findPort(from.data, connecting.handleType, connecting.handleId);
  if (!fromPort) return true;
  return connecting.handleType === "source" ? portsCompatible(fromPort, port) : portsCompatible(port, fromPort);
}

/** The type a wire carries, from its source port; reroutes pass through
 *  whatever arrives at them. */
export function wireType(edge: Edge, nodes: FlowNode[], edges: Edge[], depth = 0): PortType {
  const n = nodes.find((n) => n.id === edge.source);
  if (!n) return "any";
  if (n.data.kind === "reroute" && depth < 16) {
    const up = edges.find((e) => e.target === n.id);
    return up ? wireType(up, nodes, edges, depth + 1) : "any";
  }
  return findPort(n.data, "source", edge.sourceHandle ?? "")?.type ?? "any";
}

// Autosave: every document, and which one is in front. Positions change
// often while dragging, so writes are debounced, with a ceiling so a long
// drag still checkpoints, and a flush when the page is hidden or unloaded
// so the last edit is never the one that gets lost. Undo history is not
// kept.
const SAVE_DEBOUNCE = 400, SAVE_MAX_WAIT = 2000;

/** The session as it would be written now. */
export function serializeSession(live = useStore.getState()): Session | null {
  if (!live.active) return null;
  const strip = (d: Doc | State, id: string, name: string): SessionDoc =>
    ({ id, name, nodes: d.nodes.map(({ measured: _m, dragging: _d, selected: _s, ...n }) => n), edges: d.edges, network: d.network, ruleset: d.ruleset, view: d.view });
  const docs = live.docs.map((d) => strip(d.id === live.active ? live : d, d.id, d.name));
  const closed = live.closed.map((d) => strip(d, d.id, d.name));
  return { v: 2, active: live.active, docs, closed };
}

let saveTimer: ReturnType<typeof setTimeout> | undefined;
let firstPending = 0;
/** Write the session now. Returns false when storage refused it. */
export function flushSession(): boolean {
  flushPendingEdits();
  clearTimeout(saveTimer); saveTimer = undefined; firstPending = 0;
  return writeSession();
}
/** Write only when this tab has unsaved work, so hiding an idle tab does
 *  not overwrite what another tab saved. */
function flushIfDirty(): void {
  if (saveTimer === undefined && pendingEdits.size === 0) return;
  flushSession();
}
function writeSession(): boolean {
  const sess = serializeSession();
  if (!sess) return true;
  const write = (s: Session) => {
    localStorage.setItem(SESSION_KEY, JSON.stringify(s));
    if (useStore.getState().saveError) useStore.setState({ saveError: false });
  };
  try { write(sess); return true; } catch { /* over quota, probably */ }
  // Reopenable documents are worth less than open ones: drop them and try
  // again before telling the user the write failed.
  try { write({ ...sess, closed: [] }); return true; } catch {
    if (!useStore.getState().saveError) useStore.setState({ saveError: true });
    return false;
  }
}
useStore.subscribe((s, prev) => {
  if (s.nodes === prev.nodes && s.edges === prev.edges && s.network === prev.network && s.ruleset === prev.ruleset
    && s.view === prev.view && s.docs === prev.docs && s.active === prev.active && s.closed === prev.closed) return;
  const now = Date.now();
  if (!firstPending) firstPending = now;
  clearTimeout(saveTimer);
  saveTimer = setTimeout(flushSession, Math.max(0, Math.min(SAVE_DEBOUNCE, firstPending + SAVE_MAX_WAIT - now)));
});
if (typeof window !== "undefined") {
  // Unconditional: an editor can hold a keystroke the store has not seen.
  window.addEventListener("pagehide", flushIfDirty);
  document.addEventListener("visibilitychange", () => { if (document.visibilityState === "hidden") flushIfDirty(); });
}

/** The value arriving at an input port, if any wire feeds it. */
export function portValue(id: string, port: string): Value | undefined {
  const s = useStore.getState();
  const e = s.edges.find((e) => e.target === id && e.targetHandle === port);
  return e ? s.computed[e.source]?.outputs[e.sourceHandle ?? "value"] : undefined;
}

