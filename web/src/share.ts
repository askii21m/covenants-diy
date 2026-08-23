// Permalinks. The whole document travels in the URL fragment, compressed:
// no server stores anything, so a link cannot rot and Cloudflare never
// sees what anyone is designing. A fragment is not sent in the HTTP
// request at all, which matters for a tool people sketch real keys into.
//
// A link is untrusted input from anyone, so decoding is bounded at every
// step: the fragment length, the decompressed size, and the number of
// nodes and edges. Everything that survives still goes through
// sanitizeFlow before it reaches the editor.

import type { Edge } from "@xyflow/react";
import { sanitizeFlow, type Flow, type FlowNode } from "./store";

/** Fragment key. `#g=` for graph. */
export const FRAGMENT = "g";

// A vault is about 1.4KB encoded and the largest example about 2KB, so
// these leave room for graphs several times bigger while refusing anything
// that could only be an attack or a mistake.
const MAX_FRAGMENT = 256 * 1024;
const MAX_DECODED = 4 * 1024 * 1024;
const MAX_NODES = 2000;
const MAX_EDGES = 4000;

/** The wire form: nodes become positions in an array, so their ids vanish
 *  from both the nodes and the edges that name them. */
interface Wire {
  v: 1;
  n?: string;
  w?: string;
  r?: string;
  /** [kind, x, y, everything else] */
  N: Array<[string, number, number, Record<string, unknown>]>;
  /** [from node, from port, to node, to port] */
  E: Array<[number, string | null, number, string | null]>;
}

export interface SharedDoc { name?: string; flow: Partial<Flow> }

function toBase64Url(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(s: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) return null;
  try {
    const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch { return null; }
}

function blobOf(bytes: Uint8Array): Blob {
  return new Blob([bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer]);
}

async function deflate(bytes: Uint8Array): Promise<Uint8Array> {
  const stream = blobOf(bytes).stream().pipeThrough(new CompressionStream("deflate-raw"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

/** Inflate, giving up the moment the output passes `cap`. Without this a
 *  few hundred bytes of fragment could ask for gigabytes of memory. */
async function inflate(bytes: Uint8Array, cap: number): Promise<Uint8Array | null> {
  const reader = blobOf(bytes).stream().pipeThrough(new DecompressionStream("deflate-raw")).getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > cap) { await reader.cancel(); return null; }
      chunks.push(value);
    }
  } catch { return null; }
  const out = new Uint8Array(total);
  let at = 0;
  for (const c of chunks) { out.set(c, at); at += c.length; }
  return out;
}

/** The fragment for a document, without the leading `#g=`. */
export async function encodeFlow(doc: SharedDoc): Promise<string> {
  const nodes = doc.flow.nodes ?? [];
  const order = new Map(nodes.map((n, i) => [n.id, i]));
  const wire: Wire = {
    v: 1,
    n: doc.name,
    w: doc.flow.network,
    r: doc.flow.ruleset,
    N: nodes.map((n) => {
      // React Flow's own fields are the editor's, not the document's.
      const { kind, ...rest } = n.data;
      return [String(kind), Math.round(n.position.x), Math.round(n.position.y), rest];
    }),
    E: (doc.flow.edges ?? []).flatMap((e) => {
      const from = order.get(e.source), to = order.get(e.target);
      return from == null || to == null ? [] : [[from, e.sourceHandle ?? null, to, e.targetHandle ?? null] as [number, string | null, number, string | null]];
    }),
  };
  return toBase64Url(await deflate(new TextEncoder().encode(JSON.stringify(wire))));
}

/** A document from a fragment, or nothing if it is not one we can trust. */
export async function decodeFlow(fragment: string): Promise<SharedDoc | null> {
  if (!fragment || fragment.length > MAX_FRAGMENT) return null;
  const raw = fromBase64Url(fragment);
  if (!raw) return null;
  const bytes = await inflate(raw, MAX_DECODED);
  if (!bytes) return null;

  let wire: Wire;
  try { wire = JSON.parse(new TextDecoder().decode(bytes)) as Wire; } catch { return null; }
  if (!wire || wire.v !== 1 || !Array.isArray(wire.N) || !Array.isArray(wire.E)) return null;
  if (wire.N.length > MAX_NODES || wire.E.length > MAX_EDGES) return null;

  // Ids are minted here rather than carried, so a link cannot collide with
  // whatever is already open.
  const nodes: FlowNode[] = [];
  const ids: string[] = [];
  for (const entry of wire.N) {
    if (!Array.isArray(entry) || entry.length < 4) return null;
    const [kind, x, y, data] = entry;
    if (typeof kind !== "string" || !data || typeof data !== "object") return null;
    const id = `${kind}_${nodes.length.toString(36)}`;
    ids.push(id);
    nodes.push({ id, position: { x: Number(x), y: Number(y) }, data: { name: "", ...data, kind } } as FlowNode);
  }
  const edges: Edge[] = [];
  for (const entry of wire.E) {
    if (!Array.isArray(entry) || entry.length < 4) continue;
    const [from, sh, to, th] = entry;
    if (!ids[from as number] || !ids[to as number]) continue;
    edges.push({
      id: `e_${ids[from as number]}.${sh}->${ids[to as number]}.${th}`,
      source: ids[from as number], sourceHandle: typeof sh === "string" ? sh : null,
      target: ids[to as number], targetHandle: typeof th === "string" ? th : null,
    });
  }

  // Everything a link carries is still run past the same sanitizer an
  // imported file goes through.
  const flow = sanitizeFlow({ nodes, edges, network: wire.w, ruleset: wire.r });
  if (!flow) return null;
  return { name: typeof wire.n === "string" ? wire.n : undefined, flow };
}

/** A link that carries the graph itself, so it needs nothing to exist. */
const ID_PATTERN = /^[A-Za-z0-9_-]{10,20}$/;

/** A permalink. The graph is stored, which is what keeps the link short
 *  enough to be one; a link that carried the graph came out at kilobytes.
 *  Throws rather than falling back, so a failed upload is never quietly
 *  handed back as a URL nobody can paste. */
export async function shortLink(doc: SharedDoc): Promise<string> {
  const payload = await encodeFlow(doc);
  const res = await fetch("/api/share", {
    method: "POST",
    headers: { "content-type": "text/plain" },
    body: payload,
  });
  if (!res.ok) throw new Error(`share refused: ${res.status}`);
  const body = (await res.json()) as { id?: unknown };
  if (typeof body.id !== "string" || !ID_PATTERN.test(body.id)) throw new Error("share returned no id");
  return `${window.location.origin}/g/${body.id}`;
}

/** The fragment on the current URL, if it carries a graph. */
export function fragmentOnUrl(): string | null {
  const h = window.location.hash.replace(/^#/, "");
  if (!h.startsWith(`${FRAGMENT}=`)) return null;
  return h.slice(FRAGMENT.length + 1);
}

/** The id in the path, if this URL names a stored graph. */
export function idOnUrl(): string | null {
  const m = /^\/g\/([A-Za-z0-9_-]+)\/?$/.exec(window.location.pathname);
  return m && ID_PATTERN.test(m[1]) ? m[1] : null;
}

/** Fetch a stored graph and decode it. The payload is held to every bound
 *  a pasted fragment is: the server is not trusted more than a stranger. */
export async function fetchShared(id: string): Promise<SharedDoc | null> {
  if (!ID_PATTERN.test(id)) return null;
  try {
    const res = await fetch(`/api/g/${id}`);
    if (!res.ok) return null;
    const payload = await res.text();
    return await decodeFlow(payload);
  } catch { return null; }
}
