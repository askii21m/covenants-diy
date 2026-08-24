// Shared by the three endpoints. Kept deliberately small: this is the only
// code in the project that runs on someone else's machine and accepts
// input from anyone who can reach the site.

export interface Env {
  GRAPHS: D1Database;
  ASSETS: Fetcher;
}

/** The same bounds the browser applies, restated here because a request
 *  need not have come from the browser. */
export const MAX_PAYLOAD = 64 * 1024;
export const MAX_DECODED = 4 * 1024 * 1024;
export const MAX_NODES = 2000;
export const MAX_EDGES = 4000;

export const ID_PATTERN = /^[A-Za-z0-9_-]{10,20}$/;

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
    },
  });
}

function fromBase64Url(s: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) return null;
  try {
    const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

/** Inflate, abandoning the stream the moment it passes the cap. A few
 *  hundred bytes of deflate can otherwise ask for gigabytes. */
async function inflate(bytes: Uint8Array, cap: number): Promise<Uint8Array | null> {
  const blob = new Blob([bytes.slice().buffer as ArrayBuffer]);
  const reader = blob.stream().pipeThrough(new DecompressionStream("deflate-raw")).getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > cap) {
        await reader.cancel();
        return null;
      }
      chunks.push(value);
    }
  } catch {
    return null;
  }
  const out = new Uint8Array(total);
  let at = 0;
  for (const c of chunks) {
    out.set(c, at);
    at += c.length;
  }
  return out;
}

export interface Summary {
  nodes: number;
  edges: number;
  network: string | null;
  ruleset: string | null;
  kinds: string;
}

/** What a payload is, if it is a graph at all. Storing without this would
 *  make the endpoint a place to keep arbitrary bytes. */
export async function summarise(payload: string): Promise<Summary | null> {
  const raw = fromBase64Url(payload);
  if (!raw) return null;
  const bytes = await inflate(raw, MAX_DECODED);
  if (!bytes) return null;
  let doc: { v?: unknown; N?: unknown; E?: unknown; w?: unknown; r?: unknown };
  try {
    doc = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    return null;
  }
  if (!doc || doc.v !== 1 || !Array.isArray(doc.N) || !Array.isArray(doc.E)) return null;
  if (doc.N.length > MAX_NODES || doc.E.length > MAX_EDGES) return null;

  const kinds = new Set<string>();
  for (const n of doc.N) {
    if (!Array.isArray(n) || typeof n[0] !== "string") return null;
    kinds.add(n[0]);
  }
  return {
    nodes: doc.N.length,
    edges: doc.E.length,
    network: typeof doc.w === "string" ? doc.w.slice(0, 16) : null,
    ruleset: typeof doc.r === "string" ? doc.r.slice(0, 16) : null,
    kinds: [...kinds].sort().join(","),
  };
}

/** Content addressed, so sharing the same graph twice gives the same link
 *  and costs no extra storage. */
export async function idFor(payload: string, extra = ""): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(payload + extra));
  let s = "";
  for (const b of new Uint8Array(digest)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
