// The node catalog. A node kind declares its ports and how to compute its
// outputs from its typed fields and whatever is wired in. Ports can depend
// on the fields (a Template with three outputs has three value ports), so
// they are functions of the node's data.

import { wasm, type Ruleset, type Network } from "./engine";

/** Values that travel on wires. Arrays are witness stacks. */
export type Value = string | number | string[] | null;

/** What travels on a wire. Bytes are bytes, so the hex family connects
 *  freely and differs only in colour; outpoints, witnesses, numbers and
 *  addresses are distinct shapes and refuse each other. */
export type PortType =
  "hash" | "script" | "tx" | "spk" | "hex" | "outpoint" | "witness" | "number" | "text" | "address" | "any";

const HEXISH: ReadonlySet<PortType> = new Set(["hash", "script", "tx", "spk", "hex"]);

/** Whether one kind of value may stand in for another. The coarse filter,
 *  used to decide what to offer in a menu. A connection is settled by
 *  `portsCompatible`, which also knows what each port will accept. */
export function compatible(src: PortType, dst: PortType): boolean {
  if (src === "any" || dst === "any" || src === dst) return true;
  if (HEXISH.has(src) && HEXISH.has(dst)) return true;
  if (src === "number" && dst === "text") return true;
  if (src === "address" && dst === "text") return true;
  return false;
}

/** Whether a wire from one port may land on another.
 *
 *  Types are not the whole story. A port that offers a fixed list of
 *  choices is typed `text` because a choice is spelled out in words, but
 *  it accepts only its own list: an address and a number are both text
 *  enough to satisfy the type and are not one of its options. Without
 *  this, a taproot address could be dropped on a sighash's hash type. */
export function portsCompatible(src: Port, dst: Port): boolean {
  if (!compatible(src.type, dst.type)) return false;
  if (!dst.options) return true;
  const from = src.options;
  return from != null && from.length === dst.options.length && from.every((o, i) => o === dst.options![i]);
}

export interface Port {
  id: string;
  label: string;
  type: PortType;
  /** A field the user can type into when nothing is wired. */
  field?: "text" | "number" | "hex" | "select";
  options?: string[];
  /** Rendered as a block rather than a row (the script editor). */
  wide?: boolean;
  /** Range a numeric field may hold. Enforced before the node computes,
   *  and given to the input so it cannot be typed past. A field that takes
   *  a value the node cannot honour is the editor lying about what will
   *  happen. */
  min?: number;
  max?: number;
}

/** Consensus limits, so the fields say what Bitcoin actually allows. */
export const U32_MAX = 4_294_967_295;
export const I32_MIN = -2_147_483_648,
  I32_MAX = 2_147_483_647;
/** 21 million bitcoin, in satoshis. */
export const MAX_MONEY = 2_100_000_000_000_000;

/** A numeric field with the range it really accepts. */
const N = (id: string, label: string, min: number, max: number): Port => ({
  id,
  label,
  type: "number",
  field: "number",
  min,
  max,
});

/** A count the +/- buttons drive, clamped so an imported or hand-edited
 *  document cannot ask for a negative or fractional number of ports. */
export const COUNTS: Record<string, { min: number; max: number }> = {
  nIn: { min: 1, max: 32 },
  nOut: { min: 1, max: 32 },
  nLeaves: { min: 1, max: 16 },
  nItems: { min: 0, max: 32 },
  nParts: { min: 1, max: 16 },
};
export function count(f: NodeFields, key: string, dflt: number): number {
  const b = COUNTS[key] ?? { min: 0, max: 64 };
  const n = Math.floor(num(f[key] as Value, dflt));
  return Number.isFinite(n) ? Math.max(b.min, Math.min(b.max, n)) : dflt;
}

/** Checks a numeric field against the range its port declares. Returns the
 *  first thing wrong, or nothing. */
export function outOfRange(fields: NodeFields, wired: Record<string, Value>, ports: Port[]): string | undefined {
  for (const p of ports) {
    if (p.field !== "number" && p.min == null && p.max == null) continue;
    if (p.min == null && p.max == null) continue;
    const raw = wired[p.id] ?? fields[p.id];
    if (raw == null || raw === "") continue;
    const n = typeof raw === "number" ? raw : Number(String(raw).replace(/[\s,_]/g, ""));
    if (!Number.isFinite(n)) return `${p.label} is not a number`;
    if (!Number.isInteger(n)) return `${p.label} must be a whole number`;
    if (p.min != null && n < p.min) return `${p.label} cannot be below ${p.min.toLocaleString("en-US")}`;
    if (p.max != null && n > p.max) return `${p.label} cannot be above ${p.max.toLocaleString("en-US")}`;
  }
  return undefined;
}

export interface NodeFields {
  name: string;
  [key: string]: unknown;
}

export interface Context {
  network: Network;
  ruleset: Ruleset;
}

export interface Computed {
  outputs: Record<string, Value>;
  /** Shown on the node header and in the detail panel. */
  status?: "ok" | "warn" | "error";
  message?: string;
  /** Anything the detail panel wants: a trace, a parsed tx, refs. */
  extra?: unknown;
}

export interface NodeKind {
  kind: string;
  label: string;
  category: string;
  description: string;
  defaults: () => NodeFields;
  inputs: (fields: NodeFields) => Port[];
  outputs: (fields: NodeFields) => Port[];
  compute: (fields: NodeFields, wired: Record<string, Value>, ctx: Context) => Computed;
}

const P = (id: string, label: string, type: PortType, field?: Port["field"], wide?: boolean): Port =>
  wide ? { id, label, type, field, wide } : field ? { id, label, type, field } : { id, label, type };

const str = (v: Value | undefined): string => (v == null ? "" : Array.isArray(v) ? v.join("") : String(v));
const num = (v: Value | undefined, dflt = 0): number => {
  if (v == null || v === "") return dflt;
  const n = typeof v === "number" ? v : Number(String(v).replace(/[\s,_]/g, ""));
  return Number.isFinite(n) ? n : dflt;
};
const arr = (v: Value | undefined): string[] => (Array.isArray(v) ? v : v == null || v === "" ? [] : [String(v)]);

/** Typed field unless something is wired into the port. */
function get(fields: NodeFields, wired: Record<string, Value>, id: string): Value | undefined {
  return wired[id] !== undefined ? wired[id] : (fields[id] as Value | undefined);
}

function fail(message: string, outputs: Record<string, Value> = {}): Computed {
  return { outputs, status: "error", message };
}

function caught(e: unknown): string {
  return String(e).replace(/^Error:\s*/, "");
}

// ---------------------------------------------------------------------------

const input: NodeKind = {
  kind: "input",
  label: "Input",
  category: "Canvas",
  description: "A value you type. Hex, a number, or text.",
  defaults: () => ({ name: "input", value: "" }),
  inputs: () => [P("value", "value", "any", "text")],
  outputs: () => [P("value", "value", "any")],
  compute: (f, w) => ({ outputs: { value: str(get(f, w, "value")) } }),
};

const template: NodeKind = {
  kind: "template",
  label: "Template",
  category: "Covenants",
  description:
    "A transaction without prevouts or witnesses: what a covenant commits to. Emits the BIP-119 hash per input.",
  defaults: () => ({
    name: "template",
    version: 2,
    locktime: 0,
    nIn: 1,
    nOut: 1,
    in0_seq: 0xfffffffd,
    out0_value: 10_000,
    out0_spk: "",
  }),
  inputs: (f) => {
    const ports: Port[] = [N("version", "version", I32_MIN, I32_MAX), N("locktime", "locktime", 0, U32_MAX)];
    for (let i = 0; i < count(f, "nIn", 1); i++) ports.push(N(`in${i}_seq`, `in ${i} seq`, 0, U32_MAX));
    for (let j = 0; j < count(f, "nOut", 1); j++) {
      ports.push(N(`out${j}_value`, `out ${j} sat`, 0, MAX_MONEY));
      ports.push(P(`out${j}_spk`, `out ${j} spk`, "spk", "hex"));
    }
    return ports;
  },
  outputs: (f) => {
    const ports: Port[] = [];
    for (let i = 0; i < count(f, "nIn", 1); i++) ports.push(P(`ctv${i}`, `ctv[${i}]`, "hash"));
    ports.push(P("template", "template hex", "tx"));
    return ports;
  },
  compute: (f, w) => {
    const nIn = count(f, "nIn", 1),
      nOut = count(f, "nOut", 1);
    const inputs = Array.from({ length: nIn }, (_, i) => ({
      sequence: num(get(f, w, `in${i}_seq`), 0xffffffff) >>> 0,
    }));
    const outputs = Array.from({ length: nOut }, (_, j) => ({
      value: num(get(f, w, `out${j}_value`)),
      script_pubkey: str(get(f, w, `out${j}_spk`)),
    }));
    if (outputs.some((o) => !o.script_pubkey)) return fail("every output needs a scriptPubKey");
    try {
      const v = wasm.template({
        version: num(get(f, w, "version"), 2),
        locktime: num(get(f, w, "locktime")),
        inputs,
        outputs,
      });
      const out: Record<string, Value> = { template: v.template };
      v.ctv.forEach((h, i) => (out[`ctv${i}`] = h));
      return { outputs: out, status: "ok", extra: { base_weight: v.base_weight } };
    } catch (e) {
      return fail(caught(e));
    }
  },
};

const tapscript: NodeKind = {
  kind: "tapscript",
  label: "Tapscript",
  category: "Covenants",
  description: "Script you write. Every @name in it is an input port; whatever is wired in is pushed there.",
  defaults: () => ({ name: "leaf", source: "@hash OP_CHECKTEMPLATEVERIFY" }),
  inputs: (f) => {
    const src = String(f.source ?? "");
    const refs: string[] = [];
    for (const line of src.split("\n")) {
      for (const word of line.split("#")[0].split(/\s+/)) {
        const m = word.match(/^@([A-Za-z_][A-Za-z0-9_]*)$/);
        if (m && !refs.includes(m[1])) refs.push(m[1]);
      }
    }
    return [P("source", "source", "text", "text", true), ...refs.map((r) => P(`ref_${r}`, `@${r}`, "hex"))];
  },
  outputs: () => [P("script", "script", "script"), P("leaf_hash", "leaf hash", "hash")],
  compute: (f, w, ctx) => {
    const bindings: Record<string, string> = {};
    for (const [k, v] of Object.entries(w))
      if (k.startsWith("ref_") && v != null && v !== "") bindings[k.slice(4)] = str(v);
    try {
      const v = wasm.assemble({ source: String(get(f, w, "source") ?? ""), bindings, ruleset: ctx.ruleset });
      if (v.error)
        return {
          outputs: { script: null, leaf_hash: null },
          status: "error",
          message: `line ${v.error.line + 1}: ${v.error.message}`,
          extra: v,
        };
      const enf = v.enforcement!;
      return {
        outputs: { script: v.script!, leaf_hash: v.leaf_hash! },
        status: enf.status === "enforced" ? "ok" : "warn",
        message:
          enf.status === "enforced"
            ? `${v.script!.length / 2} B · enforced`
            : `${enf.status}: ${enf.inactive.join(", ")} inactive`,
        extra: v,
      };
    } catch (e) {
      return fail(caught(e), { script: null, leaf_hash: null });
    }
  },
};

const taproot: NodeKind = {
  kind: "taproot",
  label: "Taproot Output",
  category: "Covenants",
  description: "Internal key and leaf scripts to an address, scriptPubKey and a control block per leaf.",
  defaults: () => ({ name: "output", nLeaves: 1, internal_key: "" }),
  inputs: (f) => {
    const ports: Port[] = [P("internal_key", "internal key", "hash", "hex")];
    for (let i = 0; i < count(f, "nLeaves", 1); i++) ports.push(P(`leaf${i}`, `leaf[${i}]`, "script"));
    return ports;
  },
  outputs: (f) => {
    const ports: Port[] = [
      P("address", "address", "address"),
      P("spk", "scriptPubKey", "spk"),
      P("output_key", "output key", "hash"),
      P("merkle_root", "merkle root", "hash"),
    ];
    for (let i = 0; i < count(f, "nLeaves", 1); i++) ports.push(P(`control${i}`, `control[${i}]`, "hex"));
    return ports;
  },
  compute: (f, w, ctx) => {
    const n = count(f, "nLeaves", 1);
    const leaves: string[] = [];
    for (let i = 0; i < n; i++) {
      const l = str(w[`leaf${i}`]);
      if (!l) return fail(`leaf[${i}] is not wired`);
      leaves.push(l);
    }
    const ik = str(get(f, w, "internal_key"));
    try {
      const v = wasm.taproot_output({ network: ctx.network, internal_key: ik || undefined, leaves });
      const out: Record<string, Value> = {
        address: v.address,
        spk: v.script_pubkey,
        output_key: v.output_key,
        merkle_root: v.merkle_root ?? "",
      };
      v.control_blocks.forEach((c, i) => (out[`control${i}`] = c));
      return { outputs: out, status: "ok", extra: v };
    } catch (e) {
      return fail(caught(e));
    }
  },
};

const transaction: NodeKind = {
  kind: "transaction",
  label: "Transaction",
  category: "Transactions",
  description: "A template bound to prevouts and witnesses. Emits hex, txid and an outpoint per output.",
  defaults: () => ({ name: "tx", nIn: 1, nOut: 1 }),
  inputs: (f) => {
    const ports: Port[] = [P("template", "template", "tx")];
    for (let i = 0; i < count(f, "nIn", 1); i++) {
      ports.push(P(`prevout${i}`, `prevout[${i}]`, "outpoint", "text"));
      ports.push(P(`witness${i}`, `witness[${i}]`, "witness"));
      ports.push(N(`value${i}`, `value[${i}] sat`, 0, MAX_MONEY));
    }
    return ports;
  },
  outputs: (f) => {
    const ports: Port[] = [P("hex", "hex", "tx"), P("txid", "txid", "hash")];
    for (let j = 0; j < count(f, "nOut", 1); j++) ports.push(P(`outpoint${j}`, `outpoint[${j}]`, "outpoint"));
    return ports;
  },
  compute: (f, w) => {
    const tpl = str(w.template);
    if (!tpl) return fail("template is not wired");
    const nIn = count(f, "nIn", 1);
    const prevouts = Array.from({ length: nIn }, (_, i) => str(get(f, w, `prevout${i}`)));
    const witnesses = Array.from({ length: nIn }, (_, i) => arr(w[`witness${i}`]));
    const values = Array.from({ length: nIn }, (_, i) => {
      const v = get(f, w, `value${i}`);
      return v == null || v === "" ? null : num(v);
    });
    try {
      const v = wasm.realize({
        template: tpl,
        prevouts,
        witnesses,
        prevout_values: values.map((v) => v ?? undefined),
      });
      const out: Record<string, Value> = { hex: v.hex, txid: v.txid };
      v.outpoints.forEach((o, j) => (out[`outpoint${j}`] = o));
      const parts = [`${v.vsize} vB`];
      if (v.fee != null) parts.push(`fee ${v.fee}`);
      parts.push(v.complete ? "complete" : "incomplete");
      return { outputs: out, status: v.complete ? "ok" : "warn", message: parts.join(" · "), extra: v };
    } catch (e) {
      return fail(caught(e));
    }
  },
};

const witness: NodeKind = {
  kind: "witness",
  label: "Witness",
  category: "Transactions",
  description: "Stack items, then the script and control block, assembled into a script-path witness.",
  defaults: () => ({ name: "witness", nItems: 0 }),
  inputs: (f) => {
    const ports: Port[] = [];
    for (let i = 0; i < count(f, "nItems", 0); i++) ports.push(P(`item${i}`, `item[${i}]`, "hex", "hex"));
    ports.push(P("script", "script", "script"), P("control", "control block", "hex"));
    return ports;
  },
  outputs: () => [P("witness", "witness", "witness")],
  compute: (f, w) => {
    const items: string[] = [];
    for (let i = 0; i < count(f, "nItems", 0); i++) items.push(str(get(f, w, `item${i}`)));
    const script = str(w.script),
      control = str(w.control);
    if (!script || !control) return fail("script and control block must be wired", { witness: null });
    return { outputs: { witness: [...items, script, control] }, status: "ok", message: `${items.length + 2} items` };
  },
};

const outpoint: NodeKind = {
  kind: "outpoint",
  label: "Outpoint",
  category: "Transactions",
  description: "A txid and vout, for a UTXO that exists outside this canvas.",
  defaults: () => ({ name: "utxo", txid: "", vout: 0, value: 0 }),
  inputs: () => [
    P("txid", "txid", "hash", "hex"),
    N("vout", "vout", 0, U32_MAX),
    N("value", "value sat", 0, MAX_MONEY),
  ],
  outputs: () => [P("outpoint", "outpoint", "outpoint"), P("value", "value sat", "number")],
  compute: (f, w) => {
    const txid = str(get(f, w, "txid"));
    if (!/^[0-9a-fA-F]{64}$/.test(txid)) return fail("txid must be 32 bytes of hex", { outpoint: null, value: null });
    return {
      outputs: { outpoint: `${txid.toLowerCase()}:${num(get(f, w, "vout"))}`, value: num(get(f, w, "value")) },
      status: "ok",
    };
  },
};

const execute: NodeKind = {
  kind: "execute",
  label: "Execute",
  category: "Covenants",
  description: "Runs a tapscript against a transaction under the ruleset and reports every step of the stack.",
  defaults: () => ({ name: "execute", input_index: 0, prevout_value: 0 }),
  inputs: () => [
    P("script", "script", "script"),
    P("witness", "witness", "witness"),
    P("tx", "tx hex", "tx"),
    N("input_index", "input index", 0, U32_MAX),
    N("prevout_value", "prevout sat", 0, MAX_MONEY),
    P("prevout_spk", "prevout spk", "spk"),
    P("control", "control block", "hex"),
  ],
  outputs: () => [P("ok", "result", "number"), P("stack", "final stack", "witness")],
  compute: (f, w, ctx) => {
    const script = str(w.script);
    if (!script) return fail("script is not wired", { ok: null, stack: null });
    const full = arr(w.witness);
    // The witness node emits [items..., script, control]; execution wants the items.
    const stack = full.length >= 2 && full[full.length - 2] === script ? full.slice(0, -2) : full;
    const control =
      str(w.control) || (full.length >= 2 && full[full.length - 2] === script ? full[full.length - 1] : "");
    const spk = str(w.prevout_spk);
    try {
      const v = wasm.execute({
        script,
        stack,
        tx: str(w.tx) || undefined,
        input_index: num(get(f, w, "input_index")),
        prevouts: spk ? [{ value: num(get(f, w, "prevout_value")), script_pubkey: spk }] : [],
        control_block: control || undefined,
        ruleset: ctx.ruleset,
      });
      return {
        outputs: { ok: v.success ? "1" : "0", stack: v.final_stack },
        status: v.success ? "ok" : "error",
        message: v.success ? `ok · ${v.steps.length} steps` : (v.error ?? "rejected"),
        extra: v,
      };
    } catch (e) {
      return fail(caught(e), { ok: null, stack: null });
    }
  },
};

const templateHash: NodeKind = {
  kind: "template_hash",
  label: "Template Hash",
  category: "Covenants",
  description:
    "BIP-446: the hash OP_TEMPLATEHASH pushes. Commits to version, locktime, every sequence, every output, the annex and this input's index, and to nothing about the coins being spent, which is what makes a signature over it rebindable.",
  defaults: () => ({ name: "template hash", input_index: 0 }),
  inputs: () => [P("tx", "tx", "tx"), N("input_index", "input index", 0, U32_MAX), P("annex", "annex", "hex", "hex")],
  outputs: () => [P("hash", "template hash", "hash")],
  compute: (f, w) => {
    const tx = str(get(f, w, "tx"));
    if (!tx) return fail("wire a transaction in", { hash: null });
    const annex = str(get(f, w, "annex"));
    try {
      return {
        outputs: {
          hash: wasm.template_hash_446({ tx, input_index: num(get(f, w, "input_index")), annex: annex || undefined }),
        },
        status: "ok",
      };
    } catch (e) {
      return fail(caught(e), { hash: null });
    }
  },
};

const slice: NodeKind = {
  kind: "slice",
  label: "Slice",
  category: "Bytes",
  description:
    "A run of bytes out of a longer string, by offset and length. What a script rebuilding its own signature message needs its witness to carry.",
  defaults: () => ({ name: "slice", data: "", offset: 0, length: 4 }),
  inputs: () => [P("data", "data", "hex", "hex"), N("offset", "offset", 0, 100_000), N("length", "length", 0, 100_000)],
  outputs: () => [P("hex", "bytes", "hex"), P("rest", "bytes after", "hex")],
  compute: (f, w) => {
    const data = str(get(f, w, "data")).trim();
    if (data.length % 2) return fail("data has an odd number of hex digits", { hex: null, rest: null });
    const total = data.length / 2;
    const offset = num(get(f, w, "offset")),
      length = num(get(f, w, "length"));
    if (offset < 0 || length < 0) return fail("offset and length cannot be negative", { hex: null, rest: null });
    if (offset + length > total)
      return fail(`wants bytes ${offset}..${offset + length} of only ${total}`, { hex: null, rest: null });
    return {
      outputs: { hex: data.slice(offset * 2, (offset + length) * 2), rest: data.slice((offset + length) * 2) },
      status: "ok",
      message: `${length} of ${total} B`,
    };
  },
};

const leBytes: NodeKind = {
  kind: "le_bytes",
  label: "Little-endian",
  category: "Bytes",
  description:
    "A number as fixed-width little-endian bytes, the way amounts, versions and sequences appear inside a signature message.",
  defaults: () => ({ name: "le", value: 0, width: 8 }),
  inputs: () => [N("value", "value", 0, MAX_MONEY), N("width", "width", 1, 8)],
  outputs: () => [P("hex", "bytes", "hex")],
  compute: (f, w) => {
    const width = Math.max(1, Math.min(8, num(get(f, w, "width"), 8)));
    const value = num(get(f, w, "value"));
    if (!Number.isSafeInteger(value) || value < 0)
      return fail("value must be a whole number, zero or more", { hex: null });
    let v = BigInt(value);
    const out: string[] = [];
    for (let i = 0; i < width; i++) {
      out.push(
        Number(v & 0xffn)
          .toString(16)
          .padStart(2, "0"),
      );
      v >>= 8n;
    }
    if (v !== 0n) return fail(`does not fit in ${width} bytes`, { hex: null });
    return { outputs: { hex: out.join("") }, status: "ok" };
  },
};

const text: NodeKind = {
  kind: "text",
  label: "Text",
  category: "Bytes",
  description:
    "UTF-8 text as bytes. What an oracle signs under BIP-348 is the message itself, not a hash of it, so the bytes are what goes on the stack.",
  defaults: () => ({ name: "text", value: "" }),
  inputs: () => [P("value", "text", "text", "text")],
  outputs: () => [P("hex", "bytes", "hex"), P("length", "length", "number")],
  compute: (f, w) => {
    const bytes = new TextEncoder().encode(str(get(f, w, "value")));
    return {
      outputs: { hex: Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join(""), length: bytes.length },
      status: "ok",
    };
  },
};

const concat: NodeKind = {
  kind: "concat",
  label: "Concat",
  category: "Bytes",
  description:
    "Joins byte strings, left to right. What OP_CAT does on the stack, for building a value the script will rebuild.",
  defaults: () => ({ name: "concat", nParts: 2, part0: "", part1: "" }),
  inputs: (f) => {
    const ports: Port[] = [];
    for (let i = 0; i < count(f, "nParts", 2); i++) ports.push(P(`part${i}`, `part[${i}]`, "hex", "hex"));
    return ports;
  },
  outputs: () => [P("hex", "bytes", "hex"), P("length", "length", "number")],
  compute: (f, w) => {
    let out = "";
    for (let i = 0; i < count(f, "nParts", 2); i++) {
      const part = str(get(f, w, `part${i}`)).trim();
      if (part && !/^[0-9a-fA-F]*$/.test(part)) return fail(`part[${i}] is not hex`, { hex: null, length: null });
      if (part.length % 2) return fail(`part[${i}] has an odd number of hex digits`, { hex: null, length: null });
      out += part.toLowerCase();
    }
    return { outputs: { hex: out, length: out.length / 2 }, status: "ok" };
  },
};

const sha256: NodeKind = {
  kind: "sha256",
  label: "SHA-256",
  category: "Bytes",
  description: "Single SHA-256 of hex data.",
  defaults: () => ({ name: "sha256", data: "" }),
  inputs: () => [P("data", "data", "hex", "hex")],
  outputs: () => [P("hash", "hash", "hash")],
  compute: (f, w) => {
    try {
      return { outputs: { hash: wasm.sha256(str(get(f, w, "data"))) }, status: "ok" };
    } catch (e) {
      return fail(caught(e), { hash: null });
    }
  },
};

const taggedHash: NodeKind = {
  kind: "tagged_hash",
  label: "Tagged Hash",
  category: "Bytes",
  description: "BIP-340 tagged hash: SHA-256(SHA-256(tag) ‖ SHA-256(tag) ‖ data).",
  defaults: () => ({ name: "tagged", tag: "TapLeaf", data: "" }),
  inputs: () => [P("tag", "tag", "text", "text"), P("data", "data", "hex", "hex")],
  outputs: () => [P("hash", "hash", "hash")],
  compute: (f, w) => {
    try {
      return { outputs: { hash: wasm.tagged_hash(str(get(f, w, "tag")), str(get(f, w, "data"))) }, status: "ok" };
    } catch (e) {
      return fail(caught(e), { hash: null });
    }
  },
};

/** A dot on a wire. Passes its input through, so long wires can be routed. */
const reroute: NodeKind = {
  kind: "reroute",
  label: "Reroute",
  category: "Canvas",
  description: "A point on a wire, for routing it around things.",
  defaults: () => ({ name: "" }),
  inputs: () => [P("in", "", "any")],
  outputs: () => [P("out", "", "any")],
  compute: (_f, w) => ({ outputs: { out: w.in ?? null } }),
};

/** A labelled box behind other nodes. Moving it moves what is inside. */
const comment: NodeKind = {
  kind: "comment",
  label: "Comment",
  category: "Canvas",
  description: "A box to group and label nodes. Moving it moves what it contains.",
  defaults: () => ({ name: "", width: 360, height: 240, color: "teal", moveContents: true }),
  inputs: () => [],
  outputs: () => [],
  compute: () => ({ outputs: {} }),
};

// --- keys and signatures -----------------------------------------------------
// Secrets are visible hex: this is a sandbox for signet and regtest, and a
// key you can see is a key you can reason about.

const randomSecret = () => {
  const b = new Uint8Array(32);
  crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
};

const key: NodeKind = {
  kind: "key",
  label: "Key",
  category: "Keys",
  description: "A secret and its BIP-340 x-only public key. A new node gets a random secret; paste your own to use it.",
  defaults: () => ({ name: "key", secret: randomSecret() }),
  inputs: () => [P("secret", "secret", "hex", "hex")],
  outputs: () => [P("pubkey", "public key", "hex"), P("sk", "secret", "hex")],
  compute: (f, w) => {
    const secret = str(get(f, w, "secret"));
    try {
      return { outputs: { pubkey: wasm.pubkey(secret), sk: secret }, status: "ok" };
    } catch (e) {
      return fail(caught(e), { pubkey: null, sk: null });
    }
  },
};

/** Hash type names, in the order the select shows them, to their bytes. */
export const HASH_TYPES: Record<string, number> = {
  DEFAULT: 0x00,
  ALL: 0x01,
  NONE: 0x02,
  SINGLE: 0x03,
  "ALL|ANYONECANPAY": 0x81,
  "NONE|ANYONECANPAY": 0x82,
  "SINGLE|ANYONECANPAY": 0x83,
  "ALL|ANYPREVOUT": 0x41,
  "NONE|ANYPREVOUT": 0x42,
  "SINGLE|ANYPREVOUT": 0x43,
  "ALL|ANYPREVOUTANYSCRIPT": 0xc1,
  "NONE|ANYPREVOUTANYSCRIPT": 0xc2,
  "SINGLE|ANYPREVOUTANYSCRIPT": 0xc3,
};

const sighash: NodeKind = {
  kind: "sighash",
  label: "Sighash",
  category: "Keys",
  description:
    "The BIP-341 script-path digest for one input of a transaction: what a signature checked in this leaf must sign. The ANYPREVOUT modes are BIP-118's.",
  defaults: () => ({ name: "sighash", hash_type: "DEFAULT", input_index: 0, prevout_value: 0, prevout_spk: "" }),
  inputs: () => [
    P("tx", "tx", "tx"),
    P("leaf", "leaf script", "script"),
    { ...P("hash_type", "hash type", "text", "select"), options: Object.keys(HASH_TYPES) },
    N("input_index", "input index", 0, U32_MAX),
    N("prevout_value", "prevout sat", 0, MAX_MONEY),
    P("prevout_spk", "prevout spk", "spk", "hex"),
  ],
  outputs: () => [
    P("sighash", "sighash", "hash"),
    P("preimage", "preimage", "hex"),
    P("type_byte", "hash type byte", "number"),
    P("leaf_hash", "leaf hash", "hash"),
  ],
  compute: (f, w) => {
    const name = str(get(f, w, "hash_type")) || "DEFAULT";
    const hash_type = HASH_TYPES[name];
    const tx = str(get(f, w, "tx")),
      leaf = str(get(f, w, "leaf"));
    const spk = str(get(f, w, "prevout_spk")),
      value = num(get(f, w, "prevout_value"));
    const empty = { sighash: null, preimage: null, type_byte: hash_type ?? null, leaf_hash: null };
    if (hash_type === undefined) return fail(`unknown hash type ${name}`, empty);
    if (!tx) return fail("wire a transaction in", empty);
    if (!leaf) return fail("wire the leaf script in", empty);
    try {
      const v = wasm.sighash({
        tx,
        input_index: num(get(f, w, "input_index")),
        prevouts: spk ? [{ value, script_pubkey: spk }] : [],
        hash_type,
        leaf_script: leaf,
      });
      return {
        outputs: { sighash: v.sighash, preimage: v.preimage, type_byte: v.hash_type, leaf_hash: v.tapleaf_hash },
        status: "ok",
        message: v.key_version === 1 ? "BIP-118 key version" : undefined,
      };
    } catch (e) {
      return fail(caught(e), empty);
    }
  },
};

const sign: NodeKind = {
  kind: "sign",
  label: "Schnorr Sign",
  category: "Keys",
  description:
    "A BIP-340 signature over a 32-byte message. For a CHECKSIG, wire the sighash and its type byte: the byte is appended unless it is DEFAULT. For CHECKSIGFROMSTACK use the raw 64 bytes.",
  defaults: () => ({ name: "sign", message: "", hash_type: 0 }),
  inputs: () => [
    P("secret", "secret", "hex", "hex"),
    P("message", "message", "hash", "hex"),
    N("hash_type", "hash type byte", 0, 255),
  ],
  outputs: () => [P("sig", "signature", "hex"), P("raw", "raw 64 bytes", "hex")],
  compute: (f, w) => {
    const secret = str(get(f, w, "secret")),
      message = str(get(f, w, "message")),
      t = num(get(f, w, "hash_type"));
    if (!secret) return fail("wire a secret in", { sig: null, raw: null });
    if (!message) return fail("wire a message in", { sig: null, raw: null });
    try {
      const raw = wasm.sign_schnorr(secret, message);
      return { outputs: { raw, sig: t ? raw + t.toString(16).padStart(2, "0") : raw }, status: "ok" };
    } catch (e) {
      return fail(caught(e), { sig: null, raw: null });
    }
  },
};

const verify: NodeKind = {
  kind: "verify",
  label: "Schnorr Verify",
  category: "Keys",
  description: "Checks a BIP-340 signature over a message outside of script. A trailing hash type byte is ignored.",
  defaults: () => ({ name: "verify", pubkey: "", message: "", signature: "" }),
  inputs: () => [
    P("pubkey", "public key", "hex", "hex"),
    P("message", "message", "hash", "hex"),
    P("signature", "signature", "hex", "hex"),
  ],
  outputs: () => [P("ok", "valid", "number")],
  compute: (f, w) => {
    const pk = str(get(f, w, "pubkey")),
      message = str(get(f, w, "message")),
      sig = str(get(f, w, "signature"));
    if (!pk || !message || !sig) return fail("wire a key, a message, and a signature in", { ok: null });
    try {
      const ok = wasm.verify_schnorr(pk, message, sig);
      return { outputs: { ok: ok ? 1 : 0 }, status: ok ? "ok" : "warn", message: ok ? "valid" : "invalid signature" };
    } catch (e) {
      return fail(caught(e), { ok: null });
    }
  },
};

export const KINDS: Record<string, NodeKind> = Object.fromEntries(
  [
    template,
    tapscript,
    taproot,
    execute,
    transaction,
    witness,
    outpoint,
    input,
    key,
    sighash,
    sign,
    verify,
    templateHash,
    slice,
    leBytes,
    text,
    concat,
    sha256,
    taggedHash,
    reroute,
    comment,
  ].map((k) => [k.kind, k]),
);
export const CATEGORIES = ["Covenants", "Transactions", "Keys", "Bytes", "Canvas"];

/** Port lookup for connection validation and wire colouring. */
export function findPort(fields: NodeFields, side: "source" | "target", id: string): Port | undefined {
  const kind = KINDS[fields.kind as string];
  if (!kind) return undefined;
  return (side === "source" ? kind.outputs(fields) : kind.inputs(fields)).find((p) => p.id === id);
}

/** The first target port on a node that accepts a value of `type`. */
export function firstCompatibleInput(fields: NodeFields, from: Port): Port | undefined {
  return KINDS[fields.kind as string]?.inputs(fields).find((p) => !p.wide && portsCompatible(from, p));
}
export function firstCompatibleOutput(fields: NodeFields, to: Port): Port | undefined {
  return KINDS[fields.kind as string]?.outputs(fields).find((p) => portsCompatible(p, to));
}
