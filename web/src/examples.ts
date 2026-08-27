// Example flows. The vault is the one from docs/vision.md, laid out the way
// a tidy Unreal graph is: the commitment chain runs left to right across
// the top, the realization chain runs left to right underneath, and every
// wire that crosses between them drops through a knot into one of a stack
// of horizontal lanes, then rises through another knot into its target.
// Drop knots sit 64px right of their source column and rise knots 64px
// left of their target column, so lane runs are dead straight and the
// vertical part of each drop clears the pin column by 32px.

import type { Edge } from "@xyflow/react";
import type { FlowNode } from "./store";
import { scriptBlock } from "./script/wrap";
import { count, KINDS, type NodeFields } from "./registry";
import type { Network } from "./engine";

/** A placeholder P2TR scriptPubKey. The witness program is 32 bytes, so
 *  the filler repeats to exactly 64 hex characters whether it is given
 *  one or two: repeating a byte 64 times built a 66-byte script whose
 *  own length prefix said 32. */
const p2tr = (b: string) => "5120" + b.repeat(Math.ceil(64 / b.length)).slice(0, 64);
const S = 416; // column pitch: 288 node + 128 gap
const col = (i: number) => i * S;
const drop = (i: number) => col(i) + 288 + 64;
const rise = (j: number) => col(j) - 64;

function node(id: string, kind: string, x: number, y: number, data: Record<string, unknown> = {}): FlowNode {
  return { id, type: "cov", position: { x, y }, data: { name: id, ...data, kind } };
}
function knot(id: string, cx: number, cy: number): FlowNode {
  return { id, type: "reroute", position: { x: cx - 16, y: cy - 16 }, data: { name: "", kind: "reroute" } };
}
function comment(
  id: string,
  name: string,
  color: string,
  x: number,
  y: number,
  width: number,
  height: number,
): FlowNode {
  return {
    id,
    type: "comment",
    position: { x, y },
    data: { name, kind: "comment", color, width, height, moveContents: true },
    zIndex: -1,
  };
}
/** A box drawn around nodes already placed, with room for its title bar. */
function around(id: string, name: string, color: string, nodes: FlowNode[], ids: string[]): FlowNode {
  const inside = nodes.filter((n) => ids.includes(n.id));
  const x0 = Math.min(...inside.map((n) => n.position.x)) - PAD;
  const y0 = Math.min(...inside.map((n) => n.position.y)) - PAD - HEAD;
  const x1 = Math.max(...inside.map((n) => n.position.x + 288)) + PAD;
  const y1 = Math.max(...inside.map((n) => n.position.y + height(n))) + PAD;
  return comment(id, name, color, x0, y0, x1 - x0, y1 - y0);
}
const PAD = 40,
  HEAD = 40;

// Node heights. Measured in the browser rather than derived: a layout that
// guesses them puts nodes through the bottom of their comment box. The key
// is the node's shape, since ports drive the height.
const ROW = 30;
/** A tapscript's chrome is taller than the other nodes': it carries the
 *  byte count and enforcement line under its ports. Measured, like the
 *  heights above. */
const TAPSCRIPT_CHROME = 98;
const MEASURED: Record<string, number> = {
  "template:1:1": 296,
  "template:1:2": 356,
  "taproot:1": 284,
  "taproot:2": 340,
  "transaction:1:1": 372,
  "transaction:1:2": 450,
  execute: 467,
  outpoint: 235,
  key: 175,
  sighash: 377,
  sign: 235,
  verify: 209,
  text: 175,
  "concat:2": 206,
  tagged_hash: 179,
  "concat:3": 236,
  sha256: 149,
  input: 149,
  template_hash: 209,
  slice: 235,
  le_bytes: 179,
};
/** Least a node with `rows` port rows can render at: every row is at least
 *  26px and the chrome above and below adds more than 60. Exported because
 *  the table above is measured by hand and has twice been left behind by a
 *  port added in the registry, which is exactly the case this floor catches:
 *  a height recorded when the node was shorter falls under it. */
export const minHeightFor = (rows: number) => rows * ROW + 60;

/** The measured table itself, exported for the same test. */
export const MEASURED_HEIGHTS: Readonly<Record<string, number>> = MEASURED;

/** The shape key for a node, exported so a test can hold the table to the
 *  ports each node actually has. */
export function shapeOf(d: Record<string, unknown>): string {
  return shape(d);
}
export function heightOf(n: FlowNode): number {
  return height(n);
}
function shape(d: Record<string, unknown>): string {
  const k = String(d.kind);
  if (k === "template" || k === "transaction") return `${k}:${Number(d.nIn ?? 1)}:${Number(d.nOut ?? 1)}`;
  if (k === "taproot") return `${k}:${Number(d.nLeaves ?? 1)}`;
  if (k === "witness") return `${k}:${Number(d.nItems ?? 0)}`;
  if (k === "concat") return `${k}:${Number(d.nParts ?? 2)}`;
  return k;
}
function height(n: FlowNode): number {
  const d = n.data as Record<string, unknown>;
  // Nodes whose ports are driven by a count grow by one row each, so they
  // get a formula rather than a table entry per count: a table only knows
  // the counts something already used.
  if (String(d.kind) === "witness") return 180 + ROW * count(d as NodeFields, "nItems", 0);
  if (String(d.kind) === "concat") return 146 + ROW * count(d as NodeFields, "nParts", 2);
  if (String(d.kind) === "tapscript") {
    // The script block grows by line up to the clamp the node applies,
    // and each @name adds a port row.
    const src = String(d.source ?? "");
    const refs = new Set(src.match(/@[A-Za-z_]\w*/g) ?? []).size;
    return TAPSCRIPT_CHROME + Math.round(scriptBlock(src).height) + (refs + 2) * ROW;
  }
  const key = shape(d);
  if (key in MEASURED) return MEASURED[key];
  // Nobody has measured this shape. Fall back to the floor its own ports
  // imply rather than one flat number, which boxes a wide node as a small
  // one and drops it out of its comment.
  const k = KINDS[String(d.kind)];
  if (!k) return 240;
  return minHeightFor(k.inputs(d as NodeFields).length + k.outputs(d as NodeFields).length);
}
/** Lane rows for the knot band between two regions: `n` lanes starting
 *  clear of everything placed above, returned with the y the next region
 *  should start at. Lanes inside a comment box would be dragged with it. */
function band(nodes: FlowNode[], n: number, gap = 32): { lane: (i: number) => number; next: number } {
  const bottom = Math.max(...nodes.map((x) => x.position.y + height(x)));
  const first = bottom + PAD + 48;
  return { lane: (i: number) => first + i * gap, next: first + (n - 1) * gap + 48 + PAD + HEAD };
}

function wire(s: string, sh: string, t: string, th: string): Edge {
  return { id: `e_${s}.${sh}->${t}.${th}`, source: s, sourceHandle: sh, target: t, targetHandle: th };
}
/** Route a wire from a source pin down into a lane and back up into a
 *  target pin, one knot per turn. Adjacent columns get a single knot: the
 *  drop out of column i and the rise into column i+1 are the same x, and
 *  two knots there would sit exactly on top of each other. */
function via(
  tag: string,
  src: [string, string],
  from: number,
  to: number,
  y: number,
  dst: [string, string],
): { nodes: FlowNode[]; edges: Edge[]; last: string } {
  const x1 = drop(from),
    x2 = rise(to);
  const ids = x1 === x2 ? [tag] : [`${tag}a`, `${tag}b`];
  const nodes = ids.map((id, i) => knot(id, i === 0 ? x1 : x2, y));
  return { nodes, edges: route(src, ids, dst), last: ids[ids.length - 1] };
}

/** One value carried along a lane and tapped at several columns: a knot
 *  where it drops, then one at each column that wants it, chained left to
 *  right. Branching every tap off a single knot instead sends long wires
 *  back across everything in between; a bus keeps them in the lane until
 *  they are needed. Returns the tap knots in order, so a caller can hang
 *  a second target off any of them. */
function bus(
  tag: string,
  src: [string, string],
  from: number,
  y: number,
  stops: Array<{ col: number; to: [string, string] }>,
): { nodes: FlowNode[]; edges: Edge[]; ids: string[] } {
  const nodes: FlowNode[] = [];
  const edges: Edge[] = [];
  const ids: string[] = [];
  let prev = src;
  let n = 0;
  // A drop knot, unless the first tap already sits at that x.
  if (rise(stops[0].col) !== drop(from)) {
    const id = `${tag}d`;
    nodes.push(knot(id, drop(from), y));
    edges.push(wire(prev[0], prev[1], id, "in"));
    prev = [id, "out"];
  }
  for (const s of stops) {
    const id = `${tag}${n++}`;
    nodes.push(knot(id, rise(s.col), y));
    edges.push(wire(prev[0], prev[1], id, "in"));
    edges.push(wire(id, "out", s.to[0], s.to[1]));
    ids.push(id);
    prev = [id, "out"];
  }
  return { nodes, edges, ids };
}

/** A chain of wires through knots: src.port -> k1 -> k2 -> ... -> dst.port */
function route(src: [string, string], knots: string[], dst: [string, string]): Edge[] {
  const hops = [src, ...knots.map((k) => [k, "out"] as [string, string])];
  const out: Edge[] = [];
  hops.forEach((h, i) => {
    const next = i + 1 < hops.length ? ([hops[i + 1][0], "in"] as [string, string]) : dst;
    out.push(wire(h[0], h[1], next[0], next[1]));
  });
  return out;
}

export interface Example {
  nodes: FlowNode[];
  edges: Edge[];
  network: Network;
  ruleset: string;
  select?: string;
}

export function vault(): Example {
  // Laid out so every wire runs one way.
  //
  // The vault is built inside out and spent outside in: `withdraw` is the
  // last transaction but the first thing that exists, and `deposit` is the
  // first coin but the last thing built. Put both chains left to right in
  // their own order and every wire between them crosses, because the
  // second consumes what the first produced in reverse.
  //
  // So the spending row starts under the far end of the building row. Each
  // transaction then sits to the right of everything it needs, and the
  // long hauls drop into lanes and run right underneath. Nothing doubles
  // back.
  const nodes: FlowNode[] = [];
  const spk = (b: string) => p2tr(b);

  // --- what the vault allows, decided before it is funded ---------------
  const withdraw = node("withdraw", "template", col(0), 0, {
    version: 2,
    locktime: 0,
    nIn: 1,
    nOut: 1,
    in0_seq: 144,
    out0_value: 98_000,
    out0_spk: spk("11"),
  });
  const hot = node("hot", "tapscript", col(1), 0, {
    source:
      "# Wait out the delay, then take\n# only the withdrawal named here.\n144 OP_CHECKSEQUENCEVERIFY OP_DROP\n@withdraw OP_CHECKTEMPLATEVERIFY",
  });
  const clawback = node("clawback", "template", col(0), 372, {
    version: 2,
    locktime: 0,
    nIn: 1,
    nOut: 1,
    in0_seq: 0xfffffffd,
    out0_value: 98_500,
    out0_spk: spk("22"),
  });
  const cold = node("cold", "tapscript", col(1), 372, {
    source: "# No delay. If that withdrawal was\n# not yours, move it to cold now.\n@clawback OP_CHECKTEMPLATEVERIFY",
  });
  // Centred between the two leaves it holds, so both wires into it are the
  // same shape and the box has no dead quarter.
  const triggerOut = node("trigger_out", "taproot", col(2), 164, { nLeaves: 2 });

  // --- and the deposit that can only become it --------------------------
  const trigger = node("trigger", "template", col(3), 0, {
    version: 2,
    locktime: 0,
    nIn: 1,
    nOut: 1,
    in0_seq: 0xfffffffd,
    out0_value: 99_000,
  });
  const depositLeaf = node("deposit_leaf", "tapscript", col(4), 0, {
    source: "# The deposit has one way out, and\n# it is the trigger above.\n@trigger OP_CHECKTEMPLATEVERIFY",
  });
  const deposit = node("deposit", "taproot", col(5), 0, { nLeaves: 1 });
  nodes.push(withdraw, hot, clawback, cold, triggerOut, trigger, depositLeaf, deposit);

  // Five lanes under the building row for the hauls that reach the far
  // right, ordered so the one landing furthest right rides lowest and they
  // never cross each other.
  const { lane, next: BOT } = band(nodes, 5);

  // --- spending it, months later ----------------------------------------
  // Each transaction sits right of everything it needs.
  const funding = node("funding", "outpoint", col(4), BOT, { txid: "f".repeat(64), vout: 1, value: 100_000 });
  const depositWit = node("deposit_witness", "witness", col(5), BOT, { nItems: 0 });
  const triggerTx = node("trigger_tx", "transaction", col(6), BOT, { nIn: 1, nOut: 1 });
  const hotWit = node("hot_witness", "witness", col(7), BOT, { nItems: 0 });
  const withdrawTx = node("withdraw_tx", "transaction", col(8), BOT, { nIn: 1, nOut: 1 });
  const run = node("check", "execute", col(9), BOT, { input_index: 0, prevout_value: 99_000 });
  nodes.push(funding, depositWit, triggerTx, hotWit, withdrawTx, run);

  const hops = [
    via("hTrig", ["trigger", "template"], 3, 6, lane(0), ["trigger_tx", "template"]),
    via("hHot", ["hot", "script"], 1, 7, lane(1), ["hot_witness", "script"]),
    via("hCtrl", ["trigger_out", "control0"], 2, 7, lane(2), ["hot_witness", "control"]),
    via("hSpk", ["trigger_out", "spk"], 2, 9, lane(3), ["check", "prevout_spk"]),
    via("hWith", ["withdraw", "template"], 0, 8, lane(4), ["withdraw_tx", "template"]),
  ];
  nodes.push(...hops.flatMap((h) => h.nodes));

  const edges: Edge[] = [
    // building: each script commits to the transaction that may spend it
    wire("withdraw", "ctv0", "hot", "ref_withdraw"),
    wire("clawback", "ctv0", "cold", "ref_clawback"),
    wire("hot", "script", "trigger_out", "leaf0"),
    wire("cold", "script", "trigger_out", "leaf1"),
    wire("trigger_out", "spk", "trigger", "out0_spk"),
    wire("trigger", "ctv0", "deposit_leaf", "ref_trigger"),
    wire("deposit_leaf", "script", "deposit", "leaf0"),
    ...hops.flatMap((h) => h.edges),
    // the hot leaf is needed twice: once as a witness, once to run
    wire(hops[1].last, "out", "check", "script"),
    // spending: straight down where the source is already overhead
    wire("deposit_leaf", "script", "deposit_witness", "script"),
    wire("deposit", "control0", "deposit_witness", "control"),
    wire("funding", "outpoint", "trigger_tx", "prevout0"),
    wire("funding", "value", "trigger_tx", "value0"),
    wire("deposit_witness", "witness", "trigger_tx", "witness0"),
    wire("trigger_tx", "outpoint0", "withdraw_tx", "prevout0"),
    wire("hot_witness", "witness", "withdraw_tx", "witness0"),
    wire("hot_witness", "witness", "check", "witness"),
    wire("withdraw_tx", "hex", "check", "tx"),
  ];

  nodes.unshift(
    around("c_ways", "Two ways out, both settled before a satoshi moves", "teal", nodes, [
      "withdraw",
      "hot",
      "clawback",
      "cold",
      "trigger_out",
    ]),
    around("c_deposit", "The deposit can become the trigger and nothing else", "amber", nodes, [
      "trigger",
      "deposit_leaf",
      "deposit",
    ]),
    around("c_spend", "Spending it: bind the coin, fill the witnesses, run the leaf", "blue", nodes, [
      "funding",
      "deposit_witness",
      "trigger_tx",
      "hot_witness",
      "withdraw_tx",
      "check",
    ]),
  );
  return { nodes, edges, network: "signet", ruleset: "ctv", select: "hot" };
}

// --- congestion control -------------------------------------------------------

/** One transaction commits to a tree of payouts. Each branch unrolls on its
 *  own schedule, so a busy block only has to carry the root. BIP-119's
 *  headline use. */
export function pool(): Example {
  // The same shape as the vault, for the same reason: a tree is built from
  // the payouts inward and spent from the root outward, so the two chains
  // consume each other backwards. The spending row starts under the far
  // end of the building row, and every wire runs one way.
  //
  // Read it as a tree standing on its side. Two pairs of payouts on the
  // left, each behind its own branch, both gathered by a root in the
  // middle, and one output on the right that is all the chain ever sees.
  const nodes: FlowNode[] = [];
  const to = (b: string) => p2tr(b);

  // --- what each pair is owed, agreed before anyone pays in -------------
  const payAB = node("pay_ab", "template", col(0), 0, {
    version: 2,
    locktime: 0,
    nIn: 1,
    nOut: 2,
    in0_seq: 0xfffffffd,
    out0_value: 24_000,
    out0_spk: to("11"),
    out1_value: 24_000,
    out1_spk: to("22"),
  });
  const branchAB = node("branch_ab", "tapscript", col(1), 0, {
    source: "# alice and bob, whenever they ask\n@pay_ab OP_CHECKTEMPLATEVERIFY",
  });
  const outAB = node("out_ab", "taproot", col(2), 0, { nLeaves: 1 });
  const payCD = node("pay_cd", "template", col(0), 412, {
    version: 2,
    locktime: 0,
    nIn: 1,
    nOut: 2,
    in0_seq: 0xfffffffd,
    out0_value: 24_000,
    out0_spk: to("33"),
    out1_value: 24_000,
    out1_spk: to("44"),
  });
  const branchCD = node("branch_cd", "tapscript", col(1), 412, {
    source: "# carol and dave, on their own clock\n@pay_cd OP_CHECKTEMPLATEVERIFY",
  });
  const outCD = node("out_cd", "taproot", col(2), 412, { nLeaves: 1 });

  // --- one root over both branches, centred where they meet -------------
  // The root sits halfway down the pair of branches, so the two wires into
  // it are the same shape and it reads as the place they meet. What
  // follows keeps the root's top line rather than its centre: three boxes
  // of different heights centred on one line look misaligned, not centred.
  const ROOT_Y = 348 - 178;
  const root = node("root", "template", col(3), ROOT_Y, {
    version: 2,
    locktime: 0,
    nIn: 1,
    nOut: 2,
    in0_seq: 0xfffffffd,
    out0_value: 49_000,
    out1_value: 49_000,
  });
  const poolLeaf = node("pool_leaf", "tapscript", col(4), ROOT_Y, {
    source: "# the only thing the block carries\n@root OP_CHECKTEMPLATEVERIFY",
  });
  const pool = node("pool", "taproot", col(5), ROOT_Y, { nLeaves: 1 });
  nodes.push(payAB, branchAB, outAB, payCD, branchCD, outCD, root, poolLeaf, pool);

  const { lane, next: BOT } = band(nodes, 5);

  // --- on chain: one transaction, then a branch whenever someone asks ---
  const funding = node("funding", "outpoint", col(4), BOT, { txid: "f".repeat(64), vout: 0, value: 100_000 });
  const poolWit = node("pool_witness", "witness", col(5), BOT, { nItems: 0 });
  const poolTx = node("pool_tx", "transaction", col(6), BOT, { nIn: 1, nOut: 2 });
  const branchWit = node("branch_witness", "witness", col(7), BOT, { nItems: 0 });
  const unroll = node("unroll_ab", "transaction", col(8), BOT, { nIn: 1, nOut: 2 });
  const run = node("check", "execute", col(9), BOT, { input_index: 0, prevout_value: 49_000 });
  nodes.push(funding, poolWit, poolTx, branchWit, unroll, run);

  // Lanes ordered by how far right they land, so they never cross.
  const hops = [
    via("hRoot", ["root", "template"], 3, 6, lane(0), ["pool_tx", "template"]),
    via("hLeaf", ["branch_ab", "script"], 1, 7, lane(1), ["branch_witness", "script"]),
    via("hCtrl", ["out_ab", "control0"], 2, 7, lane(2), ["branch_witness", "control"]),
    via("hPay", ["pay_ab", "template"], 0, 8, lane(3), ["unroll_ab", "template"]),
    via("hSpk", ["out_ab", "spk"], 2, 9, lane(4), ["check", "prevout_spk"]),
  ];
  nodes.push(...hops.flatMap((h) => h.nodes));

  const edges: Edge[] = [
    // building: every payout is committed before a satoshi moves
    wire("pay_ab", "ctv0", "branch_ab", "ref_pay_ab"),
    wire("pay_cd", "ctv0", "branch_cd", "ref_pay_cd"),
    wire("branch_ab", "script", "out_ab", "leaf0"),
    wire("branch_cd", "script", "out_cd", "leaf0"),
    wire("out_ab", "spk", "root", "out0_spk"),
    wire("out_cd", "spk", "root", "out1_spk"),
    wire("root", "ctv0", "pool_leaf", "ref_root"),
    wire("pool_leaf", "script", "pool", "leaf0"),
    ...hops.flatMap((h) => h.edges),
    wire(hops[1].last, "out", "check", "script"),
    // spending: the sources are already overhead, so these drop straight
    wire("pool_leaf", "script", "pool_witness", "script"),
    wire("pool", "control0", "pool_witness", "control"),
    wire("funding", "outpoint", "pool_tx", "prevout0"),
    wire("funding", "value", "pool_tx", "value0"),
    wire("pool_witness", "witness", "pool_tx", "witness0"),
    wire("pool_tx", "outpoint0", "unroll_ab", "prevout0"),
    wire("branch_witness", "witness", "unroll_ab", "witness0"),
    wire("branch_witness", "witness", "check", "witness"),
    wire("unroll_ab", "hex", "check", "tx"),
  ];

  nodes.unshift(
    around("c_pairs", "Every payout is settled before anyone pays in", "teal", nodes, [
      "pay_ab",
      "branch_ab",
      "out_ab",
      "pay_cd",
      "branch_cd",
      "out_cd",
    ]),
    around("c_root", "One root gathers both branches", "amber", nodes, ["root", "pool_leaf", "pool"]),
    around("c_chain", "One transaction on chain, and a branch whenever its pair asks", "blue", nodes, [
      "funding",
      "pool_witness",
      "pool_tx",
      "branch_witness",
      "unroll_ab",
      "check",
    ]),
  );
  return { nodes, edges, network: "signet", ruleset: "ctv", select: "pool_leaf" };
}

// --- delegation ---------------------------------------------------------------

/** Alice holds the coin. She hands Bob one spend by signing his key, and
 *  never gives up her own. BIP-348's plainest use. */
export function delegation(): Example {
  // Two signatures, made at different times by different people, meeting
  // in one witness. Alice signs Bob's key and goes away; months later Bob
  // signs a transaction and shows her signature beside his.
  //
  // The spend needs something from every column behind it, so the harness
  // under the top row is wider here than elsewhere: eight lanes, ordered
  // by how far right each one lands so none crosses another.
  const nodes: FlowNode[] = [];

  // --- the grant, made once and then forgotten --------------------------
  const alice = node("alice", "key", col(0), 0, { secret: "11".repeat(32) });
  const bob = node("bob", "key", col(0), 231, { secret: "22".repeat(32) });
  const grant = node("grant", "sign", col(1), 0, { hash_type: 0 });

  // --- the coin it locks, and what Bob may do with it -------------------
  const leaf = node("leaf", "tapscript", col(2), 0, {
    source: [
      "# Alice can hand Bob one spend by",
      "# signing his key, keeping her own.",
      "@bob                # her message",
      "@alice OP_CSFS OP_VERIFY",
      "@bob OP_CHECKSIG    # and Bob signs",
    ].join("\n"),
  });
  const output = node("output", "taproot", col(3), 0, { nLeaves: 1 });
  const spend = node("spend", "template", col(4), 0, {
    version: 2,
    locktime: 0,
    nIn: 1,
    nOut: 1,
    in0_seq: 0xfffffffd,
    out0_value: 99_000,
    out0_spk: p2tr("55"),
  });
  // A column of its own, so nothing sits above it: at a distance a box's
  // label floats over whatever is there, and this one would land on the
  // template. It also puts the coin directly over the transaction that
  // spends it.
  const funding = node("funding", "outpoint", col(5), 0, { txid: "f".repeat(64), vout: 0, value: 100_000 });
  nodes.push(alice, bob, grant, leaf, output, spend, funding);

  const { lane, next: BOT } = band(nodes, 8);

  // --- the spend, one node per step, left to right ----------------------
  // The transaction is built twice on purpose: a signature cannot commit
  // to the witness that carries it, so the digest is taken from the
  // unsigned one and the witness goes on afterwards.
  const unsigned = node("unsigned", "transaction", col(5), BOT, { nIn: 1, nOut: 1 });
  const sighash = node("sighash", "sighash", col(6), BOT, {
    hash_type: "DEFAULT",
    input_index: 0,
    prevout_value: 100_000,
  });
  const bobSig = node("bob_sig", "sign", col(7), BOT, {});
  const wit = node("witness", "witness", col(8), BOT, { nItems: 2 });
  const signed = node("signed", "transaction", col(9), BOT, { nIn: 1, nOut: 1 });
  const run = node("check", "execute", col(10), BOT, { input_index: 0, prevout_value: 100_000 });
  nodes.push(unsigned, sighash, bobSig, wit, signed, run);

  const hops = [
    via("hLeaf", ["leaf", "script"], 2, 6, lane(0), ["sighash", "leaf"]),
    via("hSpk", ["output", "spk"], 3, 6, lane(1), ["sighash", "prevout_spk"]),
    via("hBob", ["bob", "sk"], 0, 7, lane(2), ["bob_sig", "secret"]),
    via("hGrant", ["grant", "sig"], 1, 8, lane(3), ["witness", "item1"]),
    via("hCtrl", ["output", "control0"], 3, 8, lane(4), ["witness", "control"]),
    via("hTpl", ["spend", "template"], 4, 9, lane(5), ["signed", "template"]),
    via("hOut", ["funding", "outpoint"], 5, 9, lane(6), ["signed", "prevout0"]),
    via("hVal", ["funding", "value"], 5, 9, lane(7), ["signed", "value0"]),
  ];
  nodes.push(...hops.flatMap((h) => h.nodes));

  const edges: Edge[] = [
    // the grant: Alice's key signs Bob's key
    wire("alice", "sk", "grant", "secret"),
    wire("bob", "pubkey", "grant", "message"),
    // the leaf names both of them
    wire("bob", "pubkey", "leaf", "ref_bob"),
    wire("alice", "pubkey", "leaf", "ref_alice"),
    wire("leaf", "script", "output", "leaf0"),
    wire("output", "spk", "spend", "out0_spk"),
    ...hops.flatMap((h) => h.edges),
    // the leaf is needed three times over: to take the digest, to satisfy
    // the witness, and to run
    wire(hops[0].last, "out", "witness", "script"),
    wire(hops[0].last, "out", "check", "script"),
    wire(hops[1].last, "out", "check", "prevout_spk"),
    // the spend, step by step
    wire("spend", "template", "unsigned", "template"),
    wire("funding", "outpoint", "unsigned", "prevout0"),
    wire("funding", "value", "unsigned", "value0"),
    wire("unsigned", "hex", "sighash", "tx"),
    wire("sighash", "sighash", "bob_sig", "message"),
    wire("sighash", "type_byte", "bob_sig", "hash_type"),
    wire("bob_sig", "sig", "witness", "item0"),
    wire("witness", "witness", "signed", "witness0"),
    wire("witness", "witness", "check", "witness"),
    wire("signed", "hex", "check", "tx"),
  ];

  nodes.unshift(
    around("c_grant", "The grant: Alice signs Bob's key", "teal", nodes, ["alice", "bob", "grant"]),
    around("c_coin", "The coin, and the one spend it allows", "amber", nodes, ["leaf", "output", "spend"]),
    // Its own box rather than a lonely second row inside the one above:
    // a single node under three leaves two columns of nothing.
    around("c_funded", "Paid in", "slate", nodes, ["funding"]),
    around("c_spend", "Months later: Bob signs, and shows the grant", "blue", nodes, [
      "unsigned",
      "sighash",
      "bob_sig",
      "witness",
      "signed",
      "check",
    ]),
  );
  return { nodes, edges, network: "signet", ruleset: "csfs", select: "leaf" };
}

// --- oracle payout ------------------------------------------------------------

/** An oracle signs an outcome, and that signature is the only key to a
 *  payout that was fixed when the coin was funded. CSFS says who attested,
 *  CTV says where the money goes. */
export function oracle(): Example {
  // The shortest spend in the set, and that is the point: the attestation
  // is the entire witness. Everything else was settled before the coin
  // existed, so the oracle can only decide whether the payout happens,
  // never where it goes.
  const nodes: FlowNode[] = [];

  // --- the oracle, and the sentence it is willing to sign ---------------
  const key = node("oracle", "key", col(0), 0, { secret: "33".repeat(32) });
  const outcome = node("outcome", "text", col(0), 231, { value: "BTC-USD >= 100000 at 2026-12-31" });
  const attest = node("attestation", "sign", col(1), 0, { hash_type: 0 });
  // Not part of the spend: the same check, run outside of script, so you
  // can see that what the leaf will do is ordinary signature verification.
  const offchain = node("offchain", "verify", col(1), 291, {});

  // --- the payout, decided before anyone funds the bet ------------------
  const payout = node("payout", "template", col(2), 0, {
    version: 2,
    locktime: 0,
    nIn: 1,
    nOut: 1,
    in0_seq: 0xfffffffd,
    out0_value: 99_000,
    out0_spk: p2tr("66"),
  });
  const leaf = node("leaf", "tapscript", col(3), 0, {
    source: [
      "# Fixed before funding: the oracle",
      "# decides whether, never where.",
      "@payout OP_CTV OP_DROP",
      "@outcome        # what was attested",
      "@oracle OP_CSFS # and who attested",
    ].join("\n"),
  });
  const bet = node("bet", "taproot", col(4), 0, { nLeaves: 1 });
  const funding = node("funding", "outpoint", col(5), 0, { txid: "f".repeat(64), vout: 0, value: 100_000 });
  nodes.push(key, outcome, attest, offchain, payout, leaf, bet, funding);

  const { lane, next: BOT } = band(nodes, 7);

  // --- settling, once the oracle has spoken -----------------------------
  const wit = node("witness", "witness", col(6), BOT, { nItems: 1 });
  const settle = node("settle", "transaction", col(7), BOT, { nIn: 1, nOut: 1 });
  const run = node("check", "execute", col(8), BOT, { input_index: 0, prevout_value: 100_000 });
  nodes.push(wit, settle, run);

  const hops = [
    via("hSig", ["attestation", "sig"], 1, 6, lane(0), ["witness", "item0"]),
    via("hLeaf", ["leaf", "script"], 3, 6, lane(1), ["witness", "script"]),
    via("hCtrl", ["bet", "control0"], 4, 6, lane(2), ["witness", "control"]),
    via("hTpl", ["payout", "template"], 2, 7, lane(3), ["settle", "template"]),
    via("hOut", ["funding", "outpoint"], 5, 7, lane(4), ["settle", "prevout0"]),
    via("hVal", ["funding", "value"], 5, 7, lane(5), ["settle", "value0"]),
    via("hSpk", ["bet", "spk"], 4, 8, lane(6), ["check", "prevout_spk"]),
  ];
  nodes.push(...hops.flatMap((h) => h.nodes));

  const edges: Edge[] = [
    // the attestation: the oracle's key over the sentence itself, not a
    // hash of it, which is what BIP-348 checks
    wire("oracle", "sk", "attestation", "secret"),
    wire("outcome", "hex", "attestation", "message"),
    wire("oracle", "pubkey", "offchain", "pubkey"),
    wire("outcome", "hex", "offchain", "message"),
    wire("attestation", "sig", "offchain", "signature"),
    // the leaf names all three: where the money goes, what was said, who said it
    wire("payout", "ctv0", "leaf", "ref_payout"),
    wire("outcome", "hex", "leaf", "ref_outcome"),
    wire("oracle", "pubkey", "leaf", "ref_oracle"),
    wire("leaf", "script", "bet", "leaf0"),
    ...hops.flatMap((h) => h.edges),
    wire(hops[1].last, "out", "check", "script"),
    wire("witness", "witness", "settle", "witness0"),
    wire("witness", "witness", "check", "witness"),
    wire("settle", "hex", "check", "tx"),
  ];

  nodes.unshift(
    around("c_oracle", "The oracle, and its message", "amber", nodes, ["oracle", "outcome", "attestation", "offchain"]),
    around("c_bet", "The payout, fixed before the bet is funded", "teal", nodes, ["payout", "leaf", "bet"]),
    around("c_funded", "Paid in", "slate", nodes, ["funding"]),
    around("c_settle", "Settling: the attestation is the whole witness", "blue", nodes, ["witness", "settle", "check"]),
  );
  return { nodes, edges, network: "signet", ruleset: "ctv+csfs", select: "leaf" };
}

// --- eltoo --------------------------------------------------------------------

/** A signature that does not commit to what it spends can be rebound onto a
 *  later state. That is what makes eltoo's update path work: state N+1
 *  spends state N without anyone having pre-signed against that exact
 *  outpoint. BIP-118. */
export function eltoo(): Example {
  // The same channel as the BIP-448 example, built the older way, and laid
  // out in the same columns on purpose. Put the two side by side and the
  // only real difference is the middle of the row: a Sighash node with
  // ANYPREVOUTANYSCRIPT chosen by hand, where the other has a Template
  // Hash that names no coin by construction.
  const nodes: FlowNode[] = [];

  // --- the state ---------------------------------------------------------
  const shared = node("shared_key", "key", col(0), 0, { secret: "44".repeat(32) });
  const update = node("update", "tapscript", col(1), 0, {
    source: [
      "# 0x01 is BIP-118's key: the taproot",
      "# internal key. A signature over it",
      "# names no prevout at all.",
      "01 OP_CHECKSIG",
    ].join("\n"),
  });
  const state1 = node("state_1", "taproot", col(2), 0, { nLeaves: 1 });
  const settle = node("settlement", "template", col(3), 0, {
    version: 2,
    locktime: 0,
    nIn: 1,
    nOut: 1,
    in0_seq: 0xfffffffd,
    out0_value: 99_000,
    out0_spk: p2tr("77"),
  });
  const channel = node("channel", "outpoint", col(4), 0, { txid: "f".repeat(64), vout: 0, value: 100_000 });
  nodes.push(shared, update, state1, settle, channel);

  const { lane, next: MID } = band(nodes, 8);

  // --- the update --------------------------------------------------------
  const unsigned = node("unsigned", "transaction", col(5), MID, { nIn: 1, nOut: 1 });
  const sh = node("sighash", "sighash", col(6), MID, {
    hash_type: "ALL|ANYPREVOUTANYSCRIPT",
    input_index: 0,
    prevout_value: 100_000,
  });
  const sig = node("update_sig", "sign", col(7), MID, {});
  const wit = node("witness", "witness", col(8), MID, { nItems: 1 });
  const state2 = node("state_2", "transaction", col(9), MID, { nIn: 1, nOut: 1 });
  const run = node("check", "execute", col(10), MID, { input_index: 0, prevout_value: 100_000 });
  nodes.push(unsigned, sh, sig, wit, state2, run);

  // --- and the same signature again, against another state ---------------
  const LOW = MID + 377 + 230;
  const other = node("another_state", "outpoint", col(8), LOW, { txid: "ab".repeat(32), vout: 7, value: 100_000 });
  const rebound = node("rebound", "transaction", col(9), LOW, { nIn: 1, nOut: 1 });
  const runAgain = node("check_rebound", "execute", col(10), LOW, { input_index: 0, prevout_value: 100_000 });
  nodes.push(other, rebound, runAgain);

  // The leaf and the output's scriptPubKey are each wanted at three
  // columns, so they ride a bus and are tapped where they are needed.
  const leafBus = bus("bLeaf", ["update", "script"], 1, lane(1), [
    { col: 6, to: ["sighash", "leaf"] },
    { col: 8, to: ["witness", "script"] },
    { col: 10, to: ["check", "script"] },
  ]);
  const spkBus = bus("bSpk", ["state_1", "spk"], 2, lane(2), [
    { col: 6, to: ["sighash", "prevout_spk"] },
    { col: 10, to: ["check", "prevout_spk"] },
  ]);
  const hops = [
    via("hTpl", ["settlement", "template"], 3, 5, lane(0), ["unsigned", "template"]),
    via("hKey", ["shared_key", "sk"], 0, 7, lane(3), ["update_sig", "secret"]),
    via("hCtrl", ["state_1", "control0"], 2, 8, lane(4), ["witness", "control"]),
    via("hTpl2", ["settlement", "template"], 3, 9, lane(5), ["state_2", "template"]),
    via("hOut", ["channel", "outpoint"], 4, 9, lane(6), ["state_2", "prevout0"]),
    via("hVal", ["channel", "value"], 4, 9, lane(7), ["state_2", "value0"]),
  ];
  nodes.push(...leafBus.nodes, ...spkBus.nodes, ...hops.flatMap((h) => h.nodes));

  const edges: Edge[] = [
    wire("shared_key", "pubkey", "state_1", "internal_key"),
    wire("shared_key", "sk", "update_sig", "secret"),
    wire("update", "script", "state_1", "leaf0"),
    wire("state_1", "spk", "settlement", "out0_spk"),
    ...leafBus.edges,
    ...spkBus.edges,
    ...hops.flatMap((h) => h.edges),
    // the last tap of each bus serves the row below as well, straight down
    // the gap between columns
    wire(leafBus.ids[2], "out", "check_rebound", "script"),
    wire(spkBus.ids[1], "out", "check_rebound", "prevout_spk"),
    wire(hops[3].last, "out", "rebound", "template"),
    // the first spend
    wire("channel", "outpoint", "unsigned", "prevout0"),
    wire("channel", "value", "unsigned", "value0"),
    wire("unsigned", "hex", "sighash", "tx"),
    wire("sighash", "sighash", "update_sig", "message"),
    // the hash type rides along, so the signature carries the byte that
    // says which of the transaction it committed to
    wire("sighash", "type_byte", "update_sig", "hash_type"),
    wire("update_sig", "sig", "witness", "item0"),
    wire("witness", "witness", "state_2", "witness0"),
    wire("state_2", "hex", "check", "tx"),
    wire("witness", "witness", "check", "witness"),
    // the same witness, a different state
    wire("another_state", "outpoint", "rebound", "prevout0"),
    wire("another_state", "value", "rebound", "value0"),
    wire("witness", "witness", "rebound", "witness0"),
    wire("witness", "witness", "check_rebound", "witness"),
    wire("rebound", "hex", "check_rebound", "tx"),
  ];

  nodes.unshift(
    around("c_state", "The state: one leaf, keyed 0x01", "violet", nodes, [
      "shared_key",
      "update",
      "state_1",
      "settlement",
    ]),
    around("c_open", "Paid in", "slate", nodes, ["channel"]),
    around("c_update", "The update: ANYPREVOUTANYSCRIPT, chosen by hand", "blue", nodes, [
      "unsigned",
      "sighash",
      "update_sig",
      "witness",
      "state_2",
      "check",
    ]),
    around("c_rebind", "The same signature, a different state", "green", nodes, [
      "another_state",
      "rebound",
      "check_rebound",
    ]),
  );
  return { nodes, edges, network: "signet", ruleset: "apo", select: "update" };
}

// --- merkle inclusion ---------------------------------------------------------

/** OP_CAT lets a script rebuild a value from parts, so a script can check a
 *  merkle proof: fold the leaf and its siblings back into a root it already
 *  commits to. The building block under most CAT constructions. */
export function merkle(): Example {
  // A tree built left to right in the open, and then one branch of it
  // rebuilt inside a script. The concat sits halfway between the two
  // hashes it joins, so the merge is the shape of the thing, and what
  // follows keeps its top line.
  const nodes: FlowNode[] = [];

  // --- the tree, built off chain -----------------------------------------
  const aliceLeaf = node("alice_leaf", "text", col(0), 0, { value: "alice:50000" });
  const hashAlice = node("hash_alice", "sha256", col(1), 0, {});
  const bobLeaf = node("bob_leaf", "text", col(0), 231, { value: "bob:50000" });
  const hashBob = node("hash_bob", "sha256", col(1), 231, {});
  const MERGE = 190 - 103; // halfway down the pair of hashes
  const pair = node("pair", "concat", col(2), MERGE, { nParts: 2 });
  const root = node("root", "sha256", col(3), MERGE, {});

  // --- and the only part of it the chain ever sees ------------------------
  const proof = node("proof", "tapscript", col(4), MERGE, {
    source: [
      "# Rebuild the root from the leaf and",
      "# its sibling. OP_CAT joins them the",
      "# way the tree was built.",
      "OP_SHA256 OP_SWAP OP_CAT OP_SHA256",
      "@root OP_EQUAL",
    ].join("\n"),
  });
  const committed = node("committed", "taproot", col(5), MERGE, { nLeaves: 1 });
  const spend = node("spend", "template", col(6), MERGE, {
    version: 2,
    locktime: 0,
    nIn: 1,
    nOut: 1,
    in0_seq: 0xfffffffd,
    out0_value: 99_000,
    out0_spk: p2tr("88"),
  });
  const funding = node("funding", "outpoint", col(7), MERGE, { txid: "f".repeat(64), vout: 0, value: 100_000 });
  nodes.push(aliceLeaf, hashAlice, bobLeaf, hashBob, pair, root, proof, committed, spend, funding);

  const { lane, next: BOT } = band(nodes, 8);

  // --- claiming: show the leaf and the sibling, and let the script fold ---
  const wit = node("witness", "witness", col(8), BOT, { nItems: 2 });
  const claim = node("claim", "transaction", col(9), BOT, { nIn: 1, nOut: 1 });
  const run = node("check", "execute", col(10), BOT, { input_index: 0, prevout_value: 100_000 });
  nodes.push(wit, claim, run);

  // The proof script is wanted twice, so it rides a bus.
  const leafBus = bus("bProof", ["proof", "script"], 4, lane(3), [
    { col: 8, to: ["witness", "script"] },
    { col: 10, to: ["check", "script"] },
  ]);
  const hops = [
    // the witness carries the sibling first, then the leaf: bottom of the
    // stack is what the script reaches last
    via("hSib", ["hash_bob", "hash"], 1, 8, lane(0), ["witness", "item0"]),
    via("hLeaf", ["alice_leaf", "hex"], 0, 8, lane(1), ["witness", "item1"]),
    via("hCtrl", ["committed", "control0"], 5, 8, lane(2), ["witness", "control"]),
    via("hTpl", ["spend", "template"], 6, 9, lane(4), ["claim", "template"]),
    via("hOut", ["funding", "outpoint"], 7, 9, lane(5), ["claim", "prevout0"]),
    via("hVal", ["funding", "value"], 7, 9, lane(6), ["claim", "value0"]),
    via("hSpk", ["committed", "spk"], 5, 10, lane(7), ["check", "prevout_spk"]),
  ];
  nodes.push(...leafBus.nodes, ...hops.flatMap((h) => h.nodes));

  const edges: Edge[] = [
    wire("alice_leaf", "hex", "hash_alice", "data"),
    wire("bob_leaf", "hex", "hash_bob", "data"),
    wire("hash_alice", "hash", "pair", "part0"),
    wire("hash_bob", "hash", "pair", "part1"),
    wire("pair", "hex", "root", "data"),
    wire("root", "hash", "proof", "ref_root"),
    wire("proof", "script", "committed", "leaf0"),
    wire("committed", "spk", "spend", "out0_spk"),
    ...leafBus.edges,
    ...hops.flatMap((h) => h.edges),
    wire("witness", "witness", "claim", "witness0"),
    wire("witness", "witness", "check", "witness"),
    wire("claim", "hex", "check", "tx"),
  ];

  nodes.unshift(
    around("c_tree", "The tree, built in the open", "teal", nodes, [
      "alice_leaf",
      "hash_alice",
      "bob_leaf",
      "hash_bob",
      "pair",
      "root",
    ]),
    around("c_committed", "Only the root is committed", "amber", nodes, ["proof", "committed", "spend"]),
    around("c_funded", "Paid in", "slate", nodes, ["funding"]),
    around("c_claim", "The claim: her leaf and his hash", "blue", nodes, ["witness", "claim", "check"]),
  );
  return { nodes, edges, network: "signet", ruleset: "cat", select: "proof" };
}

// --- BIP-448 -----------------------------------------------------------------

/** BIP-448 is three opcodes together: OP_TEMPLATEHASH (BIP-446),
 *  OP_CHECKSIGFROMSTACK (BIP-348) and OP_INTERNALKEY (BIP-349). Put in a
 *  row they are a rebindable signature, and the whole leaf is three bytes.
 *  The template hash names everything about the spend except which coin it
 *  spends, so a signature over it carries onto a later state. This is what
 *  the APO example does, without needing a new key type. */
export function bip448(): Example {
  // The whole claim is that one signature spends two different coins, so
  // the second spend sits directly under the first: same columns, same
  // order, one row down. Read the two rows against each other and the only
  // difference is which outpoint went in.
  const nodes: FlowNode[] = [];

  // --- the state ---------------------------------------------------------
  const shared = node("shared_key", "key", col(0), 0, { secret: "44".repeat(32) });
  const update = node("update", "tapscript", col(1), 0, {
    source: [
      "# TEMPLATEHASH names the spend,",
      "# INTERNALKEY names the key, and",
      "# CSFS checks one signature over both.",
      "OP_TEMPLATEHASH OP_INTERNALKEY",
      "OP_CHECKSIGFROMSTACK",
    ].join("\n"),
  });
  const state1 = node("state_1", "taproot", col(2), 0, { nLeaves: 1 });
  const settle = node("settlement", "template", col(3), 0, {
    version: 2,
    locktime: 0,
    nIn: 1,
    nOut: 1,
    in0_seq: 0xfffffffd,
    out0_value: 99_000,
    out0_spk: p2tr("99"),
  });
  const channel = node("channel", "outpoint", col(4), 0, { txid: "f".repeat(64), vout: 0, value: 100_000 });
  nodes.push(shared, update, state1, settle, channel);

  const { lane, next: MID } = band(nodes, 8);

  // --- the update: sign a hash that names no coin ------------------------
  const unsigned = node("unsigned", "transaction", col(5), MID, { nIn: 1, nOut: 1 });
  const th = node("template_hash", "template_hash", col(6), MID, { input_index: 0 });
  const sig = node("update_sig", "sign", col(7), MID, { hash_type: 0 });
  const wit = node("witness", "witness", col(8), MID, { nItems: 1 });
  const state2 = node("state_2", "transaction", col(9), MID, { nIn: 1, nOut: 1 });
  const run = node("check", "execute", col(10), MID, { input_index: 0, prevout_value: 100_000 });
  nodes.push(unsigned, th, sig, wit, state2, run);

  // --- and the same signature again, against another coin ----------------
  // Directly below its twin, so the pair reads as one comparison. The
  // wires reaching it come down the gaps between columns.
  // Clear enough that this box's own label, which floats above it, does
  // not land on the row it is being compared with.
  const LOW = MID + 355 + 230;
  const other = node("another_coin", "outpoint", col(8), LOW, { txid: "ab".repeat(32), vout: 3, value: 100_000 });
  const rebound = node("rebound", "transaction", col(9), LOW, { nIn: 1, nOut: 1 });
  const runAgain = node("check_rebound", "execute", col(10), LOW, { input_index: 0, prevout_value: 100_000 });
  nodes.push(other, rebound, runAgain);

  // The leaf is wanted at two columns and the scriptPubKey at one, so they
  // ride buses and are tapped where needed, the same as the eltoo example
  // beside it.
  const leafBus = bus("bLeaf", ["update", "script"], 1, lane(2), [
    { col: 8, to: ["witness", "script"] },
    { col: 10, to: ["check", "script"] },
  ]);
  const spkBus = bus("bSpk", ["state_1", "spk"], 2, lane(7), [{ col: 10, to: ["check", "prevout_spk"] }]);
  const hops = [
    via("hTpl", ["settlement", "template"], 3, 5, lane(0), ["unsigned", "template"]),
    via("hKey", ["shared_key", "sk"], 0, 7, lane(1), ["update_sig", "secret"]),
    via("hCtrl", ["state_1", "control0"], 2, 8, lane(3), ["witness", "control"]),
    via("hTpl2", ["settlement", "template"], 3, 9, lane(4), ["state_2", "template"]),
    via("hOut", ["channel", "outpoint"], 4, 9, lane(5), ["state_2", "prevout0"]),
    via("hVal", ["channel", "value"], 4, 9, lane(6), ["state_2", "value0"]),
  ];
  nodes.push(...leafBus.nodes, ...spkBus.nodes, ...hops.flatMap((h) => h.nodes));

  const edges: Edge[] = [
    wire("shared_key", "pubkey", "state_1", "internal_key"),
    wire("update", "script", "state_1", "leaf0"),
    wire("state_1", "spk", "settlement", "out0_spk"),
    ...leafBus.edges,
    ...spkBus.edges,
    ...hops.flatMap((h) => h.edges),
    // the last tap of each bus serves the row below as well, straight down
    // the gap between columns
    wire(leafBus.ids[1], "out", "check_rebound", "script"),
    wire(spkBus.ids[0], "out", "check_rebound", "prevout_spk"),
    wire(hops[3].last, "out", "rebound", "template"),
    // the first spend
    wire("channel", "outpoint", "unsigned", "prevout0"),
    wire("channel", "value", "unsigned", "value0"),
    wire("unsigned", "hex", "template_hash", "tx"),
    // CSFS takes the bare 64 bytes: this signature was never made over a
    // transaction, so it carries no hash type byte
    wire("template_hash", "hash", "update_sig", "message"),
    wire("update_sig", "sig", "witness", "item0"),
    wire("witness", "witness", "state_2", "witness0"),
    wire("state_2", "hex", "check", "tx"),
    wire("witness", "witness", "check", "witness"),
    // the same witness, a different coin
    wire("another_coin", "outpoint", "rebound", "prevout0"),
    wire("another_coin", "value", "rebound", "value0"),
    wire("witness", "witness", "rebound", "witness0"),
    wire("witness", "witness", "check_rebound", "witness"),
    wire("rebound", "hex", "check_rebound", "tx"),
  ];

  nodes.unshift(
    around("c_state", "The state: three opcodes", "violet", nodes, ["shared_key", "update", "state_1", "settlement"]),
    around("c_open", "Paid in", "slate", nodes, ["channel"]),
    around("c_update", "The update: one signature over a hash that names no coin", "blue", nodes, [
      "unsigned",
      "template_hash",
      "update_sig",
      "witness",
      "state_2",
      "check",
    ]),
    around("c_rebind", "The same signature, a different coin", "green", nodes, [
      "another_coin",
      "rebound",
      "check_rebound",
    ]),
  );
  return { nodes, edges, network: "signet", ruleset: "bip448", select: "update" };
}

// --- hot and cold -------------------------------------------------------------

/** Two leaves and no covenant opcode at all: the taproot shape everything
 *  else here is built on top of. The hot key spends whenever it likes; the
 *  cold key spends only after a relative delay, so a stolen hot key still
 *  leaves a window. */
export function hotcold(): Example {
  const nodes: FlowNode[] = [];

  const hot = node("hot", "key", col(0), 0, { secret: "11".repeat(32) });
  const cold = node("cold", "key", col(0), 231, { secret: "22".repeat(32) });

  const hotLeaf = node("hot_leaf", "tapscript", col(1), 0, {
    source: ["# Spend now, with the hot key.", "@hot OP_CHECKSIG"].join("\n"),
  });
  const coldLeaf = node("cold_leaf", "tapscript", col(1), 231, {
    source: [
      "# Recovery: the cold key, but only",
      "# 144 blocks after the coin lands.",
      "144 OP_CHECKSEQUENCEVERIFY OP_DROP",
      "@cold OP_CHECKSIG",
    ].join("\n"),
  });

  const output = node("output", "taproot", col(2), 0, { nLeaves: 2 });
  const spend = node("spend", "template", col(3), 0, {
    version: 2,
    locktime: 0,
    nIn: 1,
    nOut: 1,
    // The cold leaf's OP_CSV reads this. One below 144 and the spend is
    // rejected, which is the whole point of the delay.
    in0_seq: 144,
    out0_value: 99_000,
    out0_spk: p2tr("55"),
  });
  const funding = node("funding", "outpoint", col(4), 0, { txid: "f".repeat(64), vout: 0, value: 100_000 });
  nodes.push(hot, cold, hotLeaf, coldLeaf, output, spend, funding);

  const { lane, next: BOT } = band(nodes, 7);

  // The cold path, one node per step. The hot leaf is built and committed
  // to but not taken here: a spend takes one leaf, and this is the one
  // worth watching, because it is the one the timelock gates.
  const unsigned = node("unsigned", "transaction", col(4), BOT, { nIn: 1, nOut: 1 });
  const sighash = node("sighash", "sighash", col(5), BOT, {
    hash_type: "DEFAULT",
    input_index: 0,
    prevout_value: 100_000,
  });
  const coldSig = node("cold_sig", "sign", col(6), BOT, {});
  const wit = node("witness", "witness", col(7), BOT, { nItems: 1 });
  const signed = node("signed", "transaction", col(8), BOT, { nIn: 1, nOut: 1 });
  const run = node("check", "execute", col(9), BOT, { input_index: 0 });
  nodes.push(unsigned, sighash, coldSig, wit, signed, run);

  const hops = [
    via("hLeaf", ["cold_leaf", "script"], 1, 5, lane(0), ["sighash", "leaf"]),
    via("hSpk", ["output", "spk"], 2, 5, lane(1), ["sighash", "prevout_spk"]),
    via("hCold", ["cold", "sk"], 0, 6, lane(2), ["cold_sig", "secret"]),
    // Leaf 1 is the cold one, so this is the control block that proves it.
    via("hCtrl", ["output", "control1"], 2, 7, lane(3), ["witness", "control"]),
    via("hTpl", ["spend", "template"], 3, 8, lane(4), ["signed", "template"]),
    via("hOut", ["funding", "outpoint"], 4, 8, lane(5), ["signed", "prevout0"]),
    via("hVal", ["funding", "value"], 4, 8, lane(6), ["signed", "value0"]),
  ];
  nodes.push(...hops.flatMap((h) => h.nodes));

  const edges: Edge[] = [
    wire("hot", "pubkey", "hot_leaf", "ref_hot"),
    wire("cold", "pubkey", "cold_leaf", "ref_cold"),
    wire("hot_leaf", "script", "output", "leaf0"),
    wire("cold_leaf", "script", "output", "leaf1"),
    ...hops.flatMap((h) => h.edges),
    wire(hops[0].last, "out", "witness", "script"),
    wire(hops[0].last, "out", "check", "script"),
    wire(hops[1].last, "out", "check", "prevout_spk"),
    wire("spend", "template", "unsigned", "template"),
    wire("funding", "outpoint", "unsigned", "prevout0"),
    wire("funding", "value", "unsigned", "value0"),
    wire("unsigned", "hex", "sighash", "tx"),
    wire("sighash", "sighash", "cold_sig", "message"),
    wire("sighash", "type_byte", "cold_sig", "hash_type"),
    wire("cold_sig", "sig", "witness", "item0"),
    wire("witness", "witness", "signed", "witness0"),
    wire("witness", "witness", "check", "witness"),
    wire("signed", "hex", "check", "tx"),
    // What the coin is worth comes from the coin itself, off the same lane
    // that carries it into the transaction, not from a number typed in
    // again here. An amount rule cannot be checked against an amount
    // nobody supplied, and a zero would satisfy one.
    wire(hops[6].last, "out", "check", "prevout_value"),
  ];

  nodes.unshift(
    around("c_keys", "Two keys, one warm and one in a safe", "teal", nodes, ["hot", "cold"]),
    around("c_coin", "One address, two ways out", "amber", nodes, ["hot_leaf", "cold_leaf", "output", "spend"]),
    around("c_funded", "Paid in", "slate", nodes, ["funding"]),
    around("c_spend", "Recovery: the cold key, once the delay is up", "blue", nodes, [
      "unsigned",
      "sighash",
      "cold_sig",
      "witness",
      "signed",
      "check",
    ]),
  );

  return { nodes, edges, network: "signet", ruleset: "none" };
}

// --- OP_VAULT ---------------------------------------------------------------

/** A vault under BIP-345, and the transaction that announces a withdrawal
 *  from it.
 *
 *  The coin sits in a two-leaf taproot. One leaf recovers it to a
 *  scriptPubKey named only by its hash, so the destination stays private
 *  until it is used. The other starts a withdrawal: OP_VAULT rebuilds the
 *  same taptree with its own leaf replaced by a timelocked CTV script, and
 *  fails unless an output of this transaction is exactly that. The delay and
 *  the destination are therefore chosen now, long after the coin arrived,
 *  and the recovery leaf comes through the rewrite untouched, which is what
 *  leaves the withdrawal interruptible while it waits.
 */
export function opvault(): Example {
  const nodes: FlowNode[] = [];

  const cold = node("cold", "key", col(0), 0, { secret: "22".repeat(32) });
  const coldLeaf = node("cold_leaf", "tapscript", col(1), 0, {
    source: ["# Where a recovery sends the coin.", "@cold OP_CHECKSIG"].join("\n"),
  });
  const coldOut = node("cold_out", "taproot", col(2), 0, { nLeaves: 1 });
  // The commitment covers the length as well as the bytes, so a scriptPubKey
  // cannot be passed off as a longer one that starts the same way. 0x22 is
  // the CompactSize for the 34 bytes of a P2TR output.
  const commit = node("commit", "concat", col(3), 0, { nParts: 2, part0: "22" });
  const rhash = node("rhash", "tagged_hash", col(4), 0, { tag: "VaultRecoverySPK" });
  const recoverLeaf = node("recover_leaf", "tapscript", col(5), 0, {
    source: [
      "# Recovery, at any time. The vault",
      "# knows the destination by hash only.",
      "@rhash OP_VAULT_RECOVER",
    ].join("\n"),
  });

  const triggerLeaf = node("trigger_leaf", "tapscript", col(5), 300, {
    source: [
      "# Start a withdrawal. The two items",
      "# above are the spend delay and the",
      "# count of leaf-update pushes; the",
      "# third is the body they prefix,",
      "# OP_CSV OP_DROP OP_CTV as data.",
      "10 2 <b275b3> OP_VAULT",
    ].join("\n"),
  });

  const vaultOut = node("vault_out", "taproot", col(6), 60, { nLeaves: 2 });

  const withdraw = node("withdraw", "template", col(3), 640, {
    version: 2,
    locktime: 0,
    nIn: 1,
    nOut: 1,
    // The rewritten leaf's OP_CSV reads this, so the withdrawal cannot
    // confirm until the delay has run.
    in0_seq: 10,
    out0_value: 99_000,
    out0_spk: p2tr("55"),
  });
  const rewrittenLeaf = node("rewritten_leaf", "tapscript", col(4), 640, {
    source: [
      "# What OP_VAULT rewrites the trigger",
      "# leaf into: the same body, now with",
      "# the withdrawal's hash in front.",
      "@ctv 10 OP_CHECKSEQUENCEVERIFY OP_DROP",
      "OP_CHECKTEMPLATEVERIFY",
    ].join("\n"),
  });
  const triggeredOut = node("triggered_out", "taproot", col(6), 640, { nLeaves: 2 });

  const triggerTpl = node("trigger_tpl", "template", col(7), 640, {
    version: 2,
    locktime: 0,
    nIn: 1,
    nOut: 1,
    in0_seq: 0xfffffffd,
    // The whole value has to come through: OP_VAULT will not let a trigger
    // spend any of it to fees.
    out0_value: 100_000,
    out0_spk: "",
  });
  const funding = node("funding", "outpoint", col(7), 980, { txid: "f".repeat(64), vout: 0, value: 100_000 });
  const wit = node("witness", "witness", col(8), 240, {
    nItems: 4,
    // Bottom to top: no revault, so an amount of zero and an index of -1;
    // then the output the trigger lands in; then the hash to lock in.
    item0: "",
    item1: "81",
    item2: "",
  });
  const triggerTx = node("trigger_tx", "transaction", col(8), 640, { nIn: 1, nOut: 1 });
  const run = node("check", "execute", col(9), 420, { input_index: 0 });

  nodes.push(
    cold,
    coldLeaf,
    coldOut,
    commit,
    rhash,
    recoverLeaf,
    triggerLeaf,
    vaultOut,
    withdraw,
    rewrittenLeaf,
    triggeredOut,
    triggerTpl,
    funding,
    wit,
    triggerTx,
    run,
  );

  const edges: Edge[] = [
    wire("cold", "pubkey", "cold_leaf", "ref_cold"),
    wire("cold_leaf", "script", "cold_out", "leaf0"),
    wire("cold_out", "spk", "commit", "part1"),
    wire("commit", "hex", "rhash", "data"),
    wire("rhash", "hash", "recover_leaf", "ref_rhash"),
    wire("recover_leaf", "script", "vault_out", "leaf0"),
    wire("trigger_leaf", "script", "vault_out", "leaf1"),
    wire("withdraw", "ctv0", "rewritten_leaf", "ref_ctv"),
    // The same recovery leaf, in both trees. That it is the same is the
    // whole reason a triggered withdrawal can still be stopped.
    wire("recover_leaf", "script", "triggered_out", "leaf0"),
    wire("rewritten_leaf", "script", "triggered_out", "leaf1"),
    wire("triggered_out", "spk", "trigger_tpl", "out0_spk"),
    wire("trigger_tpl", "template", "trigger_tx", "template"),
    wire("funding", "outpoint", "trigger_tx", "prevout0"),
    wire("funding", "value", "trigger_tx", "value0"),
    wire("withdraw", "ctv0", "witness", "item3"),
    wire("trigger_leaf", "script", "witness", "script"),
    // Leaf 1 is the trigger leaf, so this is the control block that proves
    // it, and the merkle path in it is what the rewrite is folded back up.
    wire("vault_out", "control1", "witness", "control"),
    wire("witness", "witness", "trigger_tx", "witness0"),
    wire("trigger_leaf", "script", "check", "script"),
    wire("witness", "witness", "check", "witness"),
    wire("trigger_tx", "hex", "check", "tx"),
    wire("vault_out", "spk", "check", "prevout_spk"),
    wire("funding", "value", "check", "prevout_value"),
  ];

  nodes.unshift(
    around("c_cold", "The destination a recovery pays, and its commitment", "teal", nodes, [
      "cold",
      "cold_leaf",
      "cold_out",
      "commit",
      "rhash",
    ]),
    around("c_vault", "The vault: recover at any time, or start a withdrawal", "amber", nodes, [
      "recover_leaf",
      "trigger_leaf",
      "vault_out",
    ]),
    around("c_after", "What the withdrawal must become", "blue", nodes, [
      "withdraw",
      "rewritten_leaf",
      "triggered_out",
    ]),
    around("c_trigger", "Announcing it", "slate", nodes, ["trigger_tpl", "funding", "witness", "trigger_tx", "check"]),
  );

  return { nodes, edges, network: "signet", ruleset: "ctv+vault" };
}

// --- recursive covenant with OP_CAT ------------------------------------------

/** A coin that can only ever be spent back into itself.
 *
 *  OP_CAT alone cannot see the transaction. What it can do is rebuild the
 *  message this input's signature is made over, out of pieces the witness
 *  hands it, and then prove the rebuild is honest: one signature is checked
 *  twice, once by CSFS against the message the script assembled and once by
 *  CHECKSIG against the real one. Passing both means they are the same
 *  bytes, so every piece the witness supplied is the truth.
 *
 *  One of those pieces is this input's own scriptPubKey, because
 *  ANYONECANPAY puts it in the message verbatim. The script builds the
 *  output it will accept out of that same piece. The only spend that
 *  validates is one paying back to the script now running, and to its own
 *  output in turn, forever. */
export function recursive(): Example {
  // One message becomes six pieces, and the six become one message again.
  // The layout is that sentence: a fan out from the Sighash into a column
  // of pieces, then a fan back in to the witness.
  //
  // The column is in the order the script pops them, top to bottom, which
  // is also the order the witness carries them. Because it matches, the
  // six wires into the witness are parallel and none crosses another. Any
  // other arrangement of that column tangles them.
  const nodes: FlowNode[] = [];

  // --- what the covenant needs to know before it exists ------------------
  const tagText = node("tag", "text", col(0), 0, { value: "TapSighash" });
  const key = node("covenant_key", "key", col(0), 231, { secret: "66".repeat(32) });
  const tagHash = node("tag_hash", "sha256", col(1), 0, {});
  const tagPrefix = node("tag_prefix", "concat", col(2), 0, { nParts: 2 });

  // --- the covenant ------------------------------------------------------
  const covenant = node("covenant", "tapscript", col(3), 0, {
    source: [
      "# Rebuild the message this signature",
      "# signs, from the witness pieces.",
      "OP_TOALTSTACK          # tail",
      "# The spk is kept twice over: once as",
      "# the output we pay to, once as the",
      "# input we spend. That is the loop.",
      "OP_DUP OP_TOALTSTACK",
      "OP_SWAP OP_TOALTSTACK  # middle",
      "# Bytes 10 to 41 of the message are",
      "# the outputs hash. The script works",
      "# it out rather than be handed it.",
      "OP_CAT OP_SHA256",
      "OP_CAT",
      "OP_FROMALTSTACK OP_CAT",
      "OP_FROMALTSTACK OP_CAT",
      "OP_FROMALTSTACK OP_CAT",
      "@tag OP_SWAP OP_CAT OP_SHA256",
      "# One signature, checked twice:",
      "# against what we built, and against",
      "# the real one. Both pass only if",
      "# they are the same bytes.",
      "OP_2DUP @key OP_CSFS OP_VERIFY",
      "OP_DROP",
      "OP_1NEGATE OP_CAT      # 0x81",
      "@key OP_CHECKSIG",
    ].join("\n"),
  });
  const vault = node("vault", "taproot", col(4), 0, { nLeaves: 1 });
  const next = node("next", "template", col(5), 0, {
    version: 2,
    locktime: 0,
    nIn: 1,
    nOut: 1,
    in0_seq: 0xfffffffd,
    out0_value: 99_000,
  });
  const funding = node("funding", "outpoint", col(6), 0, { txid: "f".repeat(64), vout: 0, value: 100_000 });
  nodes.push(tagText, key, tagHash, tagPrefix, covenant, vault, next, funding);

  const { lane, next: BOT } = band(nodes, 8);

  // --- the six pieces, in the order the script pops them -----------------
  const PITCH = 291; // a slice plus a gap
  const signature = node("signature", "sign", col(9), BOT + 0 * PITCH, { hash_type: 0 });
  const head = node("head", "slice", col(9), BOT + 1 * PITCH, { name: "version_locktime", offset: 0, length: 10 });
  const outValue = node("out_value", "le_bytes", col(9), BOT + 2 * PITCH, { value: 99_000, width: 8 });
  const middle = node("middle", "slice", col(9), BOT + 3 * PITCH, { name: "outpoint_amount", offset: 42, length: 45 });
  const ownSpk = node("own_spk", "slice", col(9), BOT + 4 * PITCH, { offset: 87, length: 35 });
  const tail = node("tail", "slice", col(9), BOT + 5 * PITCH, { name: "sequence_and_leaf", offset: 122, length: 41 });
  nodes.push(signature, head, outValue, middle, ownSpk, tail);

  // Everything either side of that column is centred on it, so the fan out
  // and the fan back in are the same shape.
  const TALL = 5 * PITCH + 235;
  const mid = (h: number) => BOT + Math.round((TALL - h) / 2);
  const unsigned = node("unsigned", "transaction", col(7), mid(320), { nIn: 1, nOut: 1 });
  const message = node("message", "sighash", col(8), mid(377), {
    hash_type: "ALL|ANYONECANPAY",
    input_index: 0,
    prevout_value: 100_000,
  });
  const wit = node("witness", "witness", col(10), mid(360), { nItems: 6 });
  const spendTx = node("spend_tx", "transaction", col(11), mid(320), { nIn: 1, nOut: 1 });
  const run = node("check", "execute", col(12), mid(355), { input_index: 0, prevout_value: 100_000 });
  nodes.push(unsigned, message, wit, spendTx, run);

  const scriptBus = bus("bScript", ["covenant", "script"], 3, lane(1), [
    { col: 8, to: ["message", "leaf"] },
    { col: 10, to: ["witness", "script"] },
    { col: 12, to: ["check", "script"] },
  ]);
  const spkBus = bus("bSpk", ["vault", "spk"], 4, lane(2), [
    { col: 8, to: ["message", "prevout_spk"] },
    { col: 12, to: ["check", "prevout_spk"] },
  ]);
  const hops = [
    via("hTpl", ["next", "template"], 5, 7, lane(0), ["unsigned", "template"]),
    via("hSk", ["covenant_key", "sk"], 0, 9, lane(3), ["signature", "secret"]),
    via("hCtrl", ["vault", "control0"], 4, 10, lane(4), ["witness", "control"]),
    via("hTpl2", ["next", "template"], 5, 11, lane(5), ["spend_tx", "template"]),
    via("hOut", ["funding", "outpoint"], 6, 11, lane(6), ["spend_tx", "prevout0"]),
    via("hVal", ["funding", "value"], 6, 11, lane(7), ["spend_tx", "value0"]),
  ];
  nodes.push(...scriptBus.nodes, ...spkBus.nodes, ...hops.flatMap((h) => h.nodes));

  const edges: Edge[] = [
    // the BIP-340 tagged-hash prefix is the tag's hash, twice over
    wire("tag", "hex", "tag_hash", "data"),
    wire("tag_hash", "hash", "tag_prefix", "part0"),
    wire("tag_hash", "hash", "tag_prefix", "part1"),
    wire("tag_prefix", "hex", "covenant", "ref_tag"),
    wire("covenant_key", "pubkey", "covenant", "ref_key"),
    wire("covenant", "script", "vault", "leaf0"),
    // the output it pays to is the coin it is already sitting in
    wire("vault", "spk", "next", "out0_spk"),
    ...scriptBus.edges,
    ...spkBus.edges,
    ...hops.flatMap((h) => h.edges),
    wire("funding", "outpoint", "unsigned", "prevout0"),
    wire("funding", "value", "unsigned", "value0"),
    wire("unsigned", "hex", "message", "tx"),
    // the fan out: one message, cut four ways, plus the digest to sign
    wire("message", "sighash", "signature", "message"),
    wire("message", "preimage", "head", "data"),
    wire("message", "preimage", "middle", "data"),
    wire("message", "preimage", "own_spk", "data"),
    wire("message", "preimage", "tail", "data"),
    // the fan back in, in the order the script will pop them
    wire("signature", "sig", "witness", "item0"),
    wire("head", "hex", "witness", "item1"),
    wire("out_value", "hex", "witness", "item2"),
    wire("middle", "hex", "witness", "item3"),
    wire("own_spk", "hex", "witness", "item4"),
    wire("tail", "hex", "witness", "item5"),
    wire("witness", "witness", "spend_tx", "witness0"),
    wire("witness", "witness", "check", "witness"),
    wire("spend_tx", "hex", "check", "tx"),
  ];

  nodes.unshift(
    around("c_needs", "The tag and the key", "slate", nodes, ["tag", "covenant_key", "tag_hash", "tag_prefix"]),
    around("c_cov", "It pays only to itself", "rose", nodes, ["covenant", "vault", "next"]),
    around("c_funded", "Paid in", "slate", nodes, ["funding"]),
    around("c_msg", "The message it signs", "blue", nodes, ["unsigned", "message"]),
    around("c_pieces", "Four slices, and the outputs it works out itself", "amber", nodes, [
      "signature",
      "head",
      "out_value",
      "middle",
      "own_spk",
      "tail",
    ]),
    around("c_back", "Put back together", "green", nodes, ["witness", "spend_tx", "check"]),
  );
  return { nodes, edges, network: "signet", ruleset: "csfs+cat", select: "covenant" };
}

// --- a covenant with CAT alone -----------------------------------------------

/** A covenant that needs no CHECKSIGFROMSTACK.
 *
 *  BIP-340 verification is s*G = R + e*P. Force both R and P to the
 *  generator, which is to say choose the secret keys k = x = 1, and it
 *  collapses to s = 1 + e. The signature is then a function of the message
 *  alone, so a script that can concatenate can build one: hash the message
 *  it is willing to allow, add one, and put R in front. CHECKSIG checks
 *  that manufactured signature against the real transaction, and the two
 *  agree only if the message the script built is the message the
 *  transaction makes. Nothing signs anything.
 *
 *  Adding one to a 32-byte number is not something Script can do. So the
 *  spender grinds the transaction until the challenge ends in 0x01, and the
 *  addition becomes a last byte swapped from 01 to 02. That costs about 256
 *  tries, which is why the locktime here is 131 rather than 0. */
export function catonly(): Example {
  const nodes: FlowNode[] = [];
  const DEST = p2tr("a");

  // --- the constants the script is assembled from ------------------------
  const sigTag = node("sighash_tag", "text", col(0), 0, { value: "TapSighash" });
  const chTag = node("challenge_tag", "text", col(0), 210, { value: "BIP0340/challenge" });
  // Secret key 1, so the public key is the generator itself. That is the
  // whole trick: P = G, and R = G, so s = 1 + e.
  const one = node("secret_one", "key", col(0), 420, { secret: "00".repeat(31) + "01" });
  const payValue = node("pay_value", "le_bytes", col(0), 700, { value: 99_000, width: 8 });

  const sigTagHash = node("sighash_tag_hash", "sha256", col(1), 0, {});
  const chTagHash = node("challenge_tag_hash", "sha256", col(1), 210, {});
  // value || length || scriptPubKey is one CTxOut, and its hash is what
  // BIP-341 puts in the message as sha_outputs.
  const oneOutput = node("one_output", "concat", col(1), 700, { nParts: 2, part1: "22" + DEST });

  const sigPrefix = node("sighash_prefix", "concat", col(2), 0, { nParts: 2 });
  const chPrefix = node("challenge_prefix", "concat", col(2), 210, { nParts: 4 });
  const pinned = node("pinned_output", "sha256", col(2), 700, {});

  const covenant = node("covenant", "tapscript", col(3), 0, {
    source: [
      "# Rebuild the message this input signs.",
      "@sigtag OP_SWAP OP_CAT",
      "# Bytes 138 to 169 are the outputs",
      "# hash. It comes from here, not from",
      "# the spender. That is the covenant.",
      "@pinned OP_CAT",
      "OP_SWAP OP_CAT OP_SHA256",
      "# The BIP-340 challenge over it, with",
      "# R and P both set to the generator.",
      "@challenge OP_SWAP OP_CAT OP_SHA256",
      "# Ground to end in 01, so s = e + 1 is",
      "# a byte swapped, not an addition.",
      "OP_OVER OP_1 OP_CAT OP_EQUALVERIFY",
      "OP_2 OP_CAT",
      "# The signature is R || s, and R is G.",
      "@G OP_SWAP OP_CAT",
      "@G OP_CHECKSIG",
    ].join("\n"),
  });
  const coin = node("coin", "taproot", col(4), 0, { nLeaves: 1 });
  const spend = node("spend", "template", col(5), 0, {
    version: 2,
    locktime: 131,
    nIn: 1,
    nOut: 1,
    in0_seq: 0xfffffffd,
    out0_value: 99_000,
    out0_spk: DEST,
  });
  const funding = node("funding", "outpoint", col(6), 0, { txid: "ab".repeat(32), vout: 0, value: 100_000 });
  nodes.push(
    sigTag,
    chTag,
    one,
    payValue,
    sigTagHash,
    chTagHash,
    oneOutput,
    sigPrefix,
    chPrefix,
    pinned,
    covenant,
    coin,
    spend,
    funding,
  );

  const { lane, next: BOT } = band(nodes, 6);

  // --- the message, and the three pieces the witness carries -------------
  const PITCH = 291;
  const eHead = node("e_head", "slice", col(10), BOT + 0 * PITCH, { name: "challenge_head", offset: 0, length: 31 });
  const head = node("head", "slice", col(10), BOT + 1 * PITCH, { name: "before_outputs", offset: 0, length: 138 });
  const tail = node("tail", "slice", col(10), BOT + 2 * PITCH, { name: "after_outputs", offset: 170, length: 42 });
  nodes.push(eHead, head, tail);

  const TALL = 2 * PITCH + 235;
  const mid = (h: number) => BOT + Math.round((TALL - h) / 2);
  const unsigned = node("unsigned", "transaction", col(7), mid(320), { nIn: 1, nOut: 1 });
  const message = node("message", "sighash", col(8), mid(377), {
    hash_type: "DEFAULT",
    input_index: 0,
    prevout_value: 100_000,
  });
  const challenge = node("challenge", "concat", col(9), mid(200), { nParts: 2 });
  const e = node("e", "sha256", col(9), mid(200) + 260, {});
  const wit = node("witness", "witness", col(11), mid(300), { nItems: 3 });
  const spendTx = node("spend_tx", "transaction", col(12), mid(320), { nIn: 1, nOut: 1 });
  const run = node("check", "execute", col(13), mid(355), { input_index: 0, prevout_value: 100_000 });
  nodes.push(unsigned, message, challenge, e, wit, spendTx, run);

  const scriptBus = bus("bScript", ["covenant", "script"], 3, lane(0), [
    { col: 8, to: ["message", "leaf"] },
    { col: 11, to: ["witness", "script"] },
    { col: 13, to: ["check", "script"] },
  ]);
  const spkBus = bus("bSpk", ["coin", "spk"], 4, lane(1), [
    { col: 8, to: ["message", "prevout_spk"] },
    { col: 13, to: ["check", "prevout_spk"] },
  ]);
  const chBus = bus("bCh", ["challenge_prefix", "hex"], 2, lane(2), [{ col: 9, to: ["challenge", "part0"] }]);
  const hops = [
    via("hTpl", ["spend", "template"], 5, 7, lane(3), ["unsigned", "template"]),
    via("hCtrl", ["coin", "control0"], 4, 11, lane(4), ["witness", "control"]),
    via("hTpl2", ["spend", "template"], 5, 12, lane(5), ["spend_tx", "template"]),
  ];
  nodes.push(...scriptBus.nodes, ...spkBus.nodes, ...chBus.nodes, ...hops.flatMap((h) => h.nodes));

  const edges: Edge[] = [
    wire("sighash_tag", "hex", "sighash_tag_hash", "data"),
    wire("sighash_tag_hash", "hash", "sighash_prefix", "part0"),
    wire("sighash_tag_hash", "hash", "sighash_prefix", "part1"),
    wire("challenge_tag", "hex", "challenge_tag_hash", "data"),
    wire("challenge_tag_hash", "hash", "challenge_prefix", "part0"),
    wire("challenge_tag_hash", "hash", "challenge_prefix", "part1"),
    // R and P, both the generator, both from the key whose secret is 1
    wire("secret_one", "pubkey", "challenge_prefix", "part2"),
    wire("secret_one", "pubkey", "challenge_prefix", "part3"),
    wire("pay_value", "hex", "one_output", "part0"),
    wire("one_output", "hex", "pinned_output", "data"),
    wire("sighash_prefix", "hex", "covenant", "ref_sigtag"),
    wire("pinned_output", "hash", "covenant", "ref_pinned"),
    wire("challenge_prefix", "hex", "covenant", "ref_challenge"),
    wire("secret_one", "pubkey", "covenant", "ref_G"),
    wire("covenant", "script", "coin", "leaf0"),
    ...scriptBus.edges,
    ...spkBus.edges,
    ...chBus.edges,
    ...hops.flatMap((h) => h.edges),
    wire("funding", "outpoint", "unsigned", "prevout0"),
    wire("funding", "value", "unsigned", "value0"),
    wire("unsigned", "hex", "message", "tx"),
    // the challenge the script will rebuild, and its first 31 bytes
    wire("message", "sighash", "challenge", "part1"),
    wire("challenge", "hex", "e", "data"),
    wire("e", "hash", "e_head", "data"),
    wire("message", "preimage", "head", "data"),
    wire("message", "preimage", "tail", "data"),
    // in the order the script pops them
    wire("e_head", "hex", "witness", "item0"),
    wire("tail", "hex", "witness", "item1"),
    wire("head", "hex", "witness", "item2"),
    wire("witness", "witness", "spend_tx", "witness0"),
    wire("witness", "witness", "check", "witness"),
    wire("funding", "outpoint", "spend_tx", "prevout0"),
    wire("funding", "value", "spend_tx", "value0"),
    wire("spend_tx", "hex", "check", "tx"),
  ];

  nodes.unshift(
    around("c_const", "Two tags and a key whose secret is 1", "slate", nodes, [
      "sighash_tag",
      "challenge_tag",
      "secret_one",
      "sighash_tag_hash",
      "challenge_tag_hash",
      "sighash_prefix",
      "challenge_prefix",
    ]),
    around("c_pin", "The only output it will accept", "amber", nodes, ["pay_value", "one_output", "pinned_output"]),
    around("c_cov", "No CSFS anywhere", "rose", nodes, ["covenant", "coin", "spend"]),
    around("c_funded", "Paid in", "slate", nodes, ["funding"]),
    around("c_msg", "The message, and the challenge over it", "blue", nodes, ["unsigned", "message", "challenge", "e"]),
    around("c_pieces", "Either side of the outputs hash, and the challenge", "amber", nodes, [
      "e_head",
      "head",
      "tail",
    ]),
    around("c_back", "Put back together", "green", nodes, ["witness", "spend_tx", "check"]),
  );
  return { nodes, edges, network: "signet", ruleset: "cat", select: "covenant" };
}

export interface ExampleEntry {
  /** Shown in the menu. */
  label: string;
  /** The tab name the document opens under. */
  name: string;
  /** One line on what it shows, for the menu's second column. */
  blurb: string;
  /** The proposals it needs, which is how the menu groups them. */
  needs: string;
  build: () => Example;
}

/** Grouped by what has to be deployed for the example to mean anything,
 *  in the order someone meeting covenants would want to read them:
 *  commit to a transaction, then check a signature, then rebind one, then
 *  take the transaction apart. */
export const EXAMPLE_GROUPS: Array<{ title: string; keys: string[] }> = [
  { title: "Taproot, with no covenant at all", keys: ["hotcold"] },
  { title: "CTV · commit to the next transaction", keys: ["vault", "pool"] },
  { title: "OP_VAULT · rewrite one leaf of the tree", keys: ["opvault"] },
  { title: "CSFS · check a signature over a message", keys: ["delegation", "oracle"] },
  { title: "Rebindable signatures", keys: ["bip448", "eltoo"] },
  { title: "CAT · take bytes apart and put them back", keys: ["merkle", "catonly", "recursive"] },
];

export const EXAMPLES: Record<string, ExampleEntry> = {
  hotcold: {
    label: "Hot and cold",
    name: "hot and cold",
    blurb: "Two leaves, one spendable now and one after a delay",
    needs: "none",
    build: hotcold,
  },
  opvault: {
    label: "OP_VAULT",
    name: "op_vault",
    blurb: "Announce a withdrawal by rewriting one leaf, and keep the way to stop it",
    needs: "BIP-345",
    build: opvault,
  },
  vault: {
    label: "Vault",
    name: "vault",
    blurb: "A delay to notice a theft, and a cold path to stop it",
    needs: "BIP-119",
    build: vault,
  },
  pool: {
    label: "Congestion control",
    name: "congestion control",
    blurb: "One transaction commits to a tree of payouts",
    needs: "BIP-119",
    build: pool,
  },
  delegation: {
    label: "Delegation",
    name: "delegation",
    blurb: "Hand someone one spend without handing them your key",
    needs: "BIP-348",
    build: delegation,
  },
  oracle: {
    label: "Oracle payout",
    name: "oracle payout",
    blurb: "An attestation decides whether, never where",
    needs: "BIP-348 + BIP-119",
    build: oracle,
  },
  bip448: {
    label: "Rebindable state",
    name: "bip448",
    blurb: "Three opcodes, and the update leaf is three bytes",
    needs: "BIP-448",
    build: bip448,
  },
  eltoo: {
    label: "Rebindable state, the older way",
    name: "eltoo",
    blurb: "The same channel, using an ANYPREVOUT key type",
    needs: "BIP-118",
    build: eltoo,
  },
  merkle: {
    label: "Merkle proof",
    name: "merkle proof",
    blurb: "A script folds a leaf back into a root it commits to",
    needs: "BIP-347",
    build: merkle,
  },
  catonly: {
    label: "CAT-only covenant",
    name: "cat-only covenant",
    blurb: "A covenant with no CSFS, using a signature the script builds itself",
    needs: "BIP-347",
    build: catonly,
  },
  recursive: {
    label: "Recursive covenant",
    name: "recursive covenant",
    blurb: "A coin that can only be spent back into itself",
    needs: "BIP-347 + BIP-348",
    build: recursive,
  },
};
