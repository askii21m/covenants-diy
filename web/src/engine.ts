// The wasm core. Loaded once; every node's compute calls a pure function.
import init, * as wasm from "../pkg/covenants.js";

export type Ruleset = wasm.Ruleset;
export const wasmReady = init();
// Consumers await this and see any failure. Marking it handled here keeps
// node, where the tests load the module themselves from an explicit path
// and this call has no URL to fetch, from reporting an unhandled rejection.
void wasmReady.catch(() => {});
export { wasm };

/** Every switch, in the order a header reads them. */
export const FLAGS: Array<{ id: keyof Ruleset; label: string; bip: string }> = [
  { id: "ctv", label: "OP_CHECKTEMPLATEVERIFY", bip: "BIP 119" },
  { id: "csfs", label: "OP_CHECKSIGFROMSTACK", bip: "BIP 348" },
  { id: "cat", label: "OP_CAT", bip: "BIP 347" },
  { id: "apo", label: "ANYPREVOUT", bip: "BIP 118" },
  { id: "templatehash", label: "OP_TEMPLATEHASH", bip: "BIP 446" },
  { id: "internalkey", label: "OP_INTERNALKEY", bip: "BIP 349" },
  { id: "paircommit", label: "OP_PAIRCOMMIT", bip: "BIP 442" },
  { id: "txhash", label: "OP_TXHASH", bip: "BIP 346" },
  { id: "ccv", label: "OP_CHECKCONTRACTVERIFY", bip: "BIP 443" },
];

/** Every flag off, then whatever is asked for. Built from FLAGS rather
 *  than written out, because a field left off here reads as undefined
 *  rather than false, which is not the same thing to a checkbox. */
const R = (f: Partial<Ruleset>): Ruleset =>
  ({ ...Object.fromEntries(FLAGS.map((x) => [x.id, false])), ...f }) as Ruleset;

/** Combinations that have been put forward, and the two configurations that
 *  are actually running. An opcode appears on its own only where it has been
 *  proposed that way. Nothing here ranks them. */
export const PRESETS: Array<{
  label: string;
  hint?: string;
  group: "Proposed" | "Running";
  on: Array<keyof Ruleset>;
}> = [
  { label: "CTV", hint: "BIP 119", group: "Proposed", on: ["ctv"] },
  {
    label: "CTV + CSFS",
    hint: "BIP 119 + BIP 348",
    group: "Proposed",
    on: ["ctv", "csfs"],
  },
  {
    label: "LNHANCE",
    hint: "CTV + CSFS + OP_INTERNALKEY + OP_PAIRCOMMIT",
    group: "Proposed",
    on: ["ctv", "csfs", "internalkey", "paircommit"],
  },
  {
    label: "BIP-448",
    hint: "OP_TEMPLATEHASH + CSFS + OP_INTERNALKEY",
    group: "Proposed",
    on: ["templatehash", "csfs", "internalkey"],
  },
  { label: "CAT", hint: "BIP 347", group: "Proposed", on: ["cat"] },
  { label: "APO", hint: "BIP 118", group: "Proposed", on: ["apo"] },
  { label: "TXHASH", hint: "BIP 346", group: "Proposed", on: ["txhash"] },
  { label: "CCV", hint: "BIP 443", group: "Proposed", on: ["ccv"] },
  { label: "mainnet today", hint: "none of them", group: "Running", on: [] },
  { label: "Inquisition signet", hint: "CTV, CSFS, CAT and APO", group: "Running", on: ["ctv", "csfs", "cat", "apo"] },
];

/** Names that went out in permalinks before the switches existed. A stored
 *  graph keeps working because its exact string still resolves. */
const LEGACY: Record<string, Array<keyof Ruleset>> = {
  none: [],
  ctv: ["ctv"],
  csfs: ["csfs"],
  letter: ["ctv", "csfs"],
  cat: ["cat"],
  apo: ["apo"],
  catall: ["cat", "csfs"],
  bip448: ["templatehash", "csfs", "internalkey"],
  // Frozen, not derived. A link that stored "all" meant the flags the tool
  // modelled that day; letting it track FLAGS would silently re-judge an
  // already-shared graph every time an opcode lands, and 0xbb went from
  // anyone-can-spend to enforced exactly that way.
  all: ["ctv", "csfs", "cat", "apo", "templatehash", "internalkey", "paircommit", "txhash"],
};

const on = (ids: Array<keyof Ruleset>): Ruleset => R(Object.fromEntries(ids.map((i) => [i, true])));

/** A ruleset is stored as the switches that are on, joined by "+", in the
 *  order FLAGS declares. "none" when they are all off. */
export function nameOf(flags: Ruleset): string {
  const set = FLAGS.filter((f) => flags[f.id]).map((f) => f.id);
  return set.length ? set.join("+") : "none";
}

export function flagsOf(ruleset: string): Ruleset {
  if (Object.hasOwn(LEGACY, ruleset)) return on(LEGACY[ruleset]);
  const parts = ruleset.split("+");
  const known = FLAGS.map((f) => String(f.id));
  return parts.every((p) => known.includes(p)) ? on(parts as Array<keyof Ruleset>) : on([]);
}

/** Whether a string names something this build understands, which is what
 *  decides if a link's ruleset survives or falls back. */
export const isRuleset = (s: string): boolean =>
  Object.hasOwn(LEGACY, s) || s.split("+").every((p) => FLAGS.some((f) => f.id === p));

/** What the header shows for a set of switches. */
export function summaryOf(flags: Ruleset): string {
  if (!FLAGS.some((f) => flags[f.id])) return "none";
  const preset = PRESETS.find((p) => nameOf(on(p.on)) === nameOf(flags));
  if (preset) return preset.label;
  const set = FLAGS.filter((f) => flags[f.id]);
  return set.length <= 2 ? set.map((f) => shortLabel(f.id)).join(" + ") : `${set.length} of ${FLAGS.length}`;
}

const shortLabel = (id: keyof Ruleset) =>
  ({
    ctv: "CTV",
    csfs: "CSFS",
    cat: "CAT",
    apo: "APO",
    templatehash: "TEMPLATEHASH",
    internalkey: "INTERNALKEY",
    paircommit: "PAIRCOMMIT",
    txhash: "TXHASH",
    ccv: "CCV",
  })[id];

export const NETWORKS = ["signet", "regtest"] as const;
export type Network = (typeof NETWORKS)[number];
