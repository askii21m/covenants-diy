// The wasm core is not loadable under node; the store tests only use nodes
// whose compute never reaches it (comments, knots), so every call throws.
export const wasmReady = Promise.resolve();
const throwing = new Proxy(
  {},
  {
    get: () => () => {
      throw new Error("wasm is not available in tests");
    },
  },
);
export const wasm = throwing as never;

export type Ruleset = {
  ctv: boolean;
  csfs: boolean;
  cat: boolean;
  apo: boolean;
  templatehash: boolean;
  internalkey: boolean;
  paircommit: boolean;
  txhash: boolean;
  ccv: boolean;
  vault: boolean;
};

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
  { id: "vault", label: "OP_VAULT", bip: "BIP 345" },
];

const EXCLUSIVE: Array<[keyof Ruleset, keyof Ruleset]> = [["ccv", "vault"]];

export function toggle(flags: Ruleset, id: keyof Ruleset): Ruleset {
  const next = { ...flags, [id]: !flags[id] };
  if (next[id]) {
    for (const [a, b] of EXCLUSIVE) {
      if (a === id) next[b] = false;
      else if (b === id) next[a] = false;
    }
  }
  return next;
}
export const shortLabel = (id: keyof Ruleset) => String(id).toUpperCase();
export const PRESETS: Array<{ label: string; hint?: string; on: Array<keyof Ruleset> }> = [
  { label: "none", on: [] },
  { label: "CTV", on: ["ctv"] },
];

const LEGACY: Record<string, Array<keyof Ruleset>> = {
  none: [],
  ctv: ["ctv"],
  csfs: ["csfs"],
  letter: ["ctv", "csfs"],
  cat: ["cat"],
  apo: ["apo"],
  catall: ["cat", "csfs"],
  bip448: ["templatehash", "csfs", "internalkey"],
  all: ["ctv", "csfs", "cat", "apo", "templatehash", "internalkey", "paircommit", "txhash"],
};
const on = (ids: Array<keyof Ruleset>): Ruleset =>
  FLAGS.reduce((a, f) => ({ ...a, [f.id]: ids.includes(f.id) }), {}) as Ruleset;

export const nameOf = (flags: Ruleset): string => {
  const set = FLAGS.filter((f) => flags[f.id]).map((f) => f.id);
  return set.length ? set.join("+") : "none";
};
const clashes = (parts: string[]): boolean => EXCLUSIVE.some(([a, b]) => parts.includes(a) && parts.includes(b));
export const flagsOf = (ruleset: string): Ruleset => {
  if (Object.hasOwn(LEGACY, ruleset)) return on(LEGACY[ruleset]);
  const parts = ruleset.split("+");
  if (!parts.every((p) => FLAGS.some((f) => f.id === p)) || clashes(parts)) return on([]);
  return on(parts as Array<keyof Ruleset>);
};
export const isRuleset = (s: string): boolean => {
  if (Object.hasOwn(LEGACY, s)) return true;
  const parts = s.split("+");
  return parts.every((p) => FLAGS.some((f) => f.id === p)) && !clashes(parts);
};
export const summaryOf = (flags: Ruleset): string => nameOf(flags);

export const NETWORKS = ["signet", "regtest", "bitcoin"] as const;
export type Network = (typeof NETWORKS)[number];
