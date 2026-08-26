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
];
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
  all: FLAGS.map((f) => f.id),
};
const on = (ids: Array<keyof Ruleset>): Ruleset =>
  FLAGS.reduce((a, f) => ({ ...a, [f.id]: ids.includes(f.id) }), {}) as Ruleset;

export const nameOf = (flags: Ruleset): string => {
  const set = FLAGS.filter((f) => flags[f.id]).map((f) => f.id);
  return set.length ? set.join("+") : "none";
};
export const flagsOf = (ruleset: string): Ruleset => {
  if (Object.hasOwn(LEGACY, ruleset)) return on(LEGACY[ruleset]);
  const parts = ruleset.split("+");
  return parts.every((p) => FLAGS.some((f) => f.id === p)) ? on(parts as Array<keyof Ruleset>) : on([]);
};
export const isRuleset = (s: string): boolean =>
  Object.hasOwn(LEGACY, s) || s.split("+").every((p) => FLAGS.some((f) => f.id === p));
export const summaryOf = (flags: Ruleset): string => nameOf(flags);

export const NETWORKS = ["signet", "regtest", "bitcoin"] as const;
export type Network = (typeof NETWORKS)[number];
