// The wasm core. Loaded once; every node's compute calls a pure function.
import init, * as wasm from "../pkg/covenants.js";

export type Ruleset = wasm.Ruleset;
export const wasmReady = init();
// Consumers await this and see any failure. Marking it handled here keeps
// node, where the tests load the module themselves from an explicit path
// and this call has no URL to fetch, from reporting an unhandled rejection.
void wasmReady.catch(() => {});
export { wasm };

const R = (f: Partial<Ruleset>): Ruleset =>
  ({ ctv: false, csfs: false, cat: false, apo: false, templatehash: false, internalkey: false, ...f });

export const RULESETS: Record<string, { label: string; hint?: string; flags: Ruleset }> = {
  none:   { label: "none", hint: "mainnet consensus today", flags: R({}) },
  ctv:    { label: "CTV",                    flags: R({ ctv: true }) },
  letter: { label: "CTV + CSFS",             flags: R({ ctv: true, csfs: true }) },
  cat:    { label: "CAT",                    flags: R({ cat: true }) },
  apo:    { label: "APO",                    flags: R({ apo: true }) },
  // BIP-448 is exactly these three: OP_TEMPLATEHASH, CHECKSIGFROMSTACK
  // and OP_INTERNALKEY.
  bip448: { label: "BIP-448", hint: "OP_TEMPLATEHASH + OP_CHECKSIGFROMSTACK + OP_INTERNALKEY", flags: R({ templatehash: true, csfs: true, internalkey: true }) },
  catall: { label: "CAT + CSFS",             flags: R({ cat: true, csfs: true }) },
  all:    { label: "everything", hint: "every proposal here at once, as inquisition runs them", flags: R({ ctv: true, csfs: true, cat: true, apo: true, templatehash: true, internalkey: true }) },
};

// Signet and regtest only. None of these covenants is deployed anywhere
// else, so a mainnet address out of this tool could only ever be a coin
// sent somewhere it cannot be spent from. The engine still knows mainnet;
// the editor will not hand you one.
export const NETWORKS = ["signet", "regtest"] as const;
export type Network = (typeof NETWORKS)[number];
