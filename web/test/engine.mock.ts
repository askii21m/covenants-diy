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
export const RULESETS: Record<
  string,
  { label: string; flags: { ctv: boolean; csfs: boolean; cat: boolean; apo: boolean } }
> = {
  none: { label: "none", flags: { ctv: false, csfs: false, cat: false, apo: false } },
  letter: { label: "CTV + CSFS", flags: { ctv: true, csfs: true, cat: false, apo: false } },
};
export const NETWORKS = ["signet", "regtest", "bitcoin"] as const;
export type Network = (typeof NETWORKS)[number];
export type Ruleset = { ctv: boolean; csfs: boolean; cat: boolean; apo: boolean };
