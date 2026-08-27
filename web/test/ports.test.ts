// Whether a node needs a value is not visible from the port list, so it is
// declared on the port and drawn in the row: a filled dot for one the node
// cannot compute without, hollow for one it can, half for one needed only
// sometimes. This pins the declaration, so adding a port or changing what a
// node needs has to be a deliberate edit here as well.
import { beforeAll, describe, expect, it } from "vitest";
import { readFile } from "node:fs/promises";
import init from "../pkg/covenants.js";
import { KINDS, type NodeFields } from "../src/registry";

/** Counts that give the count-driven nodes a deterministic port list. */
const SHAPES: Record<string, Partial<NodeFields>> = {
  template: { nIn: 1, nOut: 1 },
  transaction: { nIn: 1, nOut: 1 },
  taproot: { nLeaves: 1 },
  witness: { nItems: 1 },
  concat: { nParts: 2 },
  tapscript: { source: "" },
};

/** Every input a node computes without, and what makes the sometimes-needed
 *  ones necessary. Anything not listed here the node cannot do without. */
const OPTIONAL: Record<string, Record<string, true | string>> = {
  taproot: { internal_key: true },
  transaction: { witness0: true },
  witness: { item0: true },
  execute: {
    witness: true,
    tx: "if the script reads the transaction",
    prevout_value: "if an amount rule runs",
    prevout_spk: "if the script reads the coin being spent",
    control: "unless the witness already carries it",
    ccv_in: "after the first input",
    vault_in: "after the first input",
  },
  template_hash: { annex: true },
  concat: { part0: true, part1: true },
};

const fieldsFor = (kind: string) => ({ kind, ...(SHAPES[kind] ?? {}) }) as NodeFields;

describe("port requirements", () => {
  beforeAll(async () => {
    await init({ module_or_path: await readFile(new URL("../pkg/covenants_bg.wasm", import.meta.url)) });
  });

  it("declares which inputs each node computes without", () => {
    const actual: Record<string, Record<string, true | string>> = {};
    for (const [kind, k] of Object.entries(KINDS)) {
      const marked = k.inputs(fieldsFor(kind)).filter((p) => p.optional);
      if (marked.length) actual[kind] = Object.fromEntries(marked.map((p) => [p.id, p.optional!]));
    }
    expect(actual).toEqual(OPTIONAL);
  });

  // An output is produced, never supplied, so marking one says nothing and
  // would draw a dot that means something it does not.
  it("marks no output optional", () => {
    const bad: string[] = [];
    for (const [kind, k] of Object.entries(KINDS)) {
      for (const p of k.outputs(fieldsFor(kind))) if (p.optional) bad.push(`${kind}.${p.id}`);
    }
    expect(bad).toEqual([]);
  });

  // A reason is shown to a reader on hover, so it has to read as a clause
  // completing "needed ...", not as a bare flag someone typed.
  it("gives every sometimes-needed input a reason that reads as one", () => {
    const bad: string[] = [];
    for (const [kind, k] of Object.entries(KINDS)) {
      for (const p of k.inputs(fieldsFor(kind))) {
        if (typeof p.optional !== "string") continue;
        if (p.optional.length < 8 || /^[A-Z]/.test(p.optional) || p.optional.endsWith("."))
          bad.push(`${kind}.${p.id}: ${p.optional}`);
      }
    }
    expect(bad).toEqual([]);
  });
});
