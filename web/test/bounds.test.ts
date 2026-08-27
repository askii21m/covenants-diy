// A field that accepts a value the node cannot honour is the editor lying
// about what will happen. Two rules, and both are checked here:
//   a typed field refuses anything outside its range, rather than quietly
//   using something else;
//   a count, which is driven by buttons rather than typed, clamps into
//   range, and the ports drawn agree with the value computed with.
import { beforeAll, describe, expect, it } from "vitest";
import { readFile } from "node:fs/promises";
import init, * as wasm from "../pkg/covenants.js";
import {
  KINDS,
  outOfRange,
  count,
  COUNTS,
  MAX_MONEY,
  U32_MAX,
  I32_MAX,
  type NodeFields,
  type Value,
} from "../src/registry";
import { sanitizeFlow } from "../src/store";
import { NETWORKS } from "../src/engine";

const ctx = {
  network: "signet" as const,
  ruleset: {
    ctv: true,
    csfs: true,
    cat: true,
    apo: true,
    templatehash: true,
    internalkey: true,
    paircommit: true,
    txhash: true,
    ccv: true,
  },
};
let fixture: { leaf: string; spk: string; control: string; template: string; tx: string };

beforeAll(async () => {
  await init({ module_or_path: await readFile(new URL("../pkg/covenants_bg.wasm", import.meta.url)) });
  const leaf = wasm.assemble({ source: "OP_TRUE" }).script;
  const tro = wasm.taproot_output({ network: "signet", leaves: [leaf] });
  const tpl = wasm.template({
    inputs: [{ sequence: 0xfffffffd }],
    outputs: [{ value: 99_000, script_pubkey: "5120" + "11".repeat(32) }],
  });
  const tx = wasm.realize({ template: tpl.template, prevouts: ["f".repeat(64) + ":0"], prevout_values: [100_000] }).hex;
  fixture = { leaf, spk: tro.script_pubkey, control: tro.control_blocks[0], template: tpl.template, tx };
});

/** Inputs that make the node work, so the field under test is the only
 *  thing wrong. A wired value wins over a field, so nothing under test is
 *  wired here. */
function inputsFor(kind: string): Record<string, Value> {
  switch (kind) {
    case "template":
      return { out0_spk: "5120" + "11".repeat(32) };
    case "transaction":
      return { template: fixture.template, prevout0: "f".repeat(64) + ":0" };
    case "execute":
      return { script: fixture.leaf, tx: fixture.tx, prevout_spk: fixture.spk };
    case "sighash":
      return { tx: fixture.tx, leaf: fixture.leaf, prevout_spk: fixture.spk };
    case "template_hash":
      return { tx: fixture.tx };
    case "slice":
      return { data: "00112233" };
    case "sign":
      return { secret: "22".repeat(32), message: "ab".repeat(32) };
    case "witness":
      return { script: fixture.leaf, control: fixture.control };
    case "concat":
      return { part0: "aa", part1: "bb" };
    case "taproot":
      return { leaf0: fixture.leaf };
    case "key":
      return { secret: "22".repeat(32) };
    default:
      return {};
  }
}

function run(kind: string, data: NodeFields, wired: Record<string, Value>) {
  const K = KINDS[kind];
  const bad = outOfRange(data, wired, K.inputs(data));
  if (bad) return { status: "error" as const, message: bad };
  return K.compute(data, wired, ctx);
}

/** Every numeric port in the catalog, with the node it belongs to. */
function numericPorts(): Array<{ kind: string; id: string; label: string; min: number; max: number }> {
  const out: Array<{ kind: string; id: string; label: string; min: number; max: number }> = [];
  for (const K of Object.values(KINDS)) {
    for (const p of K.inputs({ ...K.defaults(), kind: K.kind } as NodeFields)) {
      if (p.field !== "number") continue;
      out.push({
        kind: K.kind,
        id: p.id,
        label: p.label,
        min: p.min ?? Number.NEGATIVE_INFINITY,
        max: p.max ?? Number.POSITIVE_INFINITY,
      });
    }
  }
  return out;
}

describe("numeric fields", () => {
  it("every one declares a range", () => {
    const unbounded = numericPorts().filter((p) => !Number.isFinite(p.min) || !Number.isFinite(p.max));
    expect(unbounded.map((p) => `${p.kind}.${p.id}`)).toEqual([]);
  });

  it("declares ranges Bitcoin actually allows", () => {
    const by = (kind: string, id: string) => numericPorts().find((p) => p.kind === kind && p.id === id);
    expect(by("template", "locktime")).toMatchObject({ min: 0, max: U32_MAX });
    expect(by("template", "in0_seq")).toMatchObject({ min: 0, max: U32_MAX });
    expect(by("template", "version")).toMatchObject({ max: I32_MAX });
    expect(by("template", "out0_value")).toMatchObject({ min: 0, max: MAX_MONEY });
    expect(by("outpoint", "vout")).toMatchObject({ min: 0, max: U32_MAX });
    expect(by("le_bytes", "width")).toMatchObject({ min: 1, max: 8 });
    expect(by("sign", "hash_type")).toMatchObject({ min: 0, max: 255 });
  });

  it("refuses anything outside the range, rather than quietly using something else", () => {
    const accepted: string[] = [];
    for (const p of numericPorts()) {
      const K = KINDS[p.kind];
      const wired = inputsFor(p.kind);
      if (p.id in wired) continue; // a wire wins over the field
      for (const bad of [p.min - 1, p.max + 1, p.min + 0.5]) {
        if (!Number.isFinite(bad)) continue;
        const data = { ...K.defaults(), kind: p.kind, txid: "f".repeat(64), [p.id]: bad } as NodeFields;
        const r = run(p.kind, data, wired);
        if (r.status !== "error")
          accepted.push(`${p.kind}.${p.id} took ${bad} -> ${JSON.stringify(r.outputs).slice(0, 60)}`);
      }
    }
    expect(accepted).toEqual([]);
  });

  it("holds a value that arrived over a wire to the same range", () => {
    const data = { ...KINDS.le_bytes.defaults(), kind: "le_bytes" } as NodeFields;
    const r = run("le_bytes", data, { width: 12 });
    expect(r.status).toBe("error");
    expect(r.message).toContain("above 8");
  });
});

describe("counts", () => {
  it("clamp into range, whatever the document says", () => {
    for (const [key, bounds] of Object.entries(COUNTS)) {
      for (const bad of [-1, 0, 1.5, 9_999, Number.NaN]) {
        const n = count({ [key]: bad } as unknown as NodeFields, key, bounds.min);
        expect(Number.isInteger(n), `${key}=${bad} gave ${n}`).toBe(true);
        expect(n, `${key}=${bad}`).toBeGreaterThanOrEqual(bounds.min);
        expect(n, `${key}=${bad}`).toBeLessThanOrEqual(bounds.max);
      }
    }
  });

  it("draw the ports they compute with", () => {
    for (const [kind, key] of [
      ["witness", "nItems"],
      ["concat", "nParts"],
      ["taproot", "nLeaves"],
      ["template", "nIn"],
      ["template", "nOut"],
      ["transaction", "nIn"],
    ] as const) {
      const K = KINDS[kind];
      for (const bad of [-1, 0, 1.5, 9_999]) {
        const data = { ...K.defaults(), kind, [key]: bad } as NodeFields;
        const used = count(data, key, COUNTS[key].min);
        expect(used).toBeLessThanOrEqual(COUNTS[key].max);
        // The ports drawn are the ones the count asks for, so the node and
        // the panel never disagree about how many there are.
        const drawn = K.inputs(data).filter((p) =>
          new RegExp(`^(item|part|leaf|in\\d|out\\d|prevout|witness|value)`).test(p.id),
        );
        expect(drawn.length, `${kind}.${key}=${bad} drew nothing for ${used}`).toBeGreaterThanOrEqual(used);
        // Whatever it says, it never complains that the count is out of range.
        const r = run(kind, data, inputsFor(kind));
        if (r.status === "error")
          expect(String(r.message), `${kind}.${key}=${bad}`).not.toMatch(/cannot be (below|above)/);
      }
    }
  });
});

describe("networks", () => {
  it("offers no mainnet", () => {
    // A sandbox that hands out a mainnet address is one paste away from a
    // coin sent somewhere it cannot be spent from: none of these covenants
    // is deployed there.
    expect(NETWORKS as readonly string[]).not.toContain("bitcoin");
    expect(NETWORKS as readonly string[]).not.toContain("mainnet");
    expect([...NETWORKS]).toEqual(["signet", "regtest"]);
  });

  it("makes every address a signet or regtest one", async () => {
    const leaf = wasm.assemble({ source: "OP_TRUE" }).script;
    for (const n of NETWORKS) {
      const addr = wasm.taproot_output({ network: n, leaves: [leaf] }).address;
      expect(addr.startsWith("tb1") || addr.startsWith("bcrt1"), `${n} gave ${addr}`).toBe(true);
    }
  });

  it("drops a network it does not offer, rather than keeping it", () => {
    // An old session or a hand-edited file naming mainnet falls back
    // instead of carrying it in.
    expect(sanitizeFlow({ nodes: [], network: "bitcoin" })!.network).toBeUndefined();
    expect(sanitizeFlow({ nodes: [], network: "signet" })!.network).toBe("signet");
  });
});
