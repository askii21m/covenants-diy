// The assembler records a byte offset for every instruction it emits and
// the interpreter reports one for every step it runs. The panel joins the
// two to put a step on the word that produced it, so they have to agree
// exactly, through a reference, a comment, and a push split over two lines.
import { beforeAll, describe, expect, it } from "vitest";
import { readFile } from "node:fs/promises";
import init, * as wasm from "../pkg/covenants.js";

const RULESET = {
  ctv: true,
  csfs: true,
  cat: true,
  apo: true,
  templatehash: true,
  internalkey: true,
  paircommit: true,
  txhash: true,
  ccv: false,
  vault: false,
};

beforeAll(async () => {
  await init({ module_or_path: await readFile(new URL("../pkg/covenants_bg.wasm", import.meta.url)) });
});

describe("spans", () => {
  it("put every executed step on the word that produced it", () => {
    const source = "OP_1\n@k OP_DROP # a comment\nOP_PUSHBYTES_2\n0102 OP_DROP";
    const v = wasm.assemble({ source, bindings: { k: "ab" }, ruleset: RULESET });
    expect(v.error == null).toBe(true);
    const t = wasm.execute({ script: v.script!, stack: [], ruleset: RULESET });
    expect(t.success).toBe(true);
    expect(t.steps.length).toBeGreaterThanOrEqual(5);
    const byOffset = new Map(v.spans.map((s) => [s.offset, s]));
    for (const s of t.steps) {
      // A trace may end on a step past the last instruction, which no word made.
      if (s.op === "<end>") continue;
      expect(byOffset.has(s.position), `step ${s.index} at byte ${s.position}`).toBe(true);
    }
    expect(v.spans.map((s) => [s.line, s.word, s.end_line, s.end_word])).toEqual([
      [0, 0, 0, 0],
      [1, 0, 1, 0],
      [1, 1, 1, 1],
      [2, 0, 3, 0],
      [3, 1, 3, 1],
    ]);
  });

  it("are empty when nothing assembled", () => {
    const v = wasm.assemble({ source: "OP_NOPE", ruleset: RULESET });
    expect(v.error != null).toBe(true);
    expect(v.spans).toEqual([]);
  });
});
