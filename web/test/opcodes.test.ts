// The catalog comes from the engine and the prose from the frontend, so
// they can drift. These hold them together.
import { beforeAll, describe, expect, it } from "vitest";
import { readFile } from "node:fs/promises";
import init, { opcodes, assemble } from "../pkg/covenants.js";
import { DESCRIPTIONS } from "../src/script/opcodes";

beforeAll(async () => {
  await init({ module_or_path: await readFile(new URL("../pkg/covenants_bg.wasm", import.meta.url)) });
});

describe("the opcode catalog", () => {
  it("offers only words that assemble, to the byte it claims", () => {
    const bad: string[] = [];
    for (const o of opcodes().opcodes) {
      for (const w of [o.name, o.alias].filter(Boolean) as string[]) {
        const r = assemble({ source: w });
        if (r.error) bad.push(`${w}: ${r.error.message}`);
        else if (parseInt(r.script.slice(0, 2), 16) !== o.byte) bad.push(`${w}: assembles to ${r.script.slice(0, 2)}, catalog says ${o.byte.toString(16)}`);
      }
    }
    expect(bad).toEqual([]);
  });

  it("describes every opcode it offers", () => {
    const missing = opcodes().opcodes.filter((o) => !DESCRIPTIONS[o.name]).map((o) => o.name);
    expect(missing).toEqual([]);
  });

  it("describes nothing it does not offer", () => {
    const names = new Set(opcodes().opcodes.map((o) => o.name));
    expect(Object.keys(DESCRIPTIONS).filter((n) => !names.has(n))).toEqual([]);
  });

  it("marks the traps: OP_SUCCESSx and what tapscript rejects", () => {
    const byName = new Map(opcodes().opcodes.map((o) => [o.name, o]));
    expect(byName.get("OP_CAT")?.status).toBe("covenant");
    expect(byName.get("OP_MUL")?.status).toBe("success");
    expect(byName.get("OP_CHECKMULTISIG")?.status).toBe("disallowed");
    expect(byName.get("OP_CHECKSIGADD")?.status).toBe("ok");
    expect(byName.get("OP_CHECKTEMPLATEVERIFY")?.deployment).toBe("ctv");
  });
});
