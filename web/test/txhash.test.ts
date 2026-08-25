// OP_TXHASH end to end, through the built wasm rather than the Rust API.
// The Rust suite already checks the hash against BIP-346's 150 published
// vectors; what this covers is the wiring between them: that the name
// assembles to the right byte, that the byte is classified against the
// deployment rather than as a generic OP_SUCCESSx, and that an active
// deployment actually executes instead of passing the script outright.
import { beforeAll, describe, expect, it } from "vitest";
import { readFile } from "node:fs/promises";
import init, * as wasm from "../pkg/covenants.js";

const ALL = {
  ctv: true,
  csfs: true,
  cat: true,
  apo: true,
  templatehash: true,
  internalkey: true,
  paircommit: true,
  txhash: true,
};
const OFF = { ...ALL, txhash: false };

/** A taproot output over one leaf, and the control block that spends it. */
function spend(source: string) {
  const leaf = wasm.assemble({ source, bindings: {}, ruleset: ALL });
  const tr = wasm.taproot_output({ network: "signet", leaves: [leaf.script!] });
  return { leaf, tr };
}

function run(source: string, ruleset: typeof ALL) {
  const { leaf, tr } = spend(source);
  return wasm.execute({
    script: leaf.script!,
    stack: [],
    ruleset,
    input_index: 0,
    prevouts: [{ value: 100000, script_pubkey: tr.script_pubkey }],
    control_block: tr.control_blocks[0],
  });
}

describe("OP_TXHASH", () => {
  beforeAll(async () => {
    await init({ module_or_path: await readFile(new URL("../pkg/covenants_bg.wasm", import.meta.url)) });
  });

  it("assembles and disassembles by name", () => {
    expect(wasm.assemble({ source: "OP_TXHASH", bindings: {}, ruleset: ALL }).script).toBe("bd");
    expect(wasm.disassemble("bd")).toBe("OP_TXHASH");
  });

  it("is enforced when active and open when not", () => {
    expect(wasm.classify("bd", ALL).status).toBe("enforced");
    const off = wasm.classify("bd", OFF);
    expect(off.status).toBe("open");
    expect(off.inactive).toEqual(["OP_TXHASH"]);
  });

  it("pushes 32 bytes for the empty selector", () => {
    const trace = run("<> OP_TXHASH", ALL);
    const stack = trace.steps[trace.steps.length - 1].stack;
    expect(stack).toHaveLength(1);
    expect(stack[0]).toHaveLength(64);
  });

  it("gives different hashes for different selectors", () => {
    const a = run("<0100> OP_TXHASH", ALL).steps.at(-1)!.stack[0];
    const b = run("<0200> OP_TXHASH", ALL).steps.at(-1)!.stack[0];
    expect(a).not.toBe(b);
  });

  it("surfaces an invalid selector as an error", () => {
    // Leading 9 inputs, of one.
    const trace = run("<01020900> OP_TXHASH", ALL);
    expect(trace.steps.at(-1)!.error).toContain("SelectionOutOfBounds");
  });

  // The bug this opcode shipped with: BIP-342 scans for OP_SUCCESSx before
  // executing, and an active deployment has to be carved out of that scan
  // or the script passes without ever running the opcode.
  it("executes rather than passing the script outright", () => {
    const active = run("<0100> OP_TXHASH OP_DROP OP_0", ALL);
    expect(active.success).toBe(false);
    const inactive = run("<0100> OP_TXHASH OP_DROP OP_0", OFF);
    expect(inactive.success).toBe(true);
  });
});
