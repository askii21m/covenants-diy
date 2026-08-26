// OP_CHECKCONTRACTVERIFY end to end, through the built wasm. The Rust suite
// checks the key derivation against an independent model; this covers the
// wiring: the name assembles to the right byte, the byte is classified
// against its own deployment rather than as a generic OP_SUCCESSx, and an
// active deployment executes instead of passing the script outright.
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
  ccv: true,
};
const OFF = { ...ALL, ccv: false };

function run(source: string, ruleset: typeof ALL) {
  const leaf = wasm.assemble({ source, bindings: {}, ruleset: ALL });
  const tr = wasm.taproot_output({ network: "signet", leaves: [leaf.script!] });
  return wasm.execute({
    script: leaf.script!,
    stack: [],
    ruleset,
    input_index: 0,
    prevouts: [{ value: 100000, script_pubkey: tr.script_pubkey }],
    control_block: tr.control_blocks[0],
  });
}

describe("OP_CHECKCONTRACTVERIFY", () => {
  beforeAll(async () => {
    await init({ module_or_path: await readFile(new URL("../pkg/covenants_bg.wasm", import.meta.url)) });
  });

  it("assembles and disassembles by name", () => {
    expect(wasm.assemble({ source: "OP_CHECKCONTRACTVERIFY", bindings: {}, ruleset: ALL }).script).toBe("bb");
    expect(wasm.assemble({ source: "OP_CCV", bindings: {}, ruleset: ALL }).script).toBe("bb");
    expect(wasm.disassemble("bb")).toBe("OP_CHECKCONTRACTVERIFY");
  });

  it("is enforced when active and open when not", () => {
    expect(wasm.classify("bb", ALL).status).toBe("enforced");
    const off = wasm.classify("bb", OFF);
    expect(off.status).toBe("open");
    expect(off.inactive).toEqual(["OP_CHECKCONTRACTVERIFY"]);
  });

  // The guard OP_TXHASH shipped without: BIP-342 scans for OP_SUCCESSx
  // before executing, so an active deployment has to be carved out.
  it("executes rather than passing the script outright", () => {
    // <> <0> <> <> <1> OP_CCV OP_0: the contract check fails on a mismatch,
    // and either way the script must not pass on the trailing OP_0.
    const src = "<> OP_0 <> <> OP_1 OP_CHECKCONTRACTVERIFY OP_0";
    expect(run(src, ALL).success).toBe(false);
    expect(run(src, OFF).success).toBe(true);
  });
});
