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

/** The contract key for the NUMS point carrying the two bytes 0x0102, from the
 *  model the Rust suite checks its vectors against. */
const NUMS_DATA = "a108a4d3b3527695cb108074d8f5d20e091aaf76ee242d9d0f081f1cd0d3d74e";

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
    // 0xbb is OP_VAULT too, and with neither deployed both are dormant.
    expect(off.inactive).toEqual(["OP_CHECKCONTRACTVERIFY", "OP_VAULT"]);
  });

  // The guard OP_TXHASH shipped without: BIP-342 scans for OP_SUCCESSx
  // before executing, so an active deployment has to be carved out.
  it("executes rather than passing the script outright", () => {
    const src = "<0102> OP_0 <> <> OP_1 OP_CHECKCONTRACTVERIFY OP_0";
    expect(run(src, ALL).success).toBe(false);
    expect(run(src, OFF).success).toBe(true);
  });

  it("passes when the output really is the contract, and says why when it is not", () => {
    // NUMS key, data 0x01, no taptree: the contract the script names.
    const contract = "5120" + NUMS_DATA;
    const leaf = wasm.assemble({
      source: "<0102> OP_0 <> <> OP_1 OP_CHECKCONTRACTVERIFY OP_1",
      bindings: {},
      ruleset: ALL,
    });
    const tr = wasm.taproot_output({ network: "signet", leaves: [leaf.script!] });
    const tx = (spk: string) =>
      wasm.template({
        version: 2,
        locktime: 0,
        inputs: [{ sequence: 4294967293 }],
        outputs: [{ value: 90000, script_pubkey: spk }],
      }).template;
    const go = (spk: string) =>
      wasm.execute({
        script: leaf.script!,
        stack: [],
        ruleset: ALL,
        input_index: 0,
        tx: tx(spk),
        prevouts: [{ value: 100000, script_pubkey: tr.script_pubkey }],
        control_block: tr.control_blocks[0],
      });

    const ok = go(contract);
    expect(ok.error, `expected the contract to match: ${ok.error}`).toBeFalsy();
    expect(ok.success).toBe(true);
    expect(ok.final_stack).toHaveLength(1);

    // One byte different is a different contract, and it says so.
    const wrong = go(contract.slice(0, -2) + (contract.endsWith("ff") ? "ee" : "ff"));
    expect(wrong.success).toBe(false);
    expect(wrong.steps[wrong.steps.length - 1].error).toContain("CcvMismatch");
  });
});
