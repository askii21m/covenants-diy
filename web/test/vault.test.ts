// BIP-345 OP_VAULT and OP_VAULT_RECOVER end to end, through the built wasm.
// The Rust suite checks the leaf rewrite against a tree rust-bitcoin builds
// independently; this covers the wiring, and the one thing only a real vault
// shows: that the tree the opcode expects is the tree this tool builds when
// asked for the same leaves.
import { beforeAll, describe, expect, it } from "vitest";
import { readFile } from "node:fs/promises";
import init, * as wasm from "../pkg/covenants.js";

const BASE = {
  ctv: true,
  csfs: true,
  cat: true,
  apo: true,
  templatehash: true,
  internalkey: true,
  paircommit: true,
  txhash: true,
};
const VAULT = { ...BASE, ccv: false, vault: true };
const OFF = { ...BASE, ccv: false, vault: false };

/** `OP_CHECKSEQUENCEVERIFY OP_DROP OP_CHECKTEMPLATEVERIFY`, the BIP's own
 *  example of a leaf-update body, pushed as data rather than run. */
const BODY = "b275b3";
const DELAY = 10;
const VALUE = 100_000;
/** Stands in for the withdrawal's BIP-119 hash, which is chosen at trigger
 *  time and locked in by the rewrite. */
const CTV_HASH = "cd".repeat(32);

const asm = (source: string) => {
  const r = wasm.assemble({ source, bindings: {}, ruleset: VAULT });
  if (!r.script) throw new Error(`${source}: ${r.error}`);
  return r.script;
};

/** A scriptPubKey the vault can name as its recovery destination. */
function recoveryDestination() {
  const spk = wasm.taproot_output({ network: "signet", leaves: [asm("OP_TRUE")] }).script_pubkey;
  // The commitment covers the length as well as the bytes: 34 for a p2tr.
  return { spk, hash: wasm.tagged_hash("VaultRecoverySPK", "22" + spk) };
}

function vault() {
  const recovery = recoveryDestination();
  const recoverLeaf = asm(`<${recovery.hash}> OP_VAULT_RECOVER`);
  const triggerLeaf = asm(`${DELAY} 2 <${BODY}> OP_VAULT`);
  const rewrittenLeaf = asm(`<${CTV_HASH}> ${DELAY} OP_CHECKSEQUENCEVERIFY OP_DROP OP_CHECKTEMPLATEVERIFY`);
  return {
    recovery,
    recoverLeaf,
    triggerLeaf,
    rewrittenLeaf,
    before: wasm.taproot_output({ network: "signet", leaves: [recoverLeaf, triggerLeaf] }),
    after: wasm.taproot_output({ network: "signet", leaves: [recoverLeaf, rewrittenLeaf] }),
  };
}

/** A one-input transaction paying the given outputs, as hex. */
function tx(outputs: Array<{ value: number; script_pubkey: string }>) {
  const t = wasm.template({ version: 2, locktime: 0, inputs: [{ sequence: 0xfffffffd }], outputs });
  return wasm.realize({ template: t.template, prevouts: [`${"f".repeat(64)}:0`], values: [VALUE] }).hex;
}

describe("OP_VAULT", () => {
  beforeAll(async () => {
    await init({ module_or_path: await readFile(new URL("../pkg/covenants_bg.wasm", import.meta.url)) });
  });

  it("assembles and disassembles by name", () => {
    expect(asm("OP_VAULT")).toBe("bb");
    expect(asm("OP_VAULT_RECOVER")).toBe("bc");
    expect(wasm.disassemble("bb", true)).toBe("OP_VAULT");
    expect(wasm.disassemble("bc")).toBe("OP_VAULT_RECOVER");
  });

  // 0xbb is BIP-443's byte too, and the bytes alone cannot say which opcode
  // was meant, so the reading follows the ruleset rather than a fixed guess.
  it("reads 0xbb as whichever of the two is deployed", () => {
    expect(wasm.disassemble("bb", false)).toBe("OP_CHECKCONTRACTVERIFY");
    expect(wasm.disassemble("bb", true)).toBe("OP_VAULT");
  });

  it("is enforced when active and open when not", () => {
    expect(wasm.classify("bb", VAULT).status).toBe("enforced");
    expect(wasm.classify("bc", VAULT).status).toBe("enforced");
    const off = wasm.classify("bc", OFF);
    expect(off.status).toBe("open");
    expect(off.inactive).toEqual(["OP_VAULT_RECOVER"]);
  });

  // The guard OP_TXHASH shipped without: BIP-342 scans for OP_SUCCESSx
  // before executing, so an active deployment has to be carved out.
  it("executes rather than passing the script outright", () => {
    const v = vault();
    const res = wasm.execute({
      script: v.triggerLeaf,
      stack: ["", "81", "", CTV_HASH],
      ruleset: VAULT,
      input_index: 0,
      tx: tx([{ value: VALUE, script_pubkey: v.before.script_pubkey }]),
      prevouts: [{ value: VALUE, script_pubkey: v.before.script_pubkey }],
      control_block: v.before.control_blocks[1],
    });
    expect(res.success).toBe(false);
    expect(res.error).toMatch(/Trigger/);
  });

  it("triggers a withdrawal into the rewritten taptree", () => {
    const v = vault();
    const res = wasm.execute({
      script: v.triggerLeaf,
      stack: ["", "81", "", CTV_HASH],
      ruleset: VAULT,
      input_index: 0,
      tx: tx([{ value: VALUE, script_pubkey: v.after.script_pubkey }]),
      prevouts: [{ value: VALUE, script_pubkey: v.before.script_pubkey }],
      control_block: v.before.control_blocks[1],
    });
    expect(res.error).toBeUndefined();
    expect(res.success).toBe(true);
    expect(res.vault_state.output_min_amount).toEqual([VALUE]);
  });

  // What makes the withdrawal interruptible: the rewrite replaces one leaf
  // and leaves the recovery leaf exactly where it was.
  it("leaves the recovery leaf spendable after the rewrite", () => {
    const v = vault();
    const res = wasm.execute({
      script: v.recoverLeaf,
      stack: [""],
      ruleset: VAULT,
      input_index: 0,
      tx: tx([{ value: VALUE, script_pubkey: v.recovery.spk }]),
      prevouts: [{ value: VALUE, script_pubkey: v.after.script_pubkey }],
      control_block: v.after.control_blocks[0],
    });
    expect(res.error).toBeUndefined();
    expect(res.success).toBe(true);
  });

  it("recovers to the committed scriptPubKey and refuses any other", () => {
    const v = vault();
    const spend = (spk: string) =>
      wasm.execute({
        script: v.recoverLeaf,
        stack: [""],
        ruleset: VAULT,
        input_index: 0,
        tx: tx([{ value: VALUE, script_pubkey: spk }]),
        prevouts: [{ value: VALUE, script_pubkey: v.before.script_pubkey }],
        control_block: v.before.control_blocks[0],
      });
    expect(spend(v.recovery.spk).success).toBe(true);
    expect(spend(v.before.script_pubkey).success).toBe(false);
  });

  it("will not run alongside OP_CHECKCONTRACTVERIFY", () => {
    const v = vault();
    expect(() =>
      wasm.execute({
        script: v.triggerLeaf,
        stack: ["", "81", "", CTV_HASH],
        ruleset: { ...BASE, ccv: true, vault: true },
        input_index: 0,
        tx: tx([{ value: VALUE, script_pubkey: v.after.script_pubkey }]),
        prevouts: [{ value: VALUE, script_pubkey: v.before.script_pubkey }],
        control_block: v.before.control_blocks[1],
      }),
    ).toThrow(/0xbb/);
  });
});
