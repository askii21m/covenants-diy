// The vault from the vision doc, built from the flat node API exactly the way
// the canvas will: each call is one node, each argument is a wire.
//   node web/smoke.mjs
import { readFile } from "node:fs/promises";
import init, { template, assemble, taproot_output, realize, execute, parse_tx, pubkey, sign_schnorr, verify_schnorr, sighash } from "./pkg/covenants.js";
await init({ module_or_path: await readFile(new URL("./pkg/covenants_bg.wasm", import.meta.url)) });

let failures = 0;
const check = (label, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  if (!ok) failures++;
  console.log(`${ok ? "ok  " : "FAIL"} ${label}${ok ? "" : `\n       got  ${JSON.stringify(got)}\n       want ${JSON.stringify(want)}`}`);
};
const p2tr = (b) => "5120" + String(b).repeat(64);
const net = "signet";

// 1-2. Templates for the leaves of the tree.
const withdraw = template({ inputs: [{ sequence: 144 }], outputs: [{ value: 98_000, script_pubkey: p2tr(1) }] });
const clawback = template({ inputs: [{ sequence: 0xfffffffd }], outputs: [{ value: 98_500, script_pubkey: p2tr(2) }] });
check("template emits one ctv per input", withdraw.ctv.length, 1);

// 3-4. Tapscripts, with @refs wired to the template hashes.
const hot = assemble({ source: "# hot\n144 OP_CHECKSEQUENCEVERIFY OP_DROP\n@withdraw OP_CHECKTEMPLATEVERIFY", bindings: { withdraw: withdraw.ctv[0] } });
const cold = assemble({ source: "@clawback OP_CTV", bindings: { clawback: clawback.ctv[0] } });
check("refs are reported", hot.refs, ["withdraw"]);
check("hot assembles", hot.error == null, true);
check("hot is enforced under the default ruleset", hot.enforcement.status, "enforced");
check("asm uses covenant names", hot.asm.endsWith("OP_CHECKTEMPLATEVERIFY"), true);
const unbound = assemble({ source: "@nothing OP_CTV" });
check("an unbound ref still reports its port", unbound.refs, ["nothing"]);
check("and says so at the word", [unbound.error.line, unbound.error.word], [0, 0]);

// 5. Taproot output for the trigger.
const trig = taproot_output({ network: net, leaves: [hot.script, cold.script] });
check("two control blocks", trig.control_blocks.length, 2);
check("signet address", trig.address.startsWith("tb1p"), true);

// 6-8. Trigger template, deposit leaf, deposit output.
const trigger = template({ inputs: [{ sequence: 0xfffffffd }], outputs: [{ value: 99_000, script_pubkey: trig.script_pubkey }] });
const depLeaf = assemble({ source: "@trigger OP_CHECKTEMPLATEVERIFY", bindings: { trigger: trigger.ctv[0] } });
const deposit = taproot_output({ network: net, leaves: [depLeaf.script] });
console.log(`deposit address  ${deposit.address}`);

// 9-11. Bind prevouts and witnesses: the Transaction nodes.
const funding = "f".repeat(64) + ":1";
const triggerTx = realize({ template: trigger.template, prevouts: [funding], witnesses: [[depLeaf.script, deposit.control_blocks[0]]], prevout_values: [100_000] });
check("trigger tx is complete", triggerTx.complete, true);
check("fee is computed", triggerTx.fee, 1000);
const withdrawTx = realize({ template: withdraw.template, prevouts: [triggerTx.outpoints[0]], witnesses: [[hot.script, trig.control_blocks[0]]] });
check("withdraw spends the trigger", withdrawTx.hex.includes(triggerTx.txid.match(/../g).reverse().join("")), true);

// 12. Execute the hot leaf against the withdraw tx.
const run = execute({ script: hot.script, tx: withdrawTx.hex, prevouts: [{ value: 99_000, script_pubkey: trig.script_pubkey }], control_block: trig.control_blocks[0] });
check("the hot path is satisfied", run.success, true);
check("five steps", run.steps.length, 5);

// Negative: a withdraw authored one block early.
const early = template({ inputs: [{ sequence: 143 }], outputs: [{ value: 98_000, script_pubkey: p2tr(1) }] });
const earlyTx = realize({ template: early.template, prevouts: [triggerTx.outpoints[0]], witnesses: [[hot.script, trig.control_blocks[0]]] });
const runEarly = execute({ script: hot.script, tx: earlyTx.hex, prevouts: [{ value: 99_000, script_pubkey: trig.script_pubkey }] });
check("one block early is rejected", runEarly.success, false);
// The timelock trips first: sequence 143 fails OP_CSV 144 before the
// template is ever compared. That is the right order and the better error.
check("and the timelock is what catches it", runEarly.error, "UnsatisfiedLocktime");

// Ruleset as a lens.
const none = { ctv: false, csfs: false, cat: false, apo: false };
const hotToday = assemble({ source: hot.asm.replace(/</g, "").replace(/>/g, ""), ruleset: none });
check("under no deployments the leaf is degraded", hotToday.enforcement.status, "degraded");
const runToday = execute({ script: hot.script, tx: withdrawTx.hex, prevouts: [{ value: 99_000, script_pubkey: trig.script_pubkey }], ruleset: none });
check("and still passes, which is the warning", runToday.success, true);

// parse round trip
const parsed = parse_tx(withdrawTx.hex);
check("parse reads the witness back", parsed.inputs[0].witness.length, 2);

// --- keys and signatures: the nodes the CSFS and APO constructions need ---
const alice = "1".repeat(64), oracle = "2".repeat(64);
const alicePk = pubkey(alice), oraclePk = pubkey(oracle);
check("pubkey is x-only", alicePk.length, 64);
const msg = "ab".repeat(32);
const sig = sign_schnorr(oracle, msg);
check("signature is 64 bytes", sig.length, 128);
check("verify accepts", verify_schnorr(oraclePk, msg, sig), true);
check("verify rejects the wrong key", verify_schnorr(alicePk, msg, sig), false);

// BIP-342 CHECKSIG: a leaf that Alice signs, through sighash -> sign -> execute.
const sigLeaf = assemble({ source: "@alice OP_CHECKSIG", bindings: { alice: alicePk } });
const sigOut = taproot_output({ network: net, leaves: [sigLeaf.script] });
const spend = template({ inputs: [{ sequence: 0xfffffffd }], outputs: [{ value: 99_000, script_pubkey: p2tr(3) }] });
const spendTx = realize({ template: spend.template, prevouts: [funding], witnesses: [[sigLeaf.script, sigOut.control_blocks[0]]], prevout_values: [100_000] });
const prev = [{ value: 100_000, script_pubkey: sigOut.script_pubkey }];
const sh = sighash({ tx: spendTx.hex, input_index: 0, prevouts: prev, hash_type: 0x00, leaf_script: sigLeaf.script });
check("default sighash uses key version 0", sh.key_version, 0);
const aliceSig = sign_schnorr(alice, sh.sighash);
const runSig = execute({ script: sigLeaf.script, stack: [aliceSig], tx: spendTx.hex, prevouts: prev, control_block: sigOut.control_blocks[0] });
check("CHECKSIG passes with the computed sighash", runSig.success, true);
const runBad = execute({ script: sigLeaf.script, stack: [sign_schnorr(oracle, sh.sighash)], tx: spendTx.hex, prevouts: prev });
check("and fails with another key", runBad.success, false);

// BIP-118: the 0x01 key is the internal key; a signature with ANYPREVOUT binds to any prevout.
const apoLeaf = assemble({ source: "01 OP_CHECKSIG" });
const apoOut = taproot_output({ network: net, internal_key: alicePk, leaves: [apoLeaf.script] });
const apoTx = realize({ template: spend.template, prevouts: [funding], witnesses: [[apoLeaf.script, apoOut.control_blocks[0]]], prevout_values: [100_000] });
const apoPrev = [{ value: 100_000, script_pubkey: apoOut.script_pubkey }];
const apoSh = sighash({ tx: apoTx.hex, input_index: 0, prevouts: apoPrev, hash_type: 0x41, leaf_script: apoLeaf.script });
check("ANYPREVOUT sighash uses key version 1", apoSh.key_version, 1);
const apoSig = sign_schnorr(alice, apoSh.sighash) + "41";
const runApo = execute({ script: apoLeaf.script, stack: [apoSig], tx: apoTx.hex, prevouts: apoPrev, control_block: apoOut.control_blocks[0], ruleset: { ctv: true, csfs: true, cat: false, apo: true } });
check("APO CHECKSIG passes under the APO ruleset", runApo.success, true);
// rebind: the same signature on a spend of a different outpoint
const otherTx = realize({ template: spend.template, prevouts: ["e".repeat(64) + ":0"], witnesses: [[apoLeaf.script, apoOut.control_blocks[0]]], prevout_values: [100_000] });
const runRebound = execute({ script: apoLeaf.script, stack: [apoSig], tx: otherTx.hex, prevouts: apoPrev, internal_key: alicePk, control_block: apoOut.control_blocks[0], ruleset: { ctv: true, csfs: true, cat: false, apo: true } });
check("and the same signature rebinds to another prevout", runRebound.success, true);

// CSFS over a variable-length message: BIP-348 does not pre-hash, so the
// oracle signs the outcome text itself.
const text = Buffer.from("BTC-USD above 100000 on 2026-12-31", "utf8").toString("hex");
const textSig = sign_schnorr(oracle, text);
check("a variable-length message signs", verify_schnorr(oraclePk, text, textSig), true);
const attest = assemble({ source: "@oracle OP_CHECKSIGFROMSTACK", bindings: { oracle: oraclePk } });
const runText = execute({ script: attest.script, stack: [textSig, text], tx: spendTx.hex, prevouts: prev });
check("and CSFS accepts it in script", runText.success, true);
const runTextBad = execute({ script: attest.script, stack: [textSig, Buffer.from("BTC-USD above 100001 on 2026-12-31", "utf8").toString("hex")], tx: spendTx.hex, prevouts: prev });
check("one character different and it fails", runTextBad.success, false);

// CSFS: the oracle signs a message; the script checks it from the stack.
const csfsLeaf = assemble({ source: "@oracle OP_CHECKSIGFROMSTACK", bindings: { oracle: oraclePk } });
const runCsfs = execute({ script: csfsLeaf.script, stack: [sig, msg], tx: spendTx.hex, prevouts: prev });
check("CSFS accepts the oracle's signature over the message", runCsfs.success, true);
const runCsfsBad = execute({ script: csfsLeaf.script, stack: [sig, "cd".repeat(32)], tx: spendTx.hex, prevouts: prev });
check("and rejects another message", runCsfsBad.success, false);

console.log(failures ? `\n${failures} FAILED` : "\nall checks passed");
process.exit(failures ? 1 : 0);
