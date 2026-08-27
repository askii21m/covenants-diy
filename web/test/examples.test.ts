// Every example must evaluate clean: no node in error, and every Execute
// node satisfied. A broken example is the first thing a visitor sees.
import { beforeAll, describe, expect, it } from "vitest";
import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import init from "../pkg/covenants.js";
import { EXAMPLES, heightOf, shapeOf, MEASURED_HEIGHTS, minHeightFor } from "../src/examples";
import { FLAGS, shortLabel } from "../src/engine";
import { evaluate } from "../src/store";
import { KINDS } from "../src/registry";

beforeAll(async () => {
  await init({ module_or_path: await readFile(new URL("../pkg/covenants_bg.wasm", import.meta.url)) });
});

describe.each(Object.entries(EXAMPLES))("%s", (key, ex) => {
  it("evaluates with no node in error", () => {
    const f = ex.build();
    const computed = evaluate(f.nodes, f.edges, f.network, f.ruleset);
    const bad = f.nodes
      .filter((n) => computed[n.id]?.status === "error")
      .map((n) => `${n.data.name || n.id} (${n.data.kind}): ${computed[n.id]?.message}`);
    expect(bad, `${key} has nodes in error`).toEqual([]);
  });

  it("satisfies every Execute node", () => {
    const f = ex.build();
    const computed = evaluate(f.nodes, f.edges, f.network, f.ruleset);
    const runs = f.nodes.filter((n) => n.data.kind === "execute");
    expect(runs.length, `${key} should execute something`).toBeGreaterThan(0);
    for (const r of runs) {
      expect(computed[r.id]?.outputs.ok, `${key}: ${r.data.name} did not pass: ${computed[r.id]?.message}`).toBe("1");
    }
  });

  it("declares every scriptPubKey at the length its own prefix promises", () => {
    // A witness program carries its length in the byte before it. Filling one
    // by repeating a byte the wrong number of times built a 66-byte script
    // whose prefix still said 32, which every hash in the graph then committed
    // to quite happily: self-consistent, and impossible on chain.
    const f = ex.build();
    const bad: string[] = [];
    for (const n of f.nodes) {
      for (const [field, value] of Object.entries(n.data)) {
        if (!/_spk$|^spk$/.test(field) || typeof value !== "string" || !value) continue;
        const len = Number.parseInt(value.slice(2, 4), 16);
        if (!/^51/.test(value)) continue;
        const declared = 4 + len * 2;
        if (value.length !== declared) {
          bad.push(`${n.data.name || n.id}.${field}: ${value.length / 2} bytes, prefix says ${2 + len}`);
        }
      }
    }
    expect(bad, `${key} has a scriptPubKey that lies about its length`).toEqual([]);
  });

  it("reports every script as enforced under its own ruleset", () => {
    const f = ex.build();
    const computed = evaluate(f.nodes, f.edges, f.network, f.ruleset);
    const bad: string[] = [];
    for (const n of f.nodes.filter((n) => n.data.kind === "tapscript")) {
      const view = computed[n.id]?.extra as { enforcement?: { status: string; inactive: string[] } } | undefined;
      const e = view?.enforcement;
      if (!e) {
        bad.push(`${n.data.name}: no enforcement report`);
        continue;
      }
      if (e.status !== "enforced") bad.push(`${n.data.name}: ${e.status} (${e.inactive.join(", ")})`);
    }
    expect(bad, `${key} declares ruleset "${ex.build().ruleset}"`).toEqual([]);
  });

  it("wires only ports that exist", () => {
    const f = ex.build();
    const byId = new Map(f.nodes.map((n) => [n.id, n]));
    for (const e of f.edges) {
      const s = byId.get(e.source),
        t = byId.get(e.target);
      expect(s, `${key}: edge from missing node ${e.source}`).toBeDefined();
      expect(t, `${key}: edge to missing node ${e.target}`).toBeDefined();
      const sk = String(s!.data.kind),
        tk = String(t!.data.kind);
      if (sk !== "reroute")
        expect(
          KINDS[sk].outputs(s!.data).map((p) => p.id),
          `${key}: ${s!.data.name}.${e.sourceHandle}`,
        ).toContain(e.sourceHandle);
      if (tk !== "reroute")
        expect(
          KINDS[tk].inputs(t!.data).map((p) => p.id),
          `${key}: ${t!.data.name}.${e.targetHandle}`,
        ).toContain(e.targetHandle);
    }
  });
});

describe.each(Object.entries(EXAMPLES))("%s layout", (key, ex) => {
  const box = (n: { position: { x: number; y: number }; data: Record<string, unknown> }) => {
    const k = String(n.data.kind);
    const w = k === "comment" ? Number(n.data.width) : k === "reroute" ? 32 : 288;
    const h = k === "comment" ? Number(n.data.height) : k === "reroute" ? 32 : heightOf(n as never);
    return { x: n.position.x, y: n.position.y, w, h };
  };
  const hits = (a: ReturnType<typeof box>, b: ReturnType<typeof box>) =>
    a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;

  it("has no two nodes on top of each other", () => {
    const f = ex.build();
    const real = f.nodes.filter((n) => n.data.kind !== "comment");
    const bad: string[] = [];
    for (let i = 0; i < real.length; i++)
      for (let j = i + 1; j < real.length; j++) {
        if (hits(box(real[i]), box(real[j]))) bad.push(`${real[i].id} / ${real[j].id}`);
      }
    expect(bad, `${key} has overlapping nodes`).toEqual([]);
  });

  it("keeps every node either fully inside a comment or fully outside it", () => {
    const f = ex.build();
    const bad: string[] = [];
    for (const c of f.nodes.filter((n) => n.data.kind === "comment")) {
      const cb = box(c);
      for (const n of f.nodes.filter((n) => n.data.kind !== "comment")) {
        const nb = box(n);
        const inside = nb.x >= cb.x && nb.y >= cb.y && nb.x + nb.w <= cb.x + cb.w && nb.y + nb.h <= cb.y + cb.h;
        if (hits(cb, nb) && !inside) bad.push(`${c.data.name}: ${n.id}`);
      }
    }
    expect(bad, `${key} has nodes straddling a comment edge`).toEqual([]);
  });

  it("gives every knot a distinct position", () => {
    const f = ex.build();
    const seen = new Map<string, string>();
    const dupes: string[] = [];
    for (const k of f.nodes.filter((n) => n.data.kind === "reroute")) {
      const at = `${k.position.x},${k.position.y}`;
      if (seen.has(at)) dupes.push(`${seen.get(at)} & ${k.id}`);
      seen.set(at, k.id);
    }
    expect(dupes, `${key} stacks knots`).toEqual([]);
  });
});

// The boot shell is what a reader without JavaScript sees and what a crawler
// indexes, and it is a hand-written copy of a list the code already holds.
// It has drifted twice: an example was added and the shell kept describing
// the set without it.
describe("boot shell", () => {
  const html = () => readFile(new URL("../index.html", import.meta.url), "utf8");
  const listed = (h: string) => {
    const ul = h.match(/<ul class="ex">([\s\S]*?)<\/ul>/);
    expect(ul, "the boot shell has no example list").not.toBeNull();
    return [...ul![1].matchAll(/<b>([^<]+)<\/b>/g)].map((m) => m[1]);
  };

  it("lists exactly the examples the menu offers", async () => {
    const shown = listed(await html()).sort();
    const known = Object.values(EXAMPLES)
      .map((e) => e.label)
      .sort();
    expect(shown).toEqual(known);
  });

  it("names every opcode the ruleset switches offer, in the same order", async () => {
    const h = await html();
    const ops = h.match(/<p class="ops">([^<]+)<\/p>/);
    expect(ops, "the boot shell has no opcode line").not.toBeNull();
    const shown = ops![1].split("·").map((s) => s.trim());
    // Not sorted: a reader meeting these compares them against the switches
    // in the order the menu lists them.
    expect(shown).toEqual(FLAGS.map((f) => shortLabel(f.id)));
  });

  // The third hand-written copy of the same list, and the one whose bytes
  // the CSP hash pins, so drift here fails silently twice over.
  it("lists every opcode in the structured data too", async () => {
    const h = await html();
    const feature = h.match(/"featureList":\s*\[([^\]]+)\]/);
    expect(feature, "the boot shell has no featureList").not.toBeNull();
    const shown = [...feature![1].matchAll(/"([^"]+)"/g)].map((m) => m[1].replace(/\s*\(BIP \d+\)$/, ""));
    expect(shown).toEqual(FLAGS.map((f) => f.label));
  });

  // The inline JSON-LD is allowed by a sha256 in _headers. Editing the block
  // without recomputing it does not fail any build; the browser just drops
  // the script.
  it("is allowed by the hash the CSP pins it to", async () => {
    const h = await html();
    const block = h.match(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/);
    expect(block, "the boot shell has no inline structured data").not.toBeNull();
    const digest = createHash("sha256").update(block![1], "utf8").digest("base64");
    const headers = await readFile(new URL("../public/_headers", import.meta.url), "utf8");
    expect(headers, "the CSP does not allow the inline block it ships").toContain(`'sha256-${digest}'`);
  });
});

// The node-height table is measured by hand in a browser, and twice a port
// was added in the registry without anyone re-measuring: the comment boxes
// drawn from it then sit too short and the node falls out of its group. The
// layout tests above cannot see it, because they size the box from the same
// table they check against. This holds the table to the ports the registry
// actually declares, which is the thing that moved both times.
describe("node heights", () => {
  /** The inverse of `shape()`: the fields that produce a given table key. */
  const fieldsFor = (key: string): Record<string, unknown> => {
    const [kind, a, b] = key.split(":");
    if (kind === "template" || kind === "transaction") return { kind, nIn: Number(a), nOut: Number(b) };
    if (kind === "taproot") return { kind, nLeaves: Number(a) };
    if (kind === "witness") return { kind, nItems: Number(a) };
    if (kind === "concat") return { kind, nParts: Number(a) };
    return { kind };
  };
  const rowsOf = (d: Record<string, unknown>) => {
    const k = KINDS[String(d.kind)];
    return k.inputs(d as never).length + k.outputs(d as never).length;
  };

  it("keys the table by shapes the node builder still produces", () => {
    for (const key of Object.keys(MEASURED_HEIGHTS)) {
      expect(shapeOf(fieldsFor(key)), `${key} is no longer a shape any node takes`).toBe(key);
    }
  });

  it("records no height a node of that many ports could not render at", () => {
    const short: string[] = [];
    for (const [key, h] of Object.entries(MEASURED_HEIGHTS)) {
      const rows = rowsOf(fieldsFor(key));
      if (h < minHeightFor(rows)) short.push(`${key}: ${h} recorded, ${rows} port rows need ${minHeightFor(rows)}`);
    }
    expect(short, "re-measure these in the browser").toEqual([]);
  });

  // Covers the kinds that get a formula instead of a table entry, and any
  // kind added since, which would otherwise take the 240 fallback silently.
  it("gives every node kind a height its ports fit inside", () => {
    const counted: Record<string, string[]> = {
      template: ["1:1", "1:2", "2:1", "2:3"],
      transaction: ["1:1", "1:2", "2:2"],
      taproot: ["1", "2", "3", "8"],
      witness: ["0", "1", "4", "9"],
      concat: ["2", "3", "6"],
    };
    const short: string[] = [];
    for (const kind of Object.keys(KINDS)) {
      if (kind === "comment" || kind === "reroute" || kind === "tapscript") continue;
      for (const suffix of counted[kind] ?? [""]) {
        const d = fieldsFor(suffix ? `${kind}:${suffix}` : kind);
        const h = heightOf({ id: "x", position: { x: 0, y: 0 }, data: d } as never);
        const rows = rowsOf(d);
        if (h < minHeightFor(rows)) short.push(`${shapeOf(d)}: ${h} for ${rows} port rows`);
      }
    }
    expect(short, "measure these in the browser and add them to MEASURED").toEqual([]);
  });
});
