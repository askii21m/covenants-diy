// Every example must evaluate clean: no node in error, and every Execute
// node satisfied. A broken example is the first thing a visitor sees.
import { beforeAll, describe, expect, it } from "vitest";
import { readFile } from "node:fs/promises";
import init from "../pkg/covenants.js";
import { EXAMPLES, heightOf } from "../src/examples";
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

  it("reports every script as enforced under its own ruleset", () => {
    const f = ex.build();
    const computed = evaluate(f.nodes, f.edges, f.network, f.ruleset);
    const bad: string[] = [];
    for (const n of f.nodes.filter((n) => n.data.kind === "tapscript")) {
      const view = computed[n.id]?.extra as { enforcement?: { status: string; inactive: string[] } } | undefined;
      const e = view?.enforcement;
      if (!e) { bad.push(`${n.data.name}: no enforcement report`); continue; }
      if (e.status !== "enforced") bad.push(`${n.data.name}: ${e.status} (${e.inactive.join(", ")})`);
    }
    expect(bad, `${key} declares ruleset "${ex.build().ruleset}"`).toEqual([]);
  });

  it("wires only ports that exist", () => {
    const f = ex.build();
    const byId = new Map(f.nodes.map((n) => [n.id, n]));
    for (const e of f.edges) {
      const s = byId.get(e.source), t = byId.get(e.target);
      expect(s, `${key}: edge from missing node ${e.source}`).toBeDefined();
      expect(t, `${key}: edge to missing node ${e.target}`).toBeDefined();
      const sk = String(s!.data.kind), tk = String(t!.data.kind);
      if (sk !== "reroute") expect(KINDS[sk].outputs(s!.data).map((p) => p.id), `${key}: ${s!.data.name}.${e.sourceHandle}`).toContain(e.sourceHandle);
      if (tk !== "reroute") expect(KINDS[tk].inputs(t!.data).map((p) => p.id), `${key}: ${t!.data.name}.${e.targetHandle}`).toContain(e.targetHandle);
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
    for (let i = 0; i < real.length; i++) for (let j = i + 1; j < real.length; j++) {
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
