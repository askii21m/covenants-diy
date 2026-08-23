import { describe, expect, it, vi } from "vitest";
vi.mock("../src/engine", () => import("./engine.mock"));
import { sanitizeFlow, savedSession } from "../src/store";

const good = { id: "a", position: { x: 1, y: 2 }, data: { kind: "comment", name: "x" } };

describe("sanitizeFlow", () => {
  it("returns null without a node list", () => {
    expect(sanitizeFlow(null)).toBeNull();
    expect(sanitizeFlow({})).toBeNull();
    expect(sanitizeFlow({ nodes: "no" })).toBeNull();
  });
  it("drops malformed nodes and edges to missing nodes, keeps the rest", () => {
    const out = sanitizeFlow({
      nodes: [good, { id: "b" }, { id: "c", position: { x: "nan", y: 0 }, data: { kind: "comment" } }, { id: "d", position: { x: 0, y: 0 }, data: { kind: "nope" } }, { id: "a", position: { x: 9, y: 9 }, data: { kind: "comment" } }, 7, null],
      edges: [{ id: "e1", source: "a", target: "a" }, { source: "a", target: "zzz" }, "x"],
      network: "moon", ruleset: "letter", name: ["not", "a", "string"],
    })!;
    expect(out.nodes!.map((n) => n.id)).toEqual(["a"]);
    expect(out.nodes![0].position).toEqual({ x: 1, y: 2 });
    expect(out.nodes![0].data.width).toBeDefined();   // defaults filled in
    expect(out.edges!.map((e) => e.id)).toEqual(["e1"]);
    expect(out.network).toBeUndefined();
    expect(out.ruleset).toBe("letter");
    expect(out.name).toBeUndefined();
  });
  it("does not carry React Flow's runtime fields", () => {
    const out = sanitizeFlow({ nodes: [{ ...good, measured: { width: 10, height: 10 }, selected: true, dragging: true }] })!;
    const n = out.nodes![0] as Record<string, unknown>;
    expect(n.measured).toBeUndefined(); expect(n.selected).toBeUndefined(); expect(n.dragging).toBeUndefined();
  });
});

describe("savedSession", () => {
  it("drops a document without nodes instead of failing the whole session", () => {
    localStorage.clear();
    localStorage.setItem("covenants.session", JSON.stringify({ v: 2, active: "x", docs: [{ id: "x", name: "bad" }, { id: "y", name: "ok", nodes: [good], edges: [] }] }));
    const s = savedSession()!;
    expect(s.docs.map((d) => d.name)).toEqual(["ok"]);
  });
  it("backs up data it cannot read, and never over an existing backup", () => {
    localStorage.clear();
    localStorage.setItem("covenants.session", "{not json");
    expect(savedSession()).toBeNull();
    expect(localStorage.getItem("covenants.session.bak")).toBe("{not json");
    // A later unreadable session must not bury the first copy, which is the
    // one most likely to hold real work.
    localStorage.setItem("covenants.session", JSON.stringify({ v: 3, docs: [] }));
    expect(savedSession()).toBeNull();
    expect(localStorage.getItem("covenants.session.bak")).toBe("{not json");
  });
});


describe("import failure", () => {
  it("rejects a file whose nodes are all unreadable rather than opening it empty", () => {
    expect(sanitizeFlow({ nodes: [{ id: "a", position: { x: 0, y: 0 }, data: { kind: "not-a-kind" } }] })).toBeNull();
    // An empty flow is legitimately empty.
    expect(sanitizeFlow({ nodes: [] })!.nodes).toEqual([]);
  });
});
