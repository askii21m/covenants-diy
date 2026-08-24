import { describe, expect, it, vi } from "vitest";
vi.mock("../src/engine", () => import("./engine.mock"));
import { nextId, remapIds, useStore } from "../src/store";

describe("ids", () => {
  it("never repeat across ten thousand mints", () => {
    const ids = new Set(Array.from({ length: 10000 }, () => nextId("n")));
    expect(ids.size).toBe(10000);
  });
  it("are remapped consistently for nodes and edges", () => {
    const flow = remapIds({
      nodes: [
        { id: "a", position: { x: 0, y: 0 }, data: { kind: "comment" } },
        { id: "b", position: { x: 0, y: 0 }, data: { kind: "reroute" } },
      ],
      edges: [{ id: "e", source: "a", sourceHandle: "out", target: "b", targetHandle: "in" }],
    });
    const [a, b] = flow.nodes!.map((n) => n.id);
    expect(a).not.toBe("a");
    expect(b).not.toBe("b");
    expect(a.startsWith("comment_")).toBe(true);
    expect(flow.edges![0]).toMatchObject({ source: a, target: b, id: `e_${a}.out->${b}.in` });
  });
  it("two documents from one flow share no node ids", () => {
    useStore.setState({ docs: [], active: "", closed: [], nodes: [], edges: [] });
    const flow = { nodes: [{ id: "a", position: { x: 0, y: 0 }, data: { kind: "comment" } }], edges: [] };
    useStore.getState().newDoc("one", flow);
    const first = useStore.getState().nodes[0].id;
    useStore.getState().newDoc("two", flow);
    expect(useStore.getState().nodes[0].id).not.toBe(first);
  });
});
