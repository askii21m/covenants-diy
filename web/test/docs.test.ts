import { beforeEach, describe, expect, it, vi } from "vitest";
vi.mock("../src/engine", () => import("./engine.mock"));
import { useStore } from "../src/store";

const comment = (id: string) => ({ id, type: "comment", position: { x: 0, y: 0 }, data: { kind: "comment", name: id, width: 100, height: 80 } });

describe("switching documents", () => {
  beforeEach(() => { useStore.setState({ docs: [], active: "", closed: [], nodes: [], edges: [], selected: null }); });

  it("does not bring a stale selection back", () => {
    const s = useStore.getState();
    const a = s.newDoc("a", { nodes: [comment("c1")], edges: [] });
    const id = useStore.getState().nodes[0].id;
    useStore.getState().select(id);
    expect(useStore.getState().nodes[0].selected).toBe(true);
    const b = useStore.getState().newDoc("b");
    useStore.getState().switchDoc(a);
    expect(useStore.getState().selected).toBeNull();
    expect(useStore.getState().nodes[0].selected).toBe(false);
    expect(b).not.toBe(a);
  });

  it("keeps undo history per document", () => {
    const s = useStore.getState();
    const a = s.newDoc("a");
    useStore.getState().addNode("comment", { x: 0, y: 0 });
    expect(useStore.getState().past).toHaveLength(1);
    const b = useStore.getState().newDoc("b");
    expect(useStore.getState().past).toHaveLength(0);
    useStore.getState().switchDoc(a);
    expect(useStore.getState().past).toHaveLength(1);
    useStore.getState().undo();
    expect(useStore.getState().nodes).toHaveLength(0);
    useStore.getState().switchDoc(b);
    expect(useStore.getState().nodes).toHaveLength(0);
  });

  it("closing the active document picks its neighbour, and the last one leaves an untitled", () => {
    const s = useStore.getState();
    const a = s.newDoc("a"), b = useStore.getState().newDoc("b"), c = useStore.getState().newDoc("c");
    useStore.getState().switchDoc(a);
    useStore.getState().closeDoc(a);
    expect(useStore.getState().active).toBe(b);
    useStore.getState().closeDoc(c);
    expect(useStore.getState().active).toBe(b);
    useStore.getState().closeDoc(b);
    expect(useStore.getState().docs.map((d) => d.name)).toEqual(["untitled"]);
  });
});
