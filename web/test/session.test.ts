import { beforeEach, describe, expect, it, vi } from "vitest";
vi.mock("../src/engine", () => import("./engine.mock"));
import { useStore, flushSession, serializeSession, registerPendingEdit } from "../src/store";

const comment = (id: string) => ({ id, type: "comment", position: { x: 0, y: 0 }, data: { kind: "comment", name: id, width: 100, height: 80 } });

describe("session autosave", () => {
  beforeEach(() => { localStorage.clear(); useStore.setState({ docs: [], active: "", closed: [], nodes: [], edges: [] }); });

  it("flushes the live document immediately, before the debounce", () => {
    const s = useStore.getState();
    s.newDoc("a", { nodes: [comment("c1")], edges: [] });
    expect(localStorage.getItem("covenants.session")).toBeNull();
    expect(flushSession()).toBe(true);
    const sess = JSON.parse(localStorage.getItem("covenants.session")!);
    expect(sess.v).toBe(2);
    expect(sess.docs.map((d: { name: string; nodes: unknown[] }) => [d.name, d.nodes.length])).toEqual([["a", 1]]);
  });

  it("serialises the live content of the active document, not its stale stash", () => {
    const s = useStore.getState();
    s.newDoc("a");
    useStore.getState().addNode("comment", { x: 1, y: 1 });
    expect(serializeSession()!.docs[0].nodes).toHaveLength(1);
  });
});

describe("closed documents", () => {
  beforeEach(() => { localStorage.clear(); useStore.setState({ docs: [], active: "", closed: [], nodes: [], edges: [] }); });

  it("survive a save and restore, so Reopen closed tab works after a reload", () => {
    const s = useStore.getState();
    s.newDoc("keep");
    const gone = useStore.getState().newDoc("gone", { nodes: [comment("c1")], edges: [] });
    useStore.getState().closeDoc(gone);
    expect(useStore.getState().closed.map((d) => d.name)).toEqual(["gone"]);
    flushSession();
    useStore.setState({ docs: [], active: "", closed: [] });
    useStore.getState().restoreSession(JSON.parse(localStorage.getItem("covenants.session")!));
    expect(useStore.getState().closed.map((d) => [d.name, d.nodes.length])).toEqual([["gone", 1]]);
    useStore.getState().reopenClosed();
    expect(useStore.getState().docs.map((d) => d.name)).toEqual(["keep", "gone"]);
    expect(useStore.getState().nodes).toHaveLength(1);
  });
});

describe("a refused write", () => {
  it("sets saveError, and the next success clears it", () => {
    localStorage.clear(); useStore.setState({ docs: [], active: "", closed: [], nodes: [], edges: [], saveError: false });
    useStore.getState().newDoc("a");
    const real = Storage.prototype.setItem;
    Storage.prototype.setItem = () => { throw new DOMException("full", "QuotaExceededError"); };
    expect(flushSession()).toBe(false);
    expect(useStore.getState().saveError).toBe(true);
    Storage.prototype.setItem = real;
    expect(flushSession()).toBe(true);
    expect(useStore.getState().saveError).toBe(false);
  });
});

describe("pending editor edits", () => {
  beforeEach(() => { localStorage.clear(); useStore.setState({ docs: [], active: "", closed: [], nodes: [], edges: [], saveError: false }); });

  it("are landed before a document switch, not dropped", () => {
    const a = useStore.getState().newDoc("a", { nodes: [comment("c1")], edges: [] });
    const id = useStore.getState().nodes[0].id;
    let held: string | null = "typed";
    const off = registerPendingEdit(() => { if (held != null) { useStore.getState().setField(id, "name", held); held = null; } });
    useStore.getState().newDoc("b");
    expect(held).toBeNull();
    useStore.getState().switchDoc(a);
    expect(useStore.getState().nodes[0].data.name).toBe("typed");
    off();
  });

  it("are landed by a session flush", () => {
    useStore.getState().newDoc("a", { nodes: [comment("c1")], edges: [] });
    const id = useStore.getState().nodes[0].id;
    const off = registerPendingEdit(() => useStore.getState().setField(id, "name", "flushed"));
    flushSession();
    const sess = JSON.parse(localStorage.getItem("covenants.session")!);
    expect(sess.docs[0].nodes[0].data.name).toBe("flushed");
    off();
  });

  it("drops the closed list rather than failing the write when storage is tight", () => {
    useStore.getState().newDoc("open");
    const gone = useStore.getState().newDoc("gone", { nodes: [comment("c1")], edges: [] });
    useStore.getState().closeDoc(gone);
    const real = Storage.prototype.setItem;
    let calls = 0;
    Storage.prototype.setItem = function (k: string, v: string) {
      if (k === "covenants.session" && ++calls === 1) throw new DOMException("full", "QuotaExceededError");
      return real.call(this, k, v);
    };
    expect(flushSession()).toBe(true);
    Storage.prototype.setItem = real;
    expect(useStore.getState().saveError).toBe(false);
    const sess = JSON.parse(localStorage.getItem("covenants.session")!);
    expect(sess.closed).toEqual([]);
    expect(sess.docs.map((d: { name: string }) => d.name)).toEqual(["open"]);
  });
});
