// Following someone's link must never cost a visitor their own work: the
// saved session comes back first and the link opens on top of it. The
// autosave writes whatever is open, so the order is the whole protection.
import { beforeEach, describe, expect, it, vi } from "vitest";
vi.mock("../src/engine", () => import("./engine.mock"));
vi.mock("../src/share", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/share")>()),
  fetchShared: vi.fn(),
}));
import { useStore, flushSession } from "../src/store";
import { fetchShared } from "../src/share";
import { boot } from "../src/boot";

const comment = (id: string) => ({
  id,
  type: "comment",
  position: { x: 0, y: 0 },
  data: { kind: "comment", name: id, width: 100, height: 80 },
});
const fetched = vi.mocked(fetchShared);
const names = () => useStore.getState().docs.map((d) => d.name);
const reset = () => useStore.setState({ docs: [], active: "", closed: [], nodes: [], edges: [] });

/** Two documents left behind by an earlier visit. */
function leaveSession() {
  useStore.getState().newDoc("a", { nodes: [comment("c1")], edges: [] });
  useStore.getState().newDoc("b");
  flushSession();
  reset();
}

beforeEach(() => {
  localStorage.clear();
  reset();
  fetched.mockReset();
  history.replaceState(null, "", "/");
});

describe("a first load that carries a link", () => {
  it("opens the shared graph on top of the saved session, and the next save keeps all three", async () => {
    leaveSession();
    history.replaceState(null, "", "/g/abcdefghij");
    fetched.mockResolvedValue({ name: "theirs", flow: { nodes: [comment("c2")], edges: [] } });
    const openExample = vi.fn();
    await boot(openExample, () => {});
    const s = useStore.getState();
    expect(names()).toEqual(["a", "b", "theirs"]);
    expect(s.docs.find((d) => d.id === s.active)?.name).toBe("theirs");
    expect(openExample).not.toHaveBeenCalled();
    expect(location.pathname).toBe("/");
    flushSession();
    const saved = JSON.parse(localStorage.getItem("covenants.session")!);
    expect(saved.docs.map((d: { name: string }) => d.name)).toEqual(["a", "b", "theirs"]);
  });

  it("keeps the session, and says so, when the link carries nothing", async () => {
    leaveSession();
    history.replaceState(null, "", "/g/abcdefghij");
    fetched.mockResolvedValue(null);
    const openExample = vi.fn();
    const say = vi.fn();
    await boot(openExample, say);
    expect(names()).toEqual(["a", "b"]);
    expect(say).toHaveBeenCalledOnce();
    expect(openExample).not.toHaveBeenCalled();
  });

  it("falls back to the vault example only when a dead link finds no session", async () => {
    history.replaceState(null, "", "/g/abcdefghij");
    fetched.mockResolvedValue(null);
    const openExample = vi.fn();
    await boot(openExample, () => {});
    expect(openExample).toHaveBeenCalledWith("vault");
  });
});

describe("a first load without a link", () => {
  it("restores the session", async () => {
    leaveSession();
    const openExample = vi.fn();
    await boot(openExample, () => {});
    expect(names()).toEqual(["a", "b"]);
    expect(openExample).not.toHaveBeenCalled();
  });

  it("opens the vault example when there is nothing to restore", async () => {
    const openExample = vi.fn();
    await boot(openExample, () => {});
    expect(openExample).toHaveBeenCalledWith("vault");
  });

  it("ignores the session under ?fresh=1 but keeps a copy of it", async () => {
    leaveSession();
    history.replaceState(null, "", "/?fresh=1");
    const openExample = vi.fn();
    await boot(openExample, () => {});
    expect(names()).toEqual([]);
    expect(openExample).toHaveBeenCalledWith("vault");
    expect(localStorage.getItem("covenants.session.bak")).not.toBeNull();
  });
});
