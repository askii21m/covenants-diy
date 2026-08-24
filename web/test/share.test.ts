// A permalink is untrusted input from anyone who can send a URL, so these
// cover the round trip and the ways a link could be hostile rather than
// merely wrong.
import { beforeAll, describe, expect, it, vi } from "vitest";
import { readFile } from "node:fs/promises";
import { deflateRawSync } from "node:zlib";
import init from "../pkg/covenants.js";
import { EXAMPLES } from "../src/examples";
import { encodeFlow, decodeFlow } from "../src/share";
import { evaluate } from "../src/store";

beforeAll(async () => {
  await init({ module_or_path: await readFile(new URL("../pkg/covenants_bg.wasm", import.meta.url)) });
});

const b64url = (b: Buffer) => b.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

describe.each(Object.entries(EXAMPLES))("%s", (key, ex) => {
  it("survives a round trip through a link, and still runs", async () => {
    const f = ex.build();
    const link = await encodeFlow({ name: ex.name, flow: f });
    const back = await decodeFlow(link);
    expect(back, `${key} did not decode`).not.toBeNull();
    expect(back!.name).toBe(ex.name);
    expect(back!.flow.nodes).toHaveLength(f.nodes.length);
    expect(back!.flow.edges).toHaveLength(f.edges.length);
    expect(back!.flow.network).toBe(f.network);
    expect(back!.flow.ruleset).toBe(f.ruleset);

    // The point of the link is the graph, not the bytes: it has to still
    // compute the same things on the other side.
    const before = evaluate(f.nodes, f.edges, f.network, f.ruleset);
    const after = evaluate(back!.flow.nodes!, back!.flow.edges!, back!.flow.network!, back!.flow.ruleset!);
    const runs = (ns: typeof f.nodes, c: typeof before) =>
      ns.filter((n) => n.data.kind === "execute").map((n) => c[n.id]?.outputs.ok);
    expect(runs(back!.flow.nodes!, after)).toEqual(runs(f.nodes, before));
    expect(runs(f.nodes, before).every((r) => r === "1")).toBe(true);
  });

  it("fits in a link people can actually paste", async () => {
    const link = await encodeFlow({ name: ex.name, flow: ex.build() });
    expect(link.length, `${key} is ${link.length} characters`).toBeLessThan(8_000);
  });
});

describe("a hostile link", () => {
  it("refuses a decompression bomb", async () => {
    // 4MB of zeros deflates to a couple of kilobytes; without a cap on the
    // output this would be a free way to make the tab ask for memory.
    const bomb = b64url(deflateRawSync(Buffer.alloc(64 * 1024 * 1024)));
    expect(bomb.length).toBeLessThan(200_000);
    expect(await decodeFlow(bomb)).toBeNull();
  });

  it("refuses more nodes than anyone would draw", async () => {
    const many = { v: 1, N: Array.from({ length: 5000 }, () => ["comment", 0, 0, {}]), E: [] };
    expect(await decodeFlow(b64url(deflateRawSync(Buffer.from(JSON.stringify(many)))))).toBeNull();
  });

  it("refuses a fragment that is not one of ours", async () => {
    for (const bad of ["", "not base64!!", "____", b64url(Buffer.from("plain, not deflated"))]) {
      expect(await decodeFlow(bad), `${bad} decoded`).toBeNull();
    }
  });

  it("refuses a version it does not know", async () => {
    const future = { v: 2, N: [], E: [] };
    expect(await decodeFlow(b64url(deflateRawSync(Buffer.from(JSON.stringify(future)))))).toBeNull();
  });

  it("drops nodes and edges it cannot make sense of, rather than failing", async () => {
    const messy = {
      v: 1,
      w: "bitcoin",
      r: "nonsense",
      N: [
        ["comment", 0, 0, { name: "ok", width: 200, height: 100 }],
        ["not-a-kind", 0, 0, {}],
      ],
      E: [
        [0, "a", 99, "b"],
        [0, "a", 1, "b"],
      ],
    };
    const back = await decodeFlow(b64url(deflateRawSync(Buffer.from(JSON.stringify(messy)))));
    expect(back).not.toBeNull();
    expect(back!.flow.nodes).toHaveLength(1); // the unknown kind is gone
    expect(back!.flow.edges).toHaveLength(0); // both edges pointed at it
    expect(back!.flow.network).toBeUndefined(); // mainnet is not offered
    expect(back!.flow.ruleset).toBeUndefined();
  });
});

// A shared graph is a stranger's bytes rendered on our origin. The editor
// has no HTML sink, so these assert the properties that keep it that way
// rather than the absence of one particular payload.
describe("a graph whose fields are an attack", () => {
  const XSS = '<img src=x onerror="window.__pwned=1">';

  it("carries hostile strings through as data, neither executing nor dropping them", async () => {
    const flow = EXAMPLES.vault.build();
    for (const n of flow.nodes) {
      for (const k of Object.keys(n.data)) {
        if (k !== "kind" && typeof (n.data as Record<string, unknown>)[k] === "string") {
          (n.data as Record<string, unknown>)[k] = XSS;
        }
      }
    }
    const back = await decodeFlow(await encodeFlow({ name: "</title><script>alert(1)</script>", flow }));
    expect(back).not.toBeNull();
    expect(back!.flow.nodes.some((n) => Object.values(n.data).includes(XSS))).toBe(true);
    expect(back!.name).toContain("<script>");
  });

  it("cannot reach Object.prototype through a crafted node", async () => {
    const wire = { v: 1, N: [["key", 0, 0, { ["__proto__"]: { polluted: "yes" } }]], E: [] };
    const back = await decodeFlow(b64url(deflateRawSync(Buffer.from(JSON.stringify(wire)))));
    expect(Object.prototype).not.toHaveProperty("polluted");
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    // The node still arrives; the key is an inert own property.
    expect(back?.flow.nodes).toHaveLength(1);
  });

  it("refuses a payload that is not base64url, so stored bytes can never be markup", async () => {
    expect(await decodeFlow("<script>alert(1)</script>")).toBeNull();
  });
});
