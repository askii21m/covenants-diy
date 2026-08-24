// The two endpoints run on Cloudflare, where the browser's checks do not
// apply, so they restate them. These cover the restatement: what the
// server accepts, what it refuses, and how it names what it keeps.
import { beforeAll, describe, expect, it } from "vitest";
import { readFile } from "node:fs/promises";
import { deflateRawSync } from "node:zlib";
import init from "../pkg/covenants.js";
import { EXAMPLES } from "../src/examples";
import { encodeFlow } from "../src/share";
import { summarise, idFor, MAX_PAYLOAD } from "../functions/_shared";

beforeAll(async () => {
  await init({ module_or_path: await readFile(new URL("../pkg/covenants_bg.wasm", import.meta.url)) });
});

const b64url = (b: Buffer) => b.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const packed = (o: unknown) => b64url(deflateRawSync(Buffer.from(JSON.stringify(o))));

describe("summarise", () => {
  it("reads a real graph, and the counts match the document", async () => {
    const flow = EXAMPLES.vault.build();
    const s = await summarise(await encodeFlow({ name: "vault", flow }));
    expect(s).not.toBeNull();
    expect(s!.nodes).toBe(flow.nodes.length);
    expect(s!.edges).toBe(flow.edges.length);
    expect(s!.network).toBe(flow.network);
    expect(s!.ruleset).toBe(flow.ruleset);
    // The covenant kind, not the renderer type: which nodes earn their
    // place in the palette is the question this column exists to answer.
    expect(s!.kinds.split(",")).toEqual([...new Set(flow.nodes.map((n) => String(n.data.kind)))].sort());
  });

  it("agrees with every bundled example", async () => {
    for (const [key, ex] of Object.entries(EXAMPLES)) {
      const flow = ex.build();
      const s = await summarise(await encodeFlow({ name: ex.name, flow }));
      expect(s, key).not.toBeNull();
      expect(s!.nodes, key).toBe(flow.nodes.length);
    }
  });

  it.each([
    ["not base64url", "!!! not base64 !!!"],
    ["base64 but not deflate", b64url(Buffer.from("hello there"))],
    ["deflate but not JSON", b64url(deflateRawSync(Buffer.from("nope")))],
    ["JSON but not a document", packed({ hello: "world" })],
    ["a version we do not know", packed({ v: 2, N: [], E: [] })],
    ["nodes that are not arrays", packed({ v: 1, N: [{ kind: "key" }], E: [] })],
    ["a node with no kind", packed({ v: 1, N: [[]], E: [] })],
    ["more nodes than the editor can hold", packed({ v: 1, N: Array.from({ length: 2001 }, () => ["key"]), E: [] })],
    [
      "more edges than the editor can hold",
      packed({ v: 1, N: [["key"]], E: Array.from({ length: 4001 }, () => [0, "a", 0, "b"]) }),
    ],
  ])("refuses %s", async (_label, payload) => {
    expect(await summarise(payload)).toBeNull();
  });

  it("abandons a decompression bomb instead of inflating it", async () => {
    // 32MB of zeros deflates to about 43KB of payload, which is inside
    // the size cap, so only the inflate cap stands between the endpoint
    // and the memory.
    const bomb = b64url(deflateRawSync(Buffer.alloc(32 * 1024 * 1024)));
    expect(bomb.length).toBeLessThan(MAX_PAYLOAD);
    expect(await summarise(bomb)).toBeNull();
  });
});

describe("idFor", () => {
  it("names the same graph the same way twice", async () => {
    const p = await encodeFlow({ name: "vault", flow: EXAMPLES.vault.build() });
    expect(await idFor(p)).toBe(await idFor(p));
  });

  it("names different graphs differently", async () => {
    const a = await idFor(await encodeFlow({ name: "vault", flow: EXAMPLES.vault.build() }));
    const b = await idFor(await encodeFlow({ name: "pool", flow: EXAMPLES.pool.build() }));
    expect(a).not.toBe(b);
  });

  it("is base64url, and long enough to cut a twenty character id from", async () => {
    const id = await idFor("anything");
    expect(id).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(id.length).toBeGreaterThanOrEqual(43);
  });

  it("takes the suffix used to break a collision into account", async () => {
    expect(await idFor("same")).not.toBe(await idFor("same", "1"));
  });
});
