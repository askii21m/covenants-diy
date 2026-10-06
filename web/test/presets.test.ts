// The "Running" presets name networks that exist, so each is pinned to what
// that network actually enforces. Bitcoin Inquisition 29.4 (22 Jul 2026)
// activates CTV, CSFS, OP_CAT, ANYPREVOUT, OP_INTERNALKEY and
// OP_TEMPLATEHASH on the default signet.
import { describe, expect, it } from "vitest";
import { PRESETS } from "../src/engine";

const running = (label: string) => PRESETS.find((p) => p.group === "Running" && p.label === label);

describe("running presets", () => {
  it("Inquisition signet enables exactly what Inquisition 29.4 activates", () => {
    expect([...running("Inquisition signet")!.on].sort()).toEqual([
      "apo",
      "cat",
      "csfs",
      "ctv",
      "internalkey",
      "templatehash",
    ]);
  });

  it("mainnet today enables none of them", () => {
    expect(running("mainnet today")!.on).toEqual([]);
  });
});
