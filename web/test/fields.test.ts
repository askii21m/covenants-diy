// A number field can only hold what a browser will read back as a number.
// Grouping digits for display produced "98 000", which a type="number"
// input sanitises to the empty string, so amounts rendered as blank fields
// and looked like the value had been discarded.
import { describe, expect, it } from "vitest";

const grouped = (n: number) => n.toLocaleString("en-US").replace(/,/g, " ");

describe("amount fields", () => {
  it("a number input cannot hold a grouped amount", () => {
    const el = document.createElement("input");
    el.type = "number";
    el.value = grouped(98_000);
    expect(grouped(98_000)).toBe("98 000");
    expect(el.value).toBe("");
  });

  it("it holds the plain form, which is what the field shows", () => {
    for (const n of [0, 1, 999, 1_000, 98_000, 21_000_000_00000000]) {
      const el = document.createElement("input");
      el.type = "number";
      el.value = String(n);
      expect(el.value, `${n} did not survive`).toBe(String(n));
    }
  });

  // The parser still strips separators, so a pasted "98 000" is understood
  // even though the field never renders one.
  it("separators are still accepted on the way in", () => {
    const parse = (v: string) => Number(v.replace(/[\s,_]/g, ""));
    expect(parse("98 000")).toBe(98_000);
    expect(parse("98,000")).toBe(98_000);
    expect(parse("98_000")).toBe(98_000);
  });
});
