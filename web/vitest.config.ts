import { defineConfig, configDefaults } from "vitest/config";

/** The wasm build loads from a file URL, which jsdom does not provide, so
 *  every test that runs a script lives in vitest.node.config.ts instead.
 *  Listed here so one `vitest run` does not collect them twice. */
export const NODE_TESTS = [
  "test/examples.test.ts",
  "test/opcodes.test.ts",
  "test/bounds.test.ts",
  "test/share.test.ts",
  "test/functions.test.ts",
  "test/txhash.test.ts",
  "test/ccv.test.ts",
];

export default defineConfig({
  test: {
    environment: "jsdom",
    include: ["test/**/*.test.ts"],
    exclude: [...configDefaults.exclude, ...NODE_TESTS],
  },
});
