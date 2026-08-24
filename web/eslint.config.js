import js from "@eslint/js";
import ts from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";
import globals from "globals";

export default ts.config(
  { ignores: ["dist/", "pkg/", "node_modules/", ".wrangler/", "public/"] },
  js.configs.recommended,
  ...ts.configs.recommended,
  // Plain scripts that run under node, not in the browser.
  {
    files: ["**/*.mjs", "*.config.ts"],
    languageOptions: { globals: globals.node },
  },
  {
    files: ["**/*.{ts,tsx}"],
    languageOptions: { globals: { ...globals.browser, ...globals.node } },
    plugins: { "react-hooks": reactHooks },
    rules: {
      ...reactHooks.configs.recommended.rules,
      // A leading underscore is this codebase's way of saying a binding is
      // deliberately unused, as in a destructure that skips fields.
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_", varsIgnorePattern: "^_" }],
      // A draft synced to a prop, and a ref kept current so an unmount can
      // flush a pending edit. Both are used deliberately and consistently
      // here; exhaustive-deps stays on, and its two omissions are annotated.
      "react-hooks/set-state-in-effect": "off",
      "react-hooks/refs": "off",
    },
  },
);
