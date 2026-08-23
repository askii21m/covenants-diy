import { defineConfig } from "vitest/config";
import { NODE_TESTS } from "./vitest.config";

export default defineConfig({ test: { environment: "node", include: NODE_TESTS } });
