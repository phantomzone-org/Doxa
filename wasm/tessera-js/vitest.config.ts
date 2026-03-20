import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Run tests sequentially — WASM modules are stateful singletons
    pool: "forks",
    poolOptions: {
      forks: { singleFork: true },
    },
  },
});
