import { defineConfig } from "vite";
import wasm from "vite-plugin-wasm";

export default defineConfig({
  plugins: [wasm()],
  build: {
    target: "esnext",
  },
  optimizeDeps: {
    exclude: ["tessera_client_wasm"],
  },
  server: {
    fs: {
      allow: [".", "../../tessera-js"],
    },
  },
});
