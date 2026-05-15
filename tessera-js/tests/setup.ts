import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";
import { initSync } from "../wasm/tessera_client_wasm.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const wasmPath = join(__dirname, "../wasm/tessera_client_wasm_bg.wasm");
initSync({ module: readFileSync(wasmPath) });
