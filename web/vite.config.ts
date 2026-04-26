/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import { readFileSync, existsSync } from "fs";
import { resolve } from "path";

function readFileOrDefault(filename: string, fallback: string): string {
  const filePath = resolve(__dirname, filename);
  return existsSync(filePath) ? readFileSync(filePath, "utf-8").trim() : fallback;
}

export default defineConfig({
  define: {
    __MODEL_CONTRACT__: JSON.stringify(readFileOrDefault("model_code_hash.txt", "DEV_MODE_NO_CONTRACT_HASH")),
    __DELEGATE_KEY__: JSON.stringify(readFileOrDefault("delegate_key.txt", "")),
    __DELEGATE_KEY_BYTES__: readFileOrDefault("delegate_key_bytes.json", "[]"),
    __DELEGATE_CODE_HASH_BYTES__: readFileOrDefault("delegate_code_hash_bytes.json", "[]"),
    __OFFLINE_MODE__: JSON.stringify(process.env.VITE_OFFLINE_MODE === "1"),
  },
  css: {
    preprocessorOptions: {
      scss: {
        api: "modern-compiler",
      },
    },
  },
  base: "./",
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
  server: {
    port: 8080,
  },
  test: {
    // Vitest scope: src/ unit tests only. The web/tests/ directory holds
    // Playwright E2E specs that import @playwright/test (not available in
    // web/node_modules); they are run by `cargo make test-ui-playwright`.
    include: ["src/**/*.{test,spec}.{ts,tsx}"],
    passWithNoTests: true,
  },
});
