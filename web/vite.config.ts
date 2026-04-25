import { defineConfig } from "vite";
import { readFileSync, existsSync } from "fs";
import { resolve } from "path";

function readFileOrDefault(filename: string, fallback: string): string {
  const filePath = resolve(__dirname, filename);
  return existsSync(filePath) ? readFileSync(filePath, "utf-8").trim() : fallback;
}

export default defineConfig({
  resolve: {
    alias: {
      "@freenetorg/freenet-stdlib/client-request": resolve(
        __dirname,
        "../../freenet-stdlib/typescript/src/client-request.ts"
      ),
      "@freenetorg/freenet-stdlib/common": resolve(
        __dirname,
        "../../freenet-stdlib/typescript/src/common.ts"
      ),
      "@freenetorg/freenet-stdlib/host-response": resolve(
        __dirname,
        "../../freenet-stdlib/typescript/src/host-response.ts"
      ),
      "@freenetorg/freenet-stdlib": resolve(
        __dirname,
        "../../freenet-stdlib/typescript/src/index.ts"
      ),
    },
  },
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
});
