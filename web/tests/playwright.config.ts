import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: ".",
  // These tiers require a live node and are driven by their own configs +
  // harness scripts (node-e2e via playwright.node.config.ts + node-e2e.sh;
  // multi-node via playwright.multinode.config.ts + multi-node-e2e.sh). The
  // offline tier must never pick them up — without the harness env
  // (GW_APP_URL/PEER_APP_URL) the multi-node specs fail in beforeAll.
  testIgnore: ["**/node-e2e/**", "**/multi-node/**"],
  timeout: 30_000,
  fullyParallel: true,
  reporter: [["html", { outputFolder: "playwright-report", open: "never" }]],
  use: {
    baseURL: process.env.BASE_URL ?? "http://localhost:8082",
    trace: "on-first-retry",
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "firefox",  use: { ...devices["Desktop Firefox"] } },
    { name: "webkit",   use: { ...devices["Desktop Safari"] } },
  ],
});
