import { defineConfig, devices } from "@playwright/test";

// Multi-node e2e tier: realistic usage journeys across TWO nodes of a live
// local Freenet network. Boot + publish + URL wiring is owned by
// scripts/multi-node-e2e.sh (GW_APP_URL / PEER_APP_URL env) — run via
// `cargo make test-ui-multi-node`, never directly.
//
// Serial single-worker on purpose: the journeys share network + delegate
// state and deliberately keep sessions open across specs to exercise live
// update delivery.
export default defineConfig({
  testDir: "./multi-node",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  // Journeys poll with generous cross-node propagation budgets.
  timeout: 420_000,
  reporter: [["list"], ["html", { outputFolder: "playwright-report-multinode", open: "never" }]],
  use: {
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
