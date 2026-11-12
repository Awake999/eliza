import { spawnSync } from "node:child_process";

const result = spawnSync(
  "bun",
  [
    "test",
    "packages/cloud/api/src/speech-retirement-route.test.ts",
    "packages/cloud/api/src/speech-retirement-coordinator.test.ts",
    "packages/cloud/api/__tests__/voice-speech-mint.test.ts",
  ],
  { stdio: "inherit" },
);
if (result.error) throw result.error;
if (result.status !== 0) process.exit(result.status ?? 1);

const credential = spawnSync(
  "bun",
  [
    "--conditions=eliza-source",
    "test",
    "packages/cloud/api/__tests__/voice-speech-rate-limit.pglite.test.ts",
    "-t",
    "speech consent retries one credential deadline",
  ],
  { stdio: "inherit" },
);
if (credential.error) throw credential.error;
if (credential.status !== 0) process.exit(credential.status ?? 1);
