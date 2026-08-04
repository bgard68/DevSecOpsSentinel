import { spawnSync } from "node:child_process";
import { readFile, rm } from "node:fs/promises";
import path from "node:path";

const reportPath = path.resolve("node_modules/.tmp/vitest-results.json");
await rm(reportPath, { force: true });

const vitestPath = path.resolve("node_modules/vitest/vitest.mjs");
const result = spawnSync(
  process.execPath,
  [vitestPath, "run", "--reporter=default", "--reporter=json", `--outputFile=${reportPath}`],
  { stdio: "inherit", shell: false },
);

if (result.error) {
  console.error(result.error.message);
  process.exit(1);
}

if (result.status !== 0) {
  process.exit(result.status ?? 1);
}

let report;
try {
  report = JSON.parse(await readFile(reportPath, "utf8"));
} catch (error) {
  console.error(`Vitest did not produce a readable JSON report: ${error.message}`);
  process.exit(1);
}

const total = Number(report.numTotalTests ?? 0);
const failed = Number(report.numFailedTests ?? 0);

if (total < 4) {
  console.error(`Expected at least 4 frontend tests, but Vitest collected ${total}.`);
  process.exit(1);
}

if (failed !== 0) {
  console.error(`Vitest reported ${failed} failed test(s).`);
  process.exit(1);
}

console.log(`Frontend test gate verified: ${total} tests passed.`);
