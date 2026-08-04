import { access } from "node:fs/promises";
import { constants } from "node:fs";
import path from "node:path";

const required = [
  path.resolve("node_modules/typescript/bin/tsc"),
  path.resolve("node_modules/vite/bin/vite.js"),
  path.resolve("node_modules/vitest/vitest.mjs"),
];

const missing = [];
for (const file of required) {
  try { await access(file, constants.R_OK); }
  catch { missing.push(file); }
}

if (missing.length > 0) {
  console.error("Frontend toolchain is incomplete. Missing:");
  for (const file of missing) console.error(` - ${file}`);
  console.error("Run: Remove-Item node_modules -Recurse -Force; npm ci");
  process.exit(1);
}
console.log("Frontend toolchain verified.");
