#!/usr/bin/env node
import path from "node:path";
import process from "node:process";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const [rawDirectory, cargoActiveFile, policyFile, outputFile] = process.argv.slice(2);
if (!rawDirectory || !cargoActiveFile || !policyFile || !outputFile) {
  console.error(
    "Usage: create-audit-report.mjs RAW_AUDIT_DIRECTORY CARGO_ACTIVE_PACKAGES " +
      "AUDIT_POLICY_JSON OUTPUT_JSON",
  );
  process.exit(2);
}
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const result = spawnSync(
  "python3",
  [
    path.join(root, "scripts/alias-sdk/rsa-remediation.py"),
    "audit",
    "--root",
    root,
    "--input",
    rawDirectory,
    "--active",
    cargoActiveFile,
    "--policy",
    policyFile,
    "--output",
    outputFile,
  ],
  { stdio: "inherit" },
);
if (result.error) throw result.error;
process.exit(result.status ?? 1);
