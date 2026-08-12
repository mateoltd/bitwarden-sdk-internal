#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const [artifactDirectory, outputDirectory] = process.argv.slice(2);
if (!artifactDirectory || !outputDirectory) {
  console.error("Usage: create-release-manifest.mjs ARTIFACT_DIRECTORY OUTPUT_DIRECTORY");
  process.exit(2);
}

const sourceCommit = process.env.SOURCE_COMMIT;
if (!/^[0-9a-f]{40}$/.test(sourceCommit ?? "")) {
  console.error("SOURCE_COMMIT must be a full Git commit SHA");
  process.exit(1);
}

const walk = (directory) =>
  fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const entryPath = path.join(directory, entry.name);
    return entry.isDirectory() ? walk(entryPath) : [entryPath];
  });
const files = walk(artifactDirectory).sort();
if (files.length === 0) {
  console.error("Release manifest gate failed: no artifacts were downloaded");
  process.exit(1);
}

const artifacts = files.map((file) => {
  const bytes = fs.readFileSync(file);
  return {
    path: path.relative(artifactDirectory, file).split(path.sep).join("/"),
    bytes: bytes.length,
    sha256: crypto.createHash("sha256").update(bytes).digest("hex"),
  };
});
const manifest = {
  schemaVersion: 1,
  sourceCommit,
  upstreamBase: fs.readFileSync(process.env.UPSTREAM_BASE_FILE, "utf8").trim(),
  clientsContract: JSON.parse(fs.readFileSync(process.env.CLIENTS_CONTRACT_FILE, "utf8")),
  artifacts,
};

fs.mkdirSync(outputDirectory, { recursive: true });
fs.writeFileSync(
  path.join(outputDirectory, "release-manifest.json"),
  `${JSON.stringify(manifest, null, 2)}\n`,
);
fs.writeFileSync(
  path.join(outputDirectory, "SHA256SUMS"),
  `${artifacts.map(({ sha256, path: artifactPath }) => `${sha256}  ${artifactPath}`).join("\n")}\n`,
);
console.log(`Release manifest records ${artifacts.length} files from ${sourceCommit}`);
