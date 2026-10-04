// Run the consumer's existing strict and library compilation checks serially.
// Each compiler exit is observed; no failed child can become a passing gate.
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

function compile(command, args) {
  const result = spawnSync(path.resolve("node_modules/.bin", command), args, {
    stdio: "inherit",
  });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}

function projects(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const file = path.join(directory, entry.name);
    if (file === path.join("libs", "shared")) return [];
    if (entry.isDirectory()) return projects(file);
    return entry.isFile() && entry.name === "tsconfig.json" ? [file] : [];
  });
}

const libraries = projects("libs").sort();
if (libraries.length === 0) throw new Error("No consumer library projects found");
compile("tsc-strict", []);
for (const project of libraries) {
  console.log(`Compiling ${project}`);
  compile("tsc", ["--noEmit", "--project", project]);
}
console.log(`Pinned fork client compilation passed (${libraries.length} library projects)`);
