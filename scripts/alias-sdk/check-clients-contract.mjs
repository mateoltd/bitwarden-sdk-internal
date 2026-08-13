#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const [contractPath, clientsPath] = process.argv.slice(2);
if (!contractPath || !clientsPath) {
  console.error("Usage: check-clients-contract.mjs CONTRACT_JSON CLIENTS_CHECKOUT");
  process.exit(2);
}

const readJson = (file) => JSON.parse(fs.readFileSync(file, "utf8"));
const contract = readJson(contractPath);
const packageJson = readJson(path.join(clientsPath, "package.json"));
const tsconfig = readJson(path.join(clientsPath, "tsconfig.base.json"));
const actual = {
  node: packageJson.engines?.node,
  typescript: packageJson.devDependencies?.typescript,
  compilerOptions: Object.fromEntries(
    Object.keys(contract.compilerOptions).map((key) => [key, tsconfig.compilerOptions?.[key]]),
  ),
};
const expected = {
  node: contract.node,
  typescript: contract.typescript,
  compilerOptions: contract.compilerOptions,
};

if (JSON.stringify(actual) !== JSON.stringify(expected)) {
  console.error("bitwarden/clients TypeScript contract drifted.");
  console.error(`Expected: ${JSON.stringify(expected, null, 2)}`);
  console.error(`Actual:   ${JSON.stringify(actual, null, 2)}`);
  process.exit(1);
}

console.log("bitwarden/clients TypeScript contract matches the pinned clean-room fixture");
