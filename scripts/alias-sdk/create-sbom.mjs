#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const [artifactDirectory, cargoMetadataFile, cargoActiveFile, packageLockFile, outputFile] =
  process.argv.slice(2);
if (!artifactDirectory || !cargoMetadataFile || !cargoActiveFile || !packageLockFile || !outputFile) {
  console.error(
    "Usage: create-sbom.mjs ARTIFACT_DIRECTORY CARGO_METADATA_JSON CARGO_ACTIVE_PACKAGES " +
      "PACKAGE_LOCK_JSON OUTPUT_JSON",
  );
  process.exit(2);
}

const readJson = (file) => JSON.parse(fs.readFileSync(file, "utf8"));
const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const cargo = readJson(cargoMetadataFile);
const npmLock = readJson(packageLockFile);
const packagesById = new Map(cargo.packages.map((pkg) => [pkg.id, pkg]));
const nodesById = new Map((cargo.resolve?.nodes ?? []).map((node) => [node.id, node]));
const activeCargoPackages = new Set(
  fs
    .readFileSync(cargoActiveFile, "utf8")
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean),
);
const selectedCargoIds = new Set(
  cargo.packages
    .filter((pkg) => activeCargoPackages.has(`${pkg.name}@${pkg.version}`))
    .map((pkg) => pkg.id),
);
for (const rootName of ["bitwarden-alias", "bitwarden-uniffi", "bitwarden-wasm-internal"]) {
  if (![...selectedCargoIds].some((id) => packagesById.get(id)?.name === rootName)) {
    throw new Error(`Active Cargo package graph is missing ${rootName}`);
  }
}

const forbiddenCargoPackages = ["bitwarden-commercial-vault", "bitwarden-pam", "bitwarden-sm"];
const forbiddenFound = [...selectedCargoIds]
  .map((id) => packagesById.get(id)?.name)
  .filter((name) => forbiddenCargoPackages.includes(name));
if (forbiddenFound.length > 0) {
  throw new Error(`Commercial packages entered the public SBOM graph: ${forbiddenFound.join(", ")}`);
}

const cargoRef = (pkg) => `pkg:cargo/${encodeURIComponent(pkg.name)}@${encodeURIComponent(pkg.version)}`;
const cargoComponents = [...selectedCargoIds]
  .map((id) => packagesById.get(id))
  .filter(Boolean)
  .sort((a, b) => cargoRef(a).localeCompare(cargoRef(b)))
  .map((pkg) => {
    const component = {
      type: "library",
      "bom-ref": cargoRef(pkg),
      name: pkg.name,
      version: pkg.version,
      purl: cargoRef(pkg),
      properties: [{ name: "bitwarden:ecosystem", value: "cargo" }],
    };
    if (pkg.license) component.licenses = [{ expression: pkg.license }];
    if (pkg.repository) component.externalReferences = [{ type: "vcs", url: pkg.repository }];
    return component;
  });

const cargoDependencies = [...selectedCargoIds]
  .map((id) => {
    const pkg = packagesById.get(id);
    if (!pkg) return undefined;
    const dependsOn = (nodesById.get(id)?.dependencies ?? [])
      .filter((dependencyId) => selectedCargoIds.has(dependencyId))
      .map((dependencyId) => cargoRef(packagesById.get(dependencyId)))
      .sort();
    return { ref: cargoRef(pkg), dependsOn };
  })
  .filter(Boolean)
  .sort((a, b) => a.ref.localeCompare(b.ref));

const npmPurlName = (name) => {
  if (!name.startsWith("@")) return encodeURIComponent(name);
  const [scope, packageName] = name.split("/", 2);
  return `${encodeURIComponent(scope)}/${encodeURIComponent(packageName)}`;
};
const npmComponentsByRef = new Map();
Object.entries(npmLock.packages ?? {})
  .filter(([packagePath, value]) => packagePath.startsWith("node_modules/") && value?.version)
  .map(([packagePath, value]) => {
    const name = packagePath.split("node_modules/").at(-1);
    const purl = `pkg:npm/${npmPurlName(name)}@${encodeURIComponent(value.version)}`;
    const component = {
      type: "library",
      "bom-ref": purl,
      name,
      version: value.version,
      purl,
      scope: "optional",
      properties: [
        { name: "bitwarden:ecosystem", value: "npm" },
        { name: "bitwarden:sbom:scope", value: "build" },
      ],
    };
    if (value.license) component.licenses = [{ expression: value.license }];
    if (value.integrity?.startsWith("sha512-")) {
      component.hashes = [
        {
          alg: "SHA-512",
          content: Buffer.from(value.integrity.slice("sha512-".length), "base64").toString("hex"),
        },
      ];
    }
    return component;
  })
  .forEach((component) => npmComponentsByRef.set(component["bom-ref"], component));
const npmComponents = [...npmComponentsByRef.values()].sort((a, b) =>
  a["bom-ref"].localeCompare(b["bom-ref"]),
);

const walk = (directory) =>
  fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const entryPath = path.join(directory, entry.name);
    return entry.isDirectory() ? walk(entryPath) : [entryPath];
  });
const artifactComponents = walk(artifactDirectory)
  .sort()
  .map((file) => {
    const relativePath = path.relative(artifactDirectory, file).split(path.sep).join("/");
    const bytes = fs.readFileSync(file);
    return {
      type: "file",
      "bom-ref": `urn:bitwarden:alias-sdk-artifact:${encodeURIComponent(relativePath)}`,
      name: relativePath,
      hashes: [{ alg: "SHA-256", content: sha256(bytes) }],
      properties: [{ name: "bitwarden:size", value: String(bytes.length) }],
    };
  });

const bom = {
  bomFormat: "CycloneDX",
  specVersion: "1.6",
  version: 1,
  metadata: {
    tools: {
      components: [
        {
          type: "application",
          name: "bitwarden-alias-sdk-release-tooling",
          version: "1",
        },
      ],
    },
    properties: [
      { name: "bitwarden:candidate-only", value: "true" },
      { name: "bitwarden:license-boundary", value: "GPL-only" },
    ],
  },
  components: [...artifactComponents, ...cargoComponents, ...npmComponents],
  dependencies: cargoDependencies,
};

fs.mkdirSync(path.dirname(outputFile), { recursive: true });
fs.writeFileSync(outputFile, `${JSON.stringify(bom, null, 2)}\n`);
console.log(
  `Created CycloneDX SBOM with ${artifactComponents.length} artifacts, ` +
    `${cargoComponents.length} Cargo components, and ${npmComponents.length} npm build components`,
);
