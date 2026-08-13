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

const requireFullCommit = (value, label) => {
  if (!/^[0-9a-f]{40}$/.test(value ?? "")) {
    throw new Error(`${label} must be a full Git commit SHA`);
  }
  return value;
};
const requireFile = (environmentName) => {
  const file = process.env[environmentName];
  if (!file || !fs.statSync(file, { throwIfNoEntry: false })?.isFile()) {
    throw new Error(`${environmentName} must name a readable file`);
  }
  return file;
};
const readJson = (file) => JSON.parse(fs.readFileSync(file, "utf8"));
const readTrimmed = (file) => fs.readFileSync(file, "utf8").trim();

const sourceCommit = requireFullCommit(process.env.SOURCE_COMMIT, "SOURCE_COMMIT");
const upstreamBase = requireFullCommit(
  readTrimmed(requireFile("UPSTREAM_BASE_FILE")),
  "UPSTREAM_BASE_FILE",
);
const integrationBase = requireFullCommit(
  readTrimmed(requireFile("INTEGRATION_BASE_FILE")),
  "INTEGRATION_BASE_FILE",
);
const providerCommit = requireFullCommit(
  readTrimmed(requireFile("PROVIDER_PIN_FILE")),
  "PROVIDER_PIN_FILE",
);
const releaseVersion = readTrimmed(requireFile("RELEASE_VERSION_FILE"));
if (!/^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/.test(releaseVersion)) {
  throw new Error(`RELEASE_VERSION_FILE is not valid SemVer: ${releaseVersion}`);
}
const aliasReferenceSchemaVersionText = readTrimmed(
  requireFile("ALIAS_REFERENCE_SCHEMA_VERSION_FILE"),
);
const aliasReferenceSchemaVersion = Number(aliasReferenceSchemaVersionText);
if (aliasReferenceSchemaVersionText !== "1" || aliasReferenceSchemaVersion !== 1) {
  throw new Error("ALIAS_REFERENCE_SCHEMA_VERSION_FILE must identify schema version 1");
}

const typescriptPackage = readJson(requireFile("TYPESCRIPT_PACKAGE_FILE"));
if (typescriptPackage.name !== "@bitwarden/sdk-internal") {
  throw new Error("The TypeScript package name is no longer @bitwarden/sdk-internal");
}
if (typescriptPackage.version !== releaseVersion) {
  throw new Error(
    `TypeScript package version ${typescriptPackage.version} does not match ${releaseVersion}`,
  );
}
if (typescriptPackage.aliasReferenceSchemaVersion !== aliasReferenceSchemaVersion) {
  throw new Error("The TypeScript package has the wrong alias reference schema version");
}

const integration = readJson(requireFile("CLIENT_INTEGRATION_FILE"));
const conformance = readJson(requireFile("CONFORMANCE_VECTORS_FILE"));
if (
  integration.schemaVersion !== 1 ||
  integration.aliasReferenceSchemaVersion !== aliasReferenceSchemaVersion ||
  !Array.isArray(integration.requiredClientIntegrationSteps) ||
  integration.requiredClientIntegrationSteps.length === 0
) {
  throw new Error("CLIENT_INTEGRATION_FILE has an unsupported or empty schema");
}
if (conformance.referenceSchema?.version !== integration.aliasReferenceSchemaVersion) {
  throw new Error("Release metadata and conformance vectors disagree on the alias schema");
}

const walk = (directory) =>
  fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const entryPath = path.join(directory, entry.name);
    return entry.isDirectory() ? walk(entryPath) : [entryPath];
  });
const files = walk(artifactDirectory).sort();
if (files.length === 0) {
  throw new Error("Release manifest gate failed: no artifacts were downloaded");
}

const artifacts = files.map((file) => {
  const bytes = fs.readFileSync(file);
  return {
    path: path.relative(artifactDirectory, file).split(path.sep).join("/"),
    bytes: bytes.length,
    sha256: crypto.createHash("sha256").update(bytes).digest("hex"),
  };
});
const artifactByPath = new Map(artifacts.map((artifact) => [artifact.path, artifact]));
const assertPackageProvenance = (directory) => {
  const sourcePath = `${directory}/VERSION`;
  const versionPath = `${directory}/PACKAGE_VERSION`;
  const schemaPath = `${directory}/ALIAS_REFERENCE_SCHEMA_VERSION`;
  if (
    !artifactByPath.has(sourcePath) ||
    !artifactByPath.has(versionPath) ||
    !artifactByPath.has(schemaPath)
  ) {
    throw new Error(`${directory} is missing source, package, or schema provenance`);
  }
  if (readTrimmed(path.join(artifactDirectory, sourcePath)) !== sourceCommit) {
    throw new Error(`${sourcePath} does not match SOURCE_COMMIT`);
  }
  if (readTrimmed(path.join(artifactDirectory, versionPath)) !== releaseVersion) {
    throw new Error(`${versionPath} does not match RELEASE_VERSION_FILE`);
  }
  if (
    readTrimmed(path.join(artifactDirectory, schemaPath)) !== String(aliasReferenceSchemaVersion)
  ) {
    throw new Error(`${schemaPath} does not match ALIAS_REFERENCE_SCHEMA_VERSION_FILE`);
  }
};

for (const directory of [
  "alias-sdk-typescript",
  "alias-sdk-swift",
  "alias-sdk-kotlin",
  "alias-sdk-android",
]) {
  assertPackageProvenance(directory);
}

const packageDefinitions = [
  {
    id: "typescriptWasm",
    name: "@bitwarden/sdk-internal",
    format: "npm-tarball",
    matches: (artifactPath) =>
      artifactPath.startsWith("alias-sdk-typescript/") && artifactPath.endsWith(".tgz"),
  },
  {
    id: "swift",
    name: "BitwardenSdk",
    format: "swift-package-tarball",
    matches: (artifactPath) =>
      artifactPath.startsWith("alias-sdk-swift/") && artifactPath.endsWith(".tar.gz"),
  },
  {
    id: "kotlinJvm",
    name: "bitwarden-alias-sdk-kotlin-host",
    format: "jar-with-host-native-library",
    matches: (artifactPath) =>
      artifactPath.startsWith("alias-sdk-kotlin/") && artifactPath.endsWith(".jar"),
    supportingMatches: (artifactPath) =>
      artifactPath.startsWith("alias-sdk-kotlin/") && artifactPath.endsWith(".so"),
  },
  {
    id: "android",
    name: "com.bitwarden.sdk",
    format: "aar",
    matches: (artifactPath) =>
      artifactPath.startsWith("alias-sdk-android/") && artifactPath.endsWith(".aar"),
  },
];
const packages = Object.fromEntries(
  packageDefinitions.map(({ id, name, format, matches, supportingMatches }) => {
    const matchingArtifacts = artifacts.filter(({ path: artifactPath }) => matches(artifactPath));
    if (matchingArtifacts.length !== 1) {
      throw new Error(
        `Release manifest expected exactly one ${id} package, found ${matchingArtifacts.length}`,
      );
    }
    const packageRecord = {
      name,
      version: releaseVersion,
      aliasReferenceSchemaVersion,
      format,
      artifact: matchingArtifacts[0],
    };
    if (supportingMatches) {
      const supportingArtifacts = artifacts.filter(({ path: artifactPath }) =>
        supportingMatches(artifactPath),
      );
      if (supportingArtifacts.length !== 1) {
        throw new Error(
          `Release manifest expected exactly one ${id} supporting artifact, found ${supportingArtifacts.length}`,
        );
      }
      packageRecord.supportingArtifacts = supportingArtifacts;
    }
    return [id, packageRecord];
  }),
);

const manifest = {
  schemaVersion: 2,
  aliasReferenceSchemaVersion,
  sourceCommit,
  releaseVersion,
  integrationBase,
  upstreamBase,
  providerPin: {
    provider: "SimpleLogin",
    repository: "https://github.com/simple-login/app.git",
    commit: providerCommit,
  },
  clientsContract: readJson(requireFile("CLIENTS_CONTRACT_FILE")),
  packages,
  requiredClientIntegrationSteps: integration.requiredClientIntegrationSteps,
  artifacts,
};

fs.mkdirSync(outputDirectory, { recursive: true });
fs.writeFileSync(
  path.join(outputDirectory, "handoff-manifest.json"),
  `${JSON.stringify(manifest, null, 2)}\n`,
);
fs.writeFileSync(
  path.join(outputDirectory, "SHA256SUMS"),
  `${artifacts.map(({ sha256, path: artifactPath }) => `${sha256}  ${artifactPath}`).join("\n")}\n`,
);
console.log(
  `Handoff manifest records ${Object.keys(packages).length} packages and ${artifacts.length} files from ${sourceCommit}`,
);
