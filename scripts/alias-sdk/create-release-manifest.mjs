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
if (path.resolve(artifactDirectory) !== path.join(path.resolve(outputDirectory), "artifacts")) {
  throw new Error("ARTIFACT_DIRECTORY must be the artifacts child of OUTPUT_DIRECTORY");
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
const previousPublicAliasHead = requireFullCommit(
  readTrimmed(requireFile("PREVIOUS_PUBLIC_ALIAS_HEAD_FILE")),
  "PREVIOUS_PUBLIC_ALIAS_HEAD_FILE",
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
const iosIntegration = readJson(requireFile("IOS_INTEGRATION_FILE"));
const conformance = readJson(requireFile("CONFORMANCE_VECTORS_FILE"));
if (
  integration.schemaVersion !== 1 ||
  integration.aliasReferenceSchemaVersion !== aliasReferenceSchemaVersion ||
  !Array.isArray(integration.requiredClientIntegrationSteps) ||
  integration.requiredClientIntegrationSteps.length === 0
) {
  throw new Error("CLIENT_INTEGRATION_FILE has an unsupported or empty schema");
}
requireFullCommit(iosIntegration.commit, "IOS_INTEGRATION_FILE commit");
requireFullCommit(iosIntegration.currentSdkSwift?.commit, "IOS_INTEGRATION_FILE SDK commit");
if (
  iosIntegration.branch !== "feat/first-class-aliases" ||
  iosIntegration.requiredArtifact !== "swift" ||
  iosIntegration.aliasReferenceSchemaVersion !== aliasReferenceSchemaVersion ||
  iosIntegration.integrationStatus !== "requires-provider-neutral-repin"
) {
  throw new Error("IOS_INTEGRATION_FILE has an unsupported integration contract");
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
    path: `artifacts/${path.relative(artifactDirectory, file).split(path.sep).join("/")}`,
    bytes: bytes.length,
    sha256: crypto.createHash("sha256").update(bytes).digest("hex"),
  };
});
const artifactByPath = new Map(artifacts.map((artifact) => [artifact.path, artifact]));
const assertPackageProvenance = (directory) => {
  const sourcePath = `artifacts/${directory}/VERSION`;
  const versionPath = `artifacts/${directory}/PACKAGE_VERSION`;
  const schemaPath = `artifacts/${directory}/ALIAS_REFERENCE_SCHEMA_VERSION`;
  const apiReportPath = `artifacts/${directory}/API-REPORT.txt`;
  const reproducibilityPath = `artifacts/${directory}/REPRODUCIBILITY.txt`;
  if (
    !artifactByPath.has(sourcePath) ||
    !artifactByPath.has(versionPath) ||
    !artifactByPath.has(schemaPath) ||
    !artifactByPath.has(apiReportPath) ||
    !artifactByPath.has(reproducibilityPath)
  ) {
    throw new Error(
      `${directory} is missing source, package, schema, API, or reproducibility evidence`,
    );
  }
  if (
    readTrimmed(path.join(artifactDirectory, sourcePath.slice("artifacts/".length))) !==
    sourceCommit
  ) {
    throw new Error(`${sourcePath} does not match SOURCE_COMMIT`);
  }
  if (
    readTrimmed(path.join(artifactDirectory, versionPath.slice("artifacts/".length))) !==
    releaseVersion
  ) {
    throw new Error(`${versionPath} does not match RELEASE_VERSION_FILE`);
  }
  if (
    readTrimmed(path.join(artifactDirectory, schemaPath.slice("artifacts/".length))) !==
    String(aliasReferenceSchemaVersion)
  ) {
    throw new Error(`${schemaPath} does not match ALIAS_REFERENCE_SCHEMA_VERSION_FILE`);
  }
  if (
    !readTrimmed(
      path.join(artifactDirectory, reproducibilityPath.slice("artifacts/".length)),
    ).includes("reproducible=true")
  ) {
    throw new Error(`${reproducibilityPath} does not record an exact rebuild match`);
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
      artifactPath.startsWith("artifacts/alias-sdk-typescript/") && artifactPath.endsWith(".tgz"),
  },
  {
    id: "swift",
    name: "BitwardenSdk",
    format: "swift-package-tarball",
    matches: (artifactPath) =>
      artifactPath.startsWith("artifacts/alias-sdk-swift/") && artifactPath.endsWith(".tar.gz"),
  },
  {
    id: "kotlinJvm",
    name: "bitwarden-alias-sdk-kotlin-host",
    format: "jar-with-host-native-library",
    matches: (artifactPath) =>
      artifactPath.startsWith("artifacts/alias-sdk-kotlin/") && artifactPath.endsWith(".jar"),
    supportingMatches: (artifactPath) =>
      artifactPath.startsWith("artifacts/alias-sdk-kotlin/") &&
      (artifactPath.endsWith(".so") || artifactPath.endsWith(".dylib")),
  },
  {
    id: "android",
    name: "com.bitwarden.sdk",
    format: "aar",
    matches: (artifactPath) =>
      artifactPath.startsWith("artifacts/alias-sdk-android/") && artifactPath.endsWith(".aar"),
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

const sbomFile = requireFile("SBOM_FILE");
const sbom = readJson(sbomFile);
if (sbom.bomFormat !== "CycloneDX" || sbom.specVersion !== "1.6") {
  throw new Error("SBOM_FILE must be a CycloneDX 1.6 document");
}
const auditPath = "artifacts/alias-sdk-assurance/AUDIT-REPORT.json";
const auditArtifact = artifactByPath.get(auditPath);
if (!auditArtifact) throw new Error(`${auditPath} is missing`);
const audit = readJson(path.join(artifactDirectory, "alias-sdk-assurance/AUDIT-REPORT.json"));
if (
  audit.cargo?.unacceptedVulnerabilityCount !== 0 ||
  !Array.isArray(audit.cargo?.acceptedRisks) ||
  audit.npm?.vulnerabilities?.total !== 0
) {
  throw new Error("Dependency audit evidence has unaccepted or malformed findings");
}
const sbomBytes = fs.readFileSync(sbomFile);
const sbomArtifact = {
  path: "SBOM.cdx.json",
  bytes: sbomBytes.length,
  sha256: crypto.createHash("sha256").update(sbomBytes).digest("hex"),
};

const sourceRepository =
  process.env.SOURCE_REPOSITORY ?? "https://github.com/bitwarden/sdk-internal";
const workflowRepository = process.env.GITHUB_REPOSITORY ?? "";
const workflowRef = process.env.GITHUB_WORKFLOW_REF ?? "";
const workflowRunId = process.env.GITHUB_RUN_ID ?? "";
const workflowRunAttempt = process.env.GITHUB_RUN_ATTEMPT ?? "";
const keylessAttestationExpected = process.env.KEYLESS_ATTESTATION_EXPECTED === "true";
const manifest = {
  schemaVersion: 3,
  aliasReferenceSchemaVersion,
  sourceCommit,
  releaseVersion,
  releaseChannel: "unreleased-prerelease",
  candidatePolicy: {
    registriesPublished: false,
    gitTagCreated: false,
    githubReleaseCreated: false,
  },
  integrationBase,
  previousPublicAliasHead,
  upstreamBase,
  providerPin: {
    adapterId: "simplelogin",
    repository: "https://github.com/simple-login/app.git",
    commit: providerCommit,
  },
  clientsContract: readJson(requireFile("CLIENTS_CONTRACT_FILE")),
  iosIntegrationContract: iosIntegration,
  packages,
  evidence: {
    sbom: sbomArtifact,
    dependencyAudit: auditArtifact,
    acceptedAuditRisks: audit.cargo.acceptedRisks,
    apiReports: Object.fromEntries(
      ["alias-sdk-typescript", "alias-sdk-swift", "alias-sdk-kotlin", "alias-sdk-android"].map(
        (directory) => [directory, artifactByPath.get(`artifacts/${directory}/API-REPORT.txt`)],
      ),
    ),
    reproducibility: Object.fromEntries(
      ["alias-sdk-typescript", "alias-sdk-swift", "alias-sdk-kotlin", "alias-sdk-android"].map(
        (directory) => [
          directory,
          artifactByPath.get(`artifacts/${directory}/REPRODUCIBILITY.txt`),
        ],
      ),
    ),
  },
  provenance: {
    sourceRepository,
    builderId: workflowRepository
      ? `https://github.com/${workflowRepository}/actions/runs/${workflowRunId}/attempts/${workflowRunAttempt}`
      : "local-unsigned",
    workflowRef,
    eventName: process.env.GITHUB_EVENT_NAME ?? "local",
    keylessAttestation: keylessAttestationExpected
      ? {
          issuer: "https://token.actions.githubusercontent.com",
          strategy: "GitHub artifact attestation over every candidate file",
          verification: `gh attestation verify --repo ${workflowRepository} <candidate-file>`,
        }
      : null,
  },
  requiredClientIntegrationSteps: integration.requiredClientIntegrationSteps,
  artifacts,
};

fs.mkdirSync(outputDirectory, { recursive: true });
fs.copyFileSync(sbomFile, path.join(outputDirectory, "SBOM.cdx.json"));
fs.writeFileSync(
  path.join(outputDirectory, "handoff-manifest.json"),
  `${JSON.stringify(manifest, null, 2)}\n`,
);
fs.writeFileSync(
  path.join(outputDirectory, "SHA256SUMS"),
  `${[...artifacts, sbomArtifact]
    .map(({ sha256, path: artifactPath }) => `${sha256}  ${artifactPath}`)
    .join("\n")}\n`,
);
console.log(
  `Handoff manifest records ${Object.keys(packages).length} packages and ${artifacts.length} files from ${sourceCommit}`,
);
