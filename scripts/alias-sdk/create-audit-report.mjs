#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const [cargoAuditFile, npmAuditFile, cargoActiveFile, policyFile, outputFile] =
  process.argv.slice(2);
if (!cargoAuditFile || !npmAuditFile || !cargoActiveFile || !policyFile || !outputFile) {
  console.error(
    "Usage: create-audit-report.mjs CARGO_AUDIT_JSON NPM_AUDIT_JSON " +
      "CARGO_ACTIVE_PACKAGES AUDIT_POLICY_JSON OUTPUT_JSON",
  );
  process.exit(2);
}

const readJson = (file) => JSON.parse(fs.readFileSync(file, "utf8"));
const cargo = readJson(cargoAuditFile);
const npm = readJson(npmAuditFile);
const policy = readJson(policyFile);
if (
  policy.schemaVersion !== 1 ||
  !Array.isArray(policy.exceptions) ||
  policy.exceptions.length !== 1
) {
  throw new Error("Audit policy schema is unsupported");
}
const activeCargoPackages = new Set(
  fs
    .readFileSync(cargoActiveFile, "utf8")
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean),
);
const cargoVulnerabilities = cargo.vulnerabilities?.list ?? [];
const npmTotals = npm.metadata?.vulnerabilities;
if (!npmTotals || typeof npmTotals !== "object") {
  throw new Error("npm audit did not return vulnerability metadata");
}
for (const severity of ["info", "low", "moderate", "high", "critical", "total"]) {
  const value = npmTotals[severity];
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`npm audit returned an invalid ${severity} count`);
  }
}
if (!Number.isSafeInteger(npm.metadata?.dependencies?.total)) {
  throw new Error("npm audit did not return dependency metadata");
}
const npmTotal = Number(npmTotals.total ?? 0);
const activeVulnerabilities = cargoVulnerabilities.filter((entry) =>
  activeCargoPackages.has(`${entry.package?.name}@${entry.package?.version}`),
);
const today = new Date().toISOString().slice(0, 10);
const acceptedRisks = [];
const unacceptedVulnerabilities = [];
for (const finding of activeVulnerabilities) {
  const exception = policy.exceptions.find(
    (entry) =>
      entry.advisoryId === finding.advisory?.id &&
      entry.package === finding.package?.name &&
      entry.version === finding.package?.version,
  );
  if (!exception || exception.expiresOn < today) {
    unacceptedVulnerabilities.push(finding);
    continue;
  }
  if (!/^\d{4}-\d{2}-\d{2}$/.test(exception.expiresOn) || exception.expiresOn > "2026-10-01") {
    throw new Error(`Audit exception ${exception.advisoryId} has an invalid or overlong expiry`);
  }
  for (const requiredField of ["dependencyPath", "riskOwner", "rationale", "limitation"]) {
    if (typeof exception[requiredField] !== "string" || exception[requiredField].length < 20) {
      throw new Error(
        `Audit exception ${exception.advisoryId} has no substantive ${requiredField}`,
      );
    }
  }
  if (!/^\d{4}-\d{2}-\d{2}$/.test(exception.reviewedOn) || exception.reviewedOn > today) {
    throw new Error(`Audit exception ${exception.advisoryId} has an invalid review date`);
  }
  acceptedRisks.push(exception);
}
for (const exception of policy.exceptions) {
  if (!acceptedRisks.includes(exception)) {
    throw new Error(
      `Audit exception ${exception.advisoryId} is expired, stale, or not an active finding`,
    );
  }
}
const activeWarnings = Object.values(cargo.warnings ?? {})
  .flat()
  .filter((entry) => activeCargoPackages.has(`${entry.package?.name}@${entry.package?.version}`))
  .map((entry) => ({
    kind: entry.kind,
    advisoryId: entry.advisory?.id,
    package: entry.package?.name,
    version: entry.package?.version,
  }))
  .sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));

const report = {
  schemaVersion: 1,
  candidateOnly: true,
  cargo: {
    auditedDependencies: cargo.lockfile?.["dependency-count"] ?? null,
    activeDependencyCount: activeCargoPackages.size,
    vulnerabilityCount: activeVulnerabilities.length,
    unacceptedVulnerabilityCount: unacceptedVulnerabilities.length,
    advisories: activeVulnerabilities
      .map((entry) => ({
        id: entry.advisory?.id,
        package: entry.package?.name,
        version: entry.package?.version,
      }))
      .sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b))),
    acceptedRisks,
    informationalWarnings: activeWarnings,
  },
  npm: {
    auditedDependencies: Number(npm.metadata?.dependencies?.total ?? 0),
    vulnerabilities: Object.fromEntries(
      ["info", "low", "moderate", "high", "critical", "total"].map((severity) => [
        severity,
        Number(npmTotals[severity] ?? 0),
      ]),
    ),
  },
};

if (report.cargo.unacceptedVulnerabilityCount !== 0 || npmTotal !== 0) {
  throw new Error(
    `Dependency audit failed: unaccepted Cargo=${report.cargo.unacceptedVulnerabilityCount}, ` +
      `npm=${npmTotal}`,
  );
}

fs.mkdirSync(path.dirname(outputFile), { recursive: true });
fs.writeFileSync(outputFile, `${JSON.stringify(report, null, 2)}\n`);
console.log(
  `Created dependency audit report with ${acceptedRisks.length} accepted Cargo risk(s) and ` +
    "zero unaccepted vulnerabilities",
);
