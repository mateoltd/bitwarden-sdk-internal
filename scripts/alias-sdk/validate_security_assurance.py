#!/usr/bin/env python3
"""Validate the public-alias security assurance traceability manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from collections import deque
from pathlib import Path
from typing import Any


REQUIRED_OPERATIONS = {
    "create",
    "persist",
    "sync",
    "autofill",
    "send-reply",
    "reconcile",
    "revoke",
    "backup-restore",
    "provider-replacement",
}
CLAIM_STATUSES = {"supported", "assumption-bound", "gap"}
EVIDENCE_TYPES = {"proof", "test", "operational"}
GRAPH_RELATIONS = {"supportedBy", "dependsOn", "boundedBy", "limitedBy"}
ID_PATTERN = re.compile(r"^(?:C|A|EV)-[A-Z0-9-]+$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
TOP_LEVEL_KEYS = {
    "schemaVersion",
    "subject",
    "evaluation",
    "scope",
    "assumptions",
    "evidence",
    "claims",
    "graph",
}


class DuplicateKeyError(ValueError):
    """Raised when JSON repeats a key."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _index(items: Any, kind: str, errors: list[str]) -> dict[str, dict[str, Any]]:
    if not isinstance(items, list):
        errors.append(f"{kind} must be an array")
        return {}
    indexed: dict[str, dict[str, Any]] = {}
    for position, item in enumerate(items):
        if not isinstance(item, dict):
            errors.append(f"{kind}[{position}] must be an object")
            continue
        item_id = item.get("id")
        if not isinstance(item_id, str) or not ID_PATTERN.fullmatch(item_id):
            errors.append(f"{kind}[{position}] has an invalid id")
            continue
        if item_id in indexed:
            errors.append(f"duplicate {kind} id: {item_id}")
            continue
        indexed[item_id] = item
    return indexed


def _git(repository_root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repository_root), *arguments],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _validate_git(
    repository_root: Path, evaluation: Any, errors: list[str]
) -> None:
    if not isinstance(evaluation, dict):
        errors.append("evaluation must be an object")
        return
    base = evaluation.get("baseCommit")
    if not isinstance(base, str) or not COMMIT_PATTERN.fullmatch(base):
        errors.append("evaluation.baseCommit must be a full lowercase commit id")
        return
    if _git(repository_root, "cat-file", "-e", f"{base}^{{commit}}").returncode:
        errors.append(f"evaluated base commit is unavailable: {base}")
        return
    if _git(repository_root, "merge-base", "--is-ancestor", base, "HEAD").returncode:
        errors.append(f"evaluated base commit is not an ancestor of HEAD: {base}")

    sources = evaluation.get("sourceBranches")
    if not isinstance(sources, list) or not sources:
        errors.append("evaluation.sourceBranches must be a non-empty array")
        return
    for position, source in enumerate(sources):
        if not isinstance(source, dict):
            errors.append(f"evaluation.sourceBranches[{position}] must be an object")
            continue
        name = source.get("name")
        commit = source.get("commit")
        if not isinstance(name, str) or not name.startswith("origin/"):
            errors.append(f"evaluation.sourceBranches[{position}] has an invalid name")
        if not isinstance(commit, str) or not COMMIT_PATTERN.fullmatch(commit):
            errors.append(f"evaluation.sourceBranches[{position}] has an invalid commit")
            continue
        if _git(repository_root, "cat-file", "-e", f"{commit}^{{commit}}").returncode:
            errors.append(f"audited source commit is unavailable: {commit}")
        elif _git(repository_root, "merge-base", "--is-ancestor", commit, base).returncode:
            errors.append(f"audited source commit is not in evaluated base: {commit}")


def validate_manifest(
    repository_root: Path, manifest_path: Path, *, check_git: bool = True
) -> list[str]:
    """Return deterministic validation errors; an empty list means success."""

    root = repository_root.resolve()
    errors: list[str] = []
    try:
        raw = manifest_path.read_text(encoding="utf-8")
        manifest = json.loads(raw, object_pairs_hook=_unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError, DuplicateKeyError) as error:
        return [f"manifest could not be loaded: {error}"]
    if not isinstance(manifest, dict):
        return ["manifest root must be an object"]

    missing_keys = TOP_LEVEL_KEYS - set(manifest)
    unknown_keys = set(manifest) - TOP_LEVEL_KEYS
    if missing_keys:
        errors.append(f"missing top-level keys: {', '.join(sorted(missing_keys))}")
    if unknown_keys:
        errors.append(f"unknown top-level keys: {', '.join(sorted(unknown_keys))}")
    if manifest.get("schemaVersion") != 1:
        errors.append("schemaVersion must be 1")
    if manifest.get("subject") != "public-alias-end-to-end-security-assurance":
        errors.append("subject is not the public alias assurance case")

    scope = manifest.get("scope")
    if not isinstance(scope, dict):
        errors.append("scope must be an object")
    else:
        operations = scope.get("requiredOperations")
        operation_set = set(operations) if isinstance(operations, list) else set()
        if operation_set != REQUIRED_OPERATIONS or len(operations or []) != len(operation_set):
            errors.append("scope.requiredOperations must contain each required operation once")
        excluded = scope.get("excluded")
        required_exclusions = {
            "personal-migration",
            "domains",
            "provider-branding",
            "secret-material",
        }
        if not isinstance(excluded, list) or not required_exclusions.issubset(excluded):
            errors.append("scope.excluded is missing a required exclusion")
        if scope.get("mathematicalScope") != "not-a-full-socio-technical-proof":
            errors.append("scope.mathematicalScope must disclaim a full system proof")

    assumptions = _index(manifest.get("assumptions"), "assumption", errors)
    evidence = _index(manifest.get("evidence"), "evidence", errors)
    claims = _index(manifest.get("claims"), "claim", errors)

    for assumption_id, assumption in assumptions.items():
        if assumption.get("proofStatus") != "not-mathematically-proven":
            errors.append(f"{assumption_id} does not flag its unproved status")
        if not isinstance(assumption.get("statement"), str) or not assumption["statement"].strip():
            errors.append(f"{assumption_id} has no statement")

    for evidence_id, item in evidence.items():
        if item.get("type") not in EVIDENCE_TYPES:
            errors.append(f"{evidence_id} has an invalid evidence type")
        relative = item.get("path")
        expected_hash = item.get("sha256")
        anchors = item.get("anchors")
        if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
            errors.append(f"{evidence_id} has an invalid relative path")
            continue
        candidate = (root / relative).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            errors.append(f"{evidence_id} path escapes the repository")
            continue
        if not candidate.is_file():
            errors.append(f"{evidence_id} evidence file is missing: {relative}")
            continue
        if not isinstance(expected_hash, str) or not SHA256_PATTERN.fullmatch(expected_hash):
            errors.append(f"{evidence_id} has an invalid SHA-256")
        else:
            actual_hash = _sha256(candidate)
            if actual_hash != expected_hash:
                errors.append(
                    f"{evidence_id} evidence is stale: expected {expected_hash}, got {actual_hash}"
                )
        if not isinstance(anchors, list) or not anchors or not all(
            isinstance(anchor, str) and anchor for anchor in anchors
        ):
            errors.append(f"{evidence_id} must declare non-empty text anchors")
            continue
        try:
            content = candidate.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            errors.append(f"{evidence_id} evidence is not readable UTF-8 text: {error}")
            continue
        for anchor in anchors:
            if anchor not in content:
                errors.append(f"{evidence_id} anchor is missing from {relative}: {anchor}")

    covered_operations: set[str] = set()
    used_evidence: set[str] = set()
    used_assumptions: set[str] = set()
    for claim_id, claim in claims.items():
        status = claim.get("status")
        if status not in CLAIM_STATUSES:
            errors.append(f"{claim_id} has an invalid status")
        claim_evidence = claim.get("evidence")
        if not isinstance(claim_evidence, list) or not claim_evidence:
            errors.append(f"{claim_id} has no proof, test, or operational evidence")
        else:
            for evidence_id in claim_evidence:
                if evidence_id not in evidence:
                    errors.append(f"{claim_id} references unknown evidence: {evidence_id}")
                else:
                    used_evidence.add(evidence_id)
        claim_assumptions = claim.get("assumptions")
        if not isinstance(claim_assumptions, list):
            errors.append(f"{claim_id}.assumptions must be an array")
            claim_assumptions = []
        if status == "assumption-bound" and not claim_assumptions:
            errors.append(f"{claim_id} is assumption-bound but has no assumptions")
        for assumption_id in claim_assumptions:
            if assumption_id not in assumptions:
                errors.append(f"{claim_id} references unknown assumption: {assumption_id}")
            else:
                used_assumptions.add(assumption_id)
        operations = claim.get("operations")
        if not isinstance(operations, list):
            errors.append(f"{claim_id}.operations must be an array")
        else:
            unknown_operations = set(operations) - REQUIRED_OPERATIONS
            if unknown_operations:
                errors.append(
                    f"{claim_id} references unknown operations: {', '.join(sorted(unknown_operations))}"
                )
            covered_operations.update(set(operations) & REQUIRED_OPERATIONS)
        if not isinstance(claim.get("statement"), str) or not claim["statement"].strip():
            errors.append(f"{claim_id} has no statement")

    missing_coverage = REQUIRED_OPERATIONS - covered_operations
    if missing_coverage:
        errors.append(f"claims do not cover operations: {', '.join(sorted(missing_coverage))}")
    for evidence_id in evidence.keys() - used_evidence:
        errors.append(f"unreferenced evidence: {evidence_id}")
    for assumption_id in assumptions.keys() - used_assumptions:
        errors.append(f"unreferenced assumption: {assumption_id}")

    graph = manifest.get("graph")
    root_claim = None
    edges: Any = None
    if not isinstance(graph, dict):
        errors.append("graph must be an object")
    else:
        root_claim = graph.get("rootClaim")
        edges = graph.get("edges")
    known_nodes = set(claims) | set(assumptions)
    adjacency: dict[str, set[str]] = {node: set() for node in known_nodes}
    seen_edges: set[tuple[str, str, str]] = set()
    if root_claim not in claims:
        errors.append("graph.rootClaim must identify a claim")
    if not isinstance(edges, list):
        errors.append("graph.edges must be an array")
    else:
        for position, edge in enumerate(edges):
            if not isinstance(edge, dict):
                errors.append(f"graph.edges[{position}] must be an object")
                continue
            source = edge.get("from")
            target = edge.get("to")
            relation = edge.get("relation")
            if source not in known_nodes or target not in known_nodes:
                errors.append(f"graph.edges[{position}] has a dangling node")
                continue
            if relation not in GRAPH_RELATIONS:
                errors.append(f"graph.edges[{position}] has an invalid relation")
                continue
            signature = (source, target, relation)
            if signature in seen_edges:
                errors.append(f"graph.edges[{position}] is duplicated")
                continue
            seen_edges.add(signature)
            adjacency[source].add(target)
    for claim_id, claim in claims.items():
        for assumption_id in claim.get("assumptions", []):
            if assumption_id in assumptions and not any(
                (claim_id, assumption_id, relation) in seen_edges
                for relation in ("boundedBy", "dependsOn")
            ):
                errors.append(
                    f"graph does not connect {claim_id} to assumption {assumption_id}"
                )
    if root_claim in claims:
        reachable = {root_claim}
        queue = deque([root_claim])
        while queue:
            for target in adjacency.get(queue.popleft(), set()):
                if target not in reachable:
                    reachable.add(target)
                    queue.append(target)
        unreachable = known_nodes - reachable
        if unreachable:
            errors.append(f"graph has unreachable nodes: {', '.join(sorted(unreachable))}")

    if check_git:
        _validate_git(root, manifest.get("evaluation"), errors)
    return sorted(set(errors))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
        help="repository root",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        help="manifest path (defaults under the repository root)",
    )
    arguments = parser.parse_args(argv)
    root = arguments.root.resolve()
    manifest = arguments.manifest or root / "docs/alias-security-assurance/traceability.json"
    errors = validate_manifest(root, manifest, check_git=True)
    if errors:
        for error in errors:
            print(f"security assurance validation failed: {error}", file=sys.stderr)
        return 1
    print(f"Security assurance traceability passed: {manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
