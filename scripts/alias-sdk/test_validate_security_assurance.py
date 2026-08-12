#!/usr/bin/env python3
"""Tests for the dependency-free security assurance manifest validator."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
REPOSITORY_ROOT = SCRIPT_DIR.parents[1]
FIXTURES = SCRIPT_DIR / "fixtures/security-assurance"
SPEC = importlib.util.spec_from_file_location(
    "validate_security_assurance", SCRIPT_DIR / "validate_security_assurance.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load security assurance validator")
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


class SecurityAssuranceValidatorTests(unittest.TestCase):
    def validate_fixture(self, name: str) -> list[str]:
        return VALIDATOR.validate_manifest(
            FIXTURES, FIXTURES / name, check_git=False
        )

    def test_valid_fixture_passes(self) -> None:
        self.assertEqual(self.validate_fixture("valid.json"), [])

    def test_missing_claim_evidence_fails(self) -> None:
        errors = self.validate_fixture("missing-evidence.json")
        self.assertIn("C-E2E-01 has no proof, test, or operational evidence", errors)
        self.assertIn("unreferenced evidence: EV-FIXTURE", errors)

    def test_stale_evidence_fails(self) -> None:
        errors = self.validate_fixture("stale-evidence.json")
        self.assertEqual(len(errors), 1)
        self.assertIn("EV-FIXTURE evidence is stale", errors[0])

    def test_missing_evidence_file_fails(self) -> None:
        manifest = json.loads((FIXTURES / "valid.json").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "manifest.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            errors = VALIDATOR.validate_manifest(root, path, check_git=False)
        self.assertIn(
            "EV-FIXTURE evidence file is missing: evidence.txt",
            errors,
        )

    def test_errors_are_unique_and_sorted(self) -> None:
        errors = self.validate_fixture("missing-evidence.json")
        self.assertEqual(errors, sorted(set(errors)))

    def test_repository_manifest_passes(self) -> None:
        errors = VALIDATOR.validate_manifest(
            REPOSITORY_ROOT,
            REPOSITORY_ROOT / "docs/alias-security-assurance/traceability.json",
            check_git=True,
        )
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
