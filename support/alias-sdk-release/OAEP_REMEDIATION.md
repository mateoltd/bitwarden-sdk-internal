# Source-bound SDK OAEP qualification

The vendored dependencies keep their original names and versions: `rsa 0.10.0-rc.18` and
`crypto-bigint 0.7.5`. RUSTSEC-2023-0071 remains an affected upstream advisory. The contract does
not qualify generic PKCS1v1.5 or declare a patched RustSec release. No risk exception is accepted.

`rsa-remediation.py` separates three operations:

1. `source` authenticates the complete production source inventory, both original/patched vendor
   catalogs and license lineage, and the existing dependency-resolution validator. The inventory
   includes every tracked or unignored source file under the crates, licensed crates, vendor and
   Cargo configuration directories, plus the root graph and package build scripts. An added caller,
   changed feature manifest, included data or patch byte invalidates the reviewed closure. This
   operation reports `SOURCE_BOUND_PATCH_VERIFIED_DELIVERY_REQUIRED`, never qualification.
2. `identity-lock` produces a temporary audit-only lockfile. It restores only the two known path
   packages' original registry identities and checksums. It never changes the build lock or builds
   original vulnerable bytes. `collect-audit-evidence.sh` retains raw audits of both locks, npm,
   tool exits, the active package inventory and the clean RustSec Git database identity. The second
   audit uses `--no-fetch`; database changes fail collection. The optional Git fields in rustsec
   0.33's no-fetch JSON may be null. They remain null in retained output, with Git provenance
   collected independently. Filtered, malformed, operationally failed, changed-advisory or
   additional-vulnerability results fail. Collection is source-bound and expires after24 hours;
   timestamps in the future fail. An omitted path dependency is not a resolved advisory.
3. `qualify` revalidates source and raw audits, then validates each delivered platform against a
   reviewed immutable delivery catalog in `audit-policy.json`. The catalog is currently empty. No
   actual SDK artifact is qualified by the source check or by synthetic validator tests.

A delivered platform must carry `RSA-OAEP-DELIVERY.json`. Its schema1 manifest binds source commit,
production source catalog, platform, the complete file inventory, compiler/LLVM, targets,
optimization/LTO/codegen profile, resolved feature graph and applicable runtime engine. Its binary
and generated-binding subjects must match checksummed delivered files. Eight checksummed proof
records are required: `optimized-code`, `runtime`, `bindings`, `vectors`, `entropy`, `property`,
`review`, and `build-provenance`. Each schema1 record identifies its kind, successful outcome,
source commit, exact build configuration and identical delivered subjects. The manifest checksum,
source, platform and build must match a reviewed catalog entry. A boolean supplied by a build is not
enough: arbitrary manifests and even correctly checksummed but unreviewed bytes are rejected. Actual
code inspection, executed runtime controls and authenticated build provenance must precede adding a
real catalog entry. Compile-only or target-specific component evidence is insufficient.

Build-only jobs and audit collection do not depend on qualification or scanner acceptance. Final
assembly still needs the unchanged policy/scanner job and separately calls this delivery contract.
The release manifest and candidate verifier both validate the real bytes; a supplied qualification
JSON cannot bypass revalidation. The scoped report retains original advisory/raw output and the full
original/patch catalogs. `SDK_OAEP_EXACT_BYTES_REMEDIATED` applies only to delivered SDK OAEP
subjects. `globalRustSecClosure` and `genericPkcs1v15Qualified` remain false.

A catalog follow-up can review already-built immutable bytes without rebuilding to obtain a new
self-referencing commit: the delivery's original commit must have the exact reviewed production
catalog in Git. The qualification report records that build source separately from the verifier
commit. Packages and bindings must still identify the original build commit. Contract/policy-only
follow-ups are not substituted as artifact source. No consumer may repin before all independent
candidate gates and matched platform/runtime/provenance obligations pass.

Focused tests run with:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s scripts/alias-sdk -p test_rsa_remediation.py -v
```

These exercise the actual production validators with temporary source and synthetic delivery
fixtures. Their positive qualification case is a validator control, not SDK security evidence. Raw
real audit outcomes and actual artifact receipts remain independent gates.
