# Downstream OAEP remediation candidate

This is the original `rsa 0.10.0-rc.18` registry source with a narrow downstream
patch. `SOURCE.json` records the original archive, source commit, every original
file and every candidate file. Original MIT/Apache notices are retained. The
package keeps its upstream name and version; it is not an advisory-free release.
RUSTSEC-2023-0071 remains tracked by the SDK dependency audit.
The standalone test lock aligns crypto-bigint, crypto-common, digest, system
entropy and cleanup versions with the SDK production graph.

The representative conversion processes the full fixed integer precision, rejects
nonzero overflow, and copies a width selected only by precision and requested
length. It does not trim at the recovered value's leading zeros. The shared
helper in RustCrypto/RSA commit `017ee05817fa6daab610653305d87a43d8aca9bd`
informed this change. No PKCS#1 v1.5 implicit-rejection change was imported.

Both OAEP decrypt implementations require the existing RSA blinding operation.
Caller-supplied entropy errors propagate. Otherwise the `getrandom` feature uses
fallible system entropy; without that feature, missing entropy returns `Rng`.
No failure retries unblinded. Blinding factors, the checked representative and
the OAEP encoded message receive explicit cleanup. Key, wire, hash, MGF and
label formats stay compatible. Other padding schemes retain their upstream APIs.
The generic MGF path now streams the seed and counter into the digest, matching
the existing typed path, instead of allocating unprotected scratch copies.

The existing complete OAEP validity scan precedes output selection. Successful
plaintext and its length are authorized outputs. This patch does not make a
claim of absolute microarchitectural noninterference or remediate every padding
scheme offered by the dependency. Qualification requires evidence and review of
the actual SDK OAEP boundary; passing tests alone do not resolve the advisory.

Run `bash scripts/alias-sdk/test-rsa-oaep.sh` from the SDK root for fixed-width,
entropy failure, both pinned Wycheproof sets, mixed MGF/label round trips and
the no-default-features build. The native CI matrix runs that same boundary.

The associated crypto-bigint 0.7.5 correction-mask candidate is applied to both
production and standalone tests. Its const compiler barrier requires Rust 1.86;
the SDK minimum remains Rust 1.88. Each dependency retains original identities,
licenses and byte-level provenance. No advisory qualification is inferred.
