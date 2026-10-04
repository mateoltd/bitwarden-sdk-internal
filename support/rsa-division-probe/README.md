# Optimized RSA division access-property control

The probe compares the exact registry crypto-bigint 0.7.5 with the local patched 0.7.5. It marks
every limb of valid recovered representatives 0 and n-1 as secret, after public input construction,
and checks both fixed-divisor reduction paths with Valgrind. Only the completed result is released
before the arithmetic assertion.

The public modulus is taken from the first SHA256 Wycheproof OAEP group at C2SP/wycheproof commit
3fa63dd0344abb611f1fb1d77e119938603ea230. It corresponds to the already checksum-pinned
support/vendor/rsa/tests/oaep-vectors/sha256.json. No private key is copied into this probe.

Run bash scripts/alias-sdk/test-rsa-division.sh on Linux with a C compiler, ar and Valgrind headers
installed. Both size and speed optimization must detect the original dependency's secret-dependent
operation and accept the patched dependency without property errors. Running outside Valgrind fails.
The runner authenticates the original borrow-correction diagnostic from structured detector output,
rejects unrelated errors, and requires completion of the arithmetic assertion. Detector exit status
alone cannot satisfy the original control. Debug information identifies the optimized diagnostic;
both profiles retain LTO and one codegen unit. The standalone lock keeps original and patched
package identities distinct.

This checks one concrete compiler-sensitive reduction boundary. It is not an RSA functional suite, a
timing-oracle exploit, full platform runtime acceptance or a proof of absolute microarchitectural
constant time. The production RNG and cryptographic APIs are unchanged.
