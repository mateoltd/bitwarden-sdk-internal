# RSA division correction candidate

This retains crypto-bigint 0.7.5 and its original MIT/Apache notices. SOURCE.json
records the original registry bytes and the complete downstream file identity.
It is not an advisory-free upstream release. RUSTSEC-2023-0071 remains tracked
for the SDK RSA call graph.

The large-divisor correction uses a subtraction-borrow mask to add back the
divisor. Optimized native code can turn the mask into a conditional divisor
load. This affects fixed-divisor reduction of recovered RSA representatives,
including the fault check after unblinding. Keep that existing mask opaque
before the correction, preserving the arithmetic, bounds and const APIs.
The maintained ctutils Choice uses the same best-effort compiler barrier.
No big-integer algorithm, key format, RNG or cleanup contract changes.

Const black_box requires Rust 1.86. The SDK minimum remains Rust 1.88.
The barrier is not a language-level constant-time guarantee. Qualification
requires actual optimized-code/access-property evidence for the supported
compiler and targets, alongside functional regressions and independent review.

The plain non-vartime boxed GCD wrapper now widens a borrowed copy of its
conditional-assignment operand to the core result's allocated precision. This
preserves independently sized inputs and zero semantics without changing the
core algorithm or the equal-width assignment assertion. The new copy has a
Zeroizing guard when the existing zeroize feature is enabled. Direct mixed-width,
zero and even-input regressions also protect the unchanged specialized routes.
