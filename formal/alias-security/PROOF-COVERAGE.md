# Proof coverage and gaps

## Machine-checked theorem inventory

| Model | Kind | Checked formula | Contract coverage |
| --- | --- | --- | --- |
| `AliasVault` | safety | `TypeOK` | Vault, reference, and opaque resource domains remain well typed. |
| `AliasVault` | safety | `StableResourceNamespace` | References round-trip `(connectionId, aliasId)` and isolate the same opaque alias ID across connections. |
| `AliasVault` | safety | `AddressIsNotIdentity` | Changing the address snapshot does not change the resource join key. |
| `AliasVault` | safety | `AuthorizedWrites` | Every reconciliation write is scoped to the active connection. |
| `AliasVault` | safety | `ReconciliationIdempotent` | Each target reaches a fixed point and cannot be rewritten twice. |
| `AliasVault` | safety | `UnrelatedVaultItemsPreserved` | Unrelated cipher payload is a frame invariant. |
| `AliasVault` | safety | `ProviderDeletePreservesVault`, `ProviderDisablePreservesVault` | Remote lifecycle transitions do not mutate vault contents. |
| `AliasVault` | safety | `CanonicalReferenceSchema` | Every serialized reference has exactly four v1 fields. |
| `AliasVault` | safety | `ConnectionMetadataExcluded` | Adapter, provider, instance, and endpoint are absent from references. |
| `AliasVault` | safety | `ReferenceVersionFailClosed` | Only v1 is accepted; missing/malformed, zero, v2, and future versions fail closed. |
| `AliasVault` | safety | `CredentialNonDisclosure` | Serialized reference information flow excludes credential sources. |
| `AliasJournal` | safety | `TypeOK`, `ConnectionScoped` | Bounded causal events stay within one active encrypted connection journal. |
| `AliasJournal` | safety | `AppendOnly`, `CausalIdentifiersUnique`, `CausalParentsExist` | Append and sync never remove history; event IDs are collision-free and causal parents are retained. |
| `AliasJournal` | safety | `MergeCommutative`, `MergeAssociative`, `MergeIdempotent` | Canonical set-union merge has the three convergence laws. |
| `AliasJournal` | safety | `DeterministicReduction` | Equal merged journals reduce to equal four-axis state. |
| `AliasJournal` | safety | `TombstonesPreventResurrection` | Any retained delete tombstone reduces to deleted after stale-device merge. |
| `AliasJournal` | safety | `ConcurrentConflictsRemainExplicit` | Concurrent incompatible latest observations reduce to conflicted. |
| `AliasJournal` | safety | `UnknownOutcomesRemainExplicit` | An unresolved post-dispatch ambiguity remains `outcome-unknown`. |
| `AliasLifecycle` | safety | `TypeOK` | Concurrent lifecycle and negotiated capability state stays in its declared domains. |
| `AliasLifecycle` | safety | `StableMutationTarget`, `AuthorizedMutations` | Every dispatch retains its connection/alias target and is connection-scoped and capability-authorized. |
| `AliasLifecycle` | safety | `UnsupportedNeverMutates`, `ExplicitCapabilityFailure` | A missing negotiated capability cannot dispatch and terminates distinctly from connection denial. |
| `AliasLifecycle` | safety | `SuccessRequiresVerifiedRead`, `ReplayedResponseIgnored` | Toggle bodies cannot establish success and replay bodies are observational. |
| `AliasLifecycle` | safety | `UnknownOutcomeNotReplayed`, `DeleteDispatchedAtMostOnce` | An ambiguous non-idempotent mutation is terminal and delete is never replayed. |
| `AliasLifecycle` | safety | `DeleteDoesNotDisable`, `DisableDoesNotDelete` | Delete and desired-enabled state remain distinct transitions. |
| `AliasLifecycle` | safety | `BoundedInterference` | Attempts never exceed the configured production bound. |
| `AliasLifecycle` | liveness | `Terminates` | Under weak client-step fairness, every request reaches a terminal result. |
| `AliasLifecycle` reliable/quiescent | liveness | `AuthorizedSetConverges` | One authorized client eventually observes its desired state. |

There are no TLA+ `ASSUME` or `AXIOM` declarations. The gate rejects their introduction. TLC checks
the formulas above as invariants or temporal properties; finite model constants define an explored
abstraction and do not assert a security result.

## Production refinement gates

| Contract area | Canonical vector or trace | Production consumers | Drift detected |
| --- | --- | --- | --- |
| Four-field v1 reference | `referenceSchema`, `referenceVectors` | Rust, UniFFI, WASM | Exact order and field set, opaque string IDs, normalization, connection isolation, and secret/metadata exclusion. |
| Fail-closed decoding | `rejectedReferenceVectors` | Rust, UniFFI, WASM | Missing/malformed/unsupported version, unknown field, provider-specific old shape, numeric ID, bad UUID/address, and bounds rejection. |
| Extensible adapter contract | `adapterVectors`, `capabilityVectors` | Rust and generated definitions | Validated normalized identifiers, provider-neutral capability names, and no named-provider common enum. |
| Causal journal convergence | `journalSchema`, `journalMergeVectors` | Rust, UniFFI, WASM, Swift, Kotlin | Canonical event shape, causal ordering, CAI merge, event-ID collision failure, explicit conflict/unknown, and tombstone dominance. |
| Reconciliation frame | `reconciliationVectors` | Rust, UniFFI, WASM | No address inference, active connection scope, plan/apply idempotence, and unrelated-field/cipher preservation. |
| Lifecycle replay discipline | `lifecycleTraces`, `operationSemantics` | Real adapter plus Rust/WASM tests | Fresh-read success, bounded interference, unknown-no-replay, not-found delete idempotence, and delete/disable separation. |
| Secret and telemetry boundary | schema forbidden fields and sentinel vectors | Cross-language generation, logging/security gates | Credential, endpoint, adapter-native payload, raw body, identifier, and address leakage. |

`conformance-vectors.json` is the shared source artifact. The production refinement test hashes every
model file in its declared order, so a TLA+ edit requires an explicit vector revision and digest.

## Checked abstraction and honest gaps

| Boundary | What is checked | Residual limitation |
| --- | --- | --- |
| TLA+ state space | Exhaustive configured abstractions with two connections, the same opaque alias value, two ciphers or devices, lifecycle loss/replay, two causal clocks, tombstones, and conflicts. | This is finite-state model checking, not an unbounded proof for arbitrary journals, devices, aliases, or vault sizes. |
| Merge algebra | Set-union laws on all reachable device journals plus canonical production vectors. | Rust sorting, bound enforcement, and collision validation are refinement obligations; TLC does not prove the compiler or serializer. |
| Causal reduction | Parent-retaining events, explicit concurrency, tombstone dominance, conflict and unknown preservation. | Wall clocks are deliberately absent. Journal encryption, durable sync transport, garbage collection, and tombstone retention policy are outside the model. |
| Normalization and bounds | Vectors cover representative opaque IDs, canonical addresses, UUIDs, adapter IDs, and forbidden shapes. | Unicode/email syntax, byte-vs-scalar bounds, URL parsing, and every adversarial input are implementation tests, not TLA+ string proofs. |
| Provider boundary | Connection scoping, capability gating, replay, loss, invalid state, and bounded interference are modeled. | TLS, remote authorization, and a consistently lying Byzantine provider are assumptions. Endpoint and native response validation live inside each adapter. |
| Lifecycle operation set | Desired enable/disable and delete are explicit TLA+ transitions; their dispatch and unknown-outcome discipline abstracts the other non-idempotent mutations. | Create and send/reply operations are exercised by production adapter/refinement traces, but do not have separate TLA+ transition branches. |
| Model-to-code refinement | Shared vectors and model digest force represented traces and checked specifications to change together. | This is translation validation for named cases, not a machine-checked total refinement theorem for Rust, WASM, UniFFI, Swift, or Kotlin. |
| Vault and journal storage | Frame conditions and logical merge/reduction. | Encryption at rest, caller transaction isolation, crash consistency, key management, zeroization, and server sync availability are outside this crate. |
| TLC implementation | TLC reports 64-bit fingerprint collision estimates for each run. | A fingerprint collision and defects in TLC/JVM remain small trusted-checker risks. |
