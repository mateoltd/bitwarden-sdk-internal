# Alias security contract

Status: normative for first-class alias references and lifecycle operations in this SDK. The
keywords MUST, MUST NOT, SHOULD, and MAY are interpreted as requirements, not as claims that an
external provider satisfies them.

## Assets and trust boundaries

The protected assets are provider credentials, provider-account identity, provider alias state,
alias-to-vault bindings, and vault items unrelated to aliases. Provider responses, vault reference
fields, decrypted `CipherView` inputs, concurrent clients, and delayed or replayed responses are
untrusted inputs. The authenticated provider origin and the caller's normal vault encryption and
persistence path are outside the proof boundary and are explicit assumptions below.

## Normative requirements

- **ID-1 Stable resource identity.** An alias resource MUST be selected by
  `(provider, canonical instance, connection UUID, provider alias ID)`. Address snapshots MUST NOT
  authorize mutations. The connection UUID MUST be a canonical RFC 4122 UUID v4, opaque,
  client-generated, persisted per provider account, and independent of credentials.
- **AUTH-1 Scoped transitions.** A lifecycle or reconciliation transition MUST target the stable
  resource named by the active connection. A foreign provider, instance, connection, alias ID, or
  cipher reference MUST be rejected or skipped without mutation.
- **REC-1 Deterministic reconciliation.** Planning MUST be non-mutating. Automatic refresh MAY
  occur only for one unambiguous current reference. Ciphers without a current reference MUST
  NOT be inferred from their username or address. Duplicate alias IDs, duplicate cipher IDs,
  duplicate reserved fields, stale plans, and conflicting current claims MUST fail or produce no
  repair. Apply MUST validate every action before its first mutation.
- **REC-2 Idempotence and frame condition.** Reapplying a valid plan MUST be a no-op once its
  postcondition is satisfied. Reconciliation MAY change only the target login username and the one
  hidden alias-reference field. All other cipher fields and all unrelated ciphers MUST remain
  unchanged.
- **LIFE-1 Disable semantics.** Disable is an explicit desired-state operation, not an exposed
  toggle. The SDK MAY issue the provider's toggle only after a read observes the opposite state.
  Every toggle MUST be followed by a fresh read; a toggle response alone MUST NOT establish success.
  Bounded interference MUST terminate with a concurrency error rather than false success.
- **LIFE-2 Delete semantics.** Delete removes only the provider alias. It MUST NOT delete, disable,
  or rewrite a vault cipher. A transport failure after dispatch MUST return an unknown outcome and
  MUST NOT cause an automatic replay. Disable and delete are distinct transitions.
- **REPLAY-1 Response handling.** Delayed or replayed toggle bodies MUST be observational only.
  Non-idempotent mutations with an unknown outcome MUST NOT be blindly retried. A successful state
  result denotes a state observed by a subsequent validated read; it does not promise that another
  authorized actor cannot mutate the provider immediately afterward.
- **REF-1 Canonical reference schema.** Version 2 reference JSON MUST contain exactly, and in
  canonical serialization order: `version`, `provider`, `providerInstance`, `connectionId`,
  `aliasId`, and `address`. Unknown fields, non-canonical instances, non-v4 connection IDs, zero
  alias IDs, unsafe addresses, visible or linked reserved fields, and oversized payloads MUST fail
  closed.
- **SECRET-1 Non-disclosure.** Reference serialization MUST NOT contain an API token, password,
  signed suffix, credential-derived connection ID, URL user information, query credential, or
  fragment credential. Parse, reconciliation, display, and debug errors MUST NOT echo a
  reference payload or provider-controlled credential material.

## Safety and liveness

Safety claims hold for every state explored by the checked finite abstractions: a bad identity,
unauthorized write, destructive reconciliation, credential-bearing schema, false response-based
success, replay after an unknown result, or delete/disable conflation is never reached.

Liveness is deliberately narrower. Under weak scheduling fairness, every lifecycle request reaches a
terminal success or explicit failure within the attempt bound. Successful convergence is proved only
for one authorized client when provider reads and mutation responses are delivered and no external
actor interferes. Continuous interference is allowed to end in `ConcurrentMutation`.

## Assumptions

1. The caller associates the correct opaque connection UUID with the authenticated provider account
   and keeps that association stable. The SDK validates its form, not its external provenance.
2. TLS server authentication and the provider's authorization decision are correct. A fresh `GET` is
   assumed to describe the requested stable alias ID at its observation point; the SDK verifies the
   returned ID and response shape.
3. Reconciliation receives a complete provider inventory when completeness-dependent missing and
   unbound results are relied on.
4. `CipherView` is already decrypted in trusted process memory. Encryption, durable storage,
   transaction isolation across caller persistence, and zeroization are outside this layer.
5. Provider alias IDs are stable and non-zero. Provider and vault storage implementations are not
   Byzantine beyond the invalid, concurrent, delayed, replayed, and transport-failure behaviors
   represented in the model and conformance traces.

## Requirements mapping

These standards identify external requirements; they do not prove this contract.

- [OWASP ASVS 5.0.0](https://github.com/OWASP/ASVS/releases/tag/v5.0.0_release): `v5.0.0-8.1.1`
  (authorization rules), `v5.0.0-8.2.2` (data-specific access), `v5.0.0-8.3.1` (trusted-layer
  enforcement), `v5.0.0-13.3.2` (least-privilege secret access), `v5.0.0-14.2.6` (minimum sensitive
  data), and `v5.0.0-16.2.5` (credential-safe logging) map to ID-1, AUTH-1, REF-1, and SECRET-1.
- [NIST SP 800-53 Rev. 5, release 5.2.0](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final): AC-3,
  AC-4, AC-6, and SI-10 map to scoped enforcement, information-flow restriction, least privilege,
  and input validation.
- [RFC 9110 section 9.2.2](https://www.rfc-editor.org/rfc/rfc9110.html#name-idempotent-methods): its
  retry rules map to LIFE-1, LIFE-2, and REPLAY-1. In particular, the SDK does not infer that a
  failed POST toggle was unapplied; it reports an unknown outcome unless it can reconcile by a
  separately successful read.
