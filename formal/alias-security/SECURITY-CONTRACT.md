# Alias security contract

Status: normative for the unreleased provider-neutral alias SDK v1. The keywords MUST, MUST NOT,
SHOULD, and MAY are requirements on the SDK and its adapters, not claims about an external service.

## Assets and trust boundaries

Protected assets are connection credentials and endpoint configuration, provider-account identity,
provider alias state, encrypted operation journals, alias-to-vault bindings, and vault data unrelated
to aliases. Adapter responses, decrypted vault inputs, concurrent clients, delayed responses, and
replayed responses are untrusted. Vault encryption and persistence, TLS server authentication, and
the remote provider's authorization decision are explicit assumptions described below.

## Normative requirements

- **ID-1 Stable alias identity.** An alias is selected only by `(connectionId, aliasId)`, where
  `connectionId` is a canonical RFC 4122 UUID v4 and `aliasId` is an opaque, non-empty, bounded
  string. Equality, authorization, reconciliation, and journal reduction MUST NOT parse the alias ID
  as an integer or infer identity from an address. The address is a required canonical integrity and
  display snapshot, but is not a join key.
- **ID-2 Connection metadata separation.** Adapter identifier, provider instance or endpoint,
  credentials, account label, and adapter configuration belong to encrypted connection metadata.
  They MUST NOT occur in stable alias identity, references, vault bindings, journals, or telemetry.
  Credentials, endpoints, account labels, and adapter-native configuration MUST NOT occur in
  generated common definitions; the validated adapter descriptor and neutral capabilities are the
  intentional common SPI. Changing credentials or a permitted endpoint MUST preserve the connection
  ID. Reconnecting a different remote account MUST use a new connection ID.
- **ADAPTER-1 Extensible provider SPI.** An adapter identifier MUST use the validated, normalized,
  extensible identifier grammar defined by the implementation contract. It is not a shared enum.
  Common code MUST dispatch through the adapter SPI and MUST NOT contain named-provider branches.
  Provider-native request or response shapes remain private to the adapter boundary.
- **CAP-1 Negotiated capabilities.** Baseline operations and optional extensions MUST be represented
  by validated provider-neutral capabilities. First-class baseline support is create, list, get,
  enable/disable, delete, and create/list/remove send-or-reply identities; behavior such as blocking
  one send-or-reply identity is an optional extension. A transition MUST check the active
  connection's capability before dispatch. Unsupported operations fail explicitly without I/O or
  state mutation.
- **AUTH-1 Scoped transitions.** A lifecycle, journal, or reconciliation transition MUST target the
  active connection and opaque alias ID. A foreign connection, alias ID, or cipher reference MUST
  fail or be skipped without mutation. An address snapshot never authorizes a provider mutation.
- **REF-1 Canonical reference schema.** Version 1 reference JSON contains exactly, and serializes in
  this order: `version`, `connectionId`, `aliasId`, `address`. Unknown fields, a non-v4 connection
  ID, empty or oversized opaque alias ID, non-canonical address, oversized payload, missing or
  malformed version, zero, version 2, and unknown future versions fail closed. There is no legacy,
  migration, dual-schema, or provider-specific decoder.
- **REC-1 Deterministic reconciliation.** Planning is pure and non-mutating. Automatic refresh is
  permitted only for one unambiguous current reference in the active connection. A cipher without a
  current reference MUST NOT be inferred from its username or address. Duplicate alias claims,
  duplicate cipher IDs, stale plans, and conflicting current claims fail or produce no repair. Apply
  validates every action before its first mutation.
- **REC-2 Idempotence and frame condition.** Reapplying a valid plan is a no-op after its
  postcondition is satisfied. Reconciliation may change only the target login username and its one
  encrypted first-class alias-reference member. All other cipher members and unrelated ciphers
  remain unchanged. Provider deletion and disable never delete or rewrite a vault item.
- **STATE-1 Orthogonal state.** Common state keeps lifecycle (`enabled`, `disabled`, `deleted`),
  operation (`none`, `prepared`, `dispatched`, `outcome-unknown`, `failed`), freshness (`current`,
  `stale`), and consistency (`clean`, `conflicted`) as separate axes. One axis MUST NOT silently
  encode another.
- **JOURNAL-1 Encrypted causal journal.** Journal events are append-only, connection-scoped,
  bounded, causally identified, and uniquely identified. They contain only common operation and
  state facts. Merge validates scope and event identity, then is deterministic, commutative,
  associative, and idempotent. Reduction is pure and total for every validated journal.
- **JOURNAL-2 Tombstones and conflicts.** A delete tombstone dominates every earlier lifecycle
  event and prevents resurrection after stale-device merge. Concurrent incompatible observations
  remain explicitly conflicted until a causally later resolution. Duplicate events are harmless;
  colliding event IDs with different content fail closed.
- **JOURNAL-3 Monotonic operation facts.** Causally later facts for one operation MUST NOT regress
  to an earlier phase. Acknowledged and failed facts are terminal; a previously unknown outcome may
  be resolved only to acknowledged or failed. Contradictory terminal facts fail closed.
- **LIFE-1 Desired-state semantics.** Enable and disable are desired-state operations, not exposed
  toggles. An adapter that only offers toggle may dispatch it only after a read observes the opposite
  state. Every toggle is followed by a fresh validated read; its response body alone cannot establish
  success. Bounded interference ends with an explicit conflict rather than false success.
- **LIFE-2 Delete and unknown outcomes.** Delete removes only the remote alias and treats a validated
  not-found response as idempotent success. A failure after any non-idempotent dispatch records and
  returns `outcome-unknown`; it MUST NOT automatically replay. Reconciliation uses a separately
  validated read or listing to resolve that event. Delete and disable remain distinct transitions.
- **REPLAY-1 Response handling.** Delayed, duplicated, or replayed mutation bodies are observational
  only. A successful lifecycle result denotes a fresh validated observation, not a promise that a
  different authorized actor cannot mutate the provider immediately afterward.
- **SECRET-1 Non-disclosure.** Credentials, endpoints, signed suffixes, URL user information,
  provider-native payloads, raw error bodies, request headers, and query strings MUST NOT occur in
  alias references, vault bindings, journals, telemetry, generated common definitions, debug output,
  or logs. Public errors expose only the neutral error taxonomy and safe bounded metadata.
- **TELEMETRY-1 Coarse allowlist.** Telemetry is restricted to coarse operation, platform, neutral
  error code, and success. Connection ID, alias ID, address, adapter identifier, endpoint, payload,
  and provider body are forbidden.

## Safety and liveness claims

For every state in the configured finite abstractions, stable identity cannot cross a connection;
unsupported or unauthorized writes do not dispatch; unrelated vault data is preserved; references
have exactly four fields and no credential source; journal merge is append-only and has the stated
algebraic properties; tombstones do not resurrect; conflicts and unknown outcomes remain explicit;
toggle bodies cannot establish success; unknown mutations are not replayed; and delete is never
conflated with disable.

Under weak client-step fairness every modeled lifecycle request terminates in success or an explicit
failure within the attempt bound. Successful convergence is claimed only for one authorized client
when validated reads and responses are delivered and external interference eventually stops.

## Assumptions and boundaries

1. The caller binds a stable opaque connection UUID to the intended authenticated remote account and
   stores adapter, endpoint, and credential metadata only in the encrypted connection record.
2. TLS authentication and the provider's authorization decision are correct. A fresh adapter read is
   assumed to identify the requested opaque alias after the adapter validates its native response.
3. Reconciliation receives a complete provider inventory when it reports missing or unbound items.
4. Vault inputs and journals are already decrypted in trusted process memory. Encryption, durable
   transactions, key management, and zeroization are outside this model.
5. Validated remote alias IDs remain stable within one connection. The provider is not Byzantine
   beyond invalid shapes, conflicts, loss, delay, replay, and ambiguous outcomes represented here.
6. TLA+ checks finite data-independent abstractions. Bounds, Unicode/email normalization, URL policy,
   serialization byte limits, cryptography, and total implementation refinement are production-test
   obligations, not theorem-prover claims.

## External requirements mapping

- [OWASP ASVS 5.0.0](https://github.com/OWASP/ASVS/releases/tag/v5.0.0_release):
  `v5.0.0-8.1.1`, `8.2.2`, `8.3.1`, `13.3.2`, `14.2.6`, and `16.2.5` map to scoped
  authorization, minimum sensitive data, trusted-layer enforcement, and credential-safe logging.
- [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final): AC-3, AC-4,
  AC-6, AU-9, and SI-10 map to scoped enforcement, protected journals, least privilege, and input
  validation.
- [RFC 9110 section 9.2.2](https://www.rfc-editor.org/rfc/rfc9110.html#name-idempotent-methods)
  informs the replay rules. The SDK never infers that a failed non-idempotent request was unapplied.
