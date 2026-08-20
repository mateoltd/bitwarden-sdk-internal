# Bitwarden Alias

GPL-only provider-neutral alias lifecycle support for the Bitwarden SDK.

The common contract is adapter-independent. A stable alias resource is keyed by the random
connection UUID and a bounded opaque remote identifier. Its canonical address is required display
and integrity data, never a join key. Adapter identifiers and service endpoints are encrypted
connection implementation metadata and do not appear in references or journals.

The canonical version 1 login binding is exactly:

```json
{
  "version": 1,
  "connectionId": "<uuid-v4>",
  "aliasId": "<opaque string>",
  "address": "<canonical address>"
}
```

Only this shape is accepted. Unknown fields, missing fields, malformed values, non-v1 values, and
the old unreleased provider-specific form fail closed. Bindings live in the first-class encrypted
`Login.aliasReference` member, not a hidden custom field.

## Adapter boundary

`AliasProviderAdapter` is an injected provider-neutral SPI with validated extensible adapter and
capability identifiers. `AliasClient` enforces connection authorization and validates every input
and output. Provider-native payloads and errors are translated at the boundary. SimpleLogin is one
real adapter; its numeric identifiers, endpoint, credential, and native models stay private to that
implementation and are excluded from generated common definitions.

The lifecycle service has no hidden storage. Its host coordinator owns encrypted durable journal
persistence and explicitly appends prepared, dispatched, and terminal events around lifecycle calls.
The SDK supplies the closed event schema, validation, canonical merge, reduction, and safe error
classifications; adapter callbacks must report `outcome-unknown` after an uncertain mutation
dispatch.

## Lifecycle and convergence

Confirmed lifecycle, operation phase, freshness, and consistency remain separate state axes. The
host records mutations before dispatch, post-dispatch transport failures become `outcome-unknown`,
and creates are never blindly replayed. SimpleLogin's alias and optional send/reply-block toggle
APIs are driven as explicit desired state with bounded read-after-write verification. Delete is
idempotent on an already-absent remote resource and never deletes or rewrites a vault item.

The encrypted append-only journal uses causal events and stable neutral error categories. Its merge
is deterministic, commutative, associative, and idempotent. Event-ID collisions fail closed;
acknowledged deletes reduce to tombstones and stale events cannot silently resurrect them.

## Vault reconciliation

`plan_alias_reconciliation` is a pure dry run over a complete connection-scoped alias inventory and
decrypted `CipherView` values. It never infers a binding from an address. Duplicate, missing,
foreign, malformed, and stale cases are explicit. Apply validates the complete plan before its first
edit and is idempotent. Only the login username and first-class alias reference can change; all
other cipher data and unrelated vault items are frame-preserved. Callers retain responsibility for
their normal encryption, transaction, and persistence path.

## Transport security

The concrete SimpleLogin adapter accepts runtime-only settings. It rejects URL credentials, queries,
fragments, non-loopback HTTP, authenticated redirects, oversized responses, and unsafe provider
data. Provider error bodies and request URLs are never retained or rendered. Credentials, endpoints,
addresses, labels, recipients, stable identifiers, and adapter names are excluded from the telemetry
record; only coarse operation, platform, neutral category, and success are allowed.
