# Bitwarden Alias

GPL-only SimpleLogin alias lifecycle support for the Bitwarden SDK.

This crate intentionally contains only the Rust SDK API. Language bindings and
commercial packaging are maintained separately.

## Transport security

The API token is accepted only as a sensitive value and sent only in the
`Authentication` header. Authenticated redirects and cookie credentials are
disabled, successful responses are capped at 512 KiB, error responses are
capped at 16 KiB, and provider error text is bounded, sanitized and token
redacted. Retained transport errors have their request URL removed.

Lifecycle requests are never automatically replayed. Explicit enable and
disable operations are serialized by provider instance and stable alias ID
across all clients in a process because SimpleLogin exposes a toggle rather
than a set-state endpoint. Provider identities and returned states are checked
before a mutation is reported as successful.

## Vault reconciliation

Alias references are stored in the encrypted hidden field
`bitwarden.alias.reference`. This is the only reserved field name and the value is
the canonical JSON emitted by the SDK. Version 2 namespaces the provider-assigned
alias ID by provider, canonical service instance and a stable connection ID. The
connection ID is a client-generated canonical UUID v4 that is persisted with
the provider connection; it must never be derived from an API token, password,
mailbox credential or any other secret. The address remains a last-known snapshot.
The provider, instance, connection ID and provider alias ID are authoritative.

Version 1 references lack a connection ID. Parsing and reconciliation reject them
until the client calls the explicit migration operation with its available provider
connections. Migration succeeds only when exactly one connection matches the
legacy provider and instance. Multiple accounts on the same origin are rejected as
ambiguous; after an explicit user selection the client can retry with that one
connection. Migration is idempotent for version 2 references.

`plan_alias_reconciliation` is a non-mutating dry run over complete provider
alias data and decrypted `bitwarden_vault::CipherView` models. It reports exact
matches, legacy address matches, duplicates, missing aliases, stale bindings,
unbound aliases and references that were skipped for safety. Only
`apply_alias_reconciliation` mutates ciphers. It validates every action before
the first edit and repeated application is idempotent. Bind, migrate and apply
return decrypted cipher models; consuming clients remain responsible for their
normal encryption and persistence path.
