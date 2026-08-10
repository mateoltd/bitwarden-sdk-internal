# Bitwarden Alias

GPL-only SimpleLogin alias lifecycle support for the Bitwarden SDK.

This crate intentionally contains only the Rust SDK API. Language bindings and
commercial packaging are maintained separately.

## Transport security

The API token is accepted only as a sensitive value and sent only in the
`Authentication` header. Authenticated redirects and cookie credentials are
disabled, successful responses are capped at 512 KiB, error responses are
capped at 16 KiB, and provider-controlled error text is never rendered.
Retained read-only transport errors have their request URL removed. Plain HTTP
self-hosting is accepted only on loopback; other provider instances must use
HTTPS.
Caller-controlled request strings and provider response fields are bounded
before serialization or return.

Lifecycle requests are never automatically replayed. Explicit enable and
disable operations are serialized by provider instance and stable alias ID
across all clients in a process because SimpleLogin exposes a toggle rather
than a set-state endpoint. A bounded read-toggle reconciliation also converges
after an observed cross-process race. Transport failures after dispatch return
an explicit unknown-outcome error so callers do not replay non-idempotent
operations, and a confirmed update whose refresh fails is reported separately.
Provider identities and returned states are checked before a mutation is
reported as successful.

## Vault reconciliation

Alias references are stored in the encrypted hidden field
`bitwarden.alias.reference`. Version 1 namespaces the provider-assigned alias ID
by provider and canonical service instance, and keeps a last-known address for
safe stale-binding detection. The stable ID is authoritative.

`plan_alias_reconciliation` is a non-mutating dry run over complete provider
alias data and decrypted `bitwarden_vault::CipherView` models. It reports exact
matches, legacy address matches, duplicates, missing aliases, stale bindings,
unbound aliases and references that were skipped for safety. Only
`apply_alias_reconciliation` mutates ciphers. It validates every action before
the first edit and repeated application is idempotent.
