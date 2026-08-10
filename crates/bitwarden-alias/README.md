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
`bitwarden.alias.reference`. Version 1 namespaces the provider-assigned alias ID
by provider and canonical service instance, and keeps a last-known address for
safe stale-binding detection. The stable ID is authoritative.

`plan_alias_reconciliation` is a non-mutating dry run over complete provider
alias data and decrypted `bitwarden_vault::CipherView` models. It reports exact
matches, legacy address matches, duplicates, missing aliases, stale bindings,
unbound aliases and references that were skipped for safety. Only
`apply_alias_reconciliation` mutates ciphers. It validates every action before
the first edit and repeated application is idempotent.
