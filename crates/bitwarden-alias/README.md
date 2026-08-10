# Bitwarden Alias

GPL-only SimpleLogin alias lifecycle support for the Bitwarden SDK.

This crate intentionally contains only the Rust SDK API. Language bindings and
commercial packaging are maintained separately.

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
