# Bitwarden Vault

Defines the data model for the vault items both encrypted and decrypted. It also handles conversions
between the two states by implementing `Encryptable`.

Alias-bound logins always use the sealed cipher-blob format. The canonical alias reference is
encrypted inside the server's opaque `data` field, is never represented as an ordinary custom field,
and therefore survives create, edit, share, sync, restore, and key-rotation paths without exposing
stable alias identity to the server schema. Unbound ciphers retain the normal staged blob-encryption
rollout policy.
