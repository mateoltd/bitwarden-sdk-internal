use bitwarden_alias::{
    Alias, AliasCipherMutationResult, AliasError, AliasJournal, AliasJournalState,
    AliasReconciliationApplyOutput, AliasReconciliationError, AliasReconciliationPlan,
    AliasReference, AliasReferenceError,
    apply_alias_reconciliation_owned as core_apply_alias_reconciliation,
    bind_alias_reference as core_bind_alias_reference,
    clear_alias_reference_if_username_changed as core_clear_alias_reference_if_username_changed,
    create_alias_reference as core_create_alias_reference,
    parse_alias_reference as core_parse_alias_reference,
    plan_alias_reconciliation as core_plan_alias_reconciliation,
    serialize_alias_reference as core_serialize_alias_reference,
};
use bitwarden_sensitive_value::{ExposeSensitive, SensitiveString};
use bitwarden_vault::CipherView;

/// Creates the canonical serialized v1 alias reference from neutral alias identity.
#[uniffi::export]
pub fn create_alias_reference(
    identity: bitwarden_alias::AliasIdentity,
) -> Result<SensitiveString, AliasReferenceError> {
    core_create_alias_reference(&identity)
}

/// Parses and validates a canonical v1 alias reference without exposing its payload in errors.
#[uniffi::export]
pub fn parse_alias_reference(
    value: SensitiveString,
) -> Result<AliasReference, AliasReferenceError> {
    // EXPOSE: The caller already owns the decrypted login member. Errors never render its value.
    core_parse_alias_reference(value.expose())
}

/// Re-serializes a parsed reference into the one canonical JSON representation.
#[uniffi::export]
pub fn serialize_alias_reference(
    reference: AliasReference,
) -> Result<SensitiveString, AliasReferenceError> {
    core_serialize_alias_reference(&reference)
}

/// Binds a canonical reference to a decrypted login cipher after username integrity validation.
#[uniffi::export]
pub fn bind_alias_reference(
    value: SensitiveString,
    cipher: CipherView,
) -> Result<AliasCipherMutationResult, AliasReferenceError> {
    // EXPOSE: Binding parses caller-owned decrypted vault metadata and never logs it.
    core_bind_alias_reference(value.expose(), cipher)
}

/// Clears a binding before save when the login username no longer matches its bound address.
#[uniffi::export]
pub fn clear_alias_reference_if_username_changed(
    cipher: CipherView,
) -> Result<AliasCipherMutationResult, AliasReferenceError> {
    core_clear_alias_reference_if_username_changed(cipher)
}

/// Computes a deterministic, read-only reconciliation plan for one stable connection.
#[uniffi::export]
pub fn plan_alias_reconciliation(
    connection_id: String,
    aliases: Vec<Alias>,
    ciphers: Vec<CipherView>,
) -> Result<AliasReconciliationPlan, AliasReconciliationError> {
    core_plan_alias_reconciliation(&connection_id, &aliases, &ciphers)
}

/// Atomically validates and applies a reconciliation plan to owned decrypted ciphers.
#[uniffi::export]
pub fn apply_alias_reconciliation(
    plan: AliasReconciliationPlan,
    aliases: Vec<Alias>,
    ciphers: Vec<CipherView>,
) -> Result<AliasReconciliationApplyOutput, AliasReconciliationError> {
    core_apply_alias_reconciliation(&plan, &aliases, ciphers)
}

/// Validates and deterministically orders an encrypted provider-neutral journal.
#[uniffi::export]
pub fn canonicalize_alias_journal(journal: AliasJournal) -> Result<AliasJournal, AliasError> {
    journal.canonicalize()
}

/// Pure set-union merge for two journals belonging to the same stable connection.
#[uniffi::export]
pub fn merge_alias_journals(
    left: AliasJournal,
    right: AliasJournal,
) -> Result<AliasJournal, AliasError> {
    left.merge(&right)
}

/// Pure deterministic reduction of canonical journal facts into operation and resource state.
#[uniffi::export]
pub fn reduce_alias_journal(journal: AliasJournal) -> Result<AliasJournalState, AliasError> {
    journal.reduce()
}
