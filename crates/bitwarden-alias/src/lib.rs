#![doc = include_str!("../README.md")]

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

mod error;
mod journal;
mod models;
mod provider;
mod reconciliation;
mod simplelogin;
mod simplelogin_error;
mod simplelogin_models;
#[cfg(feature = "uniffi")]
mod uniffi_bridge;

#[cfg(test)]
mod tests;

pub use error::{AliasError, AliasErrorCode, MAX_RETRY_AFTER_SECONDS};
pub use journal::{
    ALIAS_JOURNAL_VERSION, AliasCausalEntry, AliasJournal, AliasJournalEvent, AliasJournalState,
    AliasOperationPhase, AliasReducedOperation, AliasReducedResource, MAX_CAUSAL_ENTRIES,
    MAX_JOURNAL_EVENTS,
};
pub use models::{
    ALIAS_CONTRACT_VERSION, Alias, AliasAdapterDescriptor, AliasConnection, AliasConsistency,
    AliasFreshness, AliasIdentity, AliasLifecycleState, AliasOperationKind, AliasPage,
    AliasPlatform, AliasProviderCapabilities, AliasTelemetryEvent, CreateAliasRequest,
    CreateSendReplyIdentityRequest, DeleteAliasResult, ListAliasesRequest, MAX_ADAPTER_ID_BYTES,
    MAX_CAPABILITY_EXTENSIONS, MAX_CAPABILITY_ID_BYTES, MAX_EMAIL_ADDRESS_BYTES,
    MAX_HOSTNAME_BYTES, MAX_LABEL_BYTES, MAX_PAGE_ITEMS, MAX_PAGE_TOKEN_BYTES, MAX_REMOTE_ID_BYTES,
    SendReplyIdentity, SendReplyIdentityPage,
};
pub use provider::{AliasClient, AliasProviderAdapter, SimpleLoginAdapter};
pub use reconciliation::{
    ALIAS_RECONCILIATION_REPORT_VERSION, ALIAS_REFERENCE_VERSION, AliasCipherMutationResult,
    AliasReconciliationAction, AliasReconciliationApplyOutput, AliasReconciliationApplyResult,
    AliasReconciliationError, AliasReconciliationMode, AliasReconciliationOutcome,
    AliasReconciliationPlan, AliasReconciliationSkipReason, AliasReconciliationSummary,
    AliasReference, AliasReferenceError, MAX_ALIAS_REFERENCE_BYTES, apply_alias_reconciliation,
    apply_alias_reconciliation_owned, bind_alias_reference,
    clear_alias_reference_if_username_changed, create_alias_reference, parse_alias_reference,
    plan_alias_reconciliation, serialize_alias_reference,
};
pub use simplelogin::SimpleLoginAdapterSettings;
