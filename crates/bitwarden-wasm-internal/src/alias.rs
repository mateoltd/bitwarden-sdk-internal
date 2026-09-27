use std::sync::Arc;

use async_trait::async_trait;
use bitwarden_alias::{
    Alias, AliasCipherMutationResult, AliasConnection, AliasError, AliasErrorCode, AliasIdentity,
    AliasJournal, AliasJournalState, AliasPage, AliasReconciliationApplyOutput,
    AliasReconciliationError, AliasReconciliationPlan, AliasReference, AliasReferenceError,
    CreateAliasRequest, CreateSendReplyIdentityRequest, DeleteAliasResult, ListAliasesRequest,
    SendReplyIdentity, SendReplyIdentityPage,
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
use js_sys::{Array, Function, Promise, Reflect};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tsify::serde_wasm_bindgen;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

#[wasm_bindgen(typescript_custom_section)]
const ALIAS_ADAPTER_TYPES: &str = r#"
/** A sanitized adapter failure. Provider bodies, endpoints, and credentials are forbidden. */
export interface AliasAdapterFailure {
  code: AliasErrorCode;
  retryAfterSeconds?: number;
}

export type AliasAdapterResult<T> =
  | { status: "success"; value: T }
  | { status: "failure"; failure: AliasAdapterFailure };

/**
 * Provider-neutral lifecycle SPI implemented by the host application.
 * Connection secrets and provider-native transport remain private to this object.
 */
export interface AliasProviderAdapter {
  create(request: CreateAliasRequest): Promise<AliasAdapterResult<Alias>>;
  list(request: ListAliasesRequest): Promise<AliasAdapterResult<AliasPage>>;
  get(identity: AliasIdentity): Promise<AliasAdapterResult<Alias>>;
  setEnabled(identity: AliasIdentity, enabled: boolean): Promise<AliasAdapterResult<Alias>>;
  delete(identity: AliasIdentity): Promise<AliasAdapterResult<DeleteAliasResult>>;
  createSendReplyIdentity(
    request: CreateSendReplyIdentityRequest,
  ): Promise<AliasAdapterResult<SendReplyIdentity>>;
  listSendReplyIdentities(
    identity: AliasIdentity,
    pageToken?: string,
  ): Promise<AliasAdapterResult<SendReplyIdentityPage>>;
  removeSendReplyIdentity(identity: SendReplyIdentity): Promise<AliasAdapterResult<null>>;
  setSendReplyBlocked(
    identity: SendReplyIdentity,
    blocked: boolean,
  ): Promise<AliasAdapterResult<SendReplyIdentity>>;
}
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "AliasProviderAdapter")]
    pub type JsAliasProviderAdapter;
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WasmAliasAdapterFailure {
    code: AliasErrorCode,
    retry_after_seconds: Option<u32>,
}

#[derive(Deserialize)]
#[serde(tag = "status", rename_all = "camelCase", deny_unknown_fields)]
enum WasmAliasAdapterResult<T> {
    Success { value: T },
    Failure { failure: WasmAliasAdapterFailure },
}

fn map_adapter_failure(failure: WasmAliasAdapterFailure) -> AliasError {
    if failure.retry_after_seconds.is_some_and(|value| {
        failure.code != AliasErrorCode::RateLimited
            || u64::from(value) > bitwarden_alias::MAX_RETRY_AFTER_SECONDS
    }) {
        return AliasError::InvalidResponse;
    }
    match failure.code {
        AliasErrorCode::VaultLocked => AliasError::VaultLocked,
        AliasErrorCode::ConnectionMissing => AliasError::ConnectionMissing,
        AliasErrorCode::AuthenticationRejected => AliasError::AuthenticationRejected,
        AliasErrorCode::PermissionDenied => AliasError::PermissionDenied,
        AliasErrorCode::CapabilityUnsupported => AliasError::CapabilityUnsupported,
        AliasErrorCode::InvalidInput => AliasError::InvalidInput,
        AliasErrorCode::NotFound => AliasError::NotFound,
        AliasErrorCode::QuotaExhausted => AliasError::QuotaExhausted,
        AliasErrorCode::RateLimited => AliasError::RateLimited {
            retry_after_seconds: failure.retry_after_seconds.map(u64::from),
        },
        AliasErrorCode::Offline => AliasError::Offline,
        AliasErrorCode::Timeout => AliasError::Timeout,
        AliasErrorCode::ServiceUnavailable => AliasError::ServiceUnavailable,
        AliasErrorCode::InvalidResponse => AliasError::InvalidResponse,
        AliasErrorCode::OutcomeUnknown => AliasError::OutcomeUnknown,
        AliasErrorCode::SyncConflict => AliasError::SyncConflict,
        AliasErrorCode::LocalSecurityFailure => AliasError::LocalSecurityFailure,
    }
}

struct WasmAliasProviderAdapter {
    inner: JsValue,
    connection: AliasConnection,
}

impl WasmAliasProviderAdapter {
    async fn call<T: DeserializeOwned>(
        &self,
        method_name: &str,
        arguments: &[JsValue],
    ) -> Result<T, AliasError> {
        let method = Reflect::get(&self.inner, &JsValue::from_str(method_name))
            .map_err(|_| AliasError::LocalSecurityFailure)?;
        let function = method
            .dyn_ref::<Function>()
            .ok_or(AliasError::LocalSecurityFailure)?;
        let args = Array::new_with_length(arguments.len() as u32);
        for (index, argument) in arguments.iter().enumerate() {
            args.set(index as u32, argument.clone());
        }
        let returned = function
            .apply(&self.inner, &args)
            .map_err(|_| AliasError::LocalSecurityFailure)?;
        let settled = JsFuture::from(Promise::resolve(&returned))
            .await
            .map_err(|_| AliasError::LocalSecurityFailure)?;
        let result: WasmAliasAdapterResult<T> =
            serde_wasm_bindgen::from_value(settled).map_err(|_| AliasError::InvalidResponse)?;
        match result {
            WasmAliasAdapterResult::Success { value } => Ok(value),
            WasmAliasAdapterResult::Failure { failure } => Err(map_adapter_failure(failure)),
        }
    }

    fn argument<T: Serialize>(value: &T) -> Result<JsValue, AliasError> {
        serde_wasm_bindgen::to_value(value).map_err(|_| AliasError::LocalSecurityFailure)
    }
}

#[async_trait(?Send)]
impl bitwarden_alias::AliasProviderAdapter for WasmAliasProviderAdapter {
    fn descriptor(&self) -> bitwarden_alias::AliasAdapterDescriptor {
        self.connection.adapter.clone()
    }

    fn connection_id(&self) -> &str {
        &self.connection.connection_id
    }

    async fn create(&self, request: CreateAliasRequest) -> Result<Alias, AliasError> {
        self.call("create", &[Self::argument(&request)?]).await
    }

    async fn list(&self, request: ListAliasesRequest) -> Result<AliasPage, AliasError> {
        self.call("list", &[Self::argument(&request)?]).await
    }

    async fn get(&self, identity: AliasIdentity) -> Result<Alias, AliasError> {
        self.call("get", &[Self::argument(&identity)?]).await
    }

    async fn set_enabled(
        &self,
        identity: AliasIdentity,
        enabled: bool,
    ) -> Result<Alias, AliasError> {
        self.call(
            "setEnabled",
            &[Self::argument(&identity)?, JsValue::from_bool(enabled)],
        )
        .await
    }

    async fn delete(&self, identity: AliasIdentity) -> Result<DeleteAliasResult, AliasError> {
        self.call("delete", &[Self::argument(&identity)?]).await
    }

    async fn create_send_reply_identity(
        &self,
        request: CreateSendReplyIdentityRequest,
    ) -> Result<SendReplyIdentity, AliasError> {
        self.call("createSendReplyIdentity", &[Self::argument(&request)?])
            .await
    }

    async fn list_send_reply_identities(
        &self,
        alias: AliasIdentity,
        page_token: Option<String>,
    ) -> Result<SendReplyIdentityPage, AliasError> {
        self.call(
            "listSendReplyIdentities",
            &[Self::argument(&alias)?, Self::argument(&page_token)?],
        )
        .await
    }

    async fn remove_send_reply_identity(
        &self,
        identity: SendReplyIdentity,
    ) -> Result<(), AliasError> {
        let _: Option<()> = self
            .call("removeSendReplyIdentity", &[Self::argument(&identity)?])
            .await?;
        Ok(())
    }

    async fn set_send_reply_blocked(
        &self,
        identity: SendReplyIdentity,
        blocked: bool,
    ) -> Result<SendReplyIdentity, AliasError> {
        self.call(
            "setSendReplyBlocked",
            &[Self::argument(&identity)?, JsValue::from_bool(blocked)],
        )
        .await
    }
}

/// Stateful provider-neutral lifecycle service around a host-injected adapter.
#[wasm_bindgen]
pub struct AliasClient {
    inner: bitwarden_alias::AliasClient,
    connection: AliasConnection,
}

#[wasm_bindgen]
impl AliasClient {
    /// Creates a lifecycle service from encrypted neutral connection metadata and a host adapter.
    #[wasm_bindgen(constructor)]
    pub fn new(
        connection: AliasConnection,
        adapter: JsAliasProviderAdapter,
    ) -> Result<Self, AliasError> {
        let connection = connection.canonicalize()?;
        let bridge = WasmAliasProviderAdapter {
            inner: adapter.into(),
            connection: connection.clone(),
        };
        let inner = bitwarden_alias::AliasClient::new(Arc::new(bridge))?;
        Ok(Self { inner, connection })
    }

    /// Returns the canonical encrypted connection metadata supplied at construction.
    pub fn connection(&self) -> AliasConnection {
        self.connection.clone()
    }

    /// Creates an alias through the injected adapter.
    pub async fn create(&self, request: CreateAliasRequest) -> Result<Alias, AliasError> {
        self.inner.create(request).await
    }

    /// Lists a page of aliases through the injected adapter.
    pub async fn list(&self, request: ListAliasesRequest) -> Result<AliasPage, AliasError> {
        self.inner.list(request).await
    }

    /// Gets the current snapshot for a connection-scoped identity.
    pub async fn get(&self, identity: AliasIdentity) -> Result<Alias, AliasError> {
        self.inner.get(identity).await
    }

    /// Explicitly enables or disables an alias and validates the confirmed state.
    pub async fn set_enabled(
        &self,
        identity: AliasIdentity,
        enabled: bool,
    ) -> Result<Alias, AliasError> {
        self.inner.set_enabled(identity, enabled).await
    }

    /// Deletes an alias idempotently without modifying any bound login.
    pub async fn delete(&self, identity: AliasIdentity) -> Result<DeleteAliasResult, AliasError> {
        self.inner.delete(identity).await
    }

    /// Creates a recipient-scoped send/reply identity.
    pub async fn create_send_reply_identity(
        &self,
        request: CreateSendReplyIdentityRequest,
    ) -> Result<SendReplyIdentity, AliasError> {
        self.inner.create_send_reply_identity(request).await
    }

    /// Lists recipient-scoped send/reply identities for one alias.
    pub async fn list_send_reply_identities(
        &self,
        alias: AliasIdentity,
        page_token: Option<String>,
    ) -> Result<SendReplyIdentityPage, AliasError> {
        self.inner
            .list_send_reply_identities(alias, page_token)
            .await
    }

    /// Removes a recipient-scoped send/reply identity.
    pub async fn remove_send_reply_identity(
        &self,
        identity: SendReplyIdentity,
    ) -> Result<(), AliasError> {
        self.inner.remove_send_reply_identity(identity).await
    }

    /// Sets recipient blocking when the adapter negotiated `send-reply.block`.
    pub async fn set_send_reply_blocked(
        &self,
        identity: SendReplyIdentity,
        blocked: bool,
    ) -> Result<SendReplyIdentity, AliasError> {
        self.inner.set_send_reply_blocked(identity, blocked).await
    }
}

/// Creates the canonical serialized v1 alias reference from neutral alias identity.
#[wasm_bindgen]
pub fn create_alias_reference(
    identity: bitwarden_alias::AliasIdentity,
) -> Result<SensitiveString, AliasReferenceError> {
    core_create_alias_reference(&identity)
}

/// Parses and validates a canonical v1 alias reference without exposing its payload in errors.
#[wasm_bindgen]
pub fn parse_alias_reference(
    value: SensitiveString,
) -> Result<AliasReference, AliasReferenceError> {
    // EXPOSE: The caller already owns the decrypted login member. Errors never render its value.
    core_parse_alias_reference(value.expose())
}

/// Re-serializes a parsed reference into the one canonical JSON representation.
#[wasm_bindgen]
pub fn serialize_alias_reference(
    reference: AliasReference,
) -> Result<SensitiveString, AliasReferenceError> {
    core_serialize_alias_reference(&reference)
}

/// Binds a canonical reference to a decrypted login cipher after username integrity validation.
#[wasm_bindgen]
pub fn bind_alias_reference(
    value: SensitiveString,
    cipher: CipherView,
) -> Result<AliasCipherMutationResult, AliasReferenceError> {
    // EXPOSE: Binding parses caller-owned decrypted vault metadata and never logs it.
    core_bind_alias_reference(value.expose(), cipher)
}

/// Clears a binding before save when the login username no longer matches its bound address.
#[wasm_bindgen]
pub fn clear_alias_reference_if_username_changed(
    cipher: CipherView,
) -> Result<AliasCipherMutationResult, AliasReferenceError> {
    core_clear_alias_reference_if_username_changed(cipher)
}

/// Computes a deterministic, read-only reconciliation plan for one stable connection.
#[wasm_bindgen]
pub fn plan_alias_reconciliation(
    connection_id: String,
    aliases: Vec<Alias>,
    ciphers: Vec<CipherView>,
) -> Result<AliasReconciliationPlan, AliasReconciliationError> {
    core_plan_alias_reconciliation(&connection_id, &aliases, &ciphers)
}

/// Atomically validates and applies a reconciliation plan to owned decrypted ciphers.
#[wasm_bindgen]
pub fn apply_alias_reconciliation(
    plan: AliasReconciliationPlan,
    aliases: Vec<Alias>,
    ciphers: Vec<CipherView>,
) -> Result<AliasReconciliationApplyOutput, AliasReconciliationError> {
    core_apply_alias_reconciliation(&plan, &aliases, ciphers)
}

/// Validates and deterministically orders an encrypted provider-neutral journal.
#[wasm_bindgen]
pub fn canonicalize_alias_journal(journal: AliasJournal) -> Result<AliasJournal, AliasError> {
    journal.canonicalize()
}

/// Pure set-union merge for two journals belonging to the same stable connection.
#[wasm_bindgen]
pub fn merge_alias_journals(
    left: AliasJournal,
    right: AliasJournal,
) -> Result<AliasJournal, AliasError> {
    left.merge(&right)
}

/// Pure deterministic reduction of canonical journal facts into operation and resource state.
#[wasm_bindgen]
pub fn reduce_alias_journal(journal: AliasJournal) -> Result<AliasJournalState, AliasError> {
    journal.reduce()
}
