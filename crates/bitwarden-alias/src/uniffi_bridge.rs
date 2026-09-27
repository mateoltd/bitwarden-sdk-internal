use std::sync::Arc;

use async_trait::async_trait;

use crate::{
    ALIAS_CONTRACT_VERSION, Alias, AliasAdapterDescriptor, AliasConnection, AliasError,
    AliasIdentity, AliasPage, CreateAliasRequest, CreateSendReplyIdentityRequest,
    DeleteAliasResult, ListAliasesRequest, SendReplyIdentity, SendReplyIdentityPage,
};

impl From<uniffi::UnexpectedUniFFICallbackError> for AliasError {
    fn from(_: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::LocalSecurityFailure
    }
}

/// Provider-neutral native adapter SPI.
///
/// Credentials, endpoints, provider-native payloads, and provider error bodies stay inside the
/// Swift or Kotlin implementation. Only canonical alias records and sanitized alias errors cross
/// this callback boundary.
#[uniffi::export(with_foreign)]
#[async_trait]
pub trait AliasProviderAdapter: Send + Sync {
    fn descriptor(&self) -> Result<AliasAdapterDescriptor, AliasError>;
    fn connection_id(&self) -> Result<String, AliasError>;
    async fn create(&self, request: CreateAliasRequest) -> Result<Alias, AliasError>;
    async fn list(&self, request: ListAliasesRequest) -> Result<AliasPage, AliasError>;
    async fn get(&self, identity: AliasIdentity) -> Result<Alias, AliasError>;
    async fn set_enabled(
        &self,
        identity: AliasIdentity,
        enabled: bool,
    ) -> Result<Alias, AliasError>;
    async fn delete(&self, identity: AliasIdentity) -> Result<DeleteAliasResult, AliasError>;
    async fn create_send_reply_identity(
        &self,
        request: CreateSendReplyIdentityRequest,
    ) -> Result<SendReplyIdentity, AliasError>;
    async fn list_send_reply_identities(
        &self,
        alias: AliasIdentity,
        page_token: Option<String>,
    ) -> Result<SendReplyIdentityPage, AliasError>;
    async fn remove_send_reply_identity(
        &self,
        identity: SendReplyIdentity,
    ) -> Result<(), AliasError>;
    async fn set_send_reply_blocked(
        &self,
        identity: SendReplyIdentity,
        blocked: bool,
    ) -> Result<SendReplyIdentity, AliasError>;
}

struct ForeignAliasProviderAdapter {
    inner: Arc<dyn AliasProviderAdapter>,
    descriptor: AliasAdapterDescriptor,
    connection_id: String,
}

#[async_trait]
impl crate::provider::AliasProviderAdapter for ForeignAliasProviderAdapter {
    fn descriptor(&self) -> AliasAdapterDescriptor {
        self.descriptor.clone()
    }

    fn connection_id(&self) -> &str {
        &self.connection_id
    }

    async fn create(&self, request: CreateAliasRequest) -> Result<Alias, AliasError> {
        self.inner.create(request).await
    }

    async fn list(&self, request: ListAliasesRequest) -> Result<AliasPage, AliasError> {
        self.inner.list(request).await
    }

    async fn get(&self, identity: AliasIdentity) -> Result<Alias, AliasError> {
        self.inner.get(identity).await
    }

    async fn set_enabled(
        &self,
        identity: AliasIdentity,
        enabled: bool,
    ) -> Result<Alias, AliasError> {
        self.inner.set_enabled(identity, enabled).await
    }

    async fn delete(&self, identity: AliasIdentity) -> Result<DeleteAliasResult, AliasError> {
        self.inner.delete(identity).await
    }

    async fn create_send_reply_identity(
        &self,
        request: CreateSendReplyIdentityRequest,
    ) -> Result<SendReplyIdentity, AliasError> {
        self.inner.create_send_reply_identity(request).await
    }

    async fn list_send_reply_identities(
        &self,
        alias: AliasIdentity,
        page_token: Option<String>,
    ) -> Result<SendReplyIdentityPage, AliasError> {
        self.inner
            .list_send_reply_identities(alias, page_token)
            .await
    }

    async fn remove_send_reply_identity(
        &self,
        identity: SendReplyIdentity,
    ) -> Result<(), AliasError> {
        self.inner.remove_send_reply_identity(identity).await
    }

    async fn set_send_reply_blocked(
        &self,
        identity: SendReplyIdentity,
        blocked: bool,
    ) -> Result<SendReplyIdentity, AliasError> {
        self.inner.set_send_reply_blocked(identity, blocked).await
    }
}

/// Stateful lifecycle service around an injected provider-neutral adapter.
#[derive(uniffi::Object)]
pub struct AliasClient {
    inner: crate::provider::AliasClient,
    connection: AliasConnection,
}

#[uniffi::export(async_runtime = "tokio")]
impl AliasClient {
    #[uniffi::constructor]
    pub fn new(adapter: Arc<dyn AliasProviderAdapter>) -> Result<Self, AliasError> {
        let descriptor = adapter.descriptor().map_err(AliasError::sanitized)?;
        let connection_id = adapter.connection_id().map_err(AliasError::sanitized)?;
        let connection = AliasConnection {
            version: ALIAS_CONTRACT_VERSION,
            connection_id: connection_id.clone(),
            adapter: descriptor.clone(),
        }
        .canonicalize()?;
        let bridge = ForeignAliasProviderAdapter {
            inner: adapter,
            descriptor,
            connection_id,
        };
        let inner = crate::provider::AliasClient::new(Arc::new(bridge))?;
        Ok(Self { inner, connection })
    }

    pub fn connection(&self) -> AliasConnection {
        self.connection.clone()
    }

    pub async fn create(&self, request: CreateAliasRequest) -> Result<Alias, AliasError> {
        self.inner.create(request).await
    }

    pub async fn list(&self, request: ListAliasesRequest) -> Result<AliasPage, AliasError> {
        self.inner.list(request).await
    }

    pub async fn get(&self, identity: AliasIdentity) -> Result<Alias, AliasError> {
        self.inner.get(identity).await
    }

    pub async fn set_enabled(
        &self,
        identity: AliasIdentity,
        enabled: bool,
    ) -> Result<Alias, AliasError> {
        self.inner.set_enabled(identity, enabled).await
    }

    pub async fn delete(&self, identity: AliasIdentity) -> Result<DeleteAliasResult, AliasError> {
        self.inner.delete(identity).await
    }

    pub async fn create_send_reply_identity(
        &self,
        request: CreateSendReplyIdentityRequest,
    ) -> Result<SendReplyIdentity, AliasError> {
        self.inner.create_send_reply_identity(request).await
    }

    pub async fn list_send_reply_identities(
        &self,
        alias: AliasIdentity,
        page_token: Option<String>,
    ) -> Result<SendReplyIdentityPage, AliasError> {
        self.inner
            .list_send_reply_identities(alias, page_token)
            .await
    }

    pub async fn remove_send_reply_identity(
        &self,
        identity: SendReplyIdentity,
    ) -> Result<(), AliasError> {
        self.inner.remove_send_reply_identity(identity).await
    }

    pub async fn set_send_reply_blocked(
        &self,
        identity: SendReplyIdentity,
        blocked: bool,
    ) -> Result<SendReplyIdentity, AliasError> {
        self.inner.set_send_reply_blocked(identity, blocked).await
    }
}
