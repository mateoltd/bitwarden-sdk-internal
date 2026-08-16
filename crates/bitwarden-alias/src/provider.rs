use std::sync::Arc;

use bitwarden_sensitive_value::{ExposeSensitive, SensitiveString};

use crate::{
    Alias, AliasAdapterDescriptor, AliasConsistency, AliasError, AliasFreshness, AliasIdentity,
    AliasLifecycleState, AliasPage, AliasProviderCapabilities, CreateAliasRequest,
    CreateSendReplyIdentityRequest, DeleteAliasResult, ListAliasesRequest, SendReplyIdentity,
    SendReplyIdentityPage,
    models::validate_page_token,
    simplelogin::{SimpleLoginAdapterSettings, SimpleLoginTransport},
    simplelogin_error::SimpleLoginError,
    simplelogin_models,
};

/// Injected provider adapter SPI. Implementations translate provider-native state at this boundary;
/// native payloads, endpoints, credentials, and error bodies never cross it.
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait AliasProviderAdapter: Send + Sync {
    /// Returns the stable non-secret adapter descriptor.
    fn descriptor(&self) -> AliasAdapterDescriptor;
    /// Returns the UUID v4 assigned to this authorization.
    fn connection_id(&self) -> &str;

    /// Creates an alias from provider-neutral input.
    async fn create(&self, request: CreateAliasRequest) -> Result<Alias, AliasError>;
    /// Lists one provider-neutral page of aliases.
    async fn list(&self, request: ListAliasesRequest) -> Result<AliasPage, AliasError>;
    /// Reads the current snapshot for one stable identity.
    async fn get(&self, identity: AliasIdentity) -> Result<Alias, AliasError>;
    /// Explicitly sets alias forwarding state.
    async fn set_enabled(
        &self,
        identity: AliasIdentity,
        enabled: bool,
    ) -> Result<Alias, AliasError>;
    /// Deletes one alias idempotently.
    async fn delete(&self, identity: AliasIdentity) -> Result<DeleteAliasResult, AliasError>;
    /// Creates a recipient-scoped send/reply identity.
    async fn create_send_reply_identity(
        &self,
        request: CreateSendReplyIdentityRequest,
    ) -> Result<SendReplyIdentity, AliasError>;
    /// Lists one page of recipient-scoped send/reply identities.
    async fn list_send_reply_identities(
        &self,
        alias: AliasIdentity,
        page_token: Option<String>,
    ) -> Result<SendReplyIdentityPage, AliasError>;
    /// Removes a recipient-scoped send/reply identity.
    async fn remove_send_reply_identity(
        &self,
        identity: SendReplyIdentity,
    ) -> Result<(), AliasError>;
    /// Sets recipient blocking when the adapter exposes `send-reply.block`.
    async fn set_send_reply_blocked(
        &self,
        identity: SendReplyIdentity,
        blocked: bool,
    ) -> Result<SendReplyIdentity, AliasError>;
}

/// Provider-neutral stateful lifecycle service.
///
/// Authorization and output validation are applied around every injected adapter call. Pure
/// canonicalization, codecs, reducers, and reconciliation remain separate total functions.
#[derive(Clone)]
pub struct AliasClient {
    adapter: Arc<dyn AliasProviderAdapter>,
    connection_id: String,
    capabilities: AliasProviderCapabilities,
}

impl AliasClient {
    /// Creates a validated lifecycle client around an injected adapter.
    pub fn new(adapter: Arc<dyn AliasProviderAdapter>) -> Result<Self, AliasError> {
        let descriptor = adapter.descriptor().canonicalize()?;
        crate::models::validate_random_id(adapter.connection_id())?;
        descriptor.capabilities.validate()?;
        Ok(Self {
            connection_id: adapter.connection_id().to_owned(),
            capabilities: descriptor.capabilities,
            adapter,
        })
    }

    /// Returns the stable connection UUID used to authorize every operation.
    pub fn connection_id(&self) -> &str {
        &self.connection_id
    }

    /// Returns the canonical negotiated adapter capabilities.
    pub fn capabilities(&self) -> AliasProviderCapabilities {
        self.capabilities.clone()
    }

    /// Creates an alias through the injected adapter.
    pub async fn create(&self, mut request: CreateAliasRequest) -> Result<Alias, AliasError> {
        if let Some(hostname) = request.hostname.as_ref() {
            request.hostname = Some(SensitiveString::from(crate::models::normalize_hostname(
                hostname.expose(),
            )?));
        }
        self.validate_alias(
            self.adapter
                .create(request)
                .await
                .map_err(AliasError::sanitized)?,
        )
    }

    /// Lists a validated page of aliases.
    pub async fn list(&self, request: ListAliasesRequest) -> Result<AliasPage, AliasError> {
        validate_page_token(request.page_token.as_deref())?;
        let page = self
            .adapter
            .list(request)
            .await
            .map_err(AliasError::sanitized)?;
        if page.aliases.len() > crate::models::MAX_PAGE_ITEMS {
            return Err(AliasError::InvalidResponse);
        }
        validate_page_token(page.next_page_token.as_deref())?;
        for alias in &page.aliases {
            self.validate_alias_ref(alias)?;
        }
        Ok(page)
    }

    /// Reads the current snapshot for one authorized identity.
    pub async fn get(&self, identity: AliasIdentity) -> Result<Alias, AliasError> {
        self.authorize(&identity)?;
        let expected_identity = identity.clone();
        let alias = self.validate_alias(
            self.adapter
                .get(identity)
                .await
                .map_err(AliasError::sanitized)?,
        )?;
        if !same_identity_snapshot(&alias.identity, &expected_identity) {
            return Err(AliasError::InvalidResponse);
        }
        Ok(alias)
    }

    /// Explicitly enables or disables one authorized alias.
    pub async fn set_enabled(
        &self,
        identity: AliasIdentity,
        enabled: bool,
    ) -> Result<Alias, AliasError> {
        self.authorize(&identity)?;
        let alias = self
            .adapter
            .set_enabled(identity.clone(), enabled)
            .await
            .map_err(AliasError::sanitized)?;
        self.validate_alias_ref(&alias)?;
        if !same_identity_snapshot(&alias.identity, &identity)
            || alias.lifecycle
                != if enabled {
                    AliasLifecycleState::Enabled
                } else {
                    AliasLifecycleState::Disabled
                }
        {
            return Err(AliasError::InvalidResponse);
        }
        Ok(alias)
    }

    /// Deletes one authorized alias idempotently.
    pub async fn delete(&self, identity: AliasIdentity) -> Result<DeleteAliasResult, AliasError> {
        self.authorize(&identity)?;
        let result = self
            .adapter
            .delete(identity.clone())
            .await
            .map_err(AliasError::sanitized)?;
        result
            .identity
            .validate()
            .map_err(|_| AliasError::InvalidResponse)?;
        if result.identity.connection_id != self.connection_id {
            return Err(AliasError::InvalidResponse);
        }
        if !same_identity_snapshot(&result.identity, &identity) || !result.deleted {
            return Err(AliasError::InvalidResponse);
        }
        Ok(result)
    }

    /// Creates a recipient-scoped send/reply identity.
    pub async fn create_send_reply_identity(
        &self,
        mut request: CreateSendReplyIdentityRequest,
    ) -> Result<SendReplyIdentity, AliasError> {
        self.authorize(&request.alias)?;
        request.recipient = SensitiveString::from(crate::models::normalize_email_address(
            request.recipient.expose(),
        )?);
        let expected_alias = request.alias.clone();
        let expected_recipient = request.recipient.clone();
        let identity = self
            .adapter
            .create_send_reply_identity(request)
            .await
            .map_err(AliasError::sanitized)?;
        let identity = self.validate_send_reply_identity(identity)?;
        if !same_identity_snapshot(&identity.alias, &expected_alias)
            || identity.recipient != expected_recipient
            || !identity.valid
        {
            return Err(AliasError::InvalidResponse);
        }
        Ok(identity)
    }

    /// Lists one page of recipient-scoped send/reply identities.
    pub async fn list_send_reply_identities(
        &self,
        alias: AliasIdentity,
        page_token: Option<String>,
    ) -> Result<SendReplyIdentityPage, AliasError> {
        self.authorize(&alias)?;
        validate_page_token(page_token.as_deref())?;
        let expected_alias = alias.clone();
        let page = self
            .adapter
            .list_send_reply_identities(alias, page_token)
            .await
            .map_err(AliasError::sanitized)?;
        if page.identities.len() > crate::models::MAX_PAGE_ITEMS {
            return Err(AliasError::InvalidResponse);
        }
        validate_page_token(page.next_page_token.as_deref())?;
        for identity in &page.identities {
            self.validate_send_reply_identity_ref(identity)?;
            if !same_identity_snapshot(&identity.alias, &expected_alias) {
                return Err(AliasError::InvalidResponse);
            }
        }
        Ok(page)
    }

    /// Removes a recipient-scoped send/reply identity.
    pub async fn remove_send_reply_identity(
        &self,
        identity: SendReplyIdentity,
    ) -> Result<(), AliasError> {
        self.authorize(&identity.alias)?;
        identity.validate()?;
        if !self.block_metadata_matches(&identity) {
            return Err(AliasError::InvalidInput);
        }
        self.adapter
            .remove_send_reply_identity(identity)
            .await
            .map_err(AliasError::sanitized)
    }

    /// Sets the optional recipient block state when the adapter negotiated
    /// `send-reply.block`.
    pub async fn set_send_reply_blocked(
        &self,
        identity: SendReplyIdentity,
        blocked: bool,
    ) -> Result<SendReplyIdentity, AliasError> {
        if self
            .capabilities
            .extensions
            .binary_search_by(|extension| extension.as_str().cmp("send-reply.block"))
            .is_err()
        {
            return Err(AliasError::CapabilityUnsupported);
        }
        self.authorize(&identity.alias)?;
        identity.validate()?;
        if !self.block_metadata_matches(&identity) {
            return Err(AliasError::InvalidInput);
        }
        let expected_connection_id = identity.alias.connection_id.clone();
        let expected_alias_id = identity.alias.alias_id.clone();
        let expected_alias_address = identity.alias.address.clone();
        let expected_identity_id = identity.identity_id.clone();
        let expected_recipient = identity.recipient.clone();
        let expected_address = identity.address.clone();
        let updated = self
            .adapter
            .set_send_reply_blocked(identity, blocked)
            .await
            .map_err(AliasError::sanitized)?;
        self.validate_send_reply_identity_ref(&updated)?;
        if updated.alias.connection_id != expected_connection_id
            || updated.alias.alias_id != expected_alias_id
            || updated.alias.address != expected_alias_address
            || updated.identity_id != expected_identity_id
            || updated.recipient != expected_recipient
            || updated.address != expected_address
            || !updated.valid
            || updated.blocked != Some(blocked)
        {
            return Err(AliasError::InvalidResponse);
        }
        Ok(updated)
    }

    fn authorize(&self, identity: &AliasIdentity) -> Result<(), AliasError> {
        identity.validate()?;
        if identity.connection_id != self.connection_id {
            return Err(AliasError::PermissionDenied);
        }
        Ok(())
    }

    fn validate_alias(&self, alias: Alias) -> Result<Alias, AliasError> {
        self.validate_alias_ref(&alias)?;
        Ok(alias)
    }

    fn validate_alias_ref(&self, alias: &Alias) -> Result<(), AliasError> {
        alias.validate().map_err(|_| AliasError::InvalidResponse)?;
        if alias.identity.connection_id != self.connection_id
            || alias.capabilities != self.capabilities
            || alias.label.is_some()
            || alias.freshness != AliasFreshness::Current
            || alias.consistency != AliasConsistency::Clean
        {
            return Err(AliasError::InvalidResponse);
        }
        Ok(())
    }

    fn validate_send_reply_identity(
        &self,
        identity: SendReplyIdentity,
    ) -> Result<SendReplyIdentity, AliasError> {
        self.validate_send_reply_identity_ref(&identity)?;
        Ok(identity)
    }

    fn validate_send_reply_identity_ref(
        &self,
        identity: &SendReplyIdentity,
    ) -> Result<(), AliasError> {
        identity
            .validate()
            .map_err(|_| AliasError::InvalidResponse)?;
        if identity.alias.connection_id != self.connection_id
            || !self.block_metadata_matches(identity)
        {
            return Err(AliasError::InvalidResponse);
        }
        Ok(())
    }

    fn block_metadata_matches(&self, identity: &SendReplyIdentity) -> bool {
        identity.blocked.is_some()
            == self
                .capabilities
                .extensions
                .binary_search_by(|extension| extension.as_str().cmp("send-reply.block"))
                .is_ok()
    }
}

fn same_identity_snapshot(left: &AliasIdentity, right: &AliasIdentity) -> bool {
    left.resource_key() == right.resource_key() && left.address == right.address
}

/// Concrete SimpleLogin implementation behind the provider-neutral SPI.
#[derive(Clone)]
pub struct SimpleLoginAdapter {
    transport: SimpleLoginTransport,
    connection_id: String,
    capabilities: AliasProviderCapabilities,
}

impl SimpleLoginAdapter {
    /// Creates the concrete adapter from runtime-only SimpleLogin settings.
    pub fn new(settings: SimpleLoginAdapterSettings) -> Result<Self, AliasError> {
        let transport = SimpleLoginTransport::new(settings).map_err(map_simplelogin_error)?;
        let connection_id = transport
            .connection_id()
            .map_err(map_simplelogin_error)?
            .to_owned();
        let mut capabilities = AliasProviderCapabilities::first_class();
        capabilities.extensions = vec!["send-reply.block".to_owned()];
        capabilities.validate()?;
        Ok(Self {
            transport,
            connection_id,
            capabilities,
        })
    }

    /// Wraps this adapter in the provider-neutral lifecycle client.
    pub fn into_client(self) -> Result<AliasClient, AliasError> {
        AliasClient::new(Arc::new(self))
    }

    fn parse_alias_id(identity: &AliasIdentity) -> Result<simplelogin_models::AliasId, AliasError> {
        let value = identity
            .alias_id
            .parse::<u64>()
            .map_err(|_| AliasError::InvalidInput)?;
        if value == 0 {
            return Err(AliasError::InvalidInput);
        }
        Ok(simplelogin_models::AliasId(value))
    }

    fn parse_page(value: Option<&str>) -> Result<u32, AliasError> {
        match value {
            None => Ok(0),
            Some(value) => value.parse().map_err(|_| AliasError::InvalidInput),
        }
    }

    fn next_page_token(page: u32, has_next: bool) -> Result<Option<String>, AliasError> {
        if !has_next {
            return Ok(None);
        }
        page.checked_add(1)
            .map(|next| Some(next.to_string()))
            .ok_or(AliasError::InvalidResponse)
    }

    fn map_alias(&self, alias: simplelogin_models::Alias) -> Result<Alias, AliasError> {
        let alias = Alias {
            identity: AliasIdentity::new(
                self.connection_id.clone(),
                alias.id.to_string(),
                alias.email,
            )?,
            lifecycle: if alias.enabled {
                AliasLifecycleState::Enabled
            } else {
                AliasLifecycleState::Disabled
            },
            freshness: AliasFreshness::Current,
            consistency: AliasConsistency::Clean,
            label: None,
            capabilities: self.capabilities.clone(),
        };
        alias.validate()?;
        Ok(alias)
    }

    fn map_contact(
        &self,
        alias: AliasIdentity,
        contact: simplelogin_models::ReverseAlias,
    ) -> Result<SendReplyIdentity, AliasError> {
        let identity = SendReplyIdentity {
            alias,
            identity_id: contact.id.to_string(),
            recipient: contact.contact,
            address: contact.reverse_alias_address,
            valid: true,
            blocked: Some(contact.block_forward),
        };
        identity.validate()?;
        Ok(identity)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl AliasProviderAdapter for SimpleLoginAdapter {
    fn descriptor(&self) -> AliasAdapterDescriptor {
        AliasAdapterDescriptor {
            adapter_id: "simplelogin".to_owned(),
            capabilities: self.capabilities.clone(),
        }
    }

    fn connection_id(&self) -> &str {
        &self.connection_id
    }

    async fn create(&self, request: CreateAliasRequest) -> Result<Alias, AliasError> {
        let alias = self
            .transport
            .create_random_alias(simplelogin_models::CreateRandomAliasRequest {
                hostname: request.hostname,
                mode: None,
                note: None,
            })
            .await
            .map_err(map_simplelogin_error)?;
        self.map_alias(alias)
    }

    async fn list(&self, request: ListAliasesRequest) -> Result<AliasPage, AliasError> {
        let page_number = Self::parse_page(request.page_token.as_deref())?;
        let page = self
            .transport
            .list_aliases(simplelogin_models::ListAliasesRequest {
                page: page_number,
                filter: None,
            })
            .await
            .map_err(map_simplelogin_error)?;
        let has_next = !page.aliases.is_empty();
        let aliases = page
            .aliases
            .into_iter()
            .map(|alias| self.map_alias(alias))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(AliasPage {
            aliases,
            next_page_token: Self::next_page_token(page_number, has_next)?,
        })
    }

    async fn get(&self, identity: AliasIdentity) -> Result<Alias, AliasError> {
        let id = Self::parse_alias_id(&identity)?;
        let alias = match self.transport.get_alias(id).await {
            Ok(alias) => alias,
            Err(SimpleLoginError::Provider { status: 400 | 404 }) => {
                return Err(AliasError::NotFound);
            }
            Err(error) => return Err(map_simplelogin_error(error)),
        };
        let alias = self.map_alias(alias)?;
        if alias.identity.resource_key() != identity.resource_key() {
            return Err(AliasError::InvalidResponse);
        }
        Ok(alias)
    }

    async fn set_enabled(
        &self,
        identity: AliasIdentity,
        enabled: bool,
    ) -> Result<Alias, AliasError> {
        let id = Self::parse_alias_id(&identity)?;
        let native_alias = match self.transport.set_alias_enabled(id, enabled).await {
            Ok(alias) => alias,
            Err(SimpleLoginError::Provider { status: 400 | 404 }) => {
                return Err(AliasError::NotFound);
            }
            Err(error) => return Err(map_simplelogin_error(error)),
        };
        if native_alias.id != id || native_alias.enabled != enabled {
            return Err(AliasError::InvalidResponse);
        }
        self.map_alias(native_alias)
    }

    async fn delete(&self, identity: AliasIdentity) -> Result<DeleteAliasResult, AliasError> {
        let id = Self::parse_alias_id(&identity)?;
        match self.transport.delete_alias(id).await {
            Ok(result) if result.deleted => Ok(DeleteAliasResult {
                identity,
                deleted: true,
            }),
            Ok(_) => Err(AliasError::InvalidResponse),
            Err(SimpleLoginError::Provider { status: 404 }) => Ok(DeleteAliasResult {
                identity,
                deleted: true,
            }),
            // The pinned SimpleLogin API returns 403 for both an absent alias and an alias owned
            // by another account. Its detail endpoint distinguishes those cases without reading
            // or propagating a provider body: absent is 400, while foreign ownership stays 403.
            Err(SimpleLoginError::Provider { status: 403 }) => {
                match self.transport.get_alias(id).await {
                    Err(SimpleLoginError::Provider { status: 400 | 404 }) => {
                        Ok(DeleteAliasResult {
                            identity,
                            deleted: true,
                        })
                    }
                    Ok(_) | Err(SimpleLoginError::Provider { status: 403 }) => {
                        Err(AliasError::PermissionDenied)
                    }
                    Err(error) => Err(map_simplelogin_error(error)),
                }
            }
            Err(error) => Err(map_simplelogin_error(error)),
        }
    }

    async fn create_send_reply_identity(
        &self,
        request: CreateSendReplyIdentityRequest,
    ) -> Result<SendReplyIdentity, AliasError> {
        let id = Self::parse_alias_id(&request.alias)?;
        let contact = self
            .transport
            .create_reverse_alias(id, request.recipient)
            .await
            .map_err(map_simplelogin_error)?;
        self.map_contact(request.alias, contact)
    }

    async fn list_send_reply_identities(
        &self,
        alias: AliasIdentity,
        page_token: Option<String>,
    ) -> Result<SendReplyIdentityPage, AliasError> {
        let id = Self::parse_alias_id(&alias)?;
        let page_number = Self::parse_page(page_token.as_deref())?;
        let page = self
            .transport
            .list_reverse_aliases(id, page_number)
            .await
            .map_err(map_simplelogin_error)?;
        let has_next = !page.contacts.is_empty();
        let identities = page
            .contacts
            .into_iter()
            .map(|contact| self.map_contact(alias.clone(), contact))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(SendReplyIdentityPage {
            identities,
            next_page_token: Self::next_page_token(page_number, has_next)?,
        })
    }

    async fn remove_send_reply_identity(
        &self,
        identity: SendReplyIdentity,
    ) -> Result<(), AliasError> {
        let id = identity
            .identity_id
            .parse::<u64>()
            .map(simplelogin_models::ContactId)
            .map_err(|_| AliasError::InvalidInput)?;
        match self.transport.delete_contact(id).await {
            Ok(result) if result.deleted => Ok(()),
            Ok(_) => Err(AliasError::InvalidResponse),
            Err(SimpleLoginError::Provider { status: 404 }) => Ok(()),
            Err(error) => Err(map_simplelogin_error(error)),
        }
    }

    async fn set_send_reply_blocked(
        &self,
        identity: SendReplyIdentity,
        blocked: bool,
    ) -> Result<SendReplyIdentity, AliasError> {
        let alias_id = Self::parse_alias_id(&identity.alias)?;
        let contact_id = identity
            .identity_id
            .parse::<u64>()
            .map(simplelogin_models::ContactId)
            .map_err(|_| AliasError::InvalidInput)?;
        let contact = self
            .transport
            .set_contact_blocked(alias_id, contact_id, blocked)
            .await
            .map_err(map_simplelogin_error)?;
        if contact.id != contact_id || contact.block_forward != blocked {
            return Err(AliasError::InvalidResponse);
        }
        self.map_contact(identity.alias, contact)
    }
}

fn map_simplelogin_error(error: SimpleLoginError) -> AliasError {
    match error {
        SimpleLoginError::InvalidRequest(_)
        | SimpleLoginError::InvalidBaseUrl(_)
        | SimpleLoginError::InvalidAuthenticationToken
        | SimpleLoginError::InvalidConnectionIdentity => AliasError::InvalidInput,
        SimpleLoginError::RedirectRejected { .. } => AliasError::LocalSecurityFailure,
        SimpleLoginError::AuthenticationFailed => AliasError::AuthenticationRejected,
        SimpleLoginError::RateLimited {
            retry_after_seconds,
        } => AliasError::RateLimited {
            retry_after_seconds,
        },
        SimpleLoginError::Provider { status: 402 } => AliasError::QuotaExhausted,
        SimpleLoginError::Provider { status: 403 } => AliasError::PermissionDenied,
        SimpleLoginError::Provider { status: 404 } => AliasError::NotFound,
        SimpleLoginError::Provider { status } if status >= 500 => AliasError::ServiceUnavailable,
        SimpleLoginError::Provider { .. } => AliasError::InvalidResponse,
        SimpleLoginError::MutationOutcomeUnknown { .. }
        | SimpleLoginError::MutationCommittedButRefreshFailed { .. }
        | SimpleLoginError::MutationResponseInvalid { .. } => AliasError::OutcomeUnknown,
        SimpleLoginError::ConcurrentMutation { .. } => AliasError::SyncConflict,
        SimpleLoginError::ResponseTooLarge { .. }
        | SimpleLoginError::UnexpectedContentType
        | SimpleLoginError::InvalidResponse(_)
        | SimpleLoginError::InvalidResponseValue(_) => AliasError::InvalidResponse,
        SimpleLoginError::Transport(error) => map_transport_error(&error),
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn map_transport_error(error: &reqwest::Error) -> AliasError {
    if error.is_timeout() {
        AliasError::Timeout
    } else if error.is_connect() {
        AliasError::Offline
    } else {
        AliasError::ServiceUnavailable
    }
}

#[cfg(target_arch = "wasm32")]
fn map_transport_error(error: &reqwest::Error) -> AliasError {
    if error.is_timeout() {
        AliasError::Timeout
    } else {
        AliasError::Offline
    }
}
