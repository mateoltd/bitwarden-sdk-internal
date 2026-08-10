use bitwarden_alias::{
    Alias, AliasClientSettings, AliasCreationOptions, AliasDomain, AliasError, AliasFilter,
    AliasId, AliasPage, AliasRecommendation, AliasState, ContactId, ContactState,
    CreateCustomAliasRequest, CreateRandomAliasRequest, CustomDomain, CustomDomainId,
    DeleteAliasResult, DeleteContactResult, ListAliasesRequest, Mailbox, MailboxId, ReverseAlias,
    ReverseAliasPage, SearchAliasesRequest,
};
use bitwarden_sensitive_value::SensitiveString;
use serde::Deserialize;
use tsify::Tsify;
use wasm_bindgen::prelude::*;

/// An explicit nullable text update for lifecycle fields where omission means "leave unchanged".
#[derive(Deserialize, Tsify)]
#[serde(tag = "type", rename_all = "camelCase")]
#[tsify(from_wasm_abi)]
pub enum OptionalSensitiveStringUpdate {
    /// Clear the existing value.
    Clear,
    /// Replace the existing value.
    Set {
        /// New sensitive value.
        value: SensitiveString,
    },
}

impl OptionalSensitiveStringUpdate {
    fn into_core(self) -> Option<SensitiveString> {
        match self {
            Self::Clear => None,
            Self::Set { value } => Some(value),
        }
    }
}

/// Alias mutation input with unambiguous set, clear, and leave-unchanged semantics.
#[derive(Deserialize, Tsify)]
#[tsify(from_wasm_abi, large_number_types_as_bigints)]
pub struct AliasUpdateRequest {
    /// Set or clear the private note; omission leaves it unchanged.
    pub note: Option<OptionalSensitiveStringUpdate>,
    /// Set or clear the display name; omission leaves it unchanged.
    pub name: Option<OptionalSensitiveStringUpdate>,
    /// Replace all forwarding mailboxes; omission leaves them unchanged.
    pub mailbox_ids: Option<Vec<MailboxId>>,
    /// Enable or disable PGP; omission leaves it unchanged.
    pub disable_pgp: Option<bool>,
    /// Pin or unpin the alias; omission leaves it unchanged.
    pub pinned: Option<bool>,
}

impl From<AliasUpdateRequest> for bitwarden_alias::UpdateAliasRequest {
    fn from(value: AliasUpdateRequest) -> Self {
        Self {
            note: value.note.map(OptionalSensitiveStringUpdate::into_core),
            name: value.name.map(OptionalSensitiveStringUpdate::into_core),
            mailbox_ids: value.mailbox_ids,
            disable_pgp: value.disable_pgp,
            pinned: value.pinned,
        }
    }
}

/// Custom-domain mutation input with unambiguous display-name clearing.
#[derive(Deserialize, Tsify)]
#[tsify(from_wasm_abi, large_number_types_as_bigints)]
pub struct CustomDomainUpdateRequest {
    /// Enable or disable catch-all generation; omission leaves it unchanged.
    pub catch_all: Option<bool>,
    /// Enable or disable random-prefix generation; omission leaves it unchanged.
    pub random_prefix_generation: Option<bool>,
    /// Set or clear the display name; omission leaves it unchanged.
    pub name: Option<OptionalSensitiveStringUpdate>,
    /// Replace all forwarding mailboxes; omission leaves them unchanged.
    pub mailbox_ids: Option<Vec<MailboxId>>,
}

impl From<CustomDomainUpdateRequest> for bitwarden_alias::UpdateCustomDomainRequest {
    fn from(value: CustomDomainUpdateRequest) -> Self {
        Self {
            catch_all: value.catch_all,
            random_prefix_generation: value.random_prefix_generation,
            name: value.name.map(OptionalSensitiveStringUpdate::into_core),
            mailbox_ids: value.mailbox_ids,
        }
    }
}

/// Complete SimpleLogin alias lifecycle operations for WebAssembly consumers.
#[wasm_bindgen]
pub struct AliasClient(bitwarden_alias::AliasClient);

impl From<bitwarden_alias::AliasClient> for AliasClient {
    fn from(value: bitwarden_alias::AliasClient) -> Self {
        Self(value)
    }
}

#[wasm_bindgen]
impl AliasClient {
    /// Creates a standalone alias lifecycle client.
    #[wasm_bindgen(constructor)]
    pub fn new(settings: AliasClientSettings) -> Result<Self, AliasError> {
        bitwarden_alias::AliasClient::new(settings).map(Self)
    }

    /// Creates a random alias.
    pub async fn create_random_alias(
        &self,
        request: CreateRandomAliasRequest,
    ) -> Result<Alias, AliasError> {
        self.0.create_random_alias(request).await
    }

    /// Creates a custom alias using a signed suffix from [`Self::get_alias_options`].
    pub async fn create_custom_alias(
        &self,
        request: CreateCustomAliasRequest,
    ) -> Result<Alias, AliasError> {
        self.0.create_custom_alias(request).await
    }

    /// Gets alias creation options and any hostname recommendation.
    pub async fn get_alias_options(
        &self,
        hostname: Option<SensitiveString>,
    ) -> Result<AliasCreationOptions, AliasError> {
        self.0.get_alias_options(hostname.as_ref()).await
    }

    /// Gets the most recently associated alias for a hostname.
    pub async fn get_alias_recommendation(
        &self,
        hostname: SensitiveString,
    ) -> Result<Option<AliasRecommendation>, AliasError> {
        self.0.get_alias_recommendation(&hostname).await
    }

    /// Lists a page of aliases.
    pub async fn list_aliases(
        &self,
        page: u32,
        filter: Option<AliasFilter>,
    ) -> Result<AliasPage, AliasError> {
        self.0
            .list_aliases(ListAliasesRequest { page, filter })
            .await
    }

    /// Searches aliases by address, note, and name.
    pub async fn search_aliases(
        &self,
        request: SearchAliasesRequest,
    ) -> Result<AliasPage, AliasError> {
        self.0.search_aliases(request).await
    }

    /// Gets full lifecycle data for a stable alias identifier.
    pub async fn get_alias(&self, alias_id: AliasId) -> Result<Alias, AliasError> {
        self.0.get_alias(alias_id).await
    }

    /// Updates mutable alias fields.
    pub async fn update_alias(
        &self,
        alias_id: AliasId,
        request: AliasUpdateRequest,
    ) -> Result<Alias, AliasError> {
        self.0.update_alias(alias_id, request.into()).await
    }

    /// Explicitly sets alias forwarding state.
    pub async fn set_alias_enabled(
        &self,
        alias_id: AliasId,
        enabled: bool,
    ) -> Result<AliasState, AliasError> {
        self.0.set_alias_enabled(alias_id, enabled).await
    }

    /// Enables an alias.
    pub async fn enable_alias(&self, alias_id: AliasId) -> Result<AliasState, AliasError> {
        self.0.enable_alias(alias_id).await
    }

    /// Disables an alias.
    pub async fn disable_alias(&self, alias_id: AliasId) -> Result<AliasState, AliasError> {
        self.0.disable_alias(alias_id).await
    }

    /// Deletes an alias.
    pub async fn delete_alias(&self, alias_id: AliasId) -> Result<DeleteAliasResult, AliasError> {
        self.0.delete_alias(alias_id).await
    }

    /// Lists domains available for random alias creation.
    pub async fn list_domains(&self) -> Result<Vec<AliasDomain>, AliasError> {
        self.0.list_domains().await
    }

    /// Lists account custom domains.
    pub async fn list_custom_domains(&self) -> Result<Vec<CustomDomain>, AliasError> {
        self.0.list_custom_domains().await
    }

    /// Updates mutable custom-domain settings.
    pub async fn update_custom_domain(
        &self,
        domain_id: CustomDomainId,
        request: CustomDomainUpdateRequest,
    ) -> Result<CustomDomain, AliasError> {
        self.0.update_custom_domain(domain_id, request.into()).await
    }

    /// Lists account forwarding mailboxes.
    pub async fn list_mailboxes(&self) -> Result<Vec<Mailbox>, AliasError> {
        self.0.list_mailboxes().await
    }

    /// Lists contacts and their reverse aliases.
    pub async fn list_reverse_aliases(
        &self,
        alias_id: AliasId,
        page: u32,
    ) -> Result<ReverseAliasPage, AliasError> {
        self.0.list_reverse_aliases(alias_id, page).await
    }

    /// Lists contacts for an alias.
    pub async fn list_contacts(
        &self,
        alias_id: AliasId,
        page: u32,
    ) -> Result<ReverseAliasPage, AliasError> {
        self.0.list_contacts(alias_id, page).await
    }

    /// Creates or retrieves a reverse alias for a contact.
    pub async fn create_reverse_alias(
        &self,
        alias_id: AliasId,
        contact: SensitiveString,
    ) -> Result<ReverseAlias, AliasError> {
        self.0.create_reverse_alias(alias_id, contact).await
    }

    /// Creates a contact and returns its reverse alias.
    pub async fn create_contact(
        &self,
        alias_id: AliasId,
        contact: SensitiveString,
    ) -> Result<ReverseAlias, AliasError> {
        self.0.create_contact(alias_id, contact).await
    }

    /// Toggles whether a contact is blocked.
    pub async fn toggle_contact_blocked(
        &self,
        contact_id: ContactId,
    ) -> Result<ContactState, AliasError> {
        self.0.toggle_contact_blocked(contact_id).await
    }

    /// Deletes a contact and its reverse alias.
    pub async fn delete_contact(
        &self,
        contact_id: ContactId,
    ) -> Result<DeleteContactResult, AliasError> {
        self.0.delete_contact(contact_id).await
    }
}
