use std::{
    collections::{HashMap, HashSet},
    fmt,
    sync::{Arc, Mutex, OnceLock, Weak},
};

use bitwarden_core::Client;
use bitwarden_sensitive_value::{ExposeSensitive, SensitiveString};
use http::{HeaderValue, Method, StatusCode, header};
#[cfg(not(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none"))))]
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
#[cfg(feature = "wasm")]
use tsify::Tsify;
use url::{Host, Url};
#[cfg(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")))]
use wasm_bindgen::{JsCast, JsValue};
#[cfg(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")))]
use wasm_bindgen_futures::JsFuture;

use crate::{
    Alias, AliasCreationOptions, AliasDomain, AliasError, AliasId, AliasPage,
    AliasProviderIdentity, AliasRecommendation, AliasReference, AliasState, ContactId,
    ContactState, CreateCustomAliasRequest, CreateRandomAliasRequest, CustomDomain, CustomDomainId,
    DeleteAliasResult, DeleteContactResult, ListAliasesRequest, Mailbox, ReverseAlias,
    ReverseAliasPage, SearchAliasesRequest, UpdateAliasRequest, UpdateCustomDomainRequest,
    is_safe_email_address,
};

/// Default SimpleLogin service base URL.
pub const SIMPLELOGIN_DEFAULT_BASE_URL: &str = "https://app.simplelogin.io/";

const MAX_SUCCESS_RESPONSE_BYTES: usize = 512 * 1024;
const MAX_ERROR_RESPONSE_BYTES: usize = 16 * 1024;
const MAX_MAILBOX_IDS: usize = 20;
const MAX_TOGGLE_CONVERGENCE_ATTEMPTS: usize = 3;
const MAX_ALIAS_PREFIX_BYTES: usize = 40;
const MAX_HOSTNAME_BYTES: usize = 253;
const MAX_NAME_BYTES: usize = 128;
const MAX_NOTE_BYTES: usize = 16 * 1024;
const MAX_SEARCH_QUERY_BYTES: usize = 4 * 1024;
const MAX_SIGNED_SUFFIX_BYTES: usize = 4 * 1024;
const MAX_PROVIDER_DATE_BYTES: usize = 128;

type AliasStateLocks =
    Mutex<HashMap<(String, Option<String>, AliasId), Weak<tokio::sync::Mutex<()>>>>;

/// SimpleLogin only exposes a toggle endpoint. Serialize explicit state changes by provider and
/// stable ID across every client in this process so concurrent callers cannot double-toggle an
/// alias back to its original state. Weak entries keep the global map bounded.
static ALIAS_STATE_LOCKS: OnceLock<AliasStateLocks> = OnceLock::new();

/// Configuration used to connect an [`AliasClient`] to SimpleLogin.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(from_wasm_abi))]
#[derive(Deserialize)]
pub struct AliasClientSettings {
    /// SimpleLogin base URL, without an API path.
    pub base_url: String,
    /// SimpleLogin API key sent in the `Authentication` header.
    pub api_token: SensitiveString,
    /// Stable non-secret UUID v4 assigned to this provider account by the consuming client.
    ///
    /// This is optional for generator operations that do not create persisted vault references.
    /// Reference creation and reconciliation require it.
    #[serde(default)]
    pub connection_id: Option<String>,
}

impl fmt::Debug for AliasClientSettings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AliasClientSettings")
            .field("base_url", &"[REDACTED]")
            .field("api_token", &self.api_token)
            .finish()
    }
}

impl AliasClientSettings {
    /// Creates settings for the hosted SimpleLogin service.
    pub fn new(api_token: SensitiveString) -> Self {
        Self {
            base_url: SIMPLELOGIN_DEFAULT_BASE_URL.to_owned(),
            api_token,
            connection_id: None,
        }
    }

    /// Associates these settings with a stable, client-persisted provider connection UUID v4.
    pub fn with_connection_id(mut self, connection_id: String) -> Self {
        self.connection_id = Some(connection_id);
        self
    }

    /// Overrides the service base URL, primarily for self-hosted SimpleLogin instances.
    pub fn with_base_url(mut self, base_url: String) -> Self {
        self.base_url = base_url;
        self
    }
}

struct AliasClientInner {
    http: reqwest::Client,
    base_url: Url,
    api_token: SensitiveString,
    connection_id: Option<String>,
}

/// Client for the complete SimpleLogin alias lifecycle.
#[derive(Clone)]
pub struct AliasClient {
    inner: Arc<AliasClientInner>,
}

impl AliasClient {
    /// Creates a standalone alias client using the SDK's standard TLS configuration.
    pub fn new(settings: AliasClientSettings) -> Result<Self, AliasError> {
        let base_url = validate_base_url(&settings.base_url)?;
        validate_token(&settings.api_token)?;
        if let Some(connection_id) = settings.connection_id.as_deref() {
            AliasProviderIdentity::from_simplelogin_url(&base_url, connection_id)
                .map_err(|_| AliasError::InvalidConnectionIdentity)?;
        }
        let http = bitwarden_api_base::new_http_client_builder();
        #[cfg(not(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none"))))]
        // Lifecycle mutations are not universally replay-safe (creation and toggle in
        // particular), so override reqwest's protocol-level retry policy. Callers can decide
        // whether to retry after observing a bounded, URL-free error. The WASM transport invokes
        // fetch exactly once itself and therefore has no reqwest retry policy.
        let http = http.retry(reqwest::retry::never()).redirect(Policy::none());
        let http = http
            .build()
            .map_err(|error| AliasError::Transport(error.without_url()))?;

        Ok(Self {
            inner: Arc::new(AliasClientInner {
                http,
                base_url,
                api_token: settings.api_token,
                connection_id: settings.connection_id,
            }),
        })
    }

    /// Returns the stable provider identity used to namespace vault alias references.
    pub fn provider_identity(&self) -> Result<AliasProviderIdentity, crate::AliasReferenceError> {
        let connection_id = self
            .inner
            .connection_id
            .as_deref()
            .ok_or(crate::AliasReferenceError::MissingConnectionIdentity)?;
        AliasProviderIdentity::from_simplelogin_url(&self.inner.base_url, connection_id)
    }

    /// Creates a versioned vault reference for alias data returned by this client.
    pub fn alias_reference(
        &self,
        alias: &Alias,
    ) -> Result<AliasReference, crate::AliasReferenceError> {
        AliasReference::new(&self.provider_identity()?, alias)
    }

    /// Creates a random alias and returns its stable identity and full lifecycle data.
    pub async fn create_random_alias(
        &self,
        request: CreateRandomAliasRequest,
    ) -> Result<Alias, AliasError> {
        validate_optional_hostname(request.hostname.as_ref())?;
        validate_optional_sensitive_length(
            request.note.as_ref(),
            MAX_NOTE_BYTES,
            "alias note is too large",
        )?;

        #[derive(Serialize)]
        struct Body<'a> {
            #[serde(skip_serializing_if = "Option::is_none")]
            note: Option<&'a SensitiveString>,
        }

        let mut query = Vec::new();
        if let Some(hostname) = request.hostname.as_ref() {
            query.push(("hostname", hostname.expose().as_str()));
        }
        if let Some(mode) = request.mode {
            query.push(("mode", mode.as_str()));
        }

        let builder = self
            .request(Method::POST, "api/alias/random/new")?
            .query(&query)
            .json(&Body {
                note: request.note.as_ref(),
            });
        let alias = self
            .send_json(builder, Some("random-alias creation"))
            .await?;
        validate_mutation_response(validate_alias(&alias), "random-alias creation")?;
        Ok(alias)
    }

    /// Creates a custom alias with SimpleLogin's signed-suffix v3 API.
    pub async fn create_custom_alias(
        &self,
        request: CreateCustomAliasRequest,
    ) -> Result<Alias, AliasError> {
        validate_request_mailbox_ids(&request.mailbox_ids)?;
        validate_alias_prefix(&request.alias_prefix)?;
        validate_signed_suffix(&request.signed_suffix)?;
        validate_optional_hostname(request.hostname.as_ref())?;
        validate_optional_sensitive_length(
            request.note.as_ref(),
            MAX_NOTE_BYTES,
            "alias note is too large",
        )?;
        validate_optional_name(request.name.as_ref(), "alias name is invalid or too large")?;

        #[derive(Serialize)]
        struct Body<'a> {
            alias_prefix: &'a str,
            signed_suffix: &'a SensitiveString,
            mailbox_ids: &'a [crate::MailboxId],
            #[serde(skip_serializing_if = "Option::is_none")]
            note: Option<&'a SensitiveString>,
            #[serde(skip_serializing_if = "Option::is_none")]
            name: Option<&'a SensitiveString>,
        }

        let mut query = Vec::new();
        if let Some(hostname) = request.hostname.as_ref() {
            query.push(("hostname", hostname.expose().as_str()));
        }
        let builder = self
            .request(Method::POST, "api/v3/alias/custom/new")?
            .query(&query)
            .json(&Body {
                alias_prefix: &request.alias_prefix,
                signed_suffix: &request.signed_suffix,
                mailbox_ids: &request.mailbox_ids,
                note: request.note.as_ref(),
                name: request.name.as_ref(),
            });
        let alias = self
            .send_json(builder, Some("custom-alias creation"))
            .await?;
        validate_mutation_response(validate_alias(&alias), "custom-alias creation")?;
        Ok(alias)
    }

    /// Gets creation suffixes, a prefix suggestion, and any alias recommendation for a hostname.
    pub async fn get_alias_options(
        &self,
        hostname: Option<&SensitiveString>,
    ) -> Result<AliasCreationOptions, AliasError> {
        validate_optional_hostname(hostname)?;
        let mut query = Vec::new();
        if let Some(hostname) = hostname {
            query.push(("hostname", hostname.expose().as_str()));
        }
        let builder = self
            .request(Method::GET, "api/v5/alias/options")?
            .query(&query);
        let options = self.send_json(builder, None).await?;
        validate_alias_options(&options, hostname)?;
        Ok(options)
    }

    /// Gets the most recently associated alias for a hostname, when SimpleLogin recommends one.
    pub async fn get_alias_recommendation(
        &self,
        hostname: &SensitiveString,
    ) -> Result<Option<AliasRecommendation>, AliasError> {
        Ok(self.get_alias_options(Some(hostname)).await?.recommendation)
    }

    /// Lists a page of aliases, optionally filtered by lifecycle state.
    pub async fn list_aliases(&self, request: ListAliasesRequest) -> Result<AliasPage, AliasError> {
        let builder = self.alias_list_request(Method::GET, request.page, request.filter)?;
        let response: AliasesResponse = self.send_json(builder, None).await?;
        validate_alias_page(&response.aliases)?;
        Ok(AliasPage {
            page: request.page,
            aliases: response.aliases,
        })
    }

    /// Searches aliases by address, note, and name.
    pub async fn search_aliases(
        &self,
        request: SearchAliasesRequest,
    ) -> Result<AliasPage, AliasError> {
        validate_sensitive_length(
            &request.query,
            MAX_SEARCH_QUERY_BYTES,
            "alias search query is too large",
        )?;
        #[derive(Serialize)]
        struct Body<'a> {
            query: &'a SensitiveString,
        }

        let builder = self
            .alias_list_request(Method::POST, request.page, request.filter)?
            .json(&Body {
                query: &request.query,
            });
        let response: AliasesResponse = self.send_json(builder, None).await?;
        validate_alias_page(&response.aliases)?;
        Ok(AliasPage {
            page: request.page,
            aliases: response.aliases,
        })
    }

    /// Gets full lifecycle data for a stable alias identifier.
    pub async fn get_alias(&self, alias_id: AliasId) -> Result<Alias, AliasError> {
        validate_request_id(alias_id.0, "alias identifier must be non-zero")?;
        let builder = self.request(Method::GET, &format!("api/aliases/{alias_id}"))?;
        let alias = self.send_json(builder, None).await?;
        validate_alias(&alias)?;
        if alias.id != alias_id {
            return Err(AliasError::InvalidResponseValue(
                "provider returned a different alias identifier",
            ));
        }
        Ok(alias)
    }

    /// Updates mutable alias fields and returns refreshed lifecycle data.
    pub async fn update_alias(
        &self,
        alias_id: AliasId,
        request: UpdateAliasRequest,
    ) -> Result<Alias, AliasError> {
        validate_request_id(alias_id.0, "alias identifier must be non-zero")?;
        if request.is_empty() {
            return Err(AliasError::InvalidRequest(
                "alias update requires at least one field",
            ));
        }
        if let Some(mailbox_ids) = request.mailbox_ids.as_ref() {
            validate_request_mailbox_ids(mailbox_ids)?;
        }
        if let Some(Some(note)) = request.note.as_ref() {
            validate_sensitive_length(note, MAX_NOTE_BYTES, "alias note is too large")?;
        }
        if let Some(Some(name)) = request.name.as_ref() {
            validate_name(name, "alias name is invalid or too large")?;
        }
        let builder = self
            .request(Method::PATCH, &format!("api/aliases/{alias_id}"))?
            .json(&request);
        let response: OkResponse = self.send_json(builder, Some("alias update")).await?;
        if !response.ok {
            return Err(AliasError::MutationResponseInvalid {
                operation: "alias update",
            });
        }
        self.get_alias(alias_id)
            .await
            .map_err(|_| AliasError::MutationCommittedButRefreshFailed {
                operation: "alias update",
            })
    }

    /// Explicitly enables or disables an alias without accidentally toggling an already-correct
    /// state.
    pub async fn set_alias_enabled(
        &self,
        alias_id: AliasId,
        enabled: bool,
    ) -> Result<AliasState, AliasError> {
        validate_request_id(alias_id.0, "alias identifier must be non-zero")?;
        let state_lock = self.alias_state_lock(alias_id);
        let _guard = state_lock.lock().await;
        let mut current = self.get_alias(alias_id).await?;
        for _ in 0..MAX_TOGGLE_CONVERGENCE_ATTEMPTS {
            if current.enabled == enabled {
                return Ok(AliasState {
                    id: alias_id,
                    enabled,
                });
            }

            let builder = self.request(Method::POST, &format!("api/aliases/{alias_id}/toggle"))?;
            // The toggle response is validated but is not authoritative for convergence. A
            // delayed/replayed response, or another actor toggling between mutation and response,
            // must not make this method report an unobserved final state.
            let ToggleAliasResponse {
                enabled: _reported_enabled,
            } = self.send_json(builder, Some("alias state change")).await?;
            current = self.get_alias(alias_id).await.map_err(|_| {
                AliasError::MutationCommittedButRefreshFailed {
                    operation: "alias state change",
                }
            })?;
        }
        if current.enabled == enabled {
            return Ok(AliasState {
                id: alias_id,
                enabled,
            });
        }
        Err(AliasError::ConcurrentMutation {
            operation: "alias state change",
        })
    }

    /// Enables an alias if it is disabled.
    pub async fn enable_alias(&self, alias_id: AliasId) -> Result<AliasState, AliasError> {
        self.set_alias_enabled(alias_id, true).await
    }

    /// Disables an alias if it is enabled.
    pub async fn disable_alias(&self, alias_id: AliasId) -> Result<AliasState, AliasError> {
        self.set_alias_enabled(alias_id, false).await
    }

    /// Deletes an alias.
    pub async fn delete_alias(&self, alias_id: AliasId) -> Result<DeleteAliasResult, AliasError> {
        validate_request_id(alias_id.0, "alias identifier must be non-zero")?;
        let builder = self.request(Method::DELETE, &format!("api/aliases/{alias_id}"))?;
        let response: DeletedResponse = self.send_json(builder, Some("alias deletion")).await?;
        Ok(DeleteAliasResult {
            id: alias_id,
            deleted: response.deleted,
        })
    }

    /// Lists domains currently available for random alias generation.
    pub async fn list_domains(&self) -> Result<Vec<AliasDomain>, AliasError> {
        let builder = self.request(Method::GET, "api/v2/setting/domains")?;
        let domains: Vec<AliasDomain> = self.send_json(builder, None).await?;
        if domains
            .iter()
            .any(|domain| !is_safe_provider_identifier(domain.domain.expose(), 253))
        {
            return Err(AliasError::InvalidResponseValue(
                "provider returned an invalid alias domain",
            ));
        }
        Ok(domains)
    }

    /// Lists all custom domains owned by the authenticated account.
    pub async fn list_custom_domains(&self) -> Result<Vec<CustomDomain>, AliasError> {
        let builder = self.request(Method::GET, "api/custom_domains")?;
        let response: CustomDomainsResponse = self.send_json(builder, None).await?;
        validate_unique_nonzero_ids(response.custom_domains.iter().map(|domain| domain.id.0))?;
        for domain in &response.custom_domains {
            validate_custom_domain(domain)?;
        }
        Ok(response.custom_domains)
    }

    /// Updates a custom domain and returns the refreshed domain data supplied by SimpleLogin.
    pub async fn update_custom_domain(
        &self,
        domain_id: CustomDomainId,
        request: UpdateCustomDomainRequest,
    ) -> Result<CustomDomain, AliasError> {
        validate_request_id(domain_id.0, "custom-domain identifier must be non-zero")?;
        if request.is_empty() {
            return Err(AliasError::InvalidRequest(
                "custom-domain update requires at least one field",
            ));
        }
        if let Some(mailbox_ids) = request.mailbox_ids.as_ref() {
            validate_request_mailbox_ids(mailbox_ids)?;
        }
        if let Some(Some(name)) = request.name.as_ref() {
            validate_name(name, "custom-domain name is invalid or too large")?;
        }
        let builder = self
            .request(Method::PATCH, &format!("api/custom_domains/{domain_id}"))?
            .json(&request);
        let response: CustomDomainResponse = self
            .send_json(builder, Some("custom-domain update"))
            .await?;
        validate_mutation_response(
            validate_custom_domain(&response.custom_domain),
            "custom-domain update",
        )?;
        if response.custom_domain.id != domain_id {
            return Err(AliasError::MutationResponseInvalid {
                operation: "custom-domain update",
            });
        }
        Ok(response.custom_domain)
    }

    /// Lists all account mailboxes, including unverified mailboxes.
    pub async fn list_mailboxes(&self) -> Result<Vec<Mailbox>, AliasError> {
        let builder = self.request(Method::GET, "api/v2/mailboxes")?;
        let response: MailboxesResponse = self.send_json(builder, None).await?;
        validate_unique_nonzero_ids(response.mailboxes.iter().map(|mailbox| mailbox.id.0))?;
        if response
            .mailboxes
            .iter()
            .any(|mailbox| !is_safe_email_address(mailbox.email.expose()))
        {
            return Err(AliasError::InvalidResponseValue(
                "provider returned an invalid mailbox address",
            ));
        }
        Ok(response.mailboxes)
    }

    /// Lists contacts and their reverse aliases for an alias.
    pub async fn list_reverse_aliases(
        &self,
        alias_id: AliasId,
        page: u32,
    ) -> Result<ReverseAliasPage, AliasError> {
        validate_request_id(alias_id.0, "alias identifier must be non-zero")?;
        let builder = self
            .request(Method::GET, &format!("api/aliases/{alias_id}/contacts"))?
            .query(&[("page_id", page)]);
        let response: ContactsResponse = self.send_json(builder, None).await?;
        validate_reverse_alias_page(&response.contacts)?;
        Ok(ReverseAliasPage {
            alias_id,
            page,
            contacts: response.contacts,
        })
    }

    /// Lists contacts for an alias. Each contact includes its reverse alias.
    pub async fn list_contacts(
        &self,
        alias_id: AliasId,
        page: u32,
    ) -> Result<ReverseAliasPage, AliasError> {
        self.list_reverse_aliases(alias_id, page).await
    }

    /// Creates or retrieves the reverse alias for a contact.
    pub async fn create_reverse_alias(
        &self,
        alias_id: AliasId,
        contact: SensitiveString,
    ) -> Result<ReverseAlias, AliasError> {
        validate_request_id(alias_id.0, "alias identifier must be non-zero")?;
        if !is_safe_email_address(contact.expose()) {
            return Err(AliasError::InvalidRequest(
                "contact must be a bounded email address without whitespace or control characters",
            ));
        }
        #[derive(Serialize)]
        struct Body<'a> {
            contact: &'a SensitiveString,
        }
        let builder = self
            .request(Method::POST, &format!("api/aliases/{alias_id}/contacts"))?
            .json(&Body { contact: &contact });
        let contact = self.send_json(builder, Some("contact creation")).await?;
        validate_mutation_response(validate_reverse_alias(&contact), "contact creation")?;
        Ok(contact)
    }

    /// Creates a contact and returns the reverse alias assigned to it.
    pub async fn create_contact(
        &self,
        alias_id: AliasId,
        contact: SensitiveString,
    ) -> Result<ReverseAlias, AliasError> {
        self.create_reverse_alias(alias_id, contact).await
    }

    /// Toggles whether a contact is blocked and returns the provider's resulting state.
    pub async fn toggle_contact_blocked(
        &self,
        contact_id: ContactId,
    ) -> Result<ContactState, AliasError> {
        validate_request_id(contact_id.0, "contact identifier must be non-zero")?;
        let builder = self.request(Method::POST, &format!("api/contacts/{contact_id}/toggle"))?;
        let response: ToggleContactResponse = self
            .send_json(builder, Some("contact state toggle"))
            .await?;
        Ok(ContactState {
            id: contact_id,
            block_forward: response.block_forward,
        })
    }

    /// Deletes a contact and its reverse alias.
    pub async fn delete_contact(
        &self,
        contact_id: ContactId,
    ) -> Result<DeleteContactResult, AliasError> {
        validate_request_id(contact_id.0, "contact identifier must be non-zero")?;
        let builder = self.request(Method::DELETE, &format!("api/contacts/{contact_id}"))?;
        let response: DeletedResponse = self.send_json(builder, Some("contact deletion")).await?;
        Ok(DeleteContactResult {
            id: contact_id,
            deleted: response.deleted,
        })
    }

    fn alias_list_request(
        &self,
        method: Method,
        page: u32,
        filter: Option<crate::AliasFilter>,
    ) -> Result<reqwest::RequestBuilder, AliasError> {
        let mut builder = self
            .request(method, "api/v2/aliases")?
            .query(&[("page_id", page)]);
        if let Some(filter) = filter {
            builder = builder.query(&[(filter.as_str(), "true")]);
        }
        Ok(builder)
    }

    fn alias_state_lock(&self, alias_id: AliasId) -> Arc<tokio::sync::Mutex<()>> {
        let key = (
            self.inner.base_url.as_str().to_owned(),
            self.inner.connection_id.clone(),
            alias_id,
        );
        let mut locks = ALIAS_STATE_LOCKS
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        locks.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = locks.get(&key).and_then(Weak::upgrade) {
            return lock;
        }
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        locks.insert(key, Arc::downgrade(&lock));
        lock
    }

    fn request(
        &self,
        method: Method,
        relative_path: &str,
    ) -> Result<reqwest::RequestBuilder, AliasError> {
        let url = self
            .inner
            .base_url
            .join(relative_path)
            .map_err(|_| AliasError::InvalidRequest("invalid provider API path"))?;
        let mut authentication = HeaderValue::from_str(self.inner.api_token.expose())
            .map_err(|_| AliasError::InvalidAuthenticationToken)?;
        authentication.set_sensitive(true);
        Ok(self
            .inner
            .http
            .request(method, url)
            .header("Authentication", authentication)
            .header(header::ACCEPT, "application/json"))
    }

    #[cfg(not(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none"))))]
    async fn send_json<T: DeserializeOwned>(
        &self,
        builder: reqwest::RequestBuilder,
        mutation: Option<&'static str>,
    ) -> Result<T, AliasError> {
        let response = builder
            .send()
            .await
            .map_err(|error| transport_error(error, mutation))?;
        let status = response.status();

        if status.is_redirection() {
            return Err(AliasError::RedirectRejected {
                status: status.as_u16(),
            });
        }

        if !status.is_success() {
            let retry_after_seconds = response
                .headers()
                .get(header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse().ok());
            let _body = read_bounded(response, MAX_ERROR_RESPONSE_BYTES, mutation).await?;
            if status == StatusCode::UNAUTHORIZED {
                return Err(AliasError::AuthenticationFailed);
            }
            if status == StatusCode::TOO_MANY_REQUESTS {
                return Err(AliasError::RateLimited {
                    retry_after_seconds,
                });
            }
            return Err(AliasError::Provider {
                status: status.as_u16(),
            });
        }

        if !is_json_content_type(response.headers().get(header::CONTENT_TYPE)) {
            return Err(mutation_response_error(
                AliasError::UnexpectedContentType,
                mutation,
            ));
        }
        let body = read_bounded(response, MAX_SUCCESS_RESPONSE_BYTES, mutation)
            .await
            .map_err(|error| mutation_response_error(error, mutation))?;
        serde_json::from_slice(&body)
            .map_err(AliasError::InvalidResponse)
            .map_err(|error| mutation_response_error(error, mutation))
    }

    #[cfg(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")))]
    async fn send_json<T: DeserializeOwned>(
        &self,
        builder: reqwest::RequestBuilder,
        mutation: Option<&'static str>,
    ) -> Result<T, AliasError> {
        let request = builder
            .build()
            .map_err(|_| AliasError::InvalidRequest("provider request could not be built"))?;
        let init = web_sys::RequestInit::new();
        init.set_method(request.method().as_str());
        init.set_redirect(web_sys::RequestRedirect::Manual);
        init.set_credentials(web_sys::RequestCredentials::Omit);

        let headers = web_sys::Headers::new()
            .map_err(|_| wasm_fetch_error("provider request headers unavailable"))?;
        for (name, value) in request.headers() {
            headers
                .append(
                    name.as_str(),
                    value.to_str().map_err(|_| {
                        AliasError::InvalidRequest("invalid provider request header")
                    })?,
                )
                .map_err(|_| wasm_fetch_error("provider request header rejected"))?;
        }
        init.set_headers_headers(&headers);

        let request_body = request
            .body()
            .and_then(reqwest::Body::as_bytes)
            .map(js_sys::Uint8Array::from);
        if let Some(body) = request_body.as_ref() {
            init.set_body_opt_u8_array(Some(body));
        }

        let request = web_sys::Request::new_with_str_and_init(request.url().as_str(), &init)
            .map_err(|_| wasm_fetch_error("provider request unavailable"))?;
        let global = js_sys::global();
        let fetch = js_sys::Reflect::get(&global, &JsValue::from_str("fetch"))
            .map_err(|_| wasm_fetch_error("provider fetch unavailable"))?;
        if !fetch.is_function() {
            return Err(wasm_fetch_error("provider fetch unavailable"));
        }
        // The host fetch implementation can originate in a different JavaScript realm. Its
        // callable contract is checked above, so avoid a realm-local `instanceof Function` test.
        let fetch = fetch.unchecked_into::<js_sys::Function>();
        let response = fetch
            .call1(&global, &request)
            .map_err(|_| wasm_transport_error("provider fetch rejected", mutation))?;
        // `Promise::resolve` safely adopts promises and thenables across JavaScript realms.
        let response = JsFuture::from(js_sys::Promise::resolve(&response))
            .await
            .map_err(|_| wasm_transport_error("provider fetch failed", mutation))?;
        validate_wasm_response_shape(&response).map_err(|error| {
            mutation.map_or(error, |operation| AliasError::MutationOutcomeUnknown {
                operation,
            })
        })?;
        let response = response.unchecked_into::<web_sys::Response>();

        let status = response.status();
        if status == 0 || (300..400).contains(&status) {
            return Err(AliasError::RedirectRejected { status });
        }
        let status = StatusCode::from_u16(status)
            .map_err(|_| AliasError::InvalidResponseValue("invalid provider response status"))?;
        let response_headers = response.headers();
        let retry_after_seconds = response_headers
            .get(header::RETRY_AFTER.as_str())
            .ok()
            .flatten()
            .and_then(|value| value.parse().ok());
        let limit = if status.is_success() {
            MAX_SUCCESS_RESPONSE_BYTES
        } else {
            MAX_ERROR_RESPONSE_BYTES
        };
        let body = read_bounded_wasm(response, limit, mutation)
            .await
            .map_err(|error| {
                if status.is_success() {
                    mutation_response_error(error, mutation)
                } else {
                    error
                }
            })?;

        if !status.is_success() {
            if status == StatusCode::UNAUTHORIZED {
                return Err(AliasError::AuthenticationFailed);
            }
            if status == StatusCode::TOO_MANY_REQUESTS {
                return Err(AliasError::RateLimited {
                    retry_after_seconds,
                });
            }
            return Err(AliasError::Provider {
                status: status.as_u16(),
            });
        }

        let content_type = response_headers
            .get(header::CONTENT_TYPE.as_str())
            .ok()
            .flatten();
        if !content_type
            .as_deref()
            .is_some_and(is_json_content_type_str)
        {
            return Err(mutation_response_error(
                AliasError::UnexpectedContentType,
                mutation,
            ));
        }
        serde_json::from_slice(&body)
            .map_err(AliasError::InvalidResponse)
            .map_err(|error| mutation_response_error(error, mutation))
    }
}

/// Extension trait exposing alias operations on the SDK [`Client`].
pub trait AliasClientExt {
    /// Creates an [`AliasClient`] configured for a SimpleLogin account.
    fn aliases(&self, settings: AliasClientSettings) -> Result<AliasClient, AliasError>;
}

impl AliasClientExt for Client {
    fn aliases(&self, settings: AliasClientSettings) -> Result<AliasClient, AliasError> {
        AliasClient::new(settings)
    }
}

fn validate_base_url(value: &str) -> Result<Url, AliasError> {
    let mut url =
        Url::parse(value).map_err(|_| AliasError::InvalidBaseUrl("URL cannot be parsed"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(AliasError::InvalidBaseUrl("scheme must be HTTP or HTTPS"));
    }
    if url.host_str().is_none() {
        return Err(AliasError::InvalidBaseUrl("host is required"));
    }
    if url.scheme() == "http" && !is_loopback_host(&url) {
        return Err(AliasError::InvalidBaseUrl(
            "plain HTTP is allowed only for loopback self-hosted services",
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(AliasError::InvalidBaseUrl(
            "embedded credentials are forbidden",
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(AliasError::InvalidBaseUrl(
            "query strings and fragments are forbidden",
        ));
    }
    if !url.path().ends_with('/') {
        let mut path = url.path().to_owned();
        path.push('/');
        url.set_path(&path);
    }
    Ok(url)
}

fn is_loopback_host(url: &Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => {
            address.is_loopback()
                || address
                    .to_ipv4_mapped()
                    .is_some_and(|address| address.is_loopback())
        }
        Some(Host::Domain(domain)) => {
            let domain = domain.trim_end_matches('.');
            domain.eq_ignore_ascii_case("localhost")
                || domain.to_ascii_lowercase().ends_with(".localhost")
        }
        None => false,
    }
}

fn validate_token(token: &SensitiveString) -> Result<(), AliasError> {
    if token.expose().is_empty() {
        return Err(AliasError::InvalidAuthenticationToken);
    }
    let mut value = HeaderValue::from_str(token.expose())
        .map_err(|_| AliasError::InvalidAuthenticationToken)?;
    value.set_sensitive(true);
    Ok(())
}

fn validate_request_id(value: u64, message: &'static str) -> Result<(), AliasError> {
    if value == 0 {
        return Err(AliasError::InvalidRequest(message));
    }
    Ok(())
}

fn validate_optional_hostname(hostname: Option<&SensitiveString>) -> Result<(), AliasError> {
    let Some(hostname) = hostname else {
        return Ok(());
    };
    let value = hostname.expose();
    if value.is_empty() || value.len() > MAX_HOSTNAME_BYTES || Host::parse(value).is_err() {
        return Err(AliasError::InvalidRequest(
            "hostname must be a bounded DNS name or IP address",
        ));
    }
    Ok(())
}

fn validate_sensitive_length(
    value: &SensitiveString,
    max_bytes: usize,
    message: &'static str,
) -> Result<(), AliasError> {
    if value.expose().len() > max_bytes {
        return Err(AliasError::InvalidRequest(message));
    }
    Ok(())
}

fn validate_optional_sensitive_length(
    value: Option<&SensitiveString>,
    max_bytes: usize,
    message: &'static str,
) -> Result<(), AliasError> {
    value.map_or(Ok(()), |value| {
        validate_sensitive_length(value, max_bytes, message)
    })
}

fn validate_name(value: &SensitiveString, message: &'static str) -> Result<(), AliasError> {
    if value.expose().len() > MAX_NAME_BYTES || value.expose().chars().any(char::is_control) {
        return Err(AliasError::InvalidRequest(message));
    }
    Ok(())
}

fn validate_optional_name(
    value: Option<&SensitiveString>,
    message: &'static str,
) -> Result<(), AliasError> {
    value.map_or(Ok(()), |value| validate_name(value, message))
}

fn validate_alias_prefix(value: &str) -> Result<(), AliasError> {
    if value.is_empty()
        || value.len() > MAX_ALIAS_PREFIX_BYTES
        || !value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_')
        })
    {
        return Err(AliasError::InvalidRequest(
            "alias prefix must use at most 40 letters, numbers, dots, dashes, or underscores",
        ));
    }
    Ok(())
}

fn validate_signed_suffix(value: &SensitiveString) -> Result<(), AliasError> {
    if value.expose().is_empty()
        || value.expose().len() > MAX_SIGNED_SUFFIX_BYTES
        || value
            .expose()
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(AliasError::InvalidRequest(
            "signed alias suffix is invalid or too large",
        ));
    }
    Ok(())
}

fn validate_request_mailbox_ids(ids: &[crate::MailboxId]) -> Result<(), AliasError> {
    let mut seen = HashSet::with_capacity(ids.len().min(MAX_MAILBOX_IDS));
    if ids.is_empty()
        || ids.len() > MAX_MAILBOX_IDS
        || ids.iter().any(|id| id.0 == 0 || !seen.insert(id.0))
    {
        return Err(AliasError::InvalidRequest(
            "mailbox lists require 1 to 20 unique non-zero identifiers",
        ));
    }
    Ok(())
}

fn validate_mutation_response(
    result: Result<(), AliasError>,
    operation: &'static str,
) -> Result<(), AliasError> {
    result.map_err(|_| AliasError::MutationResponseInvalid { operation })
}

fn mutation_response_error(error: AliasError, mutation: Option<&'static str>) -> AliasError {
    match (error, mutation) {
        (error @ AliasError::MutationOutcomeUnknown { .. }, _) => error,
        (_, Some(operation)) => AliasError::MutationResponseInvalid { operation },
        (error, None) => error,
    }
}

fn validate_unique_nonzero_ids(ids: impl IntoIterator<Item = u64>) -> Result<(), AliasError> {
    let mut seen = HashSet::new();
    if ids.into_iter().any(|id| id == 0 || !seen.insert(id)) {
        return Err(AliasError::InvalidResponseValue(
            "provider returned a zero or duplicate stable identifier",
        ));
    }
    Ok(())
}

fn validate_alias(alias: &Alias) -> Result<(), AliasError> {
    validate_unique_nonzero_ids(std::iter::once(alias.id.0))?;
    if !is_safe_email_address(alias.email.expose()) {
        return Err(AliasError::InvalidResponseValue(
            "provider returned an invalid alias address",
        ));
    }
    if !is_safe_provider_text(&alias.creation_date, MAX_PROVIDER_DATE_BYTES)
        || alias
            .note
            .as_ref()
            .is_some_and(|note| note.expose().len() > MAX_NOTE_BYTES)
        || alias.name.as_ref().is_some_and(|name| {
            name.expose().len() > MAX_NAME_BYTES || name.expose().chars().any(char::is_control)
        })
    {
        return Err(AliasError::InvalidResponseValue(
            "provider returned invalid alias metadata",
        ));
    }
    if alias.mailbox.id.0 == 0
        || alias.mailboxes.is_empty()
        || alias.mailboxes.len() > MAX_MAILBOX_IDS
    {
        return Err(AliasError::InvalidResponseValue(
            "provider returned invalid alias mailbox identity",
        ));
    }
    validate_unique_nonzero_ids(alias.mailboxes.iter().map(|mailbox| mailbox.id.0))?;
    let primary_mailbox = alias
        .mailboxes
        .iter()
        .find(|mailbox| mailbox.id == alias.mailbox.id)
        .ok_or(AliasError::InvalidResponseValue(
            "provider returned conflicting alias mailbox identity",
        ))?;
    if primary_mailbox.email != alias.mailbox.email {
        return Err(AliasError::InvalidResponseValue(
            "provider returned conflicting alias mailbox identity",
        ));
    }
    if alias
        .mailboxes
        .iter()
        .any(|mailbox| !is_safe_email_address(mailbox.email.expose()))
    {
        return Err(AliasError::InvalidResponseValue(
            "provider returned an invalid mailbox address",
        ));
    }
    if let Some(activity) = alias.latest_activity.as_ref()
        && (!matches!(
            activity.action.as_str(),
            "forward" | "reply" | "block" | "bounced"
        ) || !is_safe_email_address(activity.contact.email.expose())
            || activity.contact.reverse_alias.expose().len() > 1024
            || activity
                .contact
                .reverse_alias
                .expose()
                .chars()
                .any(char::is_control))
    {
        return Err(AliasError::InvalidResponseValue(
            "provider returned invalid alias activity",
        ));
    }
    Ok(())
}

fn validate_alias_options(
    options: &AliasCreationOptions,
    requested_hostname: Option<&SensitiveString>,
) -> Result<(), AliasError> {
    if options.prefix_suggestion.len() > MAX_ALIAS_PREFIX_BYTES
        || options
            .prefix_suggestion
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
        || options.suffixes.iter().any(|suffix| {
            suffix.suffix.expose().len() > 1024
                || suffix.suffix.expose().chars().any(char::is_control)
                || suffix.signed_suffix.expose().len() > MAX_SIGNED_SUFFIX_BYTES
                || suffix.signed_suffix.expose().chars().any(char::is_control)
        })
    {
        return Err(AliasError::InvalidResponseValue(
            "provider returned invalid alias creation options",
        ));
    }
    if let Some(recommendation) = options.recommendation.as_ref()
        && (!is_safe_email_address(recommendation.alias.expose())
            || !is_safe_provider_identifier(recommendation.hostname.expose(), 253)
            || requested_hostname
                .is_some_and(|hostname| hostname.expose() != recommendation.hostname.expose()))
    {
        return Err(AliasError::InvalidResponseValue(
            "provider returned an invalid alias recommendation",
        ));
    }
    Ok(())
}

fn is_safe_provider_identifier(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && !value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
}

fn is_safe_provider_text(value: &str, max_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= max_bytes && !value.chars().any(char::is_control)
}

fn validate_alias_page(aliases: &[Alias]) -> Result<(), AliasError> {
    validate_unique_nonzero_ids(aliases.iter().map(|alias| alias.id.0))?;
    for alias in aliases {
        validate_alias(alias)?;
    }
    Ok(())
}

fn validate_custom_domain(domain: &CustomDomain) -> Result<(), AliasError> {
    validate_unique_nonzero_ids(std::iter::once(domain.id.0))?;
    if !is_safe_provider_identifier(domain.domain_name.expose(), 253)
        || !is_safe_provider_text(&domain.creation_date, MAX_PROVIDER_DATE_BYTES)
        || domain.name.as_ref().is_some_and(|name| {
            name.expose().len() > MAX_NAME_BYTES || name.expose().chars().any(char::is_control)
        })
    {
        return Err(AliasError::InvalidResponseValue(
            "provider returned an invalid custom domain",
        ));
    }
    if domain.mailboxes.len() > MAX_MAILBOX_IDS {
        return Err(AliasError::InvalidResponseValue(
            "provider returned too many custom-domain mailboxes",
        ));
    }
    validate_unique_nonzero_ids(domain.mailboxes.iter().map(|mailbox| mailbox.id.0))?;
    if domain
        .mailboxes
        .iter()
        .any(|mailbox| !is_safe_email_address(mailbox.email.expose()))
    {
        return Err(AliasError::InvalidResponseValue(
            "provider returned an invalid mailbox address",
        ));
    }
    Ok(())
}

fn validate_reverse_alias(contact: &ReverseAlias) -> Result<(), AliasError> {
    validate_unique_nonzero_ids(std::iter::once(contact.id.0))?;
    if !is_safe_provider_text(&contact.creation_date, MAX_PROVIDER_DATE_BYTES)
        || contact
            .last_email_sent_date
            .as_ref()
            .is_some_and(|date| !is_safe_provider_text(date, MAX_PROVIDER_DATE_BYTES))
        || !is_safe_email_address(contact.contact.expose())
        || !is_safe_email_address(contact.reverse_alias_address.expose())
        || contact.reverse_alias.expose().len() > 1024
        || contact.reverse_alias.expose().chars().any(char::is_control)
    {
        return Err(AliasError::InvalidResponseValue(
            "provider returned an invalid contact or reverse alias address",
        ));
    }
    Ok(())
}

fn validate_reverse_alias_page(contacts: &[ReverseAlias]) -> Result<(), AliasError> {
    validate_unique_nonzero_ids(contacts.iter().map(|contact| contact.id.0))?;
    for contact in contacts {
        validate_reverse_alias(contact)?;
    }
    Ok(())
}

#[cfg(not(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none"))))]
fn is_json_content_type(value: Option<&HeaderValue>) -> bool {
    value
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .is_some_and(|value| value == "application/json" || value.ends_with("+json"))
}

#[cfg(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")))]
fn is_json_content_type_str(value: &str) -> bool {
    value
        .split(';')
        .next()
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .is_some_and(|value| value == "application/json" || value.ends_with("+json"))
}

#[cfg(not(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none"))))]
async fn read_bounded(
    mut response: reqwest::Response,
    limit: usize,
    mutation: Option<&'static str>,
) -> Result<Vec<u8>, AliasError> {
    if response
        .content_length()
        .is_some_and(|content_length| content_length > limit as u64)
    {
        return Err(AliasError::ResponseTooLarge { limit_bytes: limit });
    }

    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| transport_error(error, mutation))?
    {
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(AliasError::ResponseTooLarge { limit_bytes: limit });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(not(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none"))))]
fn transport_error(error: reqwest::Error, mutation: Option<&'static str>) -> AliasError {
    mutation.map_or_else(
        || AliasError::Transport(error.without_url()),
        |operation| AliasError::MutationOutcomeUnknown { operation },
    )
}

#[cfg(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")))]
fn wasm_fetch_error(message: &'static str) -> AliasError {
    AliasError::InvalidResponseValue(message)
}

#[cfg(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")))]
fn wasm_transport_error(message: &'static str, mutation: Option<&'static str>) -> AliasError {
    mutation.map_or_else(
        || wasm_fetch_error(message),
        |operation| AliasError::MutationOutcomeUnknown { operation },
    )
}

#[cfg(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")))]
fn validate_wasm_response_shape(response: &JsValue) -> Result<(), AliasError> {
    if !response.is_object() {
        return Err(wasm_fetch_error(
            "provider fetch returned an invalid response",
        ));
    }
    let status = js_sys::Reflect::get(response, &JsValue::from_str("status"))
        .map_err(|_| wasm_fetch_error("provider response status unavailable"))?;
    if !status.as_f64().is_some_and(|status| {
        status.is_finite() && status.fract() == 0.0 && (0.0..=u16::MAX as f64).contains(&status)
    }) {
        return Err(wasm_fetch_error("provider response status unavailable"));
    }
    let headers = js_sys::Reflect::get(response, &JsValue::from_str("headers"))
        .map_err(|_| wasm_fetch_error("provider response headers unavailable"))?;
    let get = js_sys::Reflect::get(&headers, &JsValue::from_str("get"))
        .map_err(|_| wasm_fetch_error("provider response headers unavailable"))?;
    if !headers.is_object() || !get.is_function() {
        return Err(wasm_fetch_error("provider response headers unavailable"));
    }
    let body = js_sys::Reflect::get(response, &JsValue::from_str("body"))
        .map_err(|_| wasm_fetch_error("provider response body unavailable"))?;
    if !body.is_null() {
        let get_reader = js_sys::Reflect::get(&body, &JsValue::from_str("getReader"))
            .map_err(|_| wasm_fetch_error("provider response body unavailable"))?;
        if !body.is_object() || !get_reader.is_function() {
            return Err(wasm_fetch_error("provider response body unavailable"));
        }
    }
    Ok(())
}

#[cfg(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")))]
struct WasmReaderLock {
    reader: web_sys::ReadableStreamDefaultReader,
}

#[cfg(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")))]
impl Drop for WasmReaderLock {
    fn drop(&mut self) {
        self.reader.release_lock();
    }
}

#[cfg(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")))]
async fn read_bounded_wasm(
    response: web_sys::Response,
    limit: usize,
    mutation: Option<&'static str>,
) -> Result<Vec<u8>, AliasError> {
    if response
        .headers()
        .get(header::CONTENT_LENGTH.as_str())
        .ok()
        .flatten()
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|content_length| content_length > limit)
    {
        return Err(AliasError::ResponseTooLarge { limit_bytes: limit });
    }

    let Some(stream) = response.body() else {
        return Ok(Vec::new());
    };
    // `get_reader` is specified to return a default reader. Avoid an `instanceof` check here:
    // consumers such as Jest and browser extensions can execute the SDK across JavaScript realms,
    // where an otherwise-valid reader fails a realm-local constructor identity check.
    let reader = WasmReaderLock {
        reader: stream
            .get_reader()
            .unchecked_into::<web_sys::ReadableStreamDefaultReader>(),
    };
    let mut body = Vec::new();
    loop {
        let result = JsFuture::from(reader.reader.read())
            .await
            .map_err(|_| wasm_transport_error("provider response stream failed", mutation))?
            .unchecked_into::<web_sys::ReadableStreamReadResult>();
        if result.get_done().unwrap_or(false) {
            break;
        }
        let chunk = js_sys::Uint8Array::new(&result.get_value());
        let chunk_len = chunk.length() as usize;
        if body.len().saturating_add(chunk_len) > limit {
            let _ = reader.reader.cancel();
            return Err(AliasError::ResponseTooLarge { limit_bytes: limit });
        }
        let start = body.len();
        body.resize(start + chunk_len, 0);
        chunk.copy_to(&mut body[start..]);
    }
    Ok(body)
}

#[derive(Deserialize)]
struct AliasesResponse {
    aliases: Vec<Alias>,
}

#[derive(Deserialize)]
struct ToggleAliasResponse {
    enabled: bool,
}

#[derive(Deserialize)]
struct DeletedResponse {
    deleted: bool,
}

#[derive(Deserialize)]
struct OkResponse {
    ok: bool,
}

#[derive(Deserialize)]
struct CustomDomainsResponse {
    custom_domains: Vec<CustomDomain>,
}

#[derive(Deserialize)]
struct CustomDomainResponse {
    custom_domain: CustomDomain,
}

#[derive(Deserialize)]
struct MailboxesResponse {
    mailboxes: Vec<Mailbox>,
}

#[derive(Deserialize)]
struct ContactsResponse {
    contacts: Vec<ReverseAlias>,
}

#[derive(Deserialize)]
struct ToggleContactResponse {
    block_forward: bool,
}
