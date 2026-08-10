use std::{
    collections::{HashMap, HashSet},
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
use url::Url;
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
};

/// Default SimpleLogin service base URL.
pub const SIMPLELOGIN_DEFAULT_BASE_URL: &str = "https://app.simplelogin.io/";

const MAX_SUCCESS_RESPONSE_BYTES: usize = 512 * 1024;
const MAX_ERROR_RESPONSE_BYTES: usize = 16 * 1024;
const MAX_RENDERED_ERROR_CHARS: usize = 512;

type AliasStateLocks = Mutex<HashMap<(String, AliasId), Weak<tokio::sync::Mutex<()>>>>;

/// SimpleLogin only exposes a toggle endpoint. Serialize explicit state changes by provider and
/// stable ID across every client in this process so concurrent callers cannot double-toggle an
/// alias back to its original state. Weak entries keep the global map bounded.
static ALIAS_STATE_LOCKS: OnceLock<AliasStateLocks> = OnceLock::new();

/// Configuration used to connect an [`AliasClient`] to SimpleLogin.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[derive(Debug, Deserialize, Serialize)]
pub struct AliasClientSettings {
    /// SimpleLogin base URL, without an API path.
    pub base_url: String,
    /// SimpleLogin API key sent in the `Authentication` header.
    pub api_token: SensitiveString,
}

impl AliasClientSettings {
    /// Creates settings for the hosted SimpleLogin service.
    pub fn new(api_token: SensitiveString) -> Self {
        Self {
            base_url: SIMPLELOGIN_DEFAULT_BASE_URL.to_owned(),
            api_token,
        }
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
            }),
        })
    }

    /// Returns the stable provider identity used to namespace vault alias references.
    pub fn provider_identity(&self) -> AliasProviderIdentity {
        AliasProviderIdentity::from_simplelogin_url(&self.inner.base_url)
    }

    /// Creates a versioned vault reference for alias data returned by this client.
    pub fn alias_reference(&self, alias: &Alias) -> AliasReference {
        AliasReference::new(&self.provider_identity(), alias)
    }

    /// Creates a random alias and returns its stable identity and full lifecycle data.
    pub async fn create_random_alias(
        &self,
        request: CreateRandomAliasRequest,
    ) -> Result<Alias, AliasError> {
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
        let alias = self.send_json(builder).await?;
        validate_alias(&alias)?;
        Ok(alias)
    }

    /// Creates a custom alias with SimpleLogin's signed-suffix v3 API.
    pub async fn create_custom_alias(
        &self,
        request: CreateCustomAliasRequest,
    ) -> Result<Alias, AliasError> {
        if request.mailbox_ids.is_empty() {
            return Err(AliasError::InvalidRequest(
                "custom alias creation requires at least one mailbox",
            ));
        }
        if request.mailbox_ids.iter().any(|id| id.0 == 0) {
            return Err(AliasError::InvalidRequest(
                "mailbox identifiers must be non-zero",
            ));
        }

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
        let alias = self.send_json(builder).await?;
        validate_alias(&alias)?;
        Ok(alias)
    }

    /// Gets creation suffixes, a prefix suggestion, and any alias recommendation for a hostname.
    pub async fn get_alias_options(
        &self,
        hostname: Option<&SensitiveString>,
    ) -> Result<AliasCreationOptions, AliasError> {
        let mut query = Vec::new();
        if let Some(hostname) = hostname {
            query.push(("hostname", hostname.expose().as_str()));
        }
        let builder = self
            .request(Method::GET, "api/v5/alias/options")?
            .query(&query);
        self.send_json(builder).await
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
        let response: AliasesResponse = self.send_json(builder).await?;
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
        #[derive(Serialize)]
        struct Body<'a> {
            query: &'a SensitiveString,
        }

        let builder = self
            .alias_list_request(Method::POST, request.page, request.filter)?
            .json(&Body {
                query: &request.query,
            });
        let response: AliasesResponse = self.send_json(builder).await?;
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
        let alias = self.send_json(builder).await?;
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
        if request
            .mailbox_ids
            .as_ref()
            .is_some_and(|ids| ids.is_empty() || ids.iter().any(|id| id.0 == 0))
        {
            return Err(AliasError::InvalidRequest(
                "alias update requires non-zero mailbox identifiers",
            ));
        }
        let builder = self
            .request(Method::PATCH, &format!("api/aliases/{alias_id}"))?
            .json(&request);
        let response: OkResponse = self.send_json(builder).await?;
        if !response.ok {
            return Err(AliasError::InvalidResponseValue(
                "provider did not confirm the alias update",
            ));
        }
        self.get_alias(alias_id).await
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
        let current = self.get_alias(alias_id).await?;
        if current.enabled == enabled {
            return Ok(AliasState {
                id: alias_id,
                enabled,
            });
        }

        let builder = self.request(Method::POST, &format!("api/aliases/{alias_id}/toggle"))?;
        let response: ToggleAliasResponse = self.send_json(builder).await?;
        if response.enabled != enabled {
            return Err(AliasError::InvalidResponseValue(
                "provider returned an unexpected alias state",
            ));
        }
        Ok(AliasState {
            id: alias_id,
            enabled: response.enabled,
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
        let response: DeletedResponse = self.send_json(builder).await?;
        Ok(DeleteAliasResult {
            id: alias_id,
            deleted: response.deleted,
        })
    }

    /// Lists domains currently available for random alias generation.
    pub async fn list_domains(&self) -> Result<Vec<AliasDomain>, AliasError> {
        let builder = self.request(Method::GET, "api/v2/setting/domains")?;
        let domains: Vec<AliasDomain> = self.send_json(builder).await?;
        if domains
            .iter()
            .any(|domain| domain.domain.expose().is_empty())
        {
            return Err(AliasError::InvalidResponseValue(
                "provider returned an empty alias domain",
            ));
        }
        Ok(domains)
    }

    /// Lists all custom domains owned by the authenticated account.
    pub async fn list_custom_domains(&self) -> Result<Vec<CustomDomain>, AliasError> {
        let builder = self.request(Method::GET, "api/custom_domains")?;
        let response: CustomDomainsResponse = self.send_json(builder).await?;
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
        if request
            .mailbox_ids
            .as_ref()
            .is_some_and(|ids| ids.is_empty() || ids.iter().any(|id| id.0 == 0))
        {
            return Err(AliasError::InvalidRequest(
                "custom-domain update requires non-zero mailbox identifiers",
            ));
        }
        let builder = self
            .request(Method::PATCH, &format!("api/custom_domains/{domain_id}"))?
            .json(&request);
        let response: CustomDomainResponse = self.send_json(builder).await?;
        validate_custom_domain(&response.custom_domain)?;
        if response.custom_domain.id != domain_id {
            return Err(AliasError::InvalidResponseValue(
                "provider returned a different custom-domain identifier",
            ));
        }
        Ok(response.custom_domain)
    }

    /// Lists all account mailboxes, including unverified mailboxes.
    pub async fn list_mailboxes(&self) -> Result<Vec<Mailbox>, AliasError> {
        let builder = self.request(Method::GET, "api/v2/mailboxes")?;
        let response: MailboxesResponse = self.send_json(builder).await?;
        validate_unique_nonzero_ids(response.mailboxes.iter().map(|mailbox| mailbox.id.0))?;
        if response
            .mailboxes
            .iter()
            .any(|mailbox| mailbox.email.expose().is_empty())
        {
            return Err(AliasError::InvalidResponseValue(
                "provider returned an empty mailbox address",
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
        let response: ContactsResponse = self.send_json(builder).await?;
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
        #[derive(Serialize)]
        struct Body<'a> {
            contact: &'a SensitiveString,
        }
        let builder = self
            .request(Method::POST, &format!("api/aliases/{alias_id}/contacts"))?
            .json(&Body { contact: &contact });
        let contact = self.send_json(builder).await?;
        validate_reverse_alias(&contact)?;
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
        let response: ToggleContactResponse = self.send_json(builder).await?;
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
        let response: DeletedResponse = self.send_json(builder).await?;
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
        let key = (self.inner.base_url.as_str().to_owned(), alias_id);
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
    ) -> Result<T, AliasError> {
        let response = builder
            .send()
            .await
            .map_err(|error| AliasError::Transport(error.without_url()))?;
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
            let body = read_bounded(response, MAX_ERROR_RESPONSE_BYTES).await?;
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
                message: render_provider_error(&body, self.inner.api_token.expose()),
            });
        }

        if !is_json_content_type(response.headers().get(header::CONTENT_TYPE)) {
            return Err(AliasError::UnexpectedContentType);
        }
        let body = read_bounded(response, MAX_SUCCESS_RESPONSE_BYTES).await?;
        serde_json::from_slice(&body).map_err(AliasError::InvalidResponse)
    }

    #[cfg(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")))]
    async fn send_json<T: DeserializeOwned>(
        &self,
        builder: reqwest::RequestBuilder,
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
            .map_err(|_| wasm_fetch_error("provider fetch rejected"))?;
        // `Promise::resolve` safely adopts promises and thenables across JavaScript realms.
        let response = JsFuture::from(js_sys::Promise::resolve(&response))
            .await
            .map_err(|_| wasm_fetch_error("provider fetch failed"))?;
        validate_wasm_response_shape(&response)?;
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
        let body = read_bounded_wasm(response, limit).await?;

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
                message: render_provider_error(&body, self.inner.api_token.expose()),
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
            return Err(AliasError::UnexpectedContentType);
        }
        serde_json::from_slice(&body).map_err(AliasError::InvalidResponse)
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
    if alias.email.expose().is_empty() {
        return Err(AliasError::InvalidResponseValue(
            "provider returned an empty alias address",
        ));
    }
    if alias.mailbox.id.0 == 0 || alias.mailboxes.is_empty() {
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
        .any(|mailbox| mailbox.email.expose().is_empty())
    {
        return Err(AliasError::InvalidResponseValue(
            "provider returned an empty mailbox address",
        ));
    }
    Ok(())
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
    if domain.domain_name.expose().is_empty() {
        return Err(AliasError::InvalidResponseValue(
            "provider returned an empty custom domain",
        ));
    }
    validate_unique_nonzero_ids(domain.mailboxes.iter().map(|mailbox| mailbox.id.0))?;
    if domain
        .mailboxes
        .iter()
        .any(|mailbox| mailbox.email.expose().is_empty())
    {
        return Err(AliasError::InvalidResponseValue(
            "provider returned an empty mailbox address",
        ));
    }
    Ok(())
}

fn validate_reverse_alias(contact: &ReverseAlias) -> Result<(), AliasError> {
    validate_unique_nonzero_ids(std::iter::once(contact.id.0))?;
    if contact.contact.expose().is_empty() || contact.reverse_alias_address.expose().is_empty() {
        return Err(AliasError::InvalidResponseValue(
            "provider returned an empty contact or reverse alias address",
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
        .map_err(|error| AliasError::Transport(error.without_url()))?
    {
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(AliasError::ResponseTooLarge { limit_bytes: limit });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")))]
fn wasm_fetch_error(message: &'static str) -> AliasError {
    AliasError::InvalidResponseValue(message)
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
            .map_err(|_| wasm_fetch_error("provider response stream failed"))?
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

fn render_provider_error(body: &[u8], token: &str) -> String {
    #[derive(Deserialize)]
    struct ErrorResponse {
        error: Option<String>,
    }

    let raw = serde_json::from_slice::<ErrorResponse>(body)
        .ok()
        .and_then(|response| response.error)
        .unwrap_or_else(|| "request failed".to_owned());
    let redacted = if token.is_empty() {
        raw
    } else {
        raw.replace(token, "[REDACTED]")
    };
    let mut rendered = String::with_capacity(redacted.len().min(MAX_RENDERED_ERROR_CHARS));
    let mut previous_was_space = false;
    for character in redacted.chars().take(MAX_RENDERED_ERROR_CHARS) {
        let character = match character {
            '<' => '[',
            '>' => ']',
            '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' => continue,
            character if character.is_control() => ' ',
            character => character,
        };
        if character.is_whitespace() {
            if !previous_was_space {
                rendered.push(' ');
            }
            previous_was_space = true;
        } else {
            rendered.push(character);
            previous_was_space = false;
        }
    }
    let rendered = rendered.trim();
    if rendered.is_empty() {
        "request failed".to_owned()
    } else {
        rendered.to_owned()
    }
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
