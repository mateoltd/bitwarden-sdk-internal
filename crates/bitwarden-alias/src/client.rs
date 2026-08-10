use std::sync::Arc;

use bitwarden_core::Client;
use bitwarden_sensitive_value::{ExposeSensitive, SensitiveString};
use http::{HeaderValue, Method, StatusCode, header};
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use url::Url;

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

/// Configuration used to connect an [`AliasClient`] to SimpleLogin.
#[derive(Debug)]
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
        let http = bitwarden_api_base::new_http_client_builder()
            .redirect(Policy::none())
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
        self.send_json(builder).await
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
        self.send_json(builder).await
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
        Ok(AliasPage {
            page: request.page,
            aliases: response.aliases,
        })
    }

    /// Gets full lifecycle data for a stable alias identifier.
    pub async fn get_alias(&self, alias_id: AliasId) -> Result<Alias, AliasError> {
        let builder = self.request(Method::GET, &format!("api/aliases/{alias_id}"))?;
        self.send_json(builder).await
    }

    /// Updates mutable alias fields and returns refreshed lifecycle data.
    pub async fn update_alias(
        &self,
        alias_id: AliasId,
        request: UpdateAliasRequest,
    ) -> Result<Alias, AliasError> {
        if request.is_empty() {
            return Err(AliasError::InvalidRequest(
                "alias update requires at least one field",
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
        let current = self.get_alias(alias_id).await?;
        if current.enabled == enabled {
            return Ok(AliasState {
                id: alias_id,
                enabled,
            });
        }

        let builder = self.request(Method::POST, &format!("api/aliases/{alias_id}/toggle"))?;
        let response: ToggleAliasResponse = self.send_json(builder).await?;
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
        self.send_json(builder).await
    }

    /// Lists all custom domains owned by the authenticated account.
    pub async fn list_custom_domains(&self) -> Result<Vec<CustomDomain>, AliasError> {
        let builder = self.request(Method::GET, "api/custom_domains")?;
        let response: CustomDomainsResponse = self.send_json(builder).await?;
        Ok(response.custom_domains)
    }

    /// Updates a custom domain and returns the refreshed domain data supplied by SimpleLogin.
    pub async fn update_custom_domain(
        &self,
        domain_id: CustomDomainId,
        request: UpdateCustomDomainRequest,
    ) -> Result<CustomDomain, AliasError> {
        if request.is_empty() {
            return Err(AliasError::InvalidRequest(
                "custom-domain update requires at least one field",
            ));
        }
        let builder = self
            .request(Method::PATCH, &format!("api/custom_domains/{domain_id}"))?
            .json(&request);
        let response: CustomDomainResponse = self.send_json(builder).await?;
        Ok(response.custom_domain)
    }

    /// Lists all account mailboxes, including unverified mailboxes.
    pub async fn list_mailboxes(&self) -> Result<Vec<Mailbox>, AliasError> {
        let builder = self.request(Method::GET, "api/v2/mailboxes")?;
        let response: MailboxesResponse = self.send_json(builder).await?;
        Ok(response.mailboxes)
    }

    /// Lists contacts and their reverse aliases for an alias.
    pub async fn list_reverse_aliases(
        &self,
        alias_id: AliasId,
        page: u32,
    ) -> Result<ReverseAliasPage, AliasError> {
        let builder = self
            .request(Method::GET, &format!("api/aliases/{alias_id}/contacts"))?
            .query(&[("page_id", page)]);
        let response: ContactsResponse = self.send_json(builder).await?;
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
        #[derive(Serialize)]
        struct Body<'a> {
            contact: &'a SensitiveString,
        }
        let builder = self
            .request(Method::POST, &format!("api/aliases/{alias_id}/contacts"))?
            .json(&Body { contact: &contact });
        self.send_json(builder).await
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

fn is_json_content_type(value: Option<&HeaderValue>) -> bool {
    value
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .is_some_and(|value| value == "application/json" || value.ends_with("+json"))
}

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
