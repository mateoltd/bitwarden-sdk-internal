use std::collections::HashSet;

use bitwarden_sensitive_value::{ExposeSensitive, SensitiveString};
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;
use uuid::{Uuid, Variant, Version};

use crate::{AliasError, AliasErrorCode};

/// Current provider-neutral alias contract version.
pub const ALIAS_CONTRACT_VERSION: u32 = 1;
/// Maximum UTF-8 byte length of an adapter identifier.
pub const MAX_ADAPTER_ID_BYTES: usize = 64;
/// Maximum UTF-8 byte length of a capability extension identifier.
pub const MAX_CAPABILITY_ID_BYTES: usize = 96;
/// Maximum number of negotiated capability extensions.
pub const MAX_CAPABILITY_EXTENSIONS: usize = 128;
/// Maximum UTF-8 byte length of an opaque provider resource identifier.
pub const MAX_REMOTE_ID_BYTES: usize = 512;
/// Maximum UTF-8 byte length of a normalized email address.
pub const MAX_EMAIL_ADDRESS_BYTES: usize = 320;
/// Maximum UTF-8 byte length of an opaque page token.
pub const MAX_PAGE_TOKEN_BYTES: usize = 256;
/// Maximum number of records accepted in one provider page.
pub const MAX_PAGE_ITEMS: usize = 1_000;
/// Maximum UTF-8 byte length of a password-manager-owned label.
pub const MAX_LABEL_BYTES: usize = 512;
/// Maximum UTF-8 byte length of a normalized hostname.
pub const MAX_HOSTNAME_BYTES: usize = 253;

/// Provider-neutral operation names. These are the only operation details allowed in telemetry.
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AliasOperationKind {
    /// Create an alias.
    Create,
    /// List aliases.
    List,
    /// Read one alias.
    Get,
    /// Enable an alias.
    Enable,
    /// Disable an alias.
    Disable,
    /// Delete an alias.
    Delete,
    /// Create a recipient-scoped send/reply identity.
    CreateSendReplyIdentity,
    /// List recipient-scoped send/reply identities.
    ListSendReplyIdentities,
    /// Remove a recipient-scoped send/reply identity.
    RemoveSendReplyIdentity,
    /// Set the optional recipient block state.
    SetSendReplyBlocked,
    /// Reconcile provider aliases with bound vault items.
    Reconcile,
}

/// Required and negotiated behavior exposed by an adapter.
///
/// Baseline flags are explicit so first-class qualification is deterministic. Optional behavior
/// uses validated identifiers instead of a closed provider-specific enum.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AliasProviderCapabilities {
    /// Supports one-click alias creation.
    pub create: bool,
    /// Supports paginated alias listing.
    pub list: bool,
    /// Supports reading one alias by stable identity.
    pub get: bool,
    /// Supports explicit enable and disable operations.
    pub enable_disable: bool,
    /// Supports idempotent deletion.
    pub delete: bool,
    /// Supports creating recipient-scoped send/reply identities.
    pub create_send_reply_identity: bool,
    /// Supports listing recipient-scoped send/reply identities.
    pub list_send_reply_identities: bool,
    /// Supports removing recipient-scoped send/reply identities.
    pub remove_send_reply_identity: bool,
    /// Sorted unique extension identifiers such as `send-reply.block`.
    pub extensions: Vec<String>,
}

impl AliasProviderCapabilities {
    /// Baseline capabilities required for a first-class provider adapter.
    pub fn first_class() -> Self {
        Self {
            create: true,
            list: true,
            get: true,
            enable_disable: true,
            delete: true,
            create_send_reply_identity: true,
            list_send_reply_identities: true,
            remove_send_reply_identity: true,
            extensions: Vec::new(),
        }
    }

    pub(crate) fn validate(&self) -> Result<(), AliasError> {
        if self.extensions.len() > MAX_CAPABILITY_EXTENSIONS
            || !(self.create
                && self.list
                && self.get
                && self.enable_disable
                && self.delete
                && self.create_send_reply_identity
                && self.list_send_reply_identities
                && self.remove_send_reply_identity)
        {
            return Err(AliasError::CapabilityUnsupported);
        }
        let mut seen = HashSet::with_capacity(self.extensions.len());
        let mut previous: Option<&str> = None;
        for extension in &self.extensions {
            validate_capability_id(extension)?;
            if !seen.insert(extension.as_str())
                || previous.is_some_and(|value| value > extension.as_str())
            {
                return Err(AliasError::InvalidInput);
            }
            previous = Some(extension);
        }
        Ok(())
    }
}

/// Non-secret adapter descriptor stored only with encrypted connection metadata.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AliasAdapterDescriptor {
    /// Extensible lowercase adapter identifier, never an enum.
    pub adapter_id: String,
    /// Canonical baseline and extension capabilities exposed by the adapter.
    pub capabilities: AliasProviderCapabilities,
}

impl core::fmt::Debug for AliasAdapterDescriptor {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AliasAdapterDescriptor([REDACTED])")
    }
}

impl AliasAdapterDescriptor {
    /// Validates the descriptor and sorts its extension identifiers canonically.
    pub fn canonicalize(mut self) -> Result<Self, AliasError> {
        validate_adapter_id(&self.adapter_id)?;
        self.capabilities.extensions.sort();
        self.capabilities.validate()?;
        Ok(self)
    }
}

/// Encrypted, account-scoped connection metadata. Credentials, endpoints, labels, and adapter
/// configuration are intentionally outside the generated common contract.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AliasConnection {
    /// Provider-neutral contract version.
    pub version: u32,
    /// Stable UUID v4 assigned to this authorization.
    pub connection_id: String,
    /// Non-secret descriptor for the injected adapter.
    pub adapter: AliasAdapterDescriptor,
}

impl core::fmt::Debug for AliasConnection {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AliasConnection")
            .field("version", &self.version)
            .field("connection_id", &"[REDACTED]")
            .field("adapter", &self.adapter)
            .finish()
    }
}

impl AliasConnection {
    /// Validates and canonicalizes encrypted connection metadata.
    pub fn canonicalize(mut self) -> Result<Self, AliasError> {
        if self.version != ALIAS_CONTRACT_VERSION {
            return Err(AliasError::InvalidInput);
        }
        validate_random_id(&self.connection_id)?;
        self.adapter = self.adapter.canonicalize()?;
        Ok(self)
    }
}

/// Canonical connection-scoped alias identity.
///
/// Equality and reconciliation use only `connection_id` plus the opaque `alias_id`. The address
/// is a required normalized integrity/display snapshot, never a join key.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AliasIdentity {
    /// Provider-neutral contract version.
    pub version: u32,
    /// Stable UUID v4 of the authorization that owns the alias.
    pub connection_id: String,
    /// Opaque provider-assigned identifier. It is not parsed, trimmed, or treated as numeric.
    pub alias_id: String,
    /// Normalized alias address retained as an integrity and display snapshot.
    pub address: SensitiveString,
}

impl PartialEq for AliasIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.resource_key() == other.resource_key()
    }
}

impl Eq for AliasIdentity {}

impl core::fmt::Debug for AliasIdentity {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AliasIdentity")
            .field("version", &self.version)
            .field("connection_id", &"[REDACTED]")
            .field("alias_id", &"[REDACTED]")
            .field("address", &self.address)
            .finish()
    }
}

impl AliasIdentity {
    /// Creates and validates a canonical connection-scoped identity.
    pub fn new(
        connection_id: String,
        alias_id: String,
        address: SensitiveString,
    ) -> Result<Self, AliasError> {
        let identity = Self {
            version: ALIAS_CONTRACT_VERSION,
            connection_id,
            alias_id,
            address: SensitiveString::from(normalize_email_address(address.expose())?),
        };
        identity.validate()?;
        Ok(identity)
    }

    /// Normalizes the address and validates every identity field.
    pub fn canonicalize(mut self) -> Result<Self, AliasError> {
        if self.version != ALIAS_CONTRACT_VERSION {
            return Err(AliasError::InvalidInput);
        }
        self.address = SensitiveString::from(normalize_email_address(self.address.expose())?);
        self.validate()?;
        Ok(self)
    }

    pub(crate) fn validate(&self) -> Result<(), AliasError> {
        if self.version != ALIAS_CONTRACT_VERSION {
            return Err(AliasError::InvalidInput);
        }
        validate_random_id(&self.connection_id)?;
        validate_opaque_id(&self.alias_id)?;
        let normalized = normalize_email_address(self.address.expose())?;
        if normalized != *self.address.expose() {
            return Err(AliasError::InvalidInput);
        }
        Ok(())
    }

    pub(crate) fn resource_key(&self) -> (&str, &str) {
        (&self.connection_id, &self.alias_id)
    }
}

/// Provider-confirmed lifecycle state of an alias.
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AliasLifecycleState {
    /// Forwarding is enabled.
    Enabled,
    /// Forwarding is disabled.
    Disabled,
    /// The alias has been deleted.
    Deleted,
}

/// Freshness of a provider-neutral alias snapshot.
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AliasFreshness {
    /// The snapshot was confirmed by the adapter.
    Current,
    /// The snapshot requires a provider refresh.
    Stale,
}

/// Conflict status of a provider-neutral alias snapshot.
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AliasConsistency {
    /// No incompatible concurrent facts were observed.
    Clean,
    /// Incompatible concurrent facts require explicit resolution.
    Conflicted,
}

/// Provider-neutral alias snapshot. Provider-native payloads and provider-owned names/notes are
/// deliberately absent.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Alias {
    /// Stable connection-scoped identity.
    pub identity: AliasIdentity,
    /// Current lifecycle state.
    pub lifecycle: AliasLifecycleState,
    /// Snapshot freshness.
    pub freshness: AliasFreshness,
    /// Snapshot conflict status.
    pub consistency: AliasConsistency,
    /// Password-manager-owned encrypted label. Adapters always return `None`.
    pub label: Option<SensitiveString>,
    /// Capabilities of the adapter that returned this snapshot.
    pub capabilities: AliasProviderCapabilities,
}

impl Alias {
    pub(crate) fn validate(&self) -> Result<(), AliasError> {
        self.identity.validate()?;
        self.capabilities.validate()?;
        if self.label.as_ref().is_some_and(|label| {
            label.expose().len() > MAX_LABEL_BYTES || contains_unsafe_text(label.expose())
        }) {
            return Err(AliasError::InvalidResponse);
        }
        Ok(())
    }
}

/// Input for one-click alias creation through the injected adapter.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateAliasRequest {
    /// Explicit post-action browsing context reduced to one normalized hostname.
    pub hostname: Option<SensitiveString>,
}

/// Input for one page of aliases.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[derive(Clone, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListAliasesRequest {
    /// Opaque bounded continuation token. Absence requests the first page.
    pub page_token: Option<String>,
}

impl core::fmt::Debug for ListAliasesRequest {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ListAliasesRequest")
            .field(
                "page_token",
                &self.page_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// One validated page of provider-neutral aliases.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AliasPage {
    /// Validated aliases in this page.
    pub aliases: Vec<Alias>,
    /// Opaque continuation token, or `None` at the end.
    pub next_page_token: Option<String>,
}

impl core::fmt::Debug for AliasPage {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AliasPage")
            .field("alias_count", &self.aliases.len())
            .field(
                "next_page_token",
                &self.next_page_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// Result of an idempotent alias deletion.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeleteAliasResult {
    /// Stable identity requested for deletion.
    pub identity: AliasIdentity,
    /// `true` for both confirmed removal and an idempotent already-absent result.
    pub deleted: bool,
}

/// Recipient-scoped service-issued address for initiating or continuing a conversation.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SendReplyIdentity {
    /// Alias that owns this recipient-scoped identity.
    pub alias: AliasIdentity,
    /// Opaque provider-assigned send/reply identity identifier.
    pub identity_id: String,
    /// Normalized recipient address.
    pub recipient: SensitiveString,
    /// Normalized service-issued address used to send or reply.
    pub address: SensitiveString,
    /// Whether the identity is currently usable.
    pub valid: bool,
    /// Present only when the negotiated `send-reply.block` extension exists.
    pub blocked: Option<bool>,
}

impl core::fmt::Debug for SendReplyIdentity {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SendReplyIdentity")
            .field("alias", &self.alias)
            .field("identity_id", &"[REDACTED]")
            .field("recipient", &self.recipient)
            .field("address", &self.address)
            .field("valid", &self.valid)
            .field("blocked", &self.blocked)
            .finish()
    }
}

impl SendReplyIdentity {
    pub(crate) fn validate(&self) -> Result<(), AliasError> {
        self.alias.validate()?;
        validate_opaque_id(&self.identity_id)?;
        if normalize_email_address(self.recipient.expose())? != *self.recipient.expose()
            || normalize_email_address(self.address.expose())? != *self.address.expose()
        {
            return Err(AliasError::InvalidInput);
        }
        Ok(())
    }
}

/// Input for creating a recipient-scoped send/reply identity.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateSendReplyIdentityRequest {
    /// Alias that will own the send/reply identity.
    pub alias: AliasIdentity,
    /// Normalized recipient address.
    pub recipient: SensitiveString,
}

/// One page of recipient-scoped send/reply identities.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SendReplyIdentityPage {
    /// Validated identities in this page.
    pub identities: Vec<SendReplyIdentity>,
    /// Opaque continuation token, or `None` at the end.
    pub next_page_token: Option<String>,
}

impl core::fmt::Debug for SendReplyIdentityPage {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SendReplyIdentityPage")
            .field("identity_count", &self.identities.len())
            .field(
                "next_page_token",
                &self.next_page_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// Coarse telemetry payload allowed by the product contract.
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AliasPlatform {
    /// Web application.
    Web,
    /// Browser extension.
    BrowserExtension,
    /// Desktop application.
    Desktop,
    /// Command-line client.
    Cli,
    /// Mobile application.
    Mobile,
    /// Any other client surface.
    Other,
}

/// Coarse telemetry payload allowed by the product contract.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AliasTelemetryEvent {
    /// Coarse operation category.
    pub operation: AliasOperationKind,
    /// Coarse client platform.
    pub platform: AliasPlatform,
    /// Stable error category, when the operation failed.
    pub error_code: Option<AliasErrorCode>,
    /// Whether the operation succeeded.
    pub success: bool,
}

pub(crate) fn validate_adapter_id(value: &str) -> Result<(), AliasError> {
    validate_extensible_identifier(value, MAX_ADAPTER_ID_BYTES)
}

pub(crate) fn validate_capability_id(value: &str) -> Result<(), AliasError> {
    validate_extensible_identifier(value, MAX_CAPABILITY_ID_BYTES)
}

fn validate_extensible_identifier(value: &str, max_bytes: usize) -> Result<(), AliasError> {
    if value.is_empty()
        || value.len() > max_bytes
        || !value.is_ascii()
        || !value.as_bytes()[0].is_ascii_lowercase()
        || value.ends_with(['.', '-'])
        || value.split(['.', '-']).any(str::is_empty)
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
    {
        return Err(AliasError::InvalidInput);
    }
    Ok(())
}

pub(crate) fn validate_random_id(value: &str) -> Result<(), AliasError> {
    if value.len() != 36 {
        return Err(AliasError::InvalidInput);
    }
    let id = Uuid::parse_str(value).map_err(|_| AliasError::InvalidInput)?;
    if id.get_version() != Some(Version::Random)
        || id.get_variant() != Variant::RFC4122
        || id.hyphenated().to_string() != value
    {
        return Err(AliasError::InvalidInput);
    }
    Ok(())
}

pub(crate) fn validate_opaque_id(value: &str) -> Result<(), AliasError> {
    if value.is_empty()
        || value.len() > MAX_REMOTE_ID_BYTES
        || value.trim() != value
        || contains_unsafe_text(value)
    {
        return Err(AliasError::InvalidInput);
    }
    Ok(())
}

pub(crate) fn validate_page_token(value: Option<&str>) -> Result<(), AliasError> {
    if value.is_some_and(|token| {
        token.is_empty()
            || token.len() > MAX_PAGE_TOKEN_BYTES
            || token.trim() != token
            || contains_unsafe_text(token)
    }) {
        return Err(AliasError::InvalidInput);
    }
    Ok(())
}

pub(crate) fn normalize_hostname(value: &str) -> Result<String, AliasError> {
    let normalized = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty()
        || normalized.len() > MAX_HOSTNAME_BYTES
        || !normalized.is_ascii()
        || normalized.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(AliasError::InvalidInput);
    }
    Ok(normalized)
}

pub(crate) fn normalize_email_address(value: &str) -> Result<String, AliasError> {
    let normalized = value.trim().to_lowercase();
    let Some((local, domain)) = normalized.split_once('@') else {
        return Err(AliasError::InvalidInput);
    };
    if local.is_empty()
        || domain.is_empty()
        || domain.contains('@')
        || normalized.len() > MAX_EMAIL_ADDRESS_BYTES
        || normalized.chars().any(char::is_whitespace)
        || contains_unsafe_text(&normalized)
    {
        return Err(AliasError::InvalidInput);
    }
    Ok(normalized)
}

fn contains_unsafe_text(value: &str) -> bool {
    value
        .chars()
        .any(|character| character.is_control() || matches!(character, '<' | '>'))
}
