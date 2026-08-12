use std::{
    collections::{HashMap, HashSet},
    fmt,
};

use bitwarden_sensitive_value::{ExposeSensitive, SensitiveString};
use bitwarden_vault::{CipherId, CipherType, CipherView, FieldType, FieldView};
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "wasm")]
use tsify::Tsify;
use url::Url;
use uuid::{Uuid, Variant, Version};

use crate::{Alias, AliasId, is_safe_email_address};

/// Current schema version stored in vault alias-reference fields.
pub const ALIAS_REFERENCE_VERSION: u32 = 2;

/// Reserved hidden-field name used to persist alias identity inside an encrypted vault cipher.
pub const ALIAS_REFERENCE_FIELD_NAME: &str = "bitwarden.alias.reference";

const MAX_ALIAS_REFERENCE_BYTES: usize = 4 * 1024;

/// Alias provider represented by a vault reference.
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum AliasProvider {
    /// SimpleLogin, hosted or self-hosted.
    #[serde(rename = "simplelogin")]
    SimpleLogin,
}

/// A provider connection selected by a stable client-supplied opaque identifier.
///
/// `instance` distinguishes hosted and self-hosted services. `connection_id` distinguishes
/// accounts on the same service. A connection identifier must be a canonical UUID v4 and
/// must never be derived from or contain a credential.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[derive(Clone, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AliasProviderIdentity {
    /// Provider implementation.
    pub provider: AliasProvider,
    /// Canonical service base URL, including a trailing slash.
    pub instance: String,
    /// Canonical UUID v4 generated and persisted by the consuming client.
    pub connection_id: String,
}

impl fmt::Debug for AliasProviderIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AliasProviderIdentity")
            .field("provider", &self.provider)
            .field("instance", &"[REDACTED]")
            .field("connection_id", &self.connection_id)
            .finish()
    }
}

impl AliasProviderIdentity {
    /// Creates a canonical SimpleLogin connection identity.
    pub fn simplelogin(base_url: &str, connection_id: &str) -> Result<Self, AliasReferenceError> {
        let url = canonical_provider_url(base_url)?;
        Self::from_simplelogin_url(&url, connection_id)
    }

    pub(crate) fn from_simplelogin_url(
        url: &Url,
        connection_id: &str,
    ) -> Result<Self, AliasReferenceError> {
        validate_connection_id(connection_id)?;
        Ok(Self {
            provider: AliasProvider::SimpleLogin,
            instance: url.as_str().to_owned(),
            connection_id: connection_id.to_owned(),
        })
    }

    fn validate(&self) -> Result<(), AliasReferenceError> {
        let canonical = canonical_provider_url(&self.instance)?;
        if canonical.as_str() != self.instance {
            return Err(AliasReferenceError::InvalidValue(
                "provider instance must be canonical",
            ));
        }
        validate_connection_id(&self.connection_id)?;
        Ok(())
    }
}

/// Versioned stable reference persisted in a vault cipher.
///
/// The address is a last-known snapshot. Provider and numeric identifier are authoritative.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(Tsify),
    tsify(into_wasm_abi, from_wasm_abi, large_number_types_as_bigints)
)]
#[derive(Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AliasReference {
    /// Reference schema version.
    pub version: u32,
    /// Alias provider.
    pub provider: AliasProvider,
    /// Canonical provider instance URL.
    pub provider_instance: String,
    /// Stable client-supplied provider connection identity.
    pub connection_id: String,
    /// Stable provider-assigned alias identifier.
    pub alias_id: AliasId,
    /// Last address observed for the alias.
    pub address: SensitiveString,
}

impl fmt::Debug for AliasReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AliasReference")
            .field("version", &self.version)
            .field("provider", &self.provider)
            .field("provider_instance", &"[REDACTED]")
            .field("connection_id", &self.connection_id)
            .field("alias_id", &self.alias_id)
            .field("address", &self.address)
            .finish()
    }
}

impl AliasReference {
    /// Creates a current-version reference from real provider lifecycle data.
    pub fn new(
        identity: &AliasProviderIdentity,
        alias: &Alias,
    ) -> Result<Self, AliasReferenceError> {
        identity.validate()?;
        let reference = Self {
            version: ALIAS_REFERENCE_VERSION,
            provider: identity.provider,
            provider_instance: identity.instance.clone(),
            connection_id: identity.connection_id.clone(),
            alias_id: alias.id,
            address: SensitiveString::from(provider_alias_address(alias).to_owned()),
        };
        reference.validate()?;
        Ok(reference)
    }

    /// Returns the provider identity namespacing this reference.
    pub fn provider_identity(&self) -> AliasProviderIdentity {
        AliasProviderIdentity {
            provider: self.provider,
            instance: self.provider_instance.clone(),
            connection_id: self.connection_id.clone(),
        }
    }

    /// Encodes the reference for encrypted storage in a vault hidden field.
    pub fn encode(&self) -> Result<SensitiveString, AliasReferenceError> {
        self.validate()?;
        let value = serde_json::to_string(self).map_err(|_| AliasReferenceError::EncodingFailed)?;
        if value.len() > MAX_ALIAS_REFERENCE_BYTES {
            return Err(AliasReferenceError::TooLarge {
                limit_bytes: MAX_ALIAS_REFERENCE_BYTES,
            });
        }
        Ok(SensitiveString::from(value))
    }

    /// Decodes and validates an encrypted vault-field value.
    pub fn decode(value: &str) -> Result<Self, AliasReferenceError> {
        ensure_reference_size(value)?;
        let version = reference_version(value)?;
        if version != ALIAS_REFERENCE_VERSION {
            return Err(AliasReferenceError::UnsupportedVersion { version });
        }
        let reference: Self =
            serde_json::from_str(value).map_err(|_| AliasReferenceError::Malformed)?;
        reference.validate()?;
        Ok(reference)
    }

    /// Reads the single reserved reference field from a decrypted vault cipher.
    pub fn from_cipher(cipher: &CipherView) -> Result<Option<Self>, AliasReferenceError> {
        let Some(field) = reserved_reference_field(cipher)? else {
            return Ok(None);
        };
        let value = field
            .value
            .as_deref()
            .ok_or(AliasReferenceError::MissingValue)?;
        Self::decode(value).map(Some)
    }

    /// Attaches this reference to a login cipher and synchronizes its username.
    ///
    /// Returns `true` when the cipher changed. Duplicate reserved fields are rejected instead of
    /// being silently discarded.
    pub fn bind_to_cipher(&self, cipher: &mut CipherView) -> Result<bool, AliasReferenceError> {
        if cipher.r#type != CipherType::Login || cipher.login.is_none() {
            return Err(AliasReferenceError::NotLoginCipher);
        }
        let encoded = self.encode()?;
        // EXPOSE: CipherView is the SDK's decrypted vault editing model. The reference and alias
        // address must be supplied as plaintext so the normal vault encryption path can encrypt
        // them with the rest of the cipher. Neither value is logged here.
        let encoded = encoded.expose_owned();
        let address = self.address.expose().to_owned();
        write_reference(cipher, encoded, address)
    }

    fn validate(&self) -> Result<(), AliasReferenceError> {
        if self.version != ALIAS_REFERENCE_VERSION {
            return Err(AliasReferenceError::UnsupportedVersion {
                version: self.version,
            });
        }
        validate_connection_id(&self.connection_id)?;
        validate_reference_values(self.alias_id, &self.address, &self.provider_instance)
    }
}

/// A binding operation's updated decrypted cipher.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AliasCipherMutationResult {
    /// Updated cipher value. The caller must use the normal vault encryption and persistence path.
    pub cipher: CipherView,
    /// Whether the operation changed the cipher.
    pub changed: bool,
}

/// Creates and canonically serializes a current alias reference.
pub fn create_alias_reference(
    identity: &AliasProviderIdentity,
    alias: &Alias,
) -> Result<SensitiveString, AliasReferenceError> {
    AliasReference::new(identity, alias)?.encode()
}

/// Canonically serializes a parsed current alias reference.
pub fn serialize_alias_reference(
    reference: &AliasReference,
) -> Result<SensitiveString, AliasReferenceError> {
    reference.encode()
}

/// Parses a current alias reference.
pub fn parse_alias_reference(value: &str) -> Result<AliasReference, AliasReferenceError> {
    AliasReference::decode(value)
}

/// Parses and binds a canonical reference to a decrypted login cipher.
pub fn bind_alias_reference(
    value: &str,
    mut cipher: CipherView,
) -> Result<AliasCipherMutationResult, AliasReferenceError> {
    let reference = AliasReference::decode(value)?;
    let changed = reference.bind_to_cipher(&mut cipher)?;
    Ok(AliasCipherMutationResult { cipher, changed })
}

/// Safe failures while parsing or attaching a vault alias reference.
#[cfg_attr(feature = "uniffi", derive(uniffi::Error), uniffi(flat_error))]
#[derive(Debug, Error)]
pub enum AliasReferenceError {
    /// Provider instance is not a safe HTTP(S) base URL.
    #[error("invalid alias provider instance: {0}")]
    InvalidProviderInstance(&'static str),
    /// Connection identity is not a canonical UUID v4.
    #[error("invalid alias connection identity: {0}")]
    InvalidConnectionIdentity(&'static str),
    /// Reference operations require settings tied to a stable connection identity.
    #[error("alias provider connection identity is required")]
    MissingConnectionIdentity,
    /// Encoded reference exceeded its strict bound.
    #[error("alias reference exceeded the {limit_bytes}-byte limit")]
    TooLarge {
        /// Maximum accepted reference size.
        limit_bytes: usize,
    },
    /// JSON did not match the reference schema. Input is deliberately not rendered.
    #[error("malformed alias reference")]
    Malformed,
    /// A newer or otherwise unsupported reference version was found.
    #[error("unsupported alias reference version {version}")]
    UnsupportedVersion {
        /// Unsupported version number.
        version: u32,
    },
    /// The reserved reference field appeared more than once.
    #[error("vault cipher contains duplicate alias reference fields")]
    DuplicateFields,
    /// The reserved field must stay hidden so vault clients do not casually render metadata.
    #[error("vault alias reference field must be hidden")]
    FieldMustBeHidden,
    /// A reserved hidden field cannot also point at a linked vault property.
    #[error("vault alias reference field must not have a linked identifier")]
    FieldMustNotBeLinked,
    /// The reserved reference field had no value.
    #[error("vault alias reference field has no value")]
    MissingValue,
    /// References can only bind login ciphers.
    #[error("alias references can only bind login ciphers")]
    NotLoginCipher,
    /// A validated reference contained an impossible value.
    #[error("invalid alias reference: {0}")]
    InvalidValue(&'static str),
    /// Serialization failed without exposing the sensitive reference.
    #[error("alias reference could not be encoded")]
    EncodingFailed,
}

#[cfg(feature = "wasm")]
impl From<AliasReferenceError> for wasm_bindgen::JsValue {
    fn from(error: AliasReferenceError) -> Self {
        let js_error = js_sys::Error::new(&error.to_string());
        js_error.set_name("AliasReferenceError");
        js_error.into()
    }
}

/// Reason a cipher could not participate in reconciliation.
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AliasReconciliationSkipReason {
    /// The cipher has not received a stable vault identifier.
    MissingCipherId,
    /// The reserved field appeared more than once.
    DuplicateReferenceFields,
    /// The reserved field was not hidden.
    ReferenceFieldNotHidden,
    /// The reserved hidden field also carried a linked-field identifier.
    ReferenceFieldHasLinkedId,
    /// The reserved field had no value.
    MissingReferenceValue,
    /// The reference exceeded its strict size limit.
    ReferenceTooLarge,
    /// The reference was malformed.
    MalformedReference,
    /// The reference version is not supported.
    UnsupportedReferenceVersion,
    /// The reference belongs to another provider, instance, or connection.
    ForeignProvider,
    /// The reference was attached to a non-login cipher.
    NonLoginCipher,
    /// The reference contained another invalid value.
    InvalidReferenceValue,
}

/// One observed reconciliation result.
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(
    feature = "wasm",
    derive(Tsify),
    tsify(into_wasm_abi, from_wasm_abi, large_number_types_as_bigints)
)]
#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "status")]
pub enum AliasReconciliationOutcome {
    /// Stable reference and username both match provider lifecycle data.
    Matched {
        /// Stable alias identifier.
        alias_id: AliasId,
        /// Stable vault cipher identifier.
        cipher_id: CipherId,
    },
    /// A stable reference resolved, but its address snapshot or login username was stale.
    StaleBinding {
        /// Stable alias identifier.
        alias_id: AliasId,
        /// Stable vault cipher identifier.
        cipher_id: CipherId,
        /// Whether the reference address snapshot needs repair.
        reference_address_stale: bool,
        /// Whether the login username needs repair.
        username_stale: bool,
    },
    /// Multiple vault ciphers claimed one provider alias. No automatic repair is proposed.
    DuplicateBinding {
        /// Stable alias identifier.
        alias_id: AliasId,
        /// Every conflicting vault cipher.
        cipher_ids: Vec<CipherId>,
    },
    /// A vault reference points to an alias absent from the supplied complete provider inventory.
    MissingAlias {
        /// Stable missing alias identifier.
        alias_id: AliasId,
        /// Referencing vault cipher.
        cipher_id: CipherId,
    },
    /// A provider alias is not represented by a vault cipher.
    UnboundAlias {
        /// Stable provider alias identifier.
        alias_id: AliasId,
    },
    /// A cipher was intentionally skipped without exposing its field value.
    SkippedCipher {
        /// Vault cipher identifier, when the cipher has one.
        cipher_id: Option<CipherId>,
        /// Safe reason for skipping the cipher.
        reason: AliasReconciliationSkipReason,
    },
}

/// Explicit mutation proposed by a dry-run plan.
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(
    feature = "wasm",
    derive(Tsify),
    tsify(into_wasm_abi, from_wasm_abi, large_number_types_as_bigints)
)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "action")]
pub enum AliasReconciliationAction {
    /// Refresh an existing stable binding from authoritative provider data.
    Refresh {
        /// Stable alias identifier.
        alias_id: AliasId,
        /// Stable vault cipher identifier.
        cipher_id: CipherId,
        /// Whether the reference address snapshot differed during planning.
        reference_address_stale: bool,
        /// Whether the login username differed during planning.
        username_stale: bool,
    },
}

impl AliasReconciliationAction {
    fn alias_id(self) -> AliasId {
        match self {
            Self::Refresh { alias_id, .. } => alias_id,
        }
    }

    fn cipher_id(self) -> CipherId {
        match self {
            Self::Refresh { cipher_id, .. } => cipher_id,
        }
    }
}

/// Counts summarizing a reconciliation dry run.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(Tsify),
    tsify(into_wasm_abi, from_wasm_abi, large_number_types_as_bigints)
)]
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AliasReconciliationSummary {
    /// Exact stable matches.
    pub matched: u64,
    /// Stale bindings awaiting refresh.
    pub stale_bindings: u64,
    /// Ambiguous duplicate binding groups.
    pub duplicate_bindings: u64,
    /// References whose provider alias is missing.
    pub missing_aliases: u64,
    /// Provider aliases with no vault match.
    pub unbound_aliases: u64,
    /// Ciphers deliberately skipped for safety.
    pub skipped_ciphers: u64,
    /// Explicit safe repairs proposed.
    pub proposed_repairs: u64,
}

/// Immutable dry-run output. No cipher changes occur until [`apply_alias_reconciliation`] is called.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(Tsify),
    tsify(into_wasm_abi, from_wasm_abi, large_number_types_as_bigints)
)]
#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AliasReconciliationPlan {
    /// Provider identity used when resolving references.
    pub provider: AliasProviderIdentity,
    /// Complete set of observed outcomes.
    pub outcomes: Vec<AliasReconciliationOutcome>,
    /// Safe, explicit vault edits proposed by the plan.
    pub actions: Vec<AliasReconciliationAction>,
    /// Aggregate counts for UI and telemetry without sensitive values.
    pub summary: AliasReconciliationSummary,
}

/// Result of explicitly applying a reconciliation plan.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(Tsify),
    tsify(into_wasm_abi, from_wasm_abi, large_number_types_as_bigints)
)]
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AliasReconciliationApplyResult {
    /// Ciphers changed by this invocation.
    pub changed_cipher_ids: Vec<CipherId>,
    /// Planned actions already satisfied, including repeated idempotent application.
    pub unchanged_actions: u64,
}

/// Binding-friendly reconciliation apply output containing the updated ciphers.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AliasReconciliationApplyOutput {
    /// Updated decrypted ciphers. The caller owns normal encryption and persistence.
    pub ciphers: Vec<CipherView>,
    /// Apply summary.
    pub result: AliasReconciliationApplyResult,
}

/// Safe reconciliation failures. Addresses and reference payloads are never rendered.
#[cfg_attr(feature = "uniffi", derive(uniffi::Error), uniffi(flat_error))]
#[derive(Debug, Error)]
pub enum AliasReconciliationError {
    /// Provider data repeated an identifier and is not safe to reconcile.
    #[error("provider inventory contains duplicate alias identifier {alias_id}")]
    DuplicateAliasId {
        /// Repeated stable alias identifier.
        alias_id: AliasId,
    },
    /// Vault input repeated a stable cipher identifier.
    #[error("vault inventory contains duplicate cipher identifier {cipher_id}")]
    DuplicateCipherId {
        /// Repeated stable cipher identifier.
        cipher_id: CipherId,
    },
    /// An alias required by a previously produced plan is no longer present.
    #[error("reconciliation plan references missing alias {alias_id}")]
    AliasMissingDuringApply {
        /// Missing stable alias identifier.
        alias_id: AliasId,
    },
    /// A cipher required by a previously produced plan is no longer present.
    #[error("reconciliation plan references missing cipher {cipher_id}")]
    CipherMissingDuringApply {
        /// Missing stable cipher identifier.
        cipher_id: CipherId,
    },
    /// The plan was edited or its target changed incompatibly after planning.
    #[error("reconciliation plan is stale: {0}")]
    StalePlan(&'static str),
    /// A versioned reference could not be encoded or validated.
    #[error(transparent)]
    Reference(#[from] AliasReferenceError),
}

#[cfg(feature = "wasm")]
impl From<AliasReconciliationError> for wasm_bindgen::JsValue {
    fn from(error: AliasReconciliationError) -> Self {
        let js_error = js_sys::Error::new(&error.to_string());
        js_error.set_name("AliasReconciliationError");
        js_error.into()
    }
}

struct Claim {
    cipher_index: usize,
    cipher_id: CipherId,
    alias_id: AliasId,
    reference: AliasReference,
}

/// Computes a deterministic, non-mutating reconciliation plan in linear expected time.
///
/// `aliases` must be a complete inventory for `provider`; otherwise missing/unbound outcomes are
/// necessarily incomplete. Ordinary vault logins that do not match an alias are ignored.
pub fn plan_alias_reconciliation(
    provider: &AliasProviderIdentity,
    aliases: &[Alias],
    ciphers: &[CipherView],
) -> Result<AliasReconciliationPlan, AliasReconciliationError> {
    provider.validate()?;
    for alias in aliases {
        // Validate every provider object up front so a dry run never proposes an action that
        // could fail reference encoding during explicit apply.
        let _encoded = AliasReference::new(provider, alias)?.encode()?;
    }
    let alias_index = index_aliases(aliases)?;
    validate_cipher_ids(ciphers)?;

    let mut outcomes = Vec::new();
    let mut claims = Vec::new();

    for (cipher_index, cipher) in ciphers.iter().enumerate() {
        match AliasReference::from_cipher(cipher) {
            Ok(Some(reference)) => {
                let Some(cipher_id) = cipher.id else {
                    outcomes.push(AliasReconciliationOutcome::SkippedCipher {
                        cipher_id: None,
                        reason: AliasReconciliationSkipReason::MissingCipherId,
                    });
                    continue;
                };
                if reference.provider_identity() != *provider {
                    outcomes.push(AliasReconciliationOutcome::SkippedCipher {
                        cipher_id: Some(cipher_id),
                        reason: AliasReconciliationSkipReason::ForeignProvider,
                    });
                    continue;
                }
                if cipher.r#type != CipherType::Login || cipher.login.is_none() {
                    outcomes.push(AliasReconciliationOutcome::SkippedCipher {
                        cipher_id: Some(cipher_id),
                        reason: AliasReconciliationSkipReason::NonLoginCipher,
                    });
                    continue;
                }
                claims.push(Claim {
                    cipher_index,
                    cipher_id,
                    alias_id: reference.alias_id,
                    reference,
                });
            }
            Ok(None) => continue,
            Err(error) => outcomes.push(AliasReconciliationOutcome::SkippedCipher {
                cipher_id: cipher.id,
                reason: skip_reason(&error),
            }),
        }
    }

    let mut claims_by_alias: HashMap<AliasId, Vec<CipherId>> = HashMap::new();
    for claim in &claims {
        claims_by_alias
            .entry(claim.alias_id)
            .or_default()
            .push(claim.cipher_id);
    }

    let mut actions = Vec::new();
    let mut emitted_duplicates = HashSet::new();
    for claim in &claims {
        let cipher_ids = &claims_by_alias[&claim.alias_id];
        if cipher_ids.len() > 1 {
            if emitted_duplicates.insert(claim.alias_id) {
                outcomes.push(AliasReconciliationOutcome::DuplicateBinding {
                    alias_id: claim.alias_id,
                    cipher_ids: cipher_ids.clone(),
                });
            }
            continue;
        }

        let Some(alias) = alias_index.by_id.get(&claim.alias_id).copied() else {
            outcomes.push(AliasReconciliationOutcome::MissingAlias {
                alias_id: claim.alias_id,
                cipher_id: claim.cipher_id,
            });
            continue;
        };
        let cipher = &ciphers[claim.cipher_index];
        let username = cipher
            .login
            .as_ref()
            .and_then(|login| login.username.as_deref());
        let canonical_address = provider_alias_address(alias);
        // EXPOSE: reconciliation compares the decrypted address snapshot in memory and
        // emits only booleans; it never renders the address.
        let reference_address_stale = claim.reference.address.expose() != canonical_address;
        let username_stale = username != Some(canonical_address);
        if reference_address_stale || username_stale {
            outcomes.push(AliasReconciliationOutcome::StaleBinding {
                alias_id: claim.alias_id,
                cipher_id: claim.cipher_id,
                reference_address_stale,
                username_stale,
            });
            actions.push(AliasReconciliationAction::Refresh {
                alias_id: claim.alias_id,
                cipher_id: claim.cipher_id,
                reference_address_stale,
                username_stale,
            });
        } else {
            outcomes.push(AliasReconciliationOutcome::Matched {
                alias_id: claim.alias_id,
                cipher_id: claim.cipher_id,
            });
        }
    }

    for alias in aliases {
        if !claims_by_alias.contains_key(&alias.id) {
            outcomes.push(AliasReconciliationOutcome::UnboundAlias { alias_id: alias.id });
        }
    }

    let summary = summarize(&outcomes, actions.len());
    Ok(AliasReconciliationPlan {
        provider: provider.clone(),
        outcomes,
        actions,
        summary,
    })
}

/// Explicitly applies a previously produced plan to decrypted vault cipher models.
///
/// All actions are validated before the first mutation. Applying the same plan again is a safe
/// no-op, while conflicting references, duplicates, and missing inputs reject the entire apply.
pub fn apply_alias_reconciliation(
    plan: &AliasReconciliationPlan,
    aliases: &[Alias],
    ciphers: &mut [CipherView],
) -> Result<AliasReconciliationApplyResult, AliasReconciliationError> {
    let alias_index = index_aliases(aliases)?;
    let ciphers_by_id = index_ciphers(ciphers)?;

    let current = plan_alias_reconciliation(&plan.provider, aliases, ciphers)?;
    let conflicted_aliases: HashSet<AliasId> = current
        .outcomes
        .iter()
        .filter_map(|outcome| match outcome {
            AliasReconciliationOutcome::DuplicateBinding { alias_id, .. } => Some(*alias_id),
            _ => None,
        })
        .collect();

    let mut seen_actions = HashSet::new();
    struct PreparedChange {
        cipher_index: usize,
        cipher_id: CipherId,
        encoded_reference: String,
        address: String,
        already_satisfied: bool,
    }
    let mut prepared = Vec::with_capacity(plan.actions.len());

    for action in &plan.actions {
        let action = *action;
        let alias_id = action.alias_id();
        let cipher_id = action.cipher_id();
        if !seen_actions.insert(cipher_id) {
            return Err(AliasReconciliationError::StalePlan(
                "multiple actions target one cipher",
            ));
        }
        if conflicted_aliases.contains(&alias_id) {
            return Err(AliasReconciliationError::StalePlan(
                "alias binding became ambiguous",
            ));
        }
        let alias = alias_index
            .by_id
            .get(&alias_id)
            .copied()
            .ok_or(AliasReconciliationError::AliasMissingDuringApply { alias_id })?;
        let cipher_index = ciphers_by_id
            .get(&cipher_id)
            .copied()
            .ok_or(AliasReconciliationError::CipherMissingDuringApply { cipher_id })?;
        let cipher = &ciphers[cipher_index];
        if cipher.r#type != CipherType::Login || cipher.login.is_none() {
            return Err(AliasReconciliationError::StalePlan(
                "target is no longer a login cipher",
            ));
        }

        let desired = AliasReference::new(&plan.provider, alias)?;
        let current_reference = AliasReference::from_cipher(cipher)?;
        let already_satisfied = current_reference.as_ref() == Some(&desired)
            && cipher
                .login
                .as_ref()
                .and_then(|login| login.username.as_deref())
                == Some(provider_alias_address(alias));

        match current_reference.as_ref() {
            Some(reference)
                if reference.provider_identity() == plan.provider
                    && reference.alias_id == alias_id => {}
            None => {
                return Err(AliasReconciliationError::StalePlan(
                    "stable reference was removed after planning",
                ));
            }
            _ => {
                return Err(AliasReconciliationError::StalePlan(
                    "target reference changed after planning",
                ));
            }
        }

        let encoded_reference = desired.encode()?.expose_owned();
        prepared.push(PreparedChange {
            cipher_index,
            cipher_id,
            encoded_reference,
            // EXPOSE: CipherView is already decrypted and must receive the canonical provider
            // address before its normal encryption/upload flow. The value is not logged.
            address: provider_alias_address(alias).to_owned(),
            already_satisfied,
        });
    }

    let mut changed_cipher_ids = Vec::new();
    let mut unchanged_actions = 0;
    for change in prepared {
        if change.already_satisfied {
            unchanged_actions += 1;
            continue;
        }
        write_reference(
            &mut ciphers[change.cipher_index],
            change.encoded_reference,
            change.address,
        )?;
        changed_cipher_ids.push(change.cipher_id);
    }

    Ok(AliasReconciliationApplyResult {
        changed_cipher_ids,
        unchanged_actions,
    })
}

/// Applies reconciliation to owned cipher values for WASM and UniFFI consumers.
pub fn apply_alias_reconciliation_owned(
    plan: &AliasReconciliationPlan,
    aliases: &[Alias],
    mut ciphers: Vec<CipherView>,
) -> Result<AliasReconciliationApplyOutput, AliasReconciliationError> {
    let result = apply_alias_reconciliation(plan, aliases, &mut ciphers)?;
    Ok(AliasReconciliationApplyOutput { ciphers, result })
}

fn canonical_provider_url(value: &str) -> Result<Url, AliasReferenceError> {
    let mut url = Url::parse(value)
        .map_err(|_| AliasReferenceError::InvalidProviderInstance("URL cannot be parsed"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(AliasReferenceError::InvalidProviderInstance(
            "scheme must be HTTP or HTTPS",
        ));
    }
    if url.host_str().is_none() {
        return Err(AliasReferenceError::InvalidProviderInstance(
            "host is required",
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(AliasReferenceError::InvalidProviderInstance(
            "embedded credentials are forbidden",
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(AliasReferenceError::InvalidProviderInstance(
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

fn validate_connection_id(value: &str) -> Result<(), AliasReferenceError> {
    if value.len() != 36 {
        return Err(AliasReferenceError::InvalidConnectionIdentity(
            "must be a canonical UUID",
        ));
    }
    let id = Uuid::parse_str(value)
        .map_err(|_| AliasReferenceError::InvalidConnectionIdentity("must be a canonical UUID"))?;
    if id.get_version() != Some(Version::Random) || id.get_variant() != Variant::RFC4122 {
        return Err(AliasReferenceError::InvalidConnectionIdentity(
            "must be an RFC 4122 UUID v4",
        ));
    }
    if id.hyphenated().to_string() != value {
        return Err(AliasReferenceError::InvalidConnectionIdentity(
            "must use lowercase hyphenated UUID form",
        ));
    }
    Ok(())
}

fn validate_reference_values(
    alias_id: AliasId,
    address: &SensitiveString,
    provider_instance: &str,
) -> Result<(), AliasReferenceError> {
    if alias_id.0 == 0 {
        return Err(AliasReferenceError::InvalidValue(
            "alias identifier must be non-zero",
        ));
    }
    // EXPOSE: validation checks only the sensitive address's shape and never renders or logs it.
    if !is_safe_email_address(address.expose()) {
        return Err(AliasReferenceError::InvalidValue(
            "alias address must be a bounded email address without whitespace or control characters",
        ));
    }
    let canonical = canonical_provider_url(provider_instance)?;
    if canonical.as_str() != provider_instance {
        return Err(AliasReferenceError::InvalidValue(
            "provider instance must be canonical",
        ));
    }
    Ok(())
}

fn ensure_reference_size(value: &str) -> Result<(), AliasReferenceError> {
    if value.len() > MAX_ALIAS_REFERENCE_BYTES {
        return Err(AliasReferenceError::TooLarge {
            limit_bytes: MAX_ALIAS_REFERENCE_BYTES,
        });
    }
    Ok(())
}

fn reference_version(value: &str) -> Result<u32, AliasReferenceError> {
    #[derive(Deserialize)]
    struct VersionEnvelope {
        version: u32,
    }

    serde_json::from_str::<VersionEnvelope>(value)
        .map(|envelope| envelope.version)
        .map_err(|_| AliasReferenceError::Malformed)
}

fn reserved_reference_field(
    cipher: &CipherView,
) -> Result<Option<&FieldView>, AliasReferenceError> {
    let mut references = cipher
        .fields
        .iter()
        .flatten()
        .filter(|field| field.name.as_deref() == Some(ALIAS_REFERENCE_FIELD_NAME));
    let Some(field) = references.next() else {
        return Ok(None);
    };
    if references.next().is_some() {
        return Err(AliasReferenceError::DuplicateFields);
    }
    if field.r#type != FieldType::Hidden {
        return Err(AliasReferenceError::FieldMustBeHidden);
    }
    if field.linked_id.is_some() {
        return Err(AliasReferenceError::FieldMustNotBeLinked);
    }
    Ok(Some(field))
}

struct AliasIndex<'a> {
    by_id: HashMap<AliasId, &'a Alias>,
}

fn index_aliases(aliases: &[Alias]) -> Result<AliasIndex<'_>, AliasReconciliationError> {
    let mut by_id = HashMap::with_capacity(aliases.len());
    for alias in aliases {
        if by_id.insert(alias.id, alias).is_some() {
            return Err(AliasReconciliationError::DuplicateAliasId { alias_id: alias.id });
        }
    }
    Ok(AliasIndex { by_id })
}

fn validate_cipher_ids(ciphers: &[CipherView]) -> Result<(), AliasReconciliationError> {
    let mut ids = HashSet::with_capacity(ciphers.len());
    for cipher_id in ciphers.iter().filter_map(|cipher| cipher.id) {
        if !ids.insert(cipher_id) {
            return Err(AliasReconciliationError::DuplicateCipherId { cipher_id });
        }
    }
    Ok(())
}

fn index_ciphers(
    ciphers: &[CipherView],
) -> Result<HashMap<CipherId, usize>, AliasReconciliationError> {
    validate_cipher_ids(ciphers)?;
    Ok(ciphers
        .iter()
        .enumerate()
        .filter_map(|(index, cipher)| cipher.id.map(|id| (id, index)))
        .collect())
}

fn provider_alias_address(alias: &Alias) -> &str {
    // EXPOSE: reconciliation must compare and copy the provider address into decrypted vault
    // models. Callers of this helper never log or render the returned value.
    alias.email.expose()
}

fn skip_reason(error: &AliasReferenceError) -> AliasReconciliationSkipReason {
    match error {
        AliasReferenceError::TooLarge { .. } => AliasReconciliationSkipReason::ReferenceTooLarge,
        AliasReferenceError::Malformed | AliasReferenceError::EncodingFailed => {
            AliasReconciliationSkipReason::MalformedReference
        }
        AliasReferenceError::UnsupportedVersion { .. } => {
            AliasReconciliationSkipReason::UnsupportedReferenceVersion
        }
        AliasReferenceError::DuplicateFields => {
            AliasReconciliationSkipReason::DuplicateReferenceFields
        }
        AliasReferenceError::FieldMustBeHidden => {
            AliasReconciliationSkipReason::ReferenceFieldNotHidden
        }
        AliasReferenceError::FieldMustNotBeLinked => {
            AliasReconciliationSkipReason::ReferenceFieldHasLinkedId
        }
        AliasReferenceError::MissingValue => AliasReconciliationSkipReason::MissingReferenceValue,
        AliasReferenceError::NotLoginCipher => AliasReconciliationSkipReason::NonLoginCipher,
        AliasReferenceError::InvalidProviderInstance(_)
        | AliasReferenceError::InvalidConnectionIdentity(_)
        | AliasReferenceError::MissingConnectionIdentity
        | AliasReferenceError::InvalidValue(_) => {
            AliasReconciliationSkipReason::InvalidReferenceValue
        }
    }
}

fn summarize(
    outcomes: &[AliasReconciliationOutcome],
    proposed_repairs: usize,
) -> AliasReconciliationSummary {
    let mut summary = AliasReconciliationSummary {
        proposed_repairs: proposed_repairs as u64,
        ..AliasReconciliationSummary::default()
    };
    for outcome in outcomes {
        match outcome {
            AliasReconciliationOutcome::Matched { .. } => summary.matched += 1,
            AliasReconciliationOutcome::StaleBinding { .. } => summary.stale_bindings += 1,
            AliasReconciliationOutcome::DuplicateBinding { .. } => summary.duplicate_bindings += 1,
            AliasReconciliationOutcome::MissingAlias { .. } => summary.missing_aliases += 1,
            AliasReconciliationOutcome::UnboundAlias { .. } => summary.unbound_aliases += 1,
            AliasReconciliationOutcome::SkippedCipher { .. } => summary.skipped_ciphers += 1,
        }
    }
    summary
}

fn write_reference(
    cipher: &mut CipherView,
    encoded_reference: String,
    address: String,
) -> Result<bool, AliasReferenceError> {
    let Some(login) = cipher.login.as_mut() else {
        return Err(AliasReferenceError::NotLoginCipher);
    };
    if cipher.r#type != CipherType::Login {
        return Err(AliasReferenceError::NotLoginCipher);
    }

    let fields = cipher.fields.get_or_insert_with(Vec::new);
    let reference_indices: Vec<usize> = fields
        .iter()
        .enumerate()
        .filter_map(|(index, field)| {
            (field.name.as_deref() == Some(ALIAS_REFERENCE_FIELD_NAME)).then_some(index)
        })
        .collect();
    if reference_indices.len() > 1 {
        return Err(AliasReferenceError::DuplicateFields);
    }

    let username_changed = login.username.as_deref() != Some(address.as_str());
    let field_changed = if let Some(index) = reference_indices.first().copied() {
        let field = &mut fields[index];
        if field.r#type != FieldType::Hidden {
            return Err(AliasReferenceError::FieldMustBeHidden);
        }
        let current_value = field
            .value
            .as_deref()
            .ok_or(AliasReferenceError::MissingValue)?;
        // Existing metadata must be valid and current before it can be overwritten.
        AliasReference::decode(current_value)?;
        let changed =
            field.value.as_deref() != Some(encoded_reference.as_str()) || field.linked_id.is_some();
        field.linked_id = None;
        field.value = Some(encoded_reference);
        changed
    } else {
        fields.push(FieldView {
            name: Some(ALIAS_REFERENCE_FIELD_NAME.to_owned()),
            value: Some(encoded_reference),
            r#type: FieldType::Hidden,
            linked_id: None,
        });
        true
    };
    login.username = Some(address);
    Ok(username_changed || field_changed)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use bitwarden_vault::{CipherRepromptType, LoginView};

    use super::*;
    use crate::{MailboxId, MailboxRef, SIMPLELOGIN_DEFAULT_BASE_URL};

    const CONNECTION_ID: &str = "11111111-1111-4111-8111-111111111111";
    const OTHER_CONNECTION_ID: &str = "22222222-2222-4222-8222-222222222222";

    fn provider() -> AliasProviderIdentity {
        AliasProviderIdentity::simplelogin("https://aliases.example.test", CONNECTION_ID)
            .expect("test provider URL should be valid")
    }

    fn alias(id: u64, address: String) -> Alias {
        Alias {
            id: AliasId(id),
            email: SensitiveString::from(address),
            creation_date: "2026-08-10T10:00:00+00:00".to_owned(),
            creation_timestamp: 1_786_356_000,
            enabled: true,
            note: None,
            name: None,
            nb_forward: 0,
            nb_block: 0,
            nb_reply: 0,
            mailbox: MailboxRef {
                id: MailboxId(1),
                email: SensitiveString::from("owner@example.test"),
            },
            mailboxes: Vec::new(),
            support_pgp: false,
            disable_pgp: false,
            latest_activity: None,
            pinned: false,
        }
    }

    fn login_cipher(id: Option<CipherId>, username: Option<String>) -> CipherView {
        let timestamp = "2026-08-10T10:00:00Z"
            .parse()
            .expect("test timestamp should parse");
        CipherView {
            id,
            organization_id: None,
            folder_id: None,
            collection_ids: Vec::new(),
            key: None,
            name: "Alias login".to_owned(),
            notes: None,
            r#type: CipherType::Login,
            login: Some(LoginView {
                username,
                password: None,
                password_revision_date: None,
                uris: None,
                totp: None,
                autofill_on_page_load: None,
                fido2_credentials: None,
            }),
            identity: None,
            card: None,
            secure_note: None,
            ssh_key: None,
            bank_account: None,
            drivers_license: None,
            passport: None,
            favorite: false,
            reprompt: CipherRepromptType::None,
            organization_use_totp: false,
            edit: true,
            permissions: None,
            view_password: true,
            local_data: None,
            attachments: None,
            attachment_decryption_failures: None,
            fields: None,
            password_history: None,
            creation_date: timestamp,
            deleted_date: None,
            revision_date: timestamp,
            archived_date: None,
        }
    }

    fn attach_raw_reference(cipher: &mut CipherView, value: String, field_type: FieldType) {
        cipher.fields.get_or_insert_with(Vec::new).push(FieldView {
            name: Some(ALIAS_REFERENCE_FIELD_NAME.to_owned()),
            value: Some(value),
            r#type: field_type,
            linked_id: None,
        });
    }

    #[test]
    fn reference_round_trips_without_rendering_sensitive_values() {
        let provider = provider();
        let alias = alias(41, "private-alias@example.test".to_owned());
        let reference = AliasReference::new(&provider, &alias).expect("reference should construct");
        let encoded = reference.encode().expect("reference should encode");
        let decoded = AliasReference::decode(encoded.expose()).expect("reference should decode");

        assert_eq!(decoded, reference);
        assert_eq!(
            encoded.expose(),
            &format!(
                "{{\"version\":2,\"provider\":\"simplelogin\",\"providerInstance\":\"https://aliases.example.test/\",\"connectionId\":\"{CONNECTION_ID}\",\"aliasId\":41,\"address\":\"private-alias@example.test\"}}"
            )
        );
        assert!(!format!("{reference:?}").contains("private-alias"));
        assert!(
            AliasProviderIdentity::simplelogin("https://user:password@example.test", CONNECTION_ID)
                .is_err()
        );

        let oversized = format!(
            "{{\"version\":2,\"provider\":\"simplelogin\",\"providerInstance\":\"https://aliases.example.test/\",\"connectionId\":\"{CONNECTION_ID}\",\"aliasId\":41,\"address\":\"{}\"}}",
            "a".repeat(MAX_ALIAS_REFERENCE_BYTES)
        );
        assert!(matches!(
            AliasReference::decode(&oversized),
            Err(AliasReferenceError::TooLarge { .. })
        ));
        assert!(matches!(
            AliasProviderIdentity::simplelogin("https://aliases.example.test", "api-token"),
            Err(AliasReferenceError::InvalidConnectionIdentity(_))
        ));
        assert!(matches!(
            AliasProviderIdentity::simplelogin(
                "https://aliases.example.test",
                "11111111-1111-1111-8111-111111111111"
            ),
            Err(AliasReferenceError::InvalidConnectionIdentity(_))
        ));
        assert!(matches!(
            AliasProviderIdentity::simplelogin(
                "https://aliases.example.test",
                "00000000-0000-0000-0000-000000000000"
            ),
            Err(AliasReferenceError::InvalidConnectionIdentity(_))
        ));
        let with_secret_field = encoded.expose().replace(
            "\"aliasId\"",
            "\"apiToken\":\"never-store-this\",\"aliasId\"",
        );
        assert!(matches!(
            AliasReference::decode(&with_secret_field),
            Err(AliasReferenceError::Malformed)
        ));

        let mut unsafe_address =
            AliasReference::new(&provider, &alias).expect("reference should construct");
        unsafe_address.address =
            SensitiveString::from("alias@example.test\nlinked-field-injection");
        assert!(matches!(
            unsafe_address.encode(),
            Err(AliasReferenceError::InvalidValue(_))
        ));
    }

    #[test]
    fn same_origin_accounts_with_overlapping_alias_ids_remain_isolated() {
        let first = provider();
        let second =
            AliasProviderIdentity::simplelogin("https://aliases.example.test", OTHER_CONNECTION_ID)
                .expect("second connection should be valid");
        let first_alias = alias(7, "first@example.test".to_owned());
        let second_alias = alias(7, "second@example.test".to_owned());
        let first_id = CipherId::new_v4();
        let second_id = CipherId::new_v4();
        let mut first_cipher = login_cipher(Some(first_id), None);
        let mut second_cipher = login_cipher(Some(second_id), None);
        AliasReference::new(&first, &first_alias)
            .expect("first reference should construct")
            .bind_to_cipher(&mut first_cipher)
            .expect("first reference should bind");
        AliasReference::new(&second, &second_alias)
            .expect("second reference should construct")
            .bind_to_cipher(&mut second_cipher)
            .expect("second reference should bind");
        let ciphers = [first_cipher, second_cipher];

        let first_plan = plan_alias_reconciliation(&first, &[first_alias], &ciphers)
            .expect("first account should reconcile");
        assert_eq!(first_plan.summary.matched, 1);
        assert_eq!(first_plan.summary.skipped_ciphers, 1);
        assert!(first_plan.actions.is_empty());

        let second_plan = plan_alias_reconciliation(&second, &[second_alias], &ciphers)
            .expect("second account should reconcile");
        assert_eq!(second_plan.summary.matched, 1);
        assert_eq!(second_plan.summary.skipped_ciphers, 1);
        assert!(second_plan.actions.is_empty());
    }

    #[test]
    fn hosted_and_self_hosted_instances_remain_isolated() {
        let hosted =
            AliasProviderIdentity::simplelogin(SIMPLELOGIN_DEFAULT_BASE_URL, CONNECTION_ID)
                .expect("hosted connection should be valid");
        let self_hosted = AliasProviderIdentity::simplelogin(
            "https://aliases.example.test/simplelogin",
            CONNECTION_ID,
        )
        .expect("self-hosted connection should be valid");
        assert_ne!(hosted, self_hosted);

        let provider_alias = alias(9, "hosted@example.test".to_owned());
        let mut cipher = login_cipher(Some(CipherId::new_v4()), None);
        AliasReference::new(&hosted, &provider_alias)
            .expect("hosted reference should construct")
            .bind_to_cipher(&mut cipher)
            .expect("hosted reference should bind");
        let plan = plan_alias_reconciliation(&self_hosted, &[provider_alias], &[cipher])
            .expect("foreign hosted reference should be skipped");
        assert_eq!(plan.summary.skipped_ciphers, 1);
        assert_eq!(plan.summary.unbound_aliases, 1);
        assert!(plan.actions.is_empty());
    }

    #[test]
    fn adversarial_reference_addresses_never_panic_or_echo_input() {
        let provider = provider();
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        for sample in 0..4096_u64 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let length = (state as usize) % 96;
            let mut address = format!("sensitive-marker-{sample:04x}-");
            address.reserve(length);
            for index in 0..length {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(sample ^ index as u64);
                address.push((state as u8 & 0x7f) as char);
            }
            let encoded = serde_json::json!({
                "version": ALIAS_REFERENCE_VERSION,
                "provider": "simplelogin",
                "providerInstance": provider.instance.clone(),
                "connectionId": provider.connection_id.clone(),
                "aliasId": sample + 1,
                "address": address.clone(),
            })
            .to_string();
            if let Err(error) = AliasReference::decode(&encoded) {
                let rendered = format!("{error:?} {error}");
                assert!(!rendered.contains(&address));
            }
        }
    }

    #[test]
    fn dry_run_apply_and_repeated_apply_are_idempotent() {
        let provider = provider();
        let aliases = vec![
            alias(1, "one@example.test".to_owned()),
            alias(2, "two@example.test".to_owned()),
            alias(3, "three@example.test".to_owned()),
            alias(4, "four@example.test".to_owned()),
        ];

        let stale_id = CipherId::new_v4();
        let matched_id = CipherId::new_v4();
        let missing_id = CipherId::new_v4();
        let ordinary_id = CipherId::new_v4();
        let mut ciphers = vec![
            login_cipher(Some(stale_id), Some("old-two@example.test".to_owned())),
            login_cipher(Some(matched_id), None),
            login_cipher(Some(missing_id), Some("removed@example.test".to_owned())),
            login_cipher(Some(ordinary_id), Some("ONE@example.test".to_owned())),
        ];

        let mut stale_reference =
            AliasReference::new(&provider, &aliases[1]).expect("reference should construct");
        stale_reference.address = SensitiveString::from("old-two@example.test");
        stale_reference
            .bind_to_cipher(&mut ciphers[0])
            .expect("stale test reference should attach");
        AliasReference::new(&provider, &aliases[2])
            .expect("reference should construct")
            .bind_to_cipher(&mut ciphers[1])
            .expect("matching test reference should attach");
        AliasReference {
            version: ALIAS_REFERENCE_VERSION,
            provider: AliasProvider::SimpleLogin,
            provider_instance: provider.instance.clone(),
            connection_id: provider.connection_id.clone(),
            alias_id: AliasId(999),
            address: SensitiveString::from("removed@example.test"),
        }
        .bind_to_cipher(&mut ciphers[2])
        .expect("missing test reference should attach");

        let dry_run = plan_alias_reconciliation(&provider, &aliases, &ciphers)
            .expect("planning should succeed");
        assert_eq!(dry_run.summary.matched, 1);
        assert_eq!(dry_run.summary.stale_bindings, 1);
        assert_eq!(dry_run.summary.missing_aliases, 1);
        assert_eq!(dry_run.summary.unbound_aliases, 2);
        assert_eq!(dry_run.summary.proposed_repairs, 1);
        assert_eq!(
            ciphers[3].fields.as_ref().map_or(0, |fields| fields.len()),
            0,
            "dry run must not mutate the cipher"
        );

        let applied = apply_alias_reconciliation(&dry_run, &aliases, &mut ciphers)
            .expect("explicit apply should succeed");
        assert_eq!(applied.changed_cipher_ids.len(), 1);
        assert_eq!(applied.unchanged_actions, 0);
        assert_eq!(
            ciphers[0]
                .login
                .as_ref()
                .and_then(|login| login.username.as_deref()),
            Some("two@example.test")
        );

        let repeated = apply_alias_reconciliation(&dry_run, &aliases, &mut ciphers)
            .expect("repeated apply should be a safe no-op");
        assert!(repeated.changed_cipher_ids.is_empty());
        assert_eq!(repeated.unchanged_actions, 1);

        let repaired = plan_alias_reconciliation(&provider, &aliases, &ciphers)
            .expect("replanning should succeed");
        assert!(repaired.actions.is_empty());
        assert_eq!(repaired.summary.matched, 2);
        assert_eq!(repaired.summary.missing_aliases, 1);
        assert_eq!(repaired.summary.unbound_aliases, 2);
    }

    #[test]
    fn duplicates_are_reported_and_never_repaired_automatically() {
        let provider = provider();
        let aliases = vec![alias(7, "shared@example.test".to_owned())];
        let first_id = CipherId::new_v4();
        let second_id = CipherId::new_v4();
        let mut ciphers = vec![
            login_cipher(Some(first_id), Some("shared@example.test".to_owned())),
            login_cipher(Some(second_id), Some("shared@example.test".to_owned())),
        ];
        let reference =
            AliasReference::new(&provider, &aliases[0]).expect("reference should construct");
        reference
            .bind_to_cipher(&mut ciphers[0])
            .expect("first test reference should attach");
        reference
            .bind_to_cipher(&mut ciphers[1])
            .expect("second test reference should attach");

        let plan = plan_alias_reconciliation(&provider, &aliases, &ciphers)
            .expect("duplicate planning should succeed");
        assert_eq!(plan.summary.duplicate_bindings, 1);
        assert_eq!(plan.summary.proposed_repairs, 0);
        assert!(matches!(
            &plan.outcomes[0],
            AliasReconciliationOutcome::DuplicateBinding { alias_id, cipher_ids }
                if *alias_id == AliasId(7) && cipher_ids == &vec![first_id, second_id]
        ));
    }

    #[test]
    fn malformed_future_foreign_and_invalid_targets_are_safe() {
        let provider = provider();
        let aliases = vec![alias(8, "eight@example.test".to_owned())];
        let mut malformed = login_cipher(Some(CipherId::new_v4()), None);
        attach_raw_reference(
            &mut malformed,
            "token=do-not-render".to_owned(),
            FieldType::Hidden,
        );

        let mut future = login_cipher(Some(CipherId::new_v4()), None);
        attach_raw_reference(
            &mut future,
            "{\"version\":999}".to_owned(),
            FieldType::Hidden,
        );

        let mut visible = login_cipher(Some(CipherId::new_v4()), None);
        let encoded = AliasReference::new(&provider, &aliases[0])
            .expect("reference should construct")
            .encode()
            .expect("reference should encode")
            .expose_owned();
        attach_raw_reference(&mut visible, encoded, FieldType::Text);

        let mut linked = login_cipher(Some(CipherId::new_v4()), None);
        let encoded = AliasReference::new(&provider, &aliases[0])
            .expect("reference should construct")
            .encode()
            .expect("reference should encode")
            .expose_owned();
        attach_raw_reference(&mut linked, encoded, FieldType::Hidden);
        let linked_id = serde_json::from_value(serde_json::json!(100))
            .expect("username linked ID should deserialize");
        linked
            .fields
            .as_mut()
            .expect("linked fixture should have fields")[0]
            .linked_id = Some(linked_id);

        let foreign_provider =
            AliasProviderIdentity::simplelogin("https://other.example.test", OTHER_CONNECTION_ID)
                .expect("valid URL");
        let mut foreign = login_cipher(Some(CipherId::new_v4()), None);
        AliasReference::new(&foreign_provider, &aliases[0])
            .expect("reference should construct")
            .bind_to_cipher(&mut foreign)
            .expect("foreign reference should attach");

        let mut non_login = login_cipher(Some(CipherId::new_v4()), None);
        AliasReference::new(&provider, &aliases[0])
            .expect("reference should construct")
            .bind_to_cipher(&mut non_login)
            .expect("reference should attach before changing type");
        non_login.r#type = CipherType::SecureNote;
        non_login.login = None;

        let missing_id = login_cipher(None, Some("eight@example.test".to_owned()));
        let ciphers = vec![
            malformed, future, visible, linked, foreign, non_login, missing_id,
        ];
        let plan = plan_alias_reconciliation(&provider, &aliases, &ciphers)
            .expect("unsafe references should be reported, not fatal");

        assert_eq!(plan.summary.skipped_ciphers, 6);
        assert_eq!(plan.summary.unbound_aliases, 1);
        assert!(plan.actions.is_empty());
        let rendered = plan
            .outcomes
            .iter()
            .map(|outcome| format!("{outcome:?}"))
            .collect::<String>();
        assert!(!rendered.contains("do-not-render"));
        assert!(plan.outcomes.iter().any(|outcome| matches!(
            outcome,
            AliasReconciliationOutcome::SkippedCipher {
                reason: AliasReconciliationSkipReason::ReferenceFieldHasLinkedId,
                ..
            }
        )));
    }

    #[test]
    fn duplicate_oversized_and_hostile_reserved_fields_are_never_repaired() {
        let provider = provider();
        let aliases = vec![alias(18, "eighteen@example.test".to_owned())];
        let valid = AliasReference::new(&provider, &aliases[0])
            .expect("reference should construct")
            .encode()
            .expect("reference should encode")
            .expose_owned();

        let mut duplicate = login_cipher(Some(CipherId::new_v4()), None);
        attach_raw_reference(&mut duplicate, valid.clone(), FieldType::Hidden);
        attach_raw_reference(&mut duplicate, valid, FieldType::Hidden);

        let mut oversized = login_cipher(Some(CipherId::new_v4()), None);
        attach_raw_reference(
            &mut oversized,
            "x".repeat(MAX_ALIAS_REFERENCE_BYTES + 1),
            FieldType::Hidden,
        );

        let hostile_secret = "hostile-api-token-never-render";
        let mut hostile = login_cipher(Some(CipherId::new_v4()), None);
        attach_raw_reference(
            &mut hostile,
            format!(
                "{{\"version\":2,\"provider\":\"simplelogin\",\"providerInstance\":\"https://aliases.example.test/\",\"connectionId\":\"{CONNECTION_ID}\",\"aliasId\":18,\"address\":\"eighteen@example.test\",\"apiToken\":\"{hostile_secret}\"}}"
            ),
            FieldType::Hidden,
        );
        hostile.fields.get_or_insert_with(Vec::new).push(FieldView {
            name: Some("x".repeat(MAX_ALIAS_REFERENCE_BYTES * 2)),
            value: Some(hostile_secret.to_owned()),
            r#type: FieldType::Hidden,
            linked_id: None,
        });

        let mut missing = login_cipher(Some(CipherId::new_v4()), None);
        missing.fields = Some(vec![FieldView {
            name: Some(ALIAS_REFERENCE_FIELD_NAME.to_owned()),
            value: None,
            r#type: FieldType::Hidden,
            linked_id: None,
        }]);

        let ciphers = vec![duplicate, oversized, hostile, missing];
        let plan = plan_alias_reconciliation(&provider, &aliases, &ciphers)
            .expect("hostile fields should be skipped rather than aborting reconciliation");
        assert_eq!(plan.summary.skipped_ciphers, 4);
        assert_eq!(plan.summary.unbound_aliases, 1);
        assert!(plan.actions.is_empty());
        let rendered = format!("{:?}", plan.outcomes);
        assert!(!rendered.contains(hostile_secret));
    }

    #[test]
    fn apply_validates_every_action_before_mutating_any_cipher() {
        let provider = provider();
        let aliases = vec![
            alias(11, "eleven@example.test".to_owned()),
            alias(12, "twelve@example.test".to_owned()),
        ];
        let first_id = CipherId::new_v4();
        let second_id = CipherId::new_v4();
        let mut ciphers = vec![
            login_cipher(Some(first_id), Some("eleven@example.test".to_owned())),
            login_cipher(Some(second_id), Some("twelve@example.test".to_owned())),
        ];
        for (alias, cipher) in aliases.iter().zip(&mut ciphers) {
            AliasReference::new(&provider, alias)
                .expect("reference should construct")
                .bind_to_cipher(cipher)
                .expect("test reference should attach");
            cipher.login.as_mut().expect("login").username = Some("stale@example.test".to_owned());
        }
        let plan = plan_alias_reconciliation(&provider, &aliases, &ciphers)
            .expect("planning should succeed");

        ciphers[1].fields = None;
        let error = apply_alias_reconciliation(&plan, &aliases, &mut ciphers)
            .expect_err("stale plan should fail atomically");
        assert!(matches!(error, AliasReconciliationError::StalePlan(_)));
        assert!(
            AliasReference::from_cipher(&ciphers[0])
                .expect("first cipher should remain valid")
                .is_some()
        );
        assert_eq!(
            ciphers[0]
                .login
                .as_ref()
                .and_then(|login| login.username.as_deref()),
            Some("stale@example.test")
        );
    }

    #[test]
    fn reconciles_ten_thousand_real_cipher_models_in_linear_time() {
        const ITEM_COUNT: usize = 10_000;
        let provider = provider();
        let aliases: Vec<Alias> = (1..=ITEM_COUNT)
            .map(|index| alias(index as u64, format!("alias-{index}@example.test")))
            .collect();
        let mut ciphers: Vec<CipherView> = aliases
            .iter()
            .map(|alias| {
                login_cipher(
                    Some(CipherId::new_v4()),
                    Some(alias.email.expose().to_owned()),
                )
            })
            .collect();

        for (alias, cipher) in aliases.iter().zip(ciphers.iter_mut()).take(ITEM_COUNT / 2) {
            AliasReference::new(&provider, alias)
                .expect("reference should construct")
                .bind_to_cipher(cipher)
                .expect("scale fixture reference should attach");
            cipher.login.as_mut().expect("login").username = Some("stale@example.test".to_owned());
        }

        let started = Instant::now();
        let plan = plan_alias_reconciliation(&provider, &aliases, &ciphers)
            .expect("scale plan should succeed");
        assert_eq!(plan.summary.stale_bindings, (ITEM_COUNT / 2) as u64);
        assert_eq!(plan.summary.unbound_aliases, (ITEM_COUNT / 2) as u64);
        assert_eq!(plan.actions.len(), ITEM_COUNT / 2);
        let applied = apply_alias_reconciliation(&plan, &aliases, &mut ciphers)
            .expect("scale apply should succeed");
        assert_eq!(applied.changed_cipher_ids.len(), ITEM_COUNT / 2);
        let verified = plan_alias_reconciliation(&provider, &aliases, &ciphers)
            .expect("scale verification should succeed");
        assert!(verified.actions.is_empty());
        assert_eq!(verified.summary.matched, (ITEM_COUNT / 2) as u64);
        assert_eq!(verified.summary.unbound_aliases, (ITEM_COUNT / 2) as u64);
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "10k plan/apply/verify should remain comfortably linear"
        );
    }
}
