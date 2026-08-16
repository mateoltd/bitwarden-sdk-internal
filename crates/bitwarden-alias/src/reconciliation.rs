use std::collections::{HashMap, HashSet};

use bitwarden_sensitive_value::{ExposeSensitive, SensitiveString};
use bitwarden_vault::{CipherId, CipherType, CipherView};
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "wasm")]
use tsify::Tsify;

use crate::{
    ALIAS_CONTRACT_VERSION, Alias, AliasConsistency, AliasFreshness, AliasIdentity,
    AliasLifecycleState,
    models::{normalize_email_address, validate_opaque_id, validate_random_id},
};

/// Current canonical alias-reference schema version.
pub const ALIAS_REFERENCE_VERSION: u32 = ALIAS_CONTRACT_VERSION;
/// Maximum encoded size accepted for a canonical alias reference.
pub const MAX_ALIAS_REFERENCE_BYTES: usize = 4 * 1024;
/// Current reconciliation plan and report schema version.
pub const ALIAS_RECONCILIATION_REPORT_VERSION: u32 = 1;

/// Canonical v1 vault binding. Field order is normative for serialization.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[derive(Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AliasReference {
    /// Canonical alias-reference schema version.
    pub version: u32,
    /// Stable UUID v4 identifying the configured provider connection.
    pub connection_id: String,
    /// Opaque provider identifier. No numeric interpretation or normalization is permitted.
    pub alias_id: String,
    /// Normalized alias email address captured with the binding.
    pub address: SensitiveString,
}

impl Clone for AliasReference {
    fn clone(&self) -> Self {
        Self {
            version: self.version,
            connection_id: self.connection_id.clone(),
            alias_id: self.alias_id.clone(),
            address: self.address.clone(),
        }
    }
}

impl core::fmt::Debug for AliasReference {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AliasReference")
            .field("version", &self.version)
            .field("connection_id", &"[REDACTED]")
            .field("alias_id", &"[REDACTED]")
            .field("address", &self.address)
            .finish()
    }
}

impl AliasReference {
    /// Builds and validates a canonical reference from an alias identity.
    pub fn new(identity: &AliasIdentity) -> Result<Self, AliasReferenceError> {
        identity
            .validate()
            .map_err(|_| AliasReferenceError::InvalidValue)?;
        Ok(Self {
            version: ALIAS_REFERENCE_VERSION,
            connection_id: identity.connection_id.clone(),
            alias_id: identity.alias_id.clone(),
            address: identity.address.clone(),
        })
    }

    /// Reconstructs and validates the provider-neutral alias identity.
    pub fn identity(&self) -> Result<AliasIdentity, AliasReferenceError> {
        AliasIdentity::new(
            self.connection_id.clone(),
            self.alias_id.clone(),
            self.address.clone(),
        )
        .map_err(|_| AliasReferenceError::InvalidValue)
    }

    /// Serializes the reference using the canonical closed JSON schema.
    pub fn encode(&self) -> Result<SensitiveString, AliasReferenceError> {
        self.validate()?;
        let encoded =
            serde_json::to_string(self).map_err(|_| AliasReferenceError::EncodingFailed)?;
        ensure_reference_size(&encoded)?;
        Ok(SensitiveString::from(encoded))
    }

    /// Parses and validates a canonical encoded alias reference.
    pub fn decode(value: &str) -> Result<Self, AliasReferenceError> {
        ensure_reference_size(value)?;
        let version = reference_version(value)?;
        if version != ALIAS_REFERENCE_VERSION {
            return Err(AliasReferenceError::UnsupportedVersion);
        }
        let reference: Self =
            serde_json::from_str(value).map_err(|_| AliasReferenceError::Malformed)?;
        reference.validate()?;
        Ok(reference)
    }

    /// Reads a canonical alias reference from a login cipher when one is present.
    pub fn from_cipher(cipher: &CipherView) -> Result<Option<Self>, AliasReferenceError> {
        let Some(login) = cipher.login.as_ref() else {
            return Ok(None);
        };
        let Some(value) = login.alias_reference.as_deref() else {
            return Ok(None);
        };
        if cipher.r#type != CipherType::Login {
            return Err(AliasReferenceError::NotLoginCipher);
        }
        Self::decode(value).map(Some)
    }

    fn validate(&self) -> Result<(), AliasReferenceError> {
        if self.version != ALIAS_REFERENCE_VERSION {
            return Err(AliasReferenceError::UnsupportedVersion);
        }
        validate_random_id(&self.connection_id).map_err(|_| AliasReferenceError::InvalidValue)?;
        validate_opaque_id(&self.alias_id).map_err(|_| AliasReferenceError::InvalidValue)?;
        let normalized = normalize_email_address(self.address.expose())
            .map_err(|_| AliasReferenceError::InvalidValue)?;
        if normalized != *self.address.expose() {
            return Err(AliasReferenceError::InvalidValue);
        }
        Ok(())
    }
}

/// Creates an encoded canonical reference for an alias identity.
pub fn create_alias_reference(
    identity: &AliasIdentity,
) -> Result<SensitiveString, AliasReferenceError> {
    AliasReference::new(identity)?.encode()
}

/// Serializes an already constructed canonical reference.
pub fn serialize_alias_reference(
    reference: &AliasReference,
) -> Result<SensitiveString, AliasReferenceError> {
    reference.encode()
}

/// Parses an encoded canonical reference.
pub fn parse_alias_reference(value: &str) -> Result<AliasReference, AliasReferenceError> {
    AliasReference::decode(value)
}

/// Updated decrypted cipher returned to the caller's normal encryption/persistence path.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AliasCipherMutationResult {
    /// Decrypted cipher to pass through the caller's normal persistence path.
    pub cipher: CipherView,
    /// Whether the canonical binding changed.
    pub changed: bool,
}

impl core::fmt::Debug for AliasCipherMutationResult {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AliasCipherMutationResult")
            .field("cipher", &"[REDACTED]")
            .field("changed", &self.changed)
            .finish()
    }
}

/// Binds a canonical reference only when the existing login username already normalizes to the
/// same address. The function never overwrites a password, URI, TOTP, field, or unrelated item.
pub fn bind_alias_reference(
    value: &str,
    mut cipher: CipherView,
) -> Result<AliasCipherMutationResult, AliasReferenceError> {
    let reference = AliasReference::decode(value)?;
    let login = login_mut(&mut cipher)?;
    let username = login
        .username
        .as_deref()
        .ok_or(AliasReferenceError::UsernameMismatch)?;
    let normalized =
        normalize_email_address(username).map_err(|_| AliasReferenceError::UsernameMismatch)?;
    if normalized != *reference.address.expose() {
        return Err(AliasReferenceError::UsernameMismatch);
    }
    if let Some(existing) = login.alias_reference.as_deref() {
        AliasReference::decode(existing)?;
    }
    let encoded = reference.encode()?.expose_owned();
    let changed = login.alias_reference.as_deref() != Some(encoded.as_str());
    login.alias_reference = Some(encoded);
    Ok(AliasCipherMutationResult { cipher, changed })
}

/// Clears a binding before save when the username no longer matches the bound canonical address.
pub fn clear_alias_reference_if_username_changed(
    mut cipher: CipherView,
) -> Result<AliasCipherMutationResult, AliasReferenceError> {
    let login = login_mut(&mut cipher)?;
    let Some(encoded) = login.alias_reference.as_deref() else {
        return Ok(AliasCipherMutationResult {
            cipher,
            changed: false,
        });
    };
    let reference = AliasReference::decode(encoded)?;
    let matches = login
        .username
        .as_deref()
        .and_then(|username| normalize_email_address(username).ok())
        .is_some_and(|username| username == *reference.address.expose());
    if matches {
        return Ok(AliasCipherMutationResult {
            cipher,
            changed: false,
        });
    }
    login.alias_reference = None;
    Ok(AliasCipherMutationResult {
        cipher,
        changed: true,
    })
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Error), uniffi(flat_error))]
#[derive(Debug, Error)]
/// Stable failures produced while reading or writing canonical alias references.
pub enum AliasReferenceError {
    /// The encoded reference exceeds the supported size limit.
    #[error("alias reference exceeded its size limit")]
    TooLarge,
    /// The encoded value is not a valid closed-schema reference.
    #[error("malformed alias reference")]
    Malformed,
    /// The reference uses an unsupported schema version.
    #[error("unsupported alias reference version")]
    UnsupportedVersion,
    /// A field is invalid or is not in canonical form.
    #[error("invalid alias reference value")]
    InvalidValue,
    /// Alias references are only valid on login ciphers.
    #[error("alias reference requires a login cipher")]
    NotLoginCipher,
    /// The login username does not match the canonical alias address.
    #[error("alias reference address does not match the login username")]
    UsernameMismatch,
    /// Canonical serialization failed locally.
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

#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
/// Whether reconciliation is planning changes or reporting an applied result.
pub enum AliasReconciliationMode {
    /// Inspect and propose repairs without mutating ciphers.
    DryRun,
    /// Reserved report mode for an applied reconciliation result.
    Apply,
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
/// Stable reason a cipher could not participate in reconciliation.
pub enum AliasReconciliationSkipReason {
    /// The cipher has no persistent identifier.
    MissingCipherId,
    /// The encoded reference exceeds the supported size limit.
    ReferenceTooLarge,
    /// The encoded reference is malformed.
    MalformedReference,
    /// The reference uses an unsupported schema version.
    UnsupportedReferenceVersion,
    /// The reference belongs to another configured connection.
    ForeignConnection,
    /// The cipher is not a login cipher.
    NonLoginCipher,
    /// A reference field is invalid or non-canonical.
    InvalidReferenceValue,
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(
    feature = "wasm",
    derive(Tsify),
    tsify(into_wasm_abi, from_wasm_abi, large_number_types_as_bigints)
)]
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "status", deny_unknown_fields)]
/// Deterministic result for one alias binding or skipped cipher.
pub enum AliasReconciliationOutcome {
    /// A binding and login username already match the current alias.
    Matched {
        /// Opaque provider alias identifier.
        alias_id: String,
        /// Bound cipher identifier.
        cipher_id: CipherId,
    },
    /// A binding or login username needs a refresh from the current alias.
    StaleBinding {
        /// Opaque provider alias identifier.
        alias_id: String,
        /// Bound cipher identifier.
        cipher_id: CipherId,
        /// Whether the address captured in the reference is stale.
        reference_address_stale: bool,
        /// Whether the login username is stale or invalid.
        username_stale: bool,
    },
    /// Multiple ciphers claim the same alias and require user resolution.
    DuplicateBinding {
        /// Opaque provider alias identifier.
        alias_id: String,
        /// Canonically sorted identifiers of conflicting ciphers.
        cipher_ids: Vec<CipherId>,
    },
    /// A cipher references an alias absent from the current inventory.
    MissingAlias {
        /// Opaque provider alias identifier from the reference.
        alias_id: String,
        /// Bound cipher identifier.
        cipher_id: CipherId,
    },
    /// A current, non-deleted alias has no cipher binding.
    UnboundAlias {
        /// Opaque provider alias identifier.
        alias_id: String,
    },
    /// A cipher was deliberately excluded from reconciliation.
    SkippedCipher {
        /// Cipher identifier, when the cipher has one.
        cipher_id: Option<CipherId>,
        /// Stable exclusion reason.
        reason: AliasReconciliationSkipReason,
    },
}

impl core::fmt::Debug for AliasReconciliationOutcome {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AliasReconciliationOutcome([REDACTED])")
    }
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "action", deny_unknown_fields)]
/// Provider-neutral repair proposed by a reconciliation plan.
pub enum AliasReconciliationAction {
    /// Refreshes a known binding and username from the current alias inventory.
    Refresh {
        /// Opaque provider alias identifier.
        alias_id: String,
        /// Bound cipher identifier.
        cipher_id: CipherId,
        /// Whether the address captured in the reference is stale.
        reference_address_stale: bool,
        /// Whether the login username is stale or invalid.
        username_stale: bool,
    },
}

impl core::fmt::Debug for AliasReconciliationAction {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AliasReconciliationAction([REDACTED])")
    }
}

impl AliasReconciliationAction {
    fn alias_id(&self) -> &str {
        match self {
            Self::Refresh { alias_id, .. } => alias_id,
        }
    }

    fn cipher_id(&self) -> CipherId {
        match self {
            Self::Refresh { cipher_id, .. } => *cipher_id,
        }
    }
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(Tsify),
    tsify(into_wasm_abi, from_wasm_abi, large_number_types_as_bigints)
)]
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Aggregate counts for a reconciliation plan or application result.
pub struct AliasReconciliationSummary {
    /// Bindings already matching current aliases.
    pub matched: u64,
    /// Bindings needing a reference or username refresh.
    pub stale_bindings: u64,
    /// Alias identities claimed by multiple ciphers.
    pub duplicate_bindings: u64,
    /// Bindings whose alias is absent from the inventory.
    pub missing_aliases: u64,
    /// Current aliases with no binding.
    pub unbound_aliases: u64,
    /// Ciphers excluded from reconciliation.
    pub skipped_ciphers: u64,
    /// Repair actions proposed by the plan.
    pub proposed_repairs: u64,
    /// Repairs confirmed as applied by a reporting layer.
    pub applied_repairs: u64,
    /// Repairs reported as failed by a reporting layer.
    pub failed_repairs: u64,
    /// Outcomes that require user conflict resolution.
    pub conflicts: u64,
    /// Mutations whose remote result remains unknown.
    pub unknown_outcomes: u64,
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(Tsify),
    tsify(into_wasm_abi, from_wasm_abi, large_number_types_as_bigints)
)]
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Canonical deterministic reconciliation plan for one connection snapshot.
pub struct AliasReconciliationPlan {
    /// Reconciliation report schema version.
    pub version: u32,
    /// Plan mode, which must be dry-run before application.
    pub mode: AliasReconciliationMode,
    /// Stable UUID v4 of the configured provider connection.
    pub connection_id: String,
    /// Canonically ordered observations for the input snapshot.
    pub outcomes: Vec<AliasReconciliationOutcome>,
    /// Canonically ordered repairs derived from stale bindings.
    pub actions: Vec<AliasReconciliationAction>,
    /// Counts derived exactly from the outcomes and actions.
    pub summary: AliasReconciliationSummary,
}

impl core::fmt::Debug for AliasReconciliationPlan {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AliasReconciliationPlan")
            .field("version", &self.version)
            .field("mode", &self.mode)
            .field("connection_id", &"[REDACTED]")
            .field("outcome_count", &self.outcomes.len())
            .field("action_count", &self.actions.len())
            .field("summary", &self.summary)
            .finish()
    }
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(Tsify),
    tsify(into_wasm_abi, from_wasm_abi, large_number_types_as_bigints)
)]
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Result of atomically applying a validated reconciliation plan.
pub struct AliasReconciliationApplyResult {
    /// Cipher identifiers whose reference or username changed.
    pub changed_cipher_ids: Vec<CipherId>,
    /// Actions already satisfied by a prior idempotent application.
    pub unchanged_actions: u64,
}

impl core::fmt::Debug for AliasReconciliationApplyResult {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AliasReconciliationApplyResult")
            .field("changed_cipher_count", &self.changed_cipher_ids.len())
            .field("unchanged_actions", &self.unchanged_actions)
            .finish()
    }
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(Tsify),
    tsify(into_wasm_abi, from_wasm_abi, large_number_types_as_bigints)
)]
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Owned cipher collection and result returned by binding-friendly application APIs.
pub struct AliasReconciliationApplyOutput {
    /// Input ciphers with validated repairs applied.
    pub ciphers: Vec<CipherView>,
    /// Mutation result for the application.
    pub result: AliasReconciliationApplyResult,
}

impl core::fmt::Debug for AliasReconciliationApplyOutput {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AliasReconciliationApplyOutput")
            .field("cipher_count", &self.ciphers.len())
            .field("result", &self.result)
            .finish()
    }
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Error), uniffi(flat_error))]
#[derive(Debug, Error)]
/// Stable failures produced while planning or applying reconciliation.
pub enum AliasReconciliationError {
    /// An input or plan violates the canonical schema.
    #[error("invalid reconciliation input")]
    InvalidInput,
    /// The provider inventory contains the same alias identifier more than once.
    #[error("reconciliation inventory contains duplicate alias identity")]
    DuplicateAliasId,
    /// The cipher inventory contains the same persistent identifier more than once.
    #[error("reconciliation inventory contains duplicate cipher identity")]
    DuplicateCipherId,
    /// The input snapshot no longer matches the supplied plan.
    #[error("reconciliation plan is stale")]
    StalePlan,
    /// A canonical alias reference could not be read or produced.
    #[error("reconciliation reference is invalid")]
    Reference,
}

#[cfg(feature = "wasm")]
impl From<AliasReconciliationError> for wasm_bindgen::JsValue {
    fn from(error: AliasReconciliationError) -> Self {
        let js_error = js_sys::Error::new(&error.to_string());
        js_error.set_name("AliasReconciliationError");
        js_error.into()
    }
}

impl From<AliasReferenceError> for AliasReconciliationError {
    fn from(_: AliasReferenceError) -> Self {
        Self::Reference
    }
}

struct Claim {
    cipher_index: usize,
    cipher_id: CipherId,
    alias_id: String,
    reference: AliasReference,
}

/// Deterministic non-mutating plan. It never infers a binding from an address.
pub fn plan_alias_reconciliation(
    connection_id: &str,
    aliases: &[Alias],
    ciphers: &[CipherView],
) -> Result<AliasReconciliationPlan, AliasReconciliationError> {
    validate_random_id(connection_id).map_err(|_| AliasReconciliationError::InvalidInput)?;
    validate_cipher_ids(ciphers)?;
    let alias_index = index_aliases(connection_id, aliases)?;
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
                if reference.connection_id != connection_id {
                    outcomes.push(AliasReconciliationOutcome::SkippedCipher {
                        cipher_id: Some(cipher_id),
                        reason: AliasReconciliationSkipReason::ForeignConnection,
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
                    alias_id: reference.alias_id.clone(),
                    reference,
                });
            }
            Ok(None) => {}
            Err(error) => outcomes.push(AliasReconciliationOutcome::SkippedCipher {
                cipher_id: cipher.id,
                reason: skip_reason(&error),
            }),
        }
    }

    let mut claims_by_alias: HashMap<&str, Vec<CipherId>> = HashMap::new();
    for claim in &claims {
        claims_by_alias
            .entry(claim.alias_id.as_str())
            .or_default()
            .push(claim.cipher_id);
    }
    for cipher_ids in claims_by_alias.values_mut() {
        cipher_ids.sort_by_key(ToString::to_string);
    }

    let mut actions = Vec::new();
    let mut emitted_duplicates = HashSet::new();
    for claim in &claims {
        let cipher_ids = &claims_by_alias[claim.alias_id.as_str()];
        if cipher_ids.len() > 1 {
            if emitted_duplicates.insert(claim.alias_id.as_str()) {
                outcomes.push(AliasReconciliationOutcome::DuplicateBinding {
                    alias_id: claim.alias_id.clone(),
                    cipher_ids: cipher_ids.clone(),
                });
            }
            continue;
        }
        let Some(alias) = alias_index.get(claim.alias_id.as_str()).copied() else {
            outcomes.push(AliasReconciliationOutcome::MissingAlias {
                alias_id: claim.alias_id.clone(),
                cipher_id: claim.cipher_id,
            });
            continue;
        };
        let canonical_address = alias.identity.address.expose();
        let reference_address_stale = claim.reference.address.expose() != canonical_address;
        let username_stale = ciphers[claim.cipher_index]
            .login
            .as_ref()
            .and_then(|login| login.username.as_deref())
            .and_then(|username| normalize_email_address(username).ok())
            .as_deref()
            != Some(canonical_address);
        if reference_address_stale || username_stale {
            outcomes.push(AliasReconciliationOutcome::StaleBinding {
                alias_id: claim.alias_id.clone(),
                cipher_id: claim.cipher_id,
                reference_address_stale,
                username_stale,
            });
            actions.push(AliasReconciliationAction::Refresh {
                alias_id: claim.alias_id.clone(),
                cipher_id: claim.cipher_id,
                reference_address_stale,
                username_stale,
            });
        } else {
            outcomes.push(AliasReconciliationOutcome::Matched {
                alias_id: claim.alias_id.clone(),
                cipher_id: claim.cipher_id,
            });
        }
    }

    for alias in aliases {
        if alias.lifecycle != AliasLifecycleState::Deleted
            && !claims_by_alias.contains_key(alias.identity.alias_id.as_str())
        {
            outcomes.push(AliasReconciliationOutcome::UnboundAlias {
                alias_id: alias.identity.alias_id.clone(),
            });
        }
    }

    outcomes.sort_by_key(outcome_sort_key);
    actions.sort_by_key(|action| (action.alias_id().to_owned(), action.cipher_id().to_string()));
    let summary = summarize(&outcomes, actions.len());
    Ok(AliasReconciliationPlan {
        version: ALIAS_RECONCILIATION_REPORT_VERSION,
        mode: AliasReconciliationMode::DryRun,
        connection_id: connection_id.to_owned(),
        outcomes,
        actions,
        summary,
    })
}

/// Validates and atomically applies a plan to a mutable cipher snapshot.
pub fn apply_alias_reconciliation(
    plan: &AliasReconciliationPlan,
    aliases: &[Alias],
    ciphers: &mut [CipherView],
) -> Result<AliasReconciliationApplyResult, AliasReconciliationError> {
    validate_plan(plan)?;
    let alias_index = index_aliases(&plan.connection_id, aliases)?;
    let cipher_index = index_ciphers(ciphers)?;
    let current = plan_alias_reconciliation(&plan.connection_id, aliases, ciphers)?;
    if current != *plan && current != postcondition_plan(plan) {
        return Err(AliasReconciliationError::StalePlan);
    }

    struct Prepared {
        cipher_index: usize,
        cipher_id: CipherId,
        encoded: String,
        address: String,
        already_satisfied: bool,
    }
    let mut prepared = Vec::with_capacity(plan.actions.len());
    let mut seen_ciphers = HashSet::new();
    for action in &plan.actions {
        let alias_id = action.alias_id();
        let cipher_id = action.cipher_id();
        if !seen_ciphers.insert(cipher_id) {
            return Err(AliasReconciliationError::StalePlan);
        }
        let alias = alias_index
            .get(alias_id)
            .copied()
            .ok_or(AliasReconciliationError::StalePlan)?;
        let index = *cipher_index
            .get(&cipher_id)
            .ok_or(AliasReconciliationError::StalePlan)?;
        let desired = AliasReference::new(&alias.identity)?;
        let existing = AliasReference::from_cipher(&ciphers[index])?;
        let already_satisfied = existing.as_ref() == Some(&desired)
            && ciphers[index]
                .login
                .as_ref()
                .and_then(|login| login.username.as_deref())
                .and_then(|username| normalize_email_address(username).ok())
                .as_deref()
                == Some(alias.identity.address.expose());
        match existing {
            Some(reference)
                if reference.connection_id == plan.connection_id
                    && reference.alias_id == alias_id => {}
            _ => return Err(AliasReconciliationError::StalePlan),
        }
        prepared.push(Prepared {
            cipher_index: index,
            cipher_id,
            encoded: desired.encode()?.expose_owned(),
            address: alias.identity.address.expose().to_owned(),
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
        let login = login_mut(&mut ciphers[change.cipher_index])?;
        login.alias_reference = Some(change.encoded);
        login.username = Some(change.address);
        changed_cipher_ids.push(change.cipher_id);
    }
    Ok(AliasReconciliationApplyResult {
        changed_cipher_ids,
        unchanged_actions,
    })
}

fn validate_plan(plan: &AliasReconciliationPlan) -> Result<(), AliasReconciliationError> {
    if plan.version != ALIAS_RECONCILIATION_REPORT_VERSION
        || plan.mode != AliasReconciliationMode::DryRun
    {
        return Err(AliasReconciliationError::InvalidInput);
    }
    validate_random_id(&plan.connection_id).map_err(|_| AliasReconciliationError::InvalidInput)?;
    if plan
        .outcomes
        .windows(2)
        .any(|pair| outcome_sort_key(&pair[0]) > outcome_sort_key(&pair[1]))
        || plan.actions.windows(2).any(|pair| {
            (pair[0].alias_id(), pair[0].cipher_id().to_string())
                >= (pair[1].alias_id(), pair[1].cipher_id().to_string())
        })
    {
        return Err(AliasReconciliationError::InvalidInput);
    }

    let mut stale = HashMap::<(String, CipherId), (bool, bool)>::new();
    for outcome in &plan.outcomes {
        if let AliasReconciliationOutcome::StaleBinding {
            alias_id,
            cipher_id,
            reference_address_stale,
            username_stale,
        } = outcome
        {
            validate_opaque_id(alias_id).map_err(|_| AliasReconciliationError::InvalidInput)?;
            if !(*reference_address_stale || *username_stale)
                || stale
                    .insert(
                        (alias_id.clone(), *cipher_id),
                        (*reference_address_stale, *username_stale),
                    )
                    .is_some()
            {
                return Err(AliasReconciliationError::InvalidInput);
            }
        }
    }
    if stale.len() != plan.actions.len() {
        return Err(AliasReconciliationError::InvalidInput);
    }
    for action in &plan.actions {
        let AliasReconciliationAction::Refresh {
            alias_id,
            cipher_id,
            reference_address_stale,
            username_stale,
        } = action;
        validate_opaque_id(alias_id).map_err(|_| AliasReconciliationError::InvalidInput)?;
        if stale.remove(&(alias_id.clone(), *cipher_id))
            != Some((*reference_address_stale, *username_stale))
        {
            return Err(AliasReconciliationError::InvalidInput);
        }
    }
    if !stale.is_empty() || plan.summary != summarize(&plan.outcomes, plan.actions.len()) {
        return Err(AliasReconciliationError::InvalidInput);
    }
    Ok(())
}

fn postcondition_plan(plan: &AliasReconciliationPlan) -> AliasReconciliationPlan {
    let mut outcomes = plan
        .outcomes
        .iter()
        .map(|outcome| match outcome {
            AliasReconciliationOutcome::StaleBinding {
                alias_id,
                cipher_id,
                ..
            } => AliasReconciliationOutcome::Matched {
                alias_id: alias_id.clone(),
                cipher_id: *cipher_id,
            },
            outcome => outcome.clone(),
        })
        .collect::<Vec<_>>();
    outcomes.sort_by_key(outcome_sort_key);
    AliasReconciliationPlan {
        version: plan.version,
        mode: AliasReconciliationMode::DryRun,
        connection_id: plan.connection_id.clone(),
        summary: summarize(&outcomes, 0),
        outcomes,
        actions: Vec::new(),
    }
}

/// Applies a plan and returns ownership of the updated cipher snapshot for foreign bindings.
pub fn apply_alias_reconciliation_owned(
    plan: &AliasReconciliationPlan,
    aliases: &[Alias],
    mut ciphers: Vec<CipherView>,
) -> Result<AliasReconciliationApplyOutput, AliasReconciliationError> {
    let result = apply_alias_reconciliation(plan, aliases, &mut ciphers)?;
    Ok(AliasReconciliationApplyOutput { ciphers, result })
}

fn login_mut(
    cipher: &mut CipherView,
) -> Result<&mut bitwarden_vault::LoginView, AliasReferenceError> {
    if cipher.r#type != CipherType::Login {
        return Err(AliasReferenceError::NotLoginCipher);
    }
    cipher
        .login
        .as_mut()
        .ok_or(AliasReferenceError::NotLoginCipher)
}

fn ensure_reference_size(value: &str) -> Result<(), AliasReferenceError> {
    if value.len() > MAX_ALIAS_REFERENCE_BYTES {
        return Err(AliasReferenceError::TooLarge);
    }
    Ok(())
}

fn reference_version(value: &str) -> Result<u32, AliasReferenceError> {
    #[derive(Deserialize)]
    struct Envelope {
        version: u32,
    }
    serde_json::from_str::<Envelope>(value)
        .map(|envelope| envelope.version)
        .map_err(|_| AliasReferenceError::Malformed)
}

fn validate_cipher_ids(ciphers: &[CipherView]) -> Result<(), AliasReconciliationError> {
    let mut ids = HashSet::with_capacity(ciphers.len());
    for id in ciphers.iter().filter_map(|cipher| cipher.id) {
        if !ids.insert(id) {
            return Err(AliasReconciliationError::DuplicateCipherId);
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

fn index_aliases<'a>(
    connection_id: &str,
    aliases: &'a [Alias],
) -> Result<HashMap<&'a str, &'a Alias>, AliasReconciliationError> {
    let mut by_id = HashMap::with_capacity(aliases.len());
    for alias in aliases {
        alias
            .validate()
            .map_err(|_| AliasReconciliationError::InvalidInput)?;
        if alias.identity.connection_id != connection_id
            || alias.freshness != AliasFreshness::Current
            || alias.consistency != AliasConsistency::Clean
        {
            return Err(AliasReconciliationError::InvalidInput);
        }
        if by_id
            .insert(alias.identity.alias_id.as_str(), alias)
            .is_some()
        {
            return Err(AliasReconciliationError::DuplicateAliasId);
        }
    }
    Ok(by_id)
}

fn skip_reason(error: &AliasReferenceError) -> AliasReconciliationSkipReason {
    match error {
        AliasReferenceError::TooLarge => AliasReconciliationSkipReason::ReferenceTooLarge,
        AliasReferenceError::Malformed | AliasReferenceError::EncodingFailed => {
            AliasReconciliationSkipReason::MalformedReference
        }
        AliasReferenceError::UnsupportedVersion => {
            AliasReconciliationSkipReason::UnsupportedReferenceVersion
        }
        AliasReferenceError::NotLoginCipher => AliasReconciliationSkipReason::NonLoginCipher,
        AliasReferenceError::InvalidValue | AliasReferenceError::UsernameMismatch => {
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
            AliasReconciliationOutcome::DuplicateBinding { .. } => {
                summary.duplicate_bindings += 1;
                summary.conflicts += 1;
            }
            AliasReconciliationOutcome::MissingAlias { .. } => summary.missing_aliases += 1,
            AliasReconciliationOutcome::UnboundAlias { .. } => summary.unbound_aliases += 1,
            AliasReconciliationOutcome::SkippedCipher { .. } => summary.skipped_ciphers += 1,
        }
    }
    summary
}

fn outcome_sort_key(outcome: &AliasReconciliationOutcome) -> (u8, String, String) {
    match outcome {
        AliasReconciliationOutcome::Matched {
            alias_id,
            cipher_id,
        } => (0, alias_id.clone(), cipher_id.to_string()),
        AliasReconciliationOutcome::StaleBinding {
            alias_id,
            cipher_id,
            ..
        } => (1, alias_id.clone(), cipher_id.to_string()),
        AliasReconciliationOutcome::DuplicateBinding { alias_id, .. } => {
            (2, alias_id.clone(), String::new())
        }
        AliasReconciliationOutcome::MissingAlias {
            alias_id,
            cipher_id,
        } => (3, alias_id.clone(), cipher_id.to_string()),
        AliasReconciliationOutcome::UnboundAlias { alias_id } => {
            (4, alias_id.clone(), String::new())
        }
        AliasReconciliationOutcome::SkippedCipher { cipher_id, .. } => (
            5,
            String::new(),
            cipher_id.map_or_else(String::new, |id| id.to_string()),
        ),
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_sensitive_value::SensitiveString;
    use bitwarden_vault::{CipherRepromptType, CipherView, LoginView};

    use super::*;
    use crate::{AliasConsistency, AliasFreshness, AliasProviderCapabilities};

    const CONNECTION: &str = "11111111-1111-4111-8111-111111111111";

    fn alias(alias_id: &str, address: &str) -> Alias {
        Alias {
            identity: AliasIdentity::new(
                CONNECTION.to_owned(),
                alias_id.to_owned(),
                SensitiveString::from(address),
            )
            .unwrap(),
            lifecycle: AliasLifecycleState::Enabled,
            freshness: AliasFreshness::Current,
            consistency: AliasConsistency::Clean,
            label: None,
            capabilities: AliasProviderCapabilities::first_class(),
        }
    }

    fn login(username: &str) -> CipherView {
        let timestamp = "2026-08-10T10:00:00Z"
            .parse()
            .expect("test timestamp should parse");
        CipherView {
            id: Some(CipherId::new_v4()),
            organization_id: None,
            folder_id: None,
            collection_ids: Vec::new(),
            key: None,
            name: "login".to_owned(),
            notes: Some("preserve".to_owned()),
            r#type: CipherType::Login,
            login: Some(LoginView {
                username: Some(username.to_owned()),
                password: Some("preserve-password".to_owned()),
                alias_reference: None,
                password_revision_date: None,
                uris: None,
                totp: None,
                autofill_on_page_load: None,
                fido2_credentials: None,
            }),
            secure_note: None,
            card: None,
            identity: None,
            ssh_key: None,
            bank_account: None,
            drivers_license: None,
            passport: None,
            favorite: false,
            reprompt: CipherRepromptType::None,
            fields: None,
            local_data: None,
            attachments: None,
            attachment_decryption_failures: None,
            permissions: None,
            view_password: true,
            organization_use_totp: false,
            edit: true,
            password_history: None,
            creation_date: timestamp,
            deleted_date: None,
            revision_date: timestamp,
            archived_date: None,
        }
    }

    #[test]
    fn canonical_reference_is_four_fields_and_opaque() {
        let identity = alias("opaque:provider/id-007", "Case@Example.Test").identity;
        let encoded = create_alias_reference(&identity).unwrap().expose_owned();
        assert_eq!(
            encoded,
            format!(
                "{{\"version\":1,\"connectionId\":\"{CONNECTION}\",\"aliasId\":\"opaque:provider/id-007\",\"address\":\"case@example.test\"}}"
            )
        );
        assert_eq!(
            AliasReference::decode(&encoded)
                .unwrap()
                .identity()
                .unwrap(),
            identity
        );
    }

    #[test]
    fn binding_requires_username_integrity_and_clears_after_edit() {
        let identity = alias("alpha", "alias@example.test").identity;
        let encoded = create_alias_reference(&identity).unwrap().expose_owned();
        let bound = bind_alias_reference(&encoded, login("Alias@Example.Test")).unwrap();
        assert!(bound.changed);
        assert_eq!(bound.cipher.notes.as_deref(), Some("preserve"));
        let rendered = format!("{bound:?}");
        assert!(!rendered.contains("preserve-password"));
        assert!(!rendered.contains("alias@example.test"));
        let mut edited = bound.cipher;
        edited.login.as_mut().unwrap().username = Some("other@example.test".to_owned());
        let cleared = clear_alias_reference_if_username_changed(edited).unwrap();
        assert!(cleared.changed);
        assert!(cleared.cipher.login.unwrap().alias_reference.is_none());
    }

    #[test]
    fn reconciliation_is_scoped_atomic_and_idempotent() {
        let aliases = vec![alias("opaque-A", "new@example.test")];
        let old_identity = AliasIdentity::new(
            CONNECTION.to_owned(),
            "opaque-A".to_owned(),
            SensitiveString::from("old@example.test"),
        )
        .unwrap();
        let encoded = create_alias_reference(&old_identity)
            .unwrap()
            .expose_owned();
        let mut ciphers = vec![login("old@example.test"), login("ordinary@example.test")];
        ciphers[0].login.as_mut().unwrap().alias_reference = Some(encoded);
        let untouched = serde_json::to_value(&ciphers[1]).unwrap();
        let plan = plan_alias_reconciliation(CONNECTION, &aliases, &ciphers).unwrap();
        assert_eq!(plan.summary.proposed_repairs, 1);
        let rendered = format!("{plan:?}");
        assert!(!rendered.contains(CONNECTION));
        assert!(!rendered.contains("opaque-A"));
        assert!(!rendered.contains("old@example.test"));
        assert!(!rendered.contains("preserve-password"));
        let first = apply_alias_reconciliation(&plan, &aliases, &mut ciphers).unwrap();
        assert_eq!(first.changed_cipher_ids.len(), 1);
        assert_eq!(serde_json::to_value(&ciphers[1]).unwrap(), untouched);
        let second = apply_alias_reconciliation(&plan, &aliases, &mut ciphers).unwrap();
        assert_eq!(second.changed_cipher_ids.len(), 0);
        assert_eq!(second.unchanged_actions, 1);
    }

    #[test]
    fn apply_rejects_incomplete_or_tampered_plans_before_mutation() {
        let aliases = vec![alias("opaque-A", "new@example.test")];
        let old_identity = AliasIdentity::new(
            CONNECTION.to_owned(),
            "opaque-A".to_owned(),
            SensitiveString::from("old@example.test"),
        )
        .unwrap();
        let mut ciphers = vec![login("old@example.test")];
        ciphers[0].login.as_mut().unwrap().alias_reference = Some(
            create_alias_reference(&old_identity)
                .unwrap()
                .expose_owned(),
        );
        let original = serde_json::to_value(&ciphers).unwrap();

        let mut incomplete = plan_alias_reconciliation(CONNECTION, &aliases, &ciphers).unwrap();
        incomplete.actions.clear();
        incomplete.summary.proposed_repairs = 0;
        assert!(matches!(
            apply_alias_reconciliation(&incomplete, &aliases, &mut ciphers),
            Err(AliasReconciliationError::InvalidInput) | Err(AliasReconciliationError::StalePlan)
        ));
        assert_eq!(serde_json::to_value(&ciphers).unwrap(), original);

        let mut tampered = plan_alias_reconciliation(CONNECTION, &aliases, &ciphers).unwrap();
        tampered.summary.matched = 1;
        assert!(matches!(
            apply_alias_reconciliation(&tampered, &aliases, &mut ciphers),
            Err(AliasReconciliationError::InvalidInput)
        ));
        assert_eq!(serde_json::to_value(&ciphers).unwrap(), original);
    }
}
