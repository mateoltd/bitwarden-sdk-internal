use std::{
    collections::{HashMap, HashSet},
    fmt,
};

use bitwarden_sensitive_value::{ExposeSensitive, SensitiveString};
use bitwarden_vault::{CipherId, CipherType, CipherView, FieldType, FieldView};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use crate::{Alias, AliasId};

/// Current schema version stored in vault alias-reference fields.
pub const ALIAS_REFERENCE_VERSION: u32 = 1;

/// Reserved hidden-field name used to persist alias identity inside an encrypted vault cipher.
pub const ALIAS_REFERENCE_FIELD_NAME: &str = "bitwarden.alias.reference";

const MAX_ALIAS_REFERENCE_BYTES: usize = 4 * 1024;

/// Alias provider represented by a vault reference.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum AliasProvider {
    /// SimpleLogin, hosted or self-hosted.
    #[serde(rename = "simplelogin")]
    SimpleLogin,
}

/// A provider plus its concrete service instance.
///
/// The instance is part of stable identity because numeric alias identifiers can overlap between
/// hosted and self-hosted SimpleLogin installations.
#[derive(Clone, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AliasProviderIdentity {
    /// Provider implementation.
    pub provider: AliasProvider,
    /// Canonical service base URL, including a trailing slash.
    pub instance: String,
}

impl fmt::Debug for AliasProviderIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AliasProviderIdentity")
            .field("provider", &self.provider)
            .field("instance", &"[REDACTED]")
            .finish()
    }
}

impl AliasProviderIdentity {
    /// Creates a canonical SimpleLogin provider identity.
    pub fn simplelogin(base_url: &str) -> Result<Self, AliasReferenceError> {
        let url = canonical_provider_url(base_url)?;
        Ok(Self::from_simplelogin_url(&url))
    }

    pub(crate) fn from_simplelogin_url(url: &Url) -> Self {
        Self {
            provider: AliasProvider::SimpleLogin,
            instance: url.as_str().to_owned(),
        }
    }

    fn validate(&self) -> Result<(), AliasReferenceError> {
        let canonical = canonical_provider_url(&self.instance)?;
        if canonical.as_str() != self.instance {
            return Err(AliasReferenceError::InvalidValue(
                "provider instance must be canonical",
            ));
        }
        Ok(())
    }
}

/// Versioned stable reference persisted in a vault cipher.
///
/// The address is a last-known snapshot. Provider and numeric identifier are authoritative.
#[derive(Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AliasReference {
    /// Reference schema version.
    pub version: u32,
    /// Alias provider.
    pub provider: AliasProvider,
    /// Canonical provider instance URL.
    pub provider_instance: String,
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
            .field("alias_id", &self.alias_id)
            .field("address", &self.address)
            .finish()
    }
}

impl AliasReference {
    /// Creates a current-version reference from real provider lifecycle data.
    pub fn new(identity: &AliasProviderIdentity, alias: &Alias) -> Self {
        Self {
            version: ALIAS_REFERENCE_VERSION,
            provider: identity.provider,
            provider_instance: identity.instance.clone(),
            alias_id: alias.id,
            address: SensitiveString::from(provider_alias_address(alias).to_owned()),
        }
    }

    /// Returns the provider identity namespacing this reference.
    pub fn provider_identity(&self) -> AliasProviderIdentity {
        AliasProviderIdentity {
            provider: self.provider,
            instance: self.provider_instance.clone(),
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
        if value.len() > MAX_ALIAS_REFERENCE_BYTES {
            return Err(AliasReferenceError::TooLarge {
                limit_bytes: MAX_ALIAS_REFERENCE_BYTES,
            });
        }

        #[derive(Deserialize)]
        struct VersionEnvelope {
            version: u32,
        }

        let envelope: VersionEnvelope =
            serde_json::from_str(value).map_err(|_| AliasReferenceError::Malformed)?;
        if envelope.version != ALIAS_REFERENCE_VERSION {
            return Err(AliasReferenceError::UnsupportedVersion {
                version: envelope.version,
            });
        }
        let reference: Self =
            serde_json::from_str(value).map_err(|_| AliasReferenceError::Malformed)?;
        reference.validate()?;
        Ok(reference)
    }

    /// Reads the single reserved reference field from a decrypted vault cipher.
    pub fn from_cipher(cipher: &CipherView) -> Result<Option<Self>, AliasReferenceError> {
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
        if self.alias_id.0 == 0 {
            return Err(AliasReferenceError::InvalidValue(
                "alias identifier must be non-zero",
            ));
        }
        // EXPOSE: validation only checks whether the sensitive address is empty and never renders
        // or logs it.
        if self.address.expose().is_empty() {
            return Err(AliasReferenceError::InvalidValue(
                "alias address must not be empty",
            ));
        }
        let canonical = canonical_provider_url(&self.provider_instance)?;
        if canonical.as_str() != self.provider_instance {
            return Err(AliasReferenceError::InvalidValue(
                "provider instance must be canonical",
            ));
        }
        Ok(())
    }
}

/// Safe failures while parsing or attaching a vault alias reference.
#[derive(Debug, Error)]
pub enum AliasReferenceError {
    /// Provider instance is not a safe HTTP(S) base URL.
    #[error("invalid alias provider instance: {0}")]
    InvalidProviderInstance(&'static str),
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

/// Reason a cipher could not participate in reconciliation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AliasReconciliationSkipReason {
    /// The cipher has not received a stable vault identifier.
    MissingCipherId,
    /// The reserved field appeared more than once.
    DuplicateReferenceFields,
    /// The reserved field was not hidden.
    ReferenceFieldNotHidden,
    /// The reserved field had no value.
    MissingReferenceValue,
    /// The reference exceeded its strict size limit.
    ReferenceTooLarge,
    /// The reference was malformed.
    MalformedReference,
    /// The reference version is not supported.
    UnsupportedReferenceVersion,
    /// The reference belongs to another provider or provider instance.
    ForeignProvider,
    /// The reference was attached to a non-login cipher.
    NonLoginCipher,
    /// The reference contained another invalid value.
    InvalidReferenceValue,
}

/// One observed reconciliation result.
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
    /// A legacy login username matched a provider alias and can receive a stable reference.
    MatchedByAddress {
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
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "action")]
pub enum AliasReconciliationAction {
    /// Add a stable reference to an address-matched legacy login.
    Bind {
        /// Stable alias identifier.
        alias_id: AliasId,
        /// Stable vault cipher identifier.
        cipher_id: CipherId,
    },
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
            Self::Bind { alias_id, .. } | Self::Refresh { alias_id, .. } => alias_id,
        }
    }

    fn cipher_id(self) -> CipherId {
        match self {
            Self::Bind { cipher_id, .. } | Self::Refresh { cipher_id, .. } => cipher_id,
        }
    }
}

/// Counts summarizing a reconciliation dry run.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AliasReconciliationSummary {
    /// Exact stable matches.
    pub matched: usize,
    /// Legacy address matches awaiting stable binding.
    pub matched_by_address: usize,
    /// Stale bindings awaiting refresh.
    pub stale_bindings: usize,
    /// Ambiguous duplicate binding groups.
    pub duplicate_bindings: usize,
    /// References whose provider alias is missing.
    pub missing_aliases: usize,
    /// Provider aliases with no vault match.
    pub unbound_aliases: usize,
    /// Ciphers deliberately skipped for safety.
    pub skipped_ciphers: usize,
    /// Explicit safe repairs proposed.
    pub proposed_repairs: usize,
}

/// Immutable dry-run output. No cipher changes occur until [`apply_alias_reconciliation`] is called.
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
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AliasReconciliationApplyResult {
    /// Ciphers changed by this invocation.
    pub changed_cipher_ids: Vec<CipherId>,
    /// Planned actions already satisfied, including repeated idempotent application.
    pub unchanged_actions: usize,
}

/// Safe reconciliation failures. Addresses and reference payloads are never rendered.
#[derive(Debug, Error)]
pub enum AliasReconciliationError {
    /// Provider data repeated an identifier and is not safe to reconcile.
    #[error("provider inventory contains duplicate alias identifier {alias_id}")]
    DuplicateAliasId {
        /// Repeated stable alias identifier.
        alias_id: AliasId,
    },
    /// Provider data repeated an address and address matching would be ambiguous.
    #[error("provider inventory contains a duplicate alias address")]
    DuplicateAliasAddress,
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

enum ClaimSource {
    Reference(AliasReference),
    Address,
}

struct Claim {
    cipher_index: usize,
    cipher_id: CipherId,
    alias_id: AliasId,
    source: ClaimSource,
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
        let _encoded = AliasReference::new(provider, alias).encode()?;
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
                    source: ClaimSource::Reference(reference),
                });
            }
            Ok(None) => {
                let Some(username) = cipher
                    .login
                    .as_ref()
                    .and_then(|login| login.username.as_deref())
                else {
                    continue;
                };
                let Some(alias_id) = alias_index
                    .by_address
                    .get(&normalize_address(username))
                    .copied()
                else {
                    continue;
                };
                let Some(cipher_id) = cipher.id else {
                    outcomes.push(AliasReconciliationOutcome::SkippedCipher {
                        cipher_id: None,
                        reason: AliasReconciliationSkipReason::MissingCipherId,
                    });
                    continue;
                };
                claims.push(Claim {
                    cipher_index,
                    cipher_id,
                    alias_id,
                    source: ClaimSource::Address,
                });
            }
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
        match &claim.source {
            ClaimSource::Address => {
                outcomes.push(AliasReconciliationOutcome::MatchedByAddress {
                    alias_id: claim.alias_id,
                    cipher_id: claim.cipher_id,
                });
                actions.push(AliasReconciliationAction::Bind {
                    alias_id: claim.alias_id,
                    cipher_id: claim.cipher_id,
                });
            }
            ClaimSource::Reference(reference) => {
                let canonical_address = provider_alias_address(alias);
                // EXPOSE: reconciliation compares the decrypted address snapshot in memory and
                // emits only booleans; it never renders the address.
                let reference_address_stale = reference.address.expose() != canonical_address;
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

        let desired = AliasReference::new(&plan.provider, alias);
        let current_reference = AliasReference::from_cipher(cipher)?;
        let already_satisfied = current_reference.as_ref() == Some(&desired)
            && cipher
                .login
                .as_ref()
                .and_then(|login| login.username.as_deref())
                == Some(provider_alias_address(alias));

        match (action, current_reference.as_ref()) {
            (AliasReconciliationAction::Bind { .. }, None) => {
                let username = cipher
                    .login
                    .as_ref()
                    .and_then(|login| login.username.as_deref())
                    .ok_or(AliasReconciliationError::StalePlan(
                        "address-matched login lost its username",
                    ))?;
                if normalize_address(username) != normalize_address(provider_alias_address(alias)) {
                    return Err(AliasReconciliationError::StalePlan(
                        "address-matched login changed after planning",
                    ));
                }
            }
            (AliasReconciliationAction::Bind { .. }, Some(reference))
            | (AliasReconciliationAction::Refresh { .. }, Some(reference))
                if reference.provider_identity() == plan.provider
                    && reference.alias_id == alias_id => {}
            (AliasReconciliationAction::Refresh { .. }, None) => {
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

struct AliasIndex<'a> {
    by_id: HashMap<AliasId, &'a Alias>,
    by_address: HashMap<String, AliasId>,
}

fn index_aliases(aliases: &[Alias]) -> Result<AliasIndex<'_>, AliasReconciliationError> {
    let mut by_id = HashMap::with_capacity(aliases.len());
    let mut by_address = HashMap::with_capacity(aliases.len());
    for alias in aliases {
        if by_id.insert(alias.id, alias).is_some() {
            return Err(AliasReconciliationError::DuplicateAliasId { alias_id: alias.id });
        }
        if by_address
            .insert(normalize_address(provider_alias_address(alias)), alias.id)
            .is_some()
        {
            return Err(AliasReconciliationError::DuplicateAliasAddress);
        }
    }
    Ok(AliasIndex { by_id, by_address })
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

fn normalize_address(address: &str) -> String {
    address.to_lowercase()
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
        AliasReferenceError::MissingValue => AliasReconciliationSkipReason::MissingReferenceValue,
        AliasReferenceError::NotLoginCipher => AliasReconciliationSkipReason::NonLoginCipher,
        AliasReferenceError::InvalidProviderInstance(_) | AliasReferenceError::InvalidValue(_) => {
            AliasReconciliationSkipReason::InvalidReferenceValue
        }
    }
}

fn summarize(
    outcomes: &[AliasReconciliationOutcome],
    proposed_repairs: usize,
) -> AliasReconciliationSummary {
    let mut summary = AliasReconciliationSummary {
        proposed_repairs,
        ..AliasReconciliationSummary::default()
    };
    for outcome in outcomes {
        match outcome {
            AliasReconciliationOutcome::Matched { .. } => summary.matched += 1,
            AliasReconciliationOutcome::MatchedByAddress { .. } => {
                summary.matched_by_address += 1;
            }
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
        let changed = field.r#type != FieldType::Hidden
            || field.value.as_deref() != Some(encoded_reference.as_str());
        field.r#type = FieldType::Hidden;
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
    use crate::{MailboxId, MailboxRef};

    fn provider() -> AliasProviderIdentity {
        AliasProviderIdentity::simplelogin("https://aliases.example.test")
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
        let reference = AliasReference::new(&provider, &alias);
        let encoded = reference.encode().expect("reference should encode");
        let decoded = AliasReference::decode(encoded.expose()).expect("reference should decode");

        assert_eq!(decoded, reference);
        assert!(!format!("{reference:?}").contains("private-alias"));
        assert!(AliasProviderIdentity::simplelogin("https://user:password@example.test").is_err());

        let oversized = format!(
            "{{\"version\":1,\"provider\":\"simplelogin\",\"providerInstance\":\"https://aliases.example.test/\",\"aliasId\":41,\"address\":\"{}\"}}",
            "a".repeat(MAX_ALIAS_REFERENCE_BYTES)
        );
        assert!(matches!(
            AliasReference::decode(&oversized),
            Err(AliasReferenceError::TooLarge { .. })
        ));
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

        let legacy_id = CipherId::new_v4();
        let stale_id = CipherId::new_v4();
        let matched_id = CipherId::new_v4();
        let missing_id = CipherId::new_v4();
        let ordinary_id = CipherId::new_v4();
        let mut ciphers = vec![
            login_cipher(Some(legacy_id), Some("ONE@example.test".to_owned())),
            login_cipher(Some(stale_id), Some("old-two@example.test".to_owned())),
            login_cipher(Some(matched_id), None),
            login_cipher(Some(missing_id), Some("removed@example.test".to_owned())),
            login_cipher(Some(ordinary_id), Some("owner@example.test".to_owned())),
        ];

        let mut stale_reference = AliasReference::new(&provider, &aliases[1]);
        stale_reference.address = SensitiveString::from("old-two@example.test");
        stale_reference
            .bind_to_cipher(&mut ciphers[1])
            .expect("stale test reference should attach");
        AliasReference::new(&provider, &aliases[2])
            .bind_to_cipher(&mut ciphers[2])
            .expect("matching test reference should attach");
        AliasReference {
            version: ALIAS_REFERENCE_VERSION,
            provider: AliasProvider::SimpleLogin,
            provider_instance: provider.instance.clone(),
            alias_id: AliasId(999),
            address: SensitiveString::from("removed@example.test"),
        }
        .bind_to_cipher(&mut ciphers[3])
        .expect("missing test reference should attach");

        let dry_run = plan_alias_reconciliation(&provider, &aliases, &ciphers)
            .expect("planning should succeed");
        assert_eq!(dry_run.summary.matched, 1);
        assert_eq!(dry_run.summary.matched_by_address, 1);
        assert_eq!(dry_run.summary.stale_bindings, 1);
        assert_eq!(dry_run.summary.missing_aliases, 1);
        assert_eq!(dry_run.summary.unbound_aliases, 1);
        assert_eq!(dry_run.summary.proposed_repairs, 2);
        assert_eq!(
            ciphers[0].fields.as_ref().map_or(0, |fields| fields.len()),
            0,
            "dry run must not mutate the cipher"
        );

        let applied = apply_alias_reconciliation(&dry_run, &aliases, &mut ciphers)
            .expect("explicit apply should succeed");
        assert_eq!(applied.changed_cipher_ids.len(), 2);
        assert_eq!(applied.unchanged_actions, 0);
        assert_eq!(
            ciphers[1]
                .login
                .as_ref()
                .and_then(|login| login.username.as_deref()),
            Some("two@example.test")
        );

        let repeated = apply_alias_reconciliation(&dry_run, &aliases, &mut ciphers)
            .expect("repeated apply should be a safe no-op");
        assert!(repeated.changed_cipher_ids.is_empty());
        assert_eq!(repeated.unchanged_actions, 2);

        let repaired = plan_alias_reconciliation(&provider, &aliases, &ciphers)
            .expect("replanning should succeed");
        assert!(repaired.actions.is_empty());
        assert_eq!(repaired.summary.matched, 3);
        assert_eq!(repaired.summary.missing_aliases, 1);
        assert_eq!(repaired.summary.unbound_aliases, 1);
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

        let plan = plan_alias_reconciliation(&provider, &aliases, &ciphers)
            .expect("duplicate planning should succeed");
        assert_eq!(plan.summary.duplicate_bindings, 1);
        assert_eq!(plan.summary.proposed_repairs, 0);
        assert!(matches!(
            &plan.outcomes[0],
            AliasReconciliationOutcome::DuplicateBinding { alias_id, cipher_ids }
                if *alias_id == AliasId(7) && cipher_ids == &vec![first_id, second_id]
        ));

        AliasReference::new(&provider, &aliases[0])
            .bind_to_cipher(&mut ciphers[0])
            .expect("test reference should attach");
        let mixed_plan = plan_alias_reconciliation(&provider, &aliases, &ciphers)
            .expect("mixed duplicate planning should succeed");
        assert_eq!(mixed_plan.summary.duplicate_bindings, 1);
        assert!(mixed_plan.actions.is_empty());
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
            .encode()
            .expect("reference should encode")
            .expose_owned();
        attach_raw_reference(&mut visible, encoded, FieldType::Text);

        let foreign_provider =
            AliasProviderIdentity::simplelogin("https://other.example.test").expect("valid URL");
        let mut foreign = login_cipher(Some(CipherId::new_v4()), None);
        AliasReference::new(&foreign_provider, &aliases[0])
            .bind_to_cipher(&mut foreign)
            .expect("foreign reference should attach");

        let mut non_login = login_cipher(Some(CipherId::new_v4()), None);
        AliasReference::new(&provider, &aliases[0])
            .bind_to_cipher(&mut non_login)
            .expect("reference should attach before changing type");
        non_login.r#type = CipherType::SecureNote;
        non_login.login = None;

        let missing_id = login_cipher(None, Some("eight@example.test".to_owned()));
        let ciphers = vec![malformed, future, visible, foreign, non_login, missing_id];
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
        let plan = plan_alias_reconciliation(&provider, &aliases, &ciphers)
            .expect("planning should succeed");

        ciphers[1].login.as_mut().expect("login").username =
            Some("changed@example.test".to_owned());
        let error = apply_alias_reconciliation(&plan, &aliases, &mut ciphers)
            .expect_err("stale plan should fail atomically");
        assert!(matches!(error, AliasReconciliationError::StalePlan(_)));
        assert!(
            AliasReference::from_cipher(&ciphers[0])
                .expect("first cipher should remain valid")
                .is_none()
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
                .bind_to_cipher(cipher)
                .expect("scale fixture reference should attach");
        }

        let started = Instant::now();
        let plan = plan_alias_reconciliation(&provider, &aliases, &ciphers)
            .expect("scale plan should succeed");
        assert_eq!(plan.summary.matched, ITEM_COUNT / 2);
        assert_eq!(plan.actions.len(), ITEM_COUNT / 2);
        let applied = apply_alias_reconciliation(&plan, &aliases, &mut ciphers)
            .expect("scale apply should succeed");
        assert_eq!(applied.changed_cipher_ids.len(), ITEM_COUNT / 2);
        let verified = plan_alias_reconciliation(&provider, &aliases, &ciphers)
            .expect("scale verification should succeed");
        assert!(verified.actions.is_empty());
        assert_eq!(verified.summary.matched, ITEM_COUNT);
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "10k plan/apply/verify should remain comfortably linear"
        );
    }
}
