use bitwarden_sensitive_value::SensitiveString;
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;

pub(crate) const MAX_EMAIL_ADDRESS_BYTES: usize = 320;

pub(crate) fn is_safe_email_address(value: &str) -> bool {
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.is_empty()
        && !domain.contains('@')
        && value.len() <= MAX_EMAIL_ADDRESS_BYTES
        && !value.chars().any(|character| {
            character.is_control() || character.is_whitespace() || matches!(character, '<' | '>')
        })
}

macro_rules! numeric_id {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi, large_number_types_as_bigints))]
        #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
        #[serde(transparent)]
        pub struct $name(pub u64);

        #[cfg(feature = "uniffi")]
        uniffi::custom_type!($name, u64, {
            try_lift: |value| Ok(Self(value)),
            lower: |value| value.0,
        });

        impl From<u64> for $name {
            fn from(value: u64) -> Self {
                Self(value)
            }
        }

        impl From<$name> for u64 {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

numeric_id!(AliasId, "A stable provider-assigned alias identifier.");
numeric_id!(ContactId, "A stable provider-assigned contact identifier.");
numeric_id!(MailboxId, "A stable provider-assigned mailbox identifier.");
numeric_id!(
    CustomDomainId,
    "A stable provider-assigned custom-domain identifier."
);

/// A mailbox to which an alias forwards messages.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(Tsify),
    tsify(into_wasm_abi, from_wasm_abi, large_number_types_as_bigints)
)]
#[derive(Debug, Deserialize, Serialize)]
pub struct MailboxRef {
    /// Stable mailbox identifier.
    pub id: MailboxId,
    /// Mailbox email address.
    pub email: SensitiveString,
}

/// A mailbox available to the authenticated SimpleLogin account.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(Tsify),
    tsify(into_wasm_abi, from_wasm_abi, large_number_types_as_bigints)
)]
#[derive(Debug, Deserialize, Serialize)]
pub struct Mailbox {
    /// Stable mailbox identifier.
    pub id: MailboxId,
    /// Mailbox email address.
    pub email: SensitiveString,
    /// Whether the mailbox has been verified.
    pub verified: bool,
    /// Whether this is the account's default mailbox.
    #[serde(rename = "default")]
    pub is_default: bool,
    /// Provider-formatted creation date, when supplied by the server version.
    #[serde(default)]
    pub creation_date: Option<String>,
    /// Creation time as Unix seconds.
    pub creation_timestamp: i64,
    /// Number of aliases forwarding to this mailbox.
    pub nb_alias: u64,
}

/// The contact attached to an alias's latest activity.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(Tsify),
    tsify(into_wasm_abi, from_wasm_abi, large_number_types_as_bigints)
)]
#[derive(Debug, Deserialize, Serialize)]
pub struct LatestActivityContact {
    /// Contact email address.
    pub email: SensitiveString,
    /// Optional contact display name.
    pub name: Option<SensitiveString>,
    /// Provider-rendered reverse alias.
    pub reverse_alias: SensitiveString,
}

/// Most recent activity recorded for an alias.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(Tsify),
    tsify(into_wasm_abi, from_wasm_abi, large_number_types_as_bigints)
)]
#[derive(Debug, Deserialize, Serialize)]
pub struct LatestAliasActivity {
    /// Activity time as Unix seconds.
    pub timestamp: i64,
    /// Provider activity value, such as `forward`, `reply`, `block`, or `bounced`.
    pub action: String,
    /// Contact involved in the activity.
    pub contact: LatestActivityContact,
}

/// Complete SimpleLogin alias lifecycle data.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(Tsify),
    tsify(into_wasm_abi, from_wasm_abi, large_number_types_as_bigints)
)]
#[derive(Debug, Deserialize, Serialize)]
pub struct Alias {
    /// Stable alias identifier. Use this for every mutation rather than the mutable address data.
    pub id: AliasId,
    /// Alias email address.
    pub email: SensitiveString,
    /// Provider-formatted creation date.
    pub creation_date: String,
    /// Creation time as Unix seconds.
    pub creation_timestamp: i64,
    /// Whether forwarding is enabled.
    pub enabled: bool,
    /// Optional private note.
    pub note: Option<SensitiveString>,
    /// Optional display name.
    #[serde(default)]
    pub name: Option<SensitiveString>,
    /// Number of forwarded messages.
    pub nb_forward: u64,
    /// Number of blocked messages.
    pub nb_block: u64,
    /// Number of replies.
    pub nb_reply: u64,
    /// Primary forwarding mailbox.
    pub mailbox: MailboxRef,
    /// All forwarding mailboxes.
    pub mailboxes: Vec<MailboxRef>,
    /// Whether at least one forwarding mailbox supports PGP.
    pub support_pgp: bool,
    /// Whether PGP is disabled for this alias.
    pub disable_pgp: bool,
    /// Most recent alias activity, when present.
    pub latest_activity: Option<LatestAliasActivity>,
    /// Whether the alias is pinned.
    #[serde(default)]
    pub pinned: bool,
}

/// Random alias generation scheme.
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(
    feature = "wasm",
    derive(Tsify),
    tsify(into_wasm_abi, from_wasm_abi, large_number_types_as_bigints)
)]
#[derive(Deserialize, Serialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum RandomAliasMode {
    /// Generate a word-based alias.
    Word,
    /// Generate a UUID-based alias.
    Uuid,
}

impl RandomAliasMode {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Word => "word",
            Self::Uuid => "uuid",
        }
    }
}

/// Input for random alias creation.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(Tsify),
    tsify(into_wasm_abi, from_wasm_abi, large_number_types_as_bigints)
)]
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct CreateRandomAliasRequest {
    /// Optional site hostname associated with the alias.
    pub hostname: Option<SensitiveString>,
    /// Optional generation mode; the account default is used when absent.
    pub mode: Option<RandomAliasMode>,
    /// Optional private alias note.
    pub note: Option<SensitiveString>,
}

/// Input for custom alias creation using a signed suffix returned by [`AliasCreationOptions`].
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(Tsify),
    tsify(into_wasm_abi, from_wasm_abi, large_number_types_as_bigints)
)]
#[derive(Debug, Deserialize, Serialize)]
pub struct CreateCustomAliasRequest {
    /// Alias prefix, without the suffix.
    pub alias_prefix: String,
    /// Short-lived signed suffix returned by SimpleLogin.
    pub signed_suffix: SensitiveString,
    /// Verified mailbox identifiers. At least one is required by SimpleLogin's v3 endpoint.
    pub mailbox_ids: Vec<MailboxId>,
    /// Optional site hostname associated with the alias.
    pub hostname: Option<SensitiveString>,
    /// Optional private alias note.
    pub note: Option<SensitiveString>,
    /// Optional alias display name.
    pub name: Option<SensitiveString>,
}

/// Filter applied by the SimpleLogin alias list endpoint.
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(
    feature = "wasm",
    derive(Tsify),
    tsify(into_wasm_abi, from_wasm_abi, large_number_types_as_bigints)
)]
#[derive(Deserialize, Serialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum AliasFilter {
    /// Return enabled aliases.
    Enabled,
    /// Return disabled aliases.
    Disabled,
    /// Return pinned aliases.
    Pinned,
}

impl AliasFilter {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Disabled => "disabled",
            Self::Pinned => "pinned",
        }
    }
}

/// Input for one page of aliases.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(Tsify),
    tsify(into_wasm_abi, from_wasm_abi, large_number_types_as_bigints)
)]
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
pub struct ListAliasesRequest {
    /// Zero-based SimpleLogin page number.
    pub page: u32,
    /// Optional lifecycle-state filter.
    pub filter: Option<AliasFilter>,
}

/// Input for one page of alias search results.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(Tsify),
    tsify(into_wasm_abi, from_wasm_abi, large_number_types_as_bigints)
)]
#[derive(Debug, Deserialize, Serialize)]
pub struct SearchAliasesRequest {
    /// Search text matched by SimpleLogin against address, note, and name.
    pub query: SensitiveString,
    /// Zero-based SimpleLogin page number.
    pub page: u32,
    /// Optional lifecycle-state filter.
    pub filter: Option<AliasFilter>,
}

/// A page of aliases.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(Tsify),
    tsify(into_wasm_abi, from_wasm_abi, large_number_types_as_bigints)
)]
#[derive(Debug, Deserialize, Serialize)]
pub struct AliasPage {
    /// Zero-based provider page number.
    pub page: u32,
    /// Aliases returned for the page.
    pub aliases: Vec<Alias>,
}

/// An alias recommended for a previously associated hostname.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(Tsify),
    tsify(into_wasm_abi, from_wasm_abi, large_number_types_as_bigints)
)]
#[derive(Debug, Deserialize, Serialize)]
pub struct AliasRecommendation {
    /// Recommended alias address.
    pub alias: SensitiveString,
    /// Associated hostname.
    pub hostname: SensitiveString,
}

/// One custom-alias suffix and the short-lived value that authorizes its use.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(Tsify),
    tsify(into_wasm_abi, from_wasm_abi, large_number_types_as_bigints)
)]
#[derive(Debug, Deserialize, Serialize)]
pub struct AliasSuffix {
    /// Human-readable suffix.
    pub suffix: SensitiveString,
    /// Signed suffix accepted by custom alias creation.
    pub signed_suffix: SensitiveString,
    /// Whether the suffix belongs to the user's custom domain.
    pub is_custom: bool,
    /// Whether the suffix requires a premium account.
    pub is_premium: bool,
}

/// Alias creation options and any recommendation for a hostname.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(Tsify),
    tsify(into_wasm_abi, from_wasm_abi, large_number_types_as_bigints)
)]
#[derive(Debug, Deserialize, Serialize)]
pub struct AliasCreationOptions {
    /// Whether the account may create another alias.
    pub can_create: bool,
    /// Available custom-alias suffixes.
    pub suffixes: Vec<AliasSuffix>,
    /// Provider-suggested prefix.
    pub prefix_suggestion: String,
    /// Previously associated alias for the requested hostname.
    pub recommendation: Option<AliasRecommendation>,
}

/// Alias fields that can be updated.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(Tsify),
    tsify(into_wasm_abi, from_wasm_abi, large_number_types_as_bigints)
)]
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct UpdateAliasRequest {
    /// Set or clear the private note. `None` leaves it unchanged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<Option<SensitiveString>>,
    /// Set or clear the display name. `None` leaves it unchanged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<Option<SensitiveString>>,
    /// Replace all forwarding mailboxes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mailbox_ids: Option<Vec<MailboxId>>,
    /// Enable or disable PGP for this alias.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_pgp: Option<bool>,
    /// Pin or unpin this alias.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pinned: Option<bool>,
}

impl UpdateAliasRequest {
    pub(crate) fn is_empty(&self) -> bool {
        self.note.is_none()
            && self.name.is_none()
            && self.mailbox_ids.is_none()
            && self.disable_pgp.is_none()
            && self.pinned.is_none()
    }
}

/// Result of explicitly enabling or disabling an alias.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(Tsify),
    tsify(into_wasm_abi, from_wasm_abi, large_number_types_as_bigints)
)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AliasState {
    /// Stable alias identifier.
    pub id: AliasId,
    /// Current enabled state.
    pub enabled: bool,
}

/// Result of deleting an alias.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(Tsify),
    tsify(into_wasm_abi, from_wasm_abi, large_number_types_as_bigints)
)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeleteAliasResult {
    /// Stable identifier of the deleted alias.
    pub id: AliasId,
    /// Whether SimpleLogin reported deletion.
    pub deleted: bool,
}

/// A domain available for random alias generation.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(Tsify),
    tsify(into_wasm_abi, from_wasm_abi, large_number_types_as_bigints)
)]
#[derive(Debug, Deserialize, Serialize)]
pub struct AliasDomain {
    /// Domain name.
    pub domain: SensitiveString,
    /// Whether the domain belongs to the authenticated account.
    pub is_custom: bool,
}

/// A SimpleLogin custom domain.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(Tsify),
    tsify(into_wasm_abi, from_wasm_abi, large_number_types_as_bigints)
)]
#[derive(Debug, Deserialize, Serialize)]
pub struct CustomDomain {
    /// Stable custom-domain identifier.
    pub id: CustomDomainId,
    /// Domain name.
    pub domain_name: SensitiveString,
    /// Whether DNS verification is complete.
    pub is_verified: bool,
    /// Number of active aliases on the domain.
    pub nb_alias: u64,
    /// Provider-formatted creation date.
    pub creation_date: String,
    /// Creation time as Unix seconds.
    pub creation_timestamp: i64,
    /// Whether catch-all alias creation is enabled.
    pub catch_all: bool,
    /// Optional display name.
    pub name: Option<SensitiveString>,
    /// Whether random-prefix generation is enabled.
    pub random_prefix_generation: bool,
    /// Mailboxes used by the domain.
    pub mailboxes: Vec<MailboxRef>,
}

/// Mutable custom-domain settings.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(Tsify),
    tsify(into_wasm_abi, from_wasm_abi, large_number_types_as_bigints)
)]
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct UpdateCustomDomainRequest {
    /// Enable or disable catch-all alias creation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub catch_all: Option<bool>,
    /// Enable or disable random-prefix generation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub random_prefix_generation: Option<bool>,
    /// Set or clear the domain display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<Option<SensitiveString>>,
    /// Replace the domain's forwarding mailboxes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mailbox_ids: Option<Vec<MailboxId>>,
}

impl UpdateCustomDomainRequest {
    pub(crate) fn is_empty(&self) -> bool {
        self.catch_all.is_none()
            && self.random_prefix_generation.is_none()
            && self.name.is_none()
            && self.mailbox_ids.is_none()
    }
}

/// A contact and the reverse alias SimpleLogin assigned to it.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(Tsify),
    tsify(into_wasm_abi, from_wasm_abi, large_number_types_as_bigints)
)]
#[derive(Debug, Deserialize, Serialize)]
pub struct ReverseAlias {
    /// Stable contact identifier.
    pub id: ContactId,
    /// Provider-formatted creation date.
    pub creation_date: String,
    /// Creation time as Unix seconds.
    pub creation_timestamp: i64,
    /// Provider-formatted time of the last reply, when present.
    pub last_email_sent_date: Option<String>,
    /// Unix time of the last reply, when present.
    pub last_email_sent_timestamp: Option<i64>,
    /// Contact email address.
    pub contact: SensitiveString,
    /// Provider-rendered reverse alias.
    pub reverse_alias: SensitiveString,
    /// Address-only form of the reverse alias.
    pub reverse_alias_address: SensitiveString,
    /// Whether this contact already existed when it was requested.
    #[serde(default)]
    pub existed: bool,
    /// Whether messages from this contact are blocked.
    pub block_forward: bool,
}

/// A page of contacts and reverse aliases.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(Tsify),
    tsify(into_wasm_abi, from_wasm_abi, large_number_types_as_bigints)
)]
#[derive(Debug, Deserialize, Serialize)]
pub struct ReverseAliasPage {
    /// Stable alias owning the contacts.
    pub alias_id: AliasId,
    /// Zero-based provider page number.
    pub page: u32,
    /// Contacts returned for the page.
    pub contacts: Vec<ReverseAlias>,
}

/// Result of toggling contact blocking.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(Tsify),
    tsify(into_wasm_abi, from_wasm_abi, large_number_types_as_bigints)
)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContactState {
    /// Stable contact identifier.
    pub id: ContactId,
    /// Current block state.
    pub block_forward: bool,
}

/// Result of deleting a contact.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(Tsify),
    tsify(into_wasm_abi, from_wasm_abi, large_number_types_as_bigints)
)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeleteContactResult {
    /// Stable identifier of the deleted contact.
    pub id: ContactId,
    /// Whether SimpleLogin reported deletion.
    pub deleted: bool,
}
