use bitwarden_sensitive_value::SensitiveString;
use serde::{Deserialize, Serialize};

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
        #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
        #[serde(transparent)]
        pub struct $name(pub u64);

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

/// A mailbox to which an alias forwards messages.
#[derive(Debug, Deserialize, Serialize)]
pub struct MailboxRef {
    /// Stable mailbox identifier.
    pub id: MailboxId,
    /// Mailbox email address.
    pub email: SensitiveString,
}

/// The contact attached to an alias's latest activity.
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
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct CreateRandomAliasRequest {
    /// Optional site hostname associated with the alias.
    pub hostname: Option<SensitiveString>,
    /// Optional generation mode; the account default is used when absent.
    pub mode: Option<RandomAliasMode>,
    /// Optional private alias note.
    pub note: Option<SensitiveString>,
}

/// Filter applied by the SimpleLogin alias list endpoint.
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
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
pub struct ListAliasesRequest {
    /// Zero-based SimpleLogin page number.
    pub page: u32,
    /// Optional lifecycle-state filter.
    pub filter: Option<AliasFilter>,
}

/// A page of aliases.
#[derive(Debug, Deserialize, Serialize)]
pub struct AliasPage {
    /// Zero-based provider page number.
    pub page: u32,
    /// Aliases returned for the page.
    pub aliases: Vec<Alias>,
}

/// Result of deleting an alias.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeleteAliasResult {
    /// Stable identifier of the deleted alias.
    pub id: AliasId,
    /// Whether SimpleLogin reported deletion.
    pub deleted: bool,
}

/// A contact and the reverse alias SimpleLogin assigned to it.
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
#[derive(Debug, Deserialize, Serialize)]
pub struct ReverseAliasPage {
    /// Stable alias owning the contacts.
    pub alias_id: AliasId,
    /// Zero-based provider page number.
    pub page: u32,
    /// Contacts returned for the page.
    pub contacts: Vec<ReverseAlias>,
}

/// Result of deleting a contact.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeleteContactResult {
    /// Stable identifier of the deleted contact.
    pub id: ContactId,
    /// Whether SimpleLogin reported deletion.
    pub deleted: bool,
}
