use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "wasm")]
use tsify::Tsify;

/// Maximum accepted provider retry hint in seconds.
pub const MAX_RETRY_AFTER_SECONDS: u64 = 86_400;

/// Stable provider-neutral error category shared by every alias adapter and platform binding.
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AliasErrorCode {
    /// Encrypted vault state is unavailable.
    VaultLocked,
    /// The requested encrypted connection metadata is unavailable.
    ConnectionMissing,
    /// The provider rejected the injected credential.
    AuthenticationRejected,
    /// The connection is not authorized for the requested resource or operation.
    PermissionDenied,
    /// The injected adapter does not expose a required capability.
    CapabilityUnsupported,
    /// Caller input is invalid.
    InvalidInput,
    /// The requested provider resource does not exist.
    NotFound,
    /// The provider account cannot create another resource.
    QuotaExhausted,
    /// The provider requested backoff.
    RateLimited,
    /// No provider connection is currently available.
    Offline,
    /// The provider operation timed out.
    Timeout,
    /// The provider service is temporarily unavailable.
    ServiceUnavailable,
    /// Adapter output violated the provider-neutral contract.
    InvalidResponse,
    /// A mutation may have committed and must be reconciled before replay.
    OutcomeUnknown,
    /// Concurrent facts require explicit resolution.
    SyncConflict,
    /// A local adapter, callback, or serialization security check failed.
    LocalSecurityFailure,
}

impl AliasErrorCode {
    /// Canonical wire spelling used by journals, telemetry allowlists, and clients.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::VaultLocked => "vault-locked",
            Self::ConnectionMissing => "connection-missing",
            Self::AuthenticationRejected => "authentication-rejected",
            Self::PermissionDenied => "permission-denied",
            Self::CapabilityUnsupported => "capability-unsupported",
            Self::InvalidInput => "invalid-input",
            Self::NotFound => "not-found",
            Self::QuotaExhausted => "quota-exhausted",
            Self::RateLimited => "rate-limited",
            Self::Offline => "offline",
            Self::Timeout => "timeout",
            Self::ServiceUnavailable => "service-unavailable",
            Self::InvalidResponse => "invalid-response",
            Self::OutcomeUnknown => "outcome-unknown",
            Self::SyncConflict => "sync-conflict",
            Self::LocalSecurityFailure => "local-security-failure",
        }
    }
}

/// Safe alias failure. It contains no provider body, URL, credential, address, recipient, label,
/// adapter identifier, or stable resource identifier.
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
#[derive(Debug, Error)]
pub enum AliasError {
    /// Encrypted vault state is unavailable.
    #[error("alias operation failed: vault-locked")]
    VaultLocked,
    /// The requested encrypted connection metadata is unavailable.
    #[error("alias operation failed: connection-missing")]
    ConnectionMissing,
    /// The provider rejected the injected credential.
    #[error("alias operation failed: authentication-rejected")]
    AuthenticationRejected,
    /// The connection is not authorized for the requested resource or operation.
    #[error("alias operation failed: permission-denied")]
    PermissionDenied,
    /// The injected adapter does not expose a required capability.
    #[error("alias operation failed: capability-unsupported")]
    CapabilityUnsupported,
    /// Caller input is invalid.
    #[error("alias operation failed: invalid-input")]
    InvalidInput,
    /// The requested provider resource does not exist.
    #[error("alias operation failed: not-found")]
    NotFound,
    /// The provider account cannot create another resource.
    #[error("alias operation failed: quota-exhausted")]
    QuotaExhausted,
    /// The provider requested backoff.
    #[error("alias operation failed: rate-limited")]
    RateLimited {
        /// Validated provider retry hint in seconds, when supplied.
        retry_after_seconds: Option<u64>,
    },
    /// No provider connection is currently available.
    #[error("alias operation failed: offline")]
    Offline,
    /// The provider operation timed out.
    #[error("alias operation failed: timeout")]
    Timeout,
    /// The provider service is temporarily unavailable.
    #[error("alias operation failed: service-unavailable")]
    ServiceUnavailable,
    /// Adapter output violated the provider-neutral contract.
    #[error("alias operation failed: invalid-response")]
    InvalidResponse,
    /// A mutation may have committed and must be reconciled before replay.
    #[error("alias operation failed: outcome-unknown")]
    OutcomeUnknown,
    /// Concurrent facts require explicit resolution.
    #[error("alias operation failed: sync-conflict")]
    SyncConflict,
    /// A local adapter, callback, or serialization security check failed.
    #[error("alias operation failed: local-security-failure")]
    LocalSecurityFailure,
}

impl AliasError {
    /// Returns the stable category without exposing adapter details.
    pub const fn code(&self) -> AliasErrorCode {
        match self {
            Self::VaultLocked => AliasErrorCode::VaultLocked,
            Self::ConnectionMissing => AliasErrorCode::ConnectionMissing,
            Self::AuthenticationRejected => AliasErrorCode::AuthenticationRejected,
            Self::PermissionDenied => AliasErrorCode::PermissionDenied,
            Self::CapabilityUnsupported => AliasErrorCode::CapabilityUnsupported,
            Self::InvalidInput => AliasErrorCode::InvalidInput,
            Self::NotFound => AliasErrorCode::NotFound,
            Self::QuotaExhausted => AliasErrorCode::QuotaExhausted,
            Self::RateLimited { .. } => AliasErrorCode::RateLimited,
            Self::Offline => AliasErrorCode::Offline,
            Self::Timeout => AliasErrorCode::Timeout,
            Self::ServiceUnavailable => AliasErrorCode::ServiceUnavailable,
            Self::InvalidResponse => AliasErrorCode::InvalidResponse,
            Self::OutcomeUnknown => AliasErrorCode::OutcomeUnknown,
            Self::SyncConflict => AliasErrorCode::SyncConflict,
            Self::LocalSecurityFailure => AliasErrorCode::LocalSecurityFailure,
        }
    }

    pub(crate) fn sanitized(self) -> Self {
        match self {
            Self::RateLimited {
                retry_after_seconds: Some(value),
            } if value > MAX_RETRY_AFTER_SECONDS => Self::InvalidResponse,
            value => value,
        }
    }
}

impl core::fmt::Display for AliasErrorCode {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(feature = "wasm")]
impl From<AliasError> for wasm_bindgen::JsValue {
    fn from(error: AliasError) -> Self {
        let js_error = js_sys::Error::new(&error.to_string());
        js_error.set_name(error.code().as_str());
        js_error.into()
    }
}
