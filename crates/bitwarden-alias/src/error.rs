use thiserror::Error;

/// Errors returned by alias lifecycle operations.
#[cfg_attr(feature = "uniffi", derive(uniffi::Error), uniffi(flat_error))]
#[derive(Debug, Error)]
pub enum AliasError {
    /// Client settings or an operation request is invalid.
    #[error("invalid alias client request: {0}")]
    InvalidRequest(&'static str),
    /// The provider API base URL is invalid.
    #[error("invalid alias provider URL: {0}")]
    InvalidBaseUrl(&'static str),
    /// The authentication token cannot be represented as an HTTP header.
    #[error("invalid alias provider authentication token")]
    InvalidAuthenticationToken,
    /// The supplied connection identity is not a canonical UUID v4.
    #[error("invalid alias provider connection identity")]
    InvalidConnectionIdentity,
    /// The provider attempted an authenticated redirect. Redirect locations are deliberately not
    /// rendered because they can contain sensitive data.
    #[error("alias provider redirect rejected (HTTP {status})")]
    RedirectRejected {
        /// Redirect status code.
        status: u16,
    },
    /// The provider rejected authentication.
    #[error("alias provider authentication failed")]
    AuthenticationFailed,
    /// The provider rate limit was reached.
    #[error("alias provider rate limit reached")]
    RateLimited {
        /// Provider retry hint, when it is a valid number of seconds.
        retry_after_seconds: Option<u64>,
    },
    /// The provider returned an unsuccessful response.
    #[error("alias provider request failed (HTTP {status}): {message}")]
    Provider {
        /// HTTP response status.
        status: u16,
        /// Bounded, sanitized provider error message.
        message: String,
    },
    /// A provider response exceeded the SDK limit.
    #[error("alias provider response exceeded the {limit_bytes}-byte limit")]
    ResponseTooLarge {
        /// Maximum accepted response size.
        limit_bytes: usize,
    },
    /// A successful provider response was not JSON.
    #[error("alias provider returned a non-JSON response")]
    UnexpectedContentType,
    /// A successful provider response did not match the SimpleLogin API contract.
    #[error("invalid alias provider response")]
    InvalidResponse(#[source] serde_json::Error),
    /// A provider response was valid JSON but reported an impossible lifecycle result.
    #[error("invalid alias provider response: {0}")]
    InvalidResponseValue(&'static str),
    /// The HTTP request failed. URLs are removed before this error is retained or rendered.
    #[error("alias provider transport failed: {0}")]
    Transport(#[source] reqwest::Error),
}

#[cfg(feature = "wasm")]
impl From<AliasError> for wasm_bindgen::JsValue {
    fn from(error: AliasError) -> Self {
        let js_error = js_sys::Error::new(&error.to_string());
        js_error.set_name("AliasError");
        js_error.into()
    }
}
