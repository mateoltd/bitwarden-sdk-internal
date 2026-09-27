use thiserror::Error;

/// Internal failures returned by the concrete SimpleLogin adapter.
#[derive(Debug, Error)]
pub(crate) enum SimpleLoginError {
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
    ///
    /// Provider-controlled response text is deliberately omitted because it can reflect API keys,
    /// alias inputs, or terminal control sequences into application logs.
    #[error("alias provider request failed (HTTP {status})")]
    Provider {
        /// HTTP response status.
        status: u16,
    },
    /// A lifecycle mutation was dispatched, but a transport failure made its final state unknown.
    /// Callers must reconcile state instead of blindly replaying the operation.
    #[error("alias provider {operation} outcome is unknown after a transport failure")]
    MutationOutcomeUnknown {
        /// Safe operation label containing no provider or user data.
        operation: &'static str,
    },
    /// The provider confirmed a mutation, but the SDK could not refresh the resulting resource.
    /// Replaying the mutation is unsafe; callers should retry only the corresponding read.
    #[error("alias provider {operation} succeeded, but its result could not be refreshed")]
    MutationCommittedButRefreshFailed {
        /// Safe operation label containing no provider or user data.
        operation: &'static str,
    },
    /// The provider returned success for a mutation, but its response could not be validated.
    /// The operation may have committed and must be reconciled instead of replayed.
    #[error("alias provider {operation} returned an invalid response after reporting success")]
    MutationResponseInvalid {
        /// Safe operation label containing no provider or user data.
        operation: &'static str,
    },
    /// Concurrent actors prevented a toggle-only API from converging on the requested state.
    #[error(
        "alias provider {operation} did not converge because the resource changed concurrently"
    )]
    ConcurrentMutation {
        /// Safe operation label containing no provider or user data.
        operation: &'static str,
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
