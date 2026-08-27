//! Error types for the security headers library.

/// Result type alias for operations that may fail with an Error.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur when working with security headers.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Invalid Content-Security-Policy directive.
    #[error("Invalid Content-Security-Policy: {0}")]
    InvalidCsp(String),

    /// Invalid Strict-Transport-Security configuration.
    #[error("Invalid Strict-Transport-Security: {0}")]
    InvalidHsts(String),

    /// Invalid X-Frame-Options value.
    #[error("Invalid X-Frame-Options: {0}")]
    InvalidFrameOptions(String),

    /// Invalid Referrer-Policy value.
    #[error("Invalid Referrer-Policy: {0}")]
    InvalidReferrerPolicy(String),

    /// Invalid Permissions-Policy directive.
    #[error("Invalid Permissions-Policy: {0}")]
    InvalidPermissionsPolicy(String),

    /// Invalid Cross-Origin-Opener-Policy value.
    #[error("Invalid Cross-Origin-Opener-Policy: {0}")]
    InvalidCoop(String),

    /// Invalid Cross-Origin-Embedder-Policy value.
    #[error("Invalid Cross-Origin-Embedder-Policy: {0}")]
    InvalidCoep(String),

    /// Invalid Cross-Origin-Resource-Policy value.
    #[error("Invalid Cross-Origin-Resource-Policy: {0}")]
    InvalidCorp(String),

    /// Invalid header value when converting to HTTP header.
    #[cfg(feature = "middleware")]
    #[error("Invalid header value: {0}")]
    InvalidHeaderValue(#[from] http::header::InvalidHeaderValue),

    /// Configuration validation failed.
    #[error("Configuration validation failed: {0}")]
    ValidationFailed(String),
}
