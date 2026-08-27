//! # http-security-headers
//!
//! Type-safe, framework-agnostic HTTP security headers with Tower middleware support.
//!
//! ## Features
//!
//! - **Type-safe configuration**: Compile-time guarantees for header values
//! - **Builder pattern**: Ergonomic, fluent API
//! - **Preset configurations**: Strict, Balanced and Relaxed security levels
//! - **Tower middleware**: Framework-agnostic (works with Axum, Tonic, etc.), plus
//!   first-class Actix-Web support
//! - **Per-request CSP nonces**: Drop `'unsafe-inline'` without rewriting your templates
//! - **Minimal core dependencies**: The core builds on `thiserror` alone
//!
//! ## Quick Start
//!
//! ```rust
//! use http_security_headers::{SecurityHeaders, Preset};
//! use std::time::Duration;
//!
//! // Use a preset configuration
//! let headers = Preset::Strict.build();
//!
//! // Or build a custom configuration
//! let headers = SecurityHeaders::builder()
//!     .strict_transport_security(Duration::from_secs(31536000), true, false)
//!     .x_frame_options_deny()
//!     .referrer_policy_no_referrer()
//!     .build()
//!     .unwrap();
//! ```
//!
//! Every header value is rendered and validated once, by `build()`. A policy that
//! cannot become a legal HTTP header is an error there, rather than a header that
//! silently goes missing at request time.
//!
//! ## Using with Axum
//!
//! Enable the `middleware` feature in your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! http-security-headers = { version = "0.3", features = ["middleware"] }
//! ```
//!
//! Then use the middleware layer:
//!
//! ```rust,ignore
//! use axum::{Router, routing::get};
//! use http_security_headers::{Preset, SecurityHeadersLayer};
//!
//! let app = Router::new()
//!     .route("/", get(|| async { "Hello, World!" }))
//!     .layer(SecurityHeadersLayer::new(Preset::Strict.build()));
//! ```
//!
//! ## CSP nonces
//!
//! Enable the `nonce` feature and mark the directives that should carry one. The
//! middleware mints a fresh nonce per request, hands it to your handler through the
//! request extensions, and writes the matching value into the header:
//!
//! ```rust,ignore
//! use axum::{Extension, Router, routing::get};
//! use http_security_headers::{Nonce, Preset, SecurityHeadersLayer};
//!
//! async fn index(Extension(nonce): Extension<Nonce>) -> String {
//!     format!("<script nonce=\"{}\">console.log('hi')</script>", nonce)
//! }
//!
//! let app = Router::new()
//!     .route("/", get(index))
//!     .layer(SecurityHeadersLayer::new(Preset::BalancedNonce.build()));
//! ```
//!
//! ## Security Headers Supported
//!
//! - **Content-Security-Policy (CSP)**: Prevents XSS and code injection attacks
//! - **Strict-Transport-Security (HSTS)**: Forces HTTPS connections
//! - **X-Frame-Options**: Prevents clickjacking attacks
//! - **X-Content-Type-Options**: Prevents MIME type sniffing
//! - **Referrer-Policy**: Controls referrer information
//! - **Permissions-Policy**: Controls access to browser features and APIs
//! - **Cross-Origin-Opener-Policy (COOP)**: Isolates browsing contexts
//! - **Cross-Origin-Embedder-Policy (COEP)**: Controls cross-origin resource loading
//! - **Cross-Origin-Resource-Policy (CORP)**: Controls resource sharing
//!
//! ## Feature flags
//!
//! | Feature | Description |
//! |---------|-------------|
//! | `middleware` | Tower `Layer`/`Service` for any Tower-based framework |
//! | `actix` | Actix-Web middleware (implies `middleware`) |
//! | `nonce` | Per-request CSP nonce generation |
//! | `observability` | `tracing` spans and events in the middleware |

#![warn(missing_docs, missing_debug_implementations)]
#![deny(unsafe_code)]

mod config;
mod error;
pub mod policy;
pub mod preset;

#[cfg(feature = "middleware")]
pub mod middleware;

#[cfg(feature = "actix")]
pub mod actix;

pub use config::{SecurityHeaders, SecurityHeadersBuilder};
pub use error::{Error, Result};
pub use policy::{
    ContentSecurityPolicy, CrossOriginEmbedderPolicy, CrossOriginOpenerPolicy,
    CrossOriginResourcePolicy, Nonce, PermissionsPolicy, ReferrerPolicy, StrictTransportSecurity,
    XFrameOptions,
};
pub use preset::Preset;

#[cfg(feature = "middleware")]
pub use middleware::{add_security_headers, SecurityHeadersLayer};

#[cfg(feature = "actix")]
pub use actix::SecurityHeadersMiddleware;
