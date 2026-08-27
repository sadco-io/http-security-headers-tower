//! Axum example with a hand-built security headers configuration.
//!
//! Run with:
//!
//! ```text
//! cargo run --example axum_custom --features middleware
//! ```

use axum::{routing::get, Router};
use http_security_headers::{
    ContentSecurityPolicy, PermissionsPolicy, SecurityHeaders, SecurityHeadersLayer,
};
use std::net::SocketAddr;
use std::time::Duration;

#[tokio::main]
async fn main() {
    let csp = ContentSecurityPolicy::new()
        .default_src(vec!["'self'"])
        .script_src(vec!["'self'", "https://cdn.jsdelivr.net"])
        .style_src(vec![
            "'self'",
            "https://fonts.googleapis.com",
            "'unsafe-inline'",
        ])
        .font_src(vec!["'self'", "https://fonts.gstatic.com"])
        .img_src(vec!["'self'", "data:", "https:"])
        .connect_src(vec!["'self'", "https://api.example.com"])
        .frame_ancestors(vec!["'none'"])
        .base_uri(vec!["'self'"])
        .form_action(vec!["'self'"]);

    let permissions = PermissionsPolicy::new()
        .deny("camera")
        .deny("microphone")
        .deny("usb")
        .self_only("geolocation")
        .allow("payment", vec!["self", "https://checkout.example.com"]);

    let headers = SecurityHeaders::builder()
        .content_security_policy(csp)
        .strict_transport_security(Duration::from_secs(63_072_000), true, true) // 2 years with preload
        .x_frame_options_deny()
        .x_content_type_options_nosniff()
        .referrer_policy_strict_origin_when_cross_origin()
        .permissions_policy(permissions)
        .build()
        .expect("Failed to build security headers");

    let app = Router::new()
        .route("/", get(handler))
        .route("/api/data", get(api_handler))
        .layer(SecurityHeadersLayer::new(headers));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("Server running on http://{addr}");
    println!("Custom security configuration:");
    println!("  - Custom CSP with multiple trusted sources");
    println!("  - HSTS with 2-year max-age and preload");
    println!("  - X-Frame-Options: DENY");
    println!("  - Referrer-Policy: strict-origin-when-cross-origin");
    println!("  - Permissions-Policy: camera/microphone/usb denied, payment allowlisted");
    println!("\nTry:");
    println!("  curl -I http://{addr}/");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn handler() -> &'static str {
    "Hello! This response has custom security headers configured."
}

async fn api_handler() -> &'static str {
    r#"{"message": "API response with security headers"}"#
}
