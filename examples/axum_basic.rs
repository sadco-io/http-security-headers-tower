//! Basic Axum integration using a preset.
//!
//! Run with:
//!
//! ```text
//! cargo run --example axum_basic --features middleware
//! ```

use axum::{routing::get, Router};
use http_security_headers::{Preset, SecurityHeadersLayer};
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(handler))
        .route("/health", get(health_check))
        .layer(SecurityHeadersLayer::new(Preset::Strict.build()));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("Server running on http://{addr}");
    println!("Security headers applied: Preset::Strict");
    println!("\nTry:");
    println!("  curl -I http://{addr}/");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn handler() -> &'static str {
    "Hello! This response has strict security headers."
}

async fn health_check() -> &'static str {
    "OK"
}
