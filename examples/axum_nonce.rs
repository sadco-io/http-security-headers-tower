//! Axum example using a per-request CSP nonce instead of `'unsafe-inline'`.
//!
//! Run with:
//!
//! ```text
//! cargo run --example axum_nonce --features middleware,nonce
//! ```
//!
//! Then load <http://127.0.0.1:3000> in a browser. The inline script carries the
//! same nonce the CSP header names, so it runs; the second one does not carry it,
//! so the browser refuses it and logs a CSP violation to the console. That is the
//! whole point -- an injected `<script>` cannot guess the nonce.

use axum::response::Html;
use axum::{routing::get, Extension, Router};
use http_security_headers::{Nonce, Preset, SecurityHeadersLayer};
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(index))
        .layer(SecurityHeadersLayer::new(Preset::BalancedNonce.build()));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("Server running on http://{addr}");
    println!("The page runs the nonced script and blocks the un-nonced one.");
    println!("\nTry:");
    println!("  curl -sI http://{addr}/ | grep -i content-security-policy");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

/// The nonce arrives as a request extension, put there by the middleware before
/// this handler ran.
async fn index(Extension(nonce): Extension<Nonce>) -> Html<String> {
    Html(format!(
        r#"<!doctype html>
<html>
  <head><title>CSP nonce demo</title></head>
  <body>
    <h1>CSP nonce demo</h1>
    <p id="status">The nonced script did not run.</p>

    <!-- Carries the nonce, so it runs. -->
    <script nonce="{nonce}">
      document.getElementById('status').textContent = 'The nonced script ran.';
    </script>

    <!-- No nonce: this is what an injected script looks like to the browser. -->
    <script>
      document.getElementById('status').textContent = 'This should never appear.';
    </script>
  </body>
</html>"#
    ))
}
