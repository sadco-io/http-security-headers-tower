#![cfg(feature = "middleware")]

use std::convert::Infallible;
use std::sync::Arc;

use axum::{routing::get, Router};
use http::Request;
use http_security_headers::{Preset, SecurityHeadersLayer};
use tower::ServiceExt;

#[tokio::test]
async fn security_headers_layer_applies_headers_in_axum() {
    let config = Arc::new(Preset::Balanced.build());
    let app = Router::new()
        .route("/", get(|| async { Ok::<_, Infallible>("ok") }))
        .layer(SecurityHeadersLayer::new(config));

    let response = app
        .clone()
        .oneshot(Request::get("/").body(axum::body::Body::empty()).unwrap())
        .await
        .expect("request should succeed");

    let headers = response.headers();
    assert!(headers.contains_key(http::header::STRICT_TRANSPORT_SECURITY));
    assert!(headers.contains_key(http::header::X_FRAME_OPTIONS));
    assert!(headers.contains_key(http::header::X_CONTENT_TYPE_OPTIONS));
    assert!(headers.contains_key(http::header::REFERRER_POLICY));
    assert!(headers.contains_key("permissions-policy"));

    // The Balanced preset has no nonce, so the CSP is served from the
    // pre-rendered static map.
    assert_eq!(
        headers
            .get(http::header::CONTENT_SECURITY_POLICY)
            .unwrap()
            .to_str()
            .unwrap(),
        "default-src 'self'; object-src 'none'; script-src 'self' 'unsafe-inline'"
    );
}
