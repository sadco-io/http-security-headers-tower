//! End-to-end checks that a nonce issued to the handler is the nonce the browser
//! is told to trust, through a real Axum router.

use axum::body::Body;
use axum::{routing::get, Extension, Router};
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use http_security_headers::{
    ContentSecurityPolicy, Nonce, Preset, SecurityHeaders, SecurityHeadersLayer,
};
use tower::ServiceExt;

/// Echoes the nonce the middleware supplied, the way a template would embed it.
async fn echo_nonce(Extension(nonce): Extension<Nonce>) -> String {
    nonce.into_string()
}

fn app(config: SecurityHeaders) -> Router {
    Router::new()
        .route("/", get(echo_nonce))
        .layer(SecurityHeadersLayer::new(config))
}

async fn request(app: &Router) -> (String, String) {
    let response = app
        .clone()
        .oneshot(Request::get("/").body(Body::empty()).unwrap())
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::OK);

    let csp = response
        .headers()
        .get(http::header::CONTENT_SECURITY_POLICY)
        .expect("a nonce config must still emit a CSP")
        .to_str()
        .unwrap()
        .to_string();

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let nonce = String::from_utf8(body.to_vec()).unwrap();

    (csp, nonce)
}

#[tokio::test]
async fn handler_nonce_matches_the_csp_header() {
    let app = app(Preset::BalancedNonce.build());
    let (csp, nonce) = request(&app).await;

    assert!(
        csp.contains(&format!("'nonce-{nonce}'")),
        "handler received {nonce}, but the CSP was {csp}"
    );
}

#[tokio::test]
async fn nonces_do_not_repeat_across_requests() {
    let app = app(Preset::BalancedNonce.build());

    let mut seen = Vec::new();
    for _ in 0..25 {
        let (_, nonce) = request(&app).await;
        seen.push(nonce);
    }

    let total = seen.len();
    seen.sort();
    seen.dedup();

    assert_eq!(seen.len(), total, "a nonce was reused across requests");
}

#[tokio::test]
async fn nonce_config_never_ships_unsafe_inline() {
    let app = app(Preset::BalancedNonce.build());
    let (csp, _) = request(&app).await;

    assert!(!csp.contains("'unsafe-inline'"));
    assert!(csp.contains("script-src 'self' 'nonce-"));
}

#[tokio::test]
async fn only_the_marked_directives_receive_the_nonce() {
    let config = SecurityHeaders::builder()
        .content_security_policy(
            ContentSecurityPolicy::new()
                .default_src(vec!["'self'"])
                .script_src(vec!["'self'"])
                .style_src(vec!["'self'"])
                .nonce_for(["script-src"]),
        )
        .build()
        .unwrap();

    let (csp, nonce) = request(&app(config)).await;

    assert!(csp.contains(&format!("script-src 'self' 'nonce-{nonce}'")));
    assert!(
        csp.contains("style-src 'self';") || csp.ends_with("style-src 'self'"),
        "style-src should not have been given a nonce: {csp}"
    );
}

#[tokio::test]
async fn static_config_emits_no_nonce_extension() {
    // A handler that requires `Extension<Nonce>` must fail when the config never
    // asked for one -- proof the middleware is not inserting nonces unconditionally.
    let app = app(Preset::Balanced.build());

    let response = app
        .oneshot(Request::get("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}
