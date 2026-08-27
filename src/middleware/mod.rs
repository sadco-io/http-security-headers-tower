//! Tower middleware for adding security headers.
//!
//! This module provides Tower Layer and Service implementations for adding
//! security headers to HTTP responses.
//!
//! Header values are rendered once, when the [`SecurityHeaders`] configuration is
//! built, and stored as a ready-made [`HeaderMap`]. Applying them to a response is a
//! handful of refcount bumps -- no formatting, no allocation, no parsing per request.

use crate::config::CONTENT_SECURITY_POLICY;
use crate::SecurityHeaders;
use http::header::{HeaderName, HeaderValue};
use http::{HeaderMap, Request, Response};
use http_body::Body;
use pin_project_lite::pin_project;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower::{Layer, Service};

#[cfg(feature = "nonce")]
use crate::Nonce;

#[cfg(feature = "observability")]
use tracing::trace;

/// The configuration, with its header values pre-parsed into `http` types.
#[derive(Debug)]
struct Prepared {
    config: Arc<SecurityHeaders>,
    /// Every header whose value is the same for every response.
    static_headers: HeaderMap,
    /// Set when the CSP carries a per-request nonce.
    csp_name: HeaderName,
}

impl Prepared {
    fn new(config: Arc<SecurityHeaders>) -> Self {
        #[cfg(not(feature = "nonce"))]
        assert!(
            !config.needs_nonce(),
            "this SecurityHeaders configuration asks for a per-request CSP nonce, but the \
             `nonce` feature of http-security-headers is not enabled; enable it or drop the \
             `with_nonce()` / `nonce_for()` call"
        );

        let mut static_headers = HeaderMap::with_capacity(config.header_pairs().len());

        for (name, value) in config.header_pairs() {
            // Both halves were validated by `SecurityHeadersBuilder::build`: the
            // names are our own constants and the values are checked to be legal
            // header values. A failure here is a bug in this crate, not bad input,
            // and surfacing it at startup beats silently dropping the header on
            // every response -- which is what 0.2.0 did.
            let name = HeaderName::from_static(name);
            let value = HeaderValue::from_str(value)
                .expect("SecurityHeadersBuilder::build validated this header value");
            static_headers.insert(name, value);
        }

        Self {
            config,
            static_headers,
            csp_name: HeaderName::from_static(CONTENT_SECURITY_POLICY),
        }
    }

    /// Applies every static header to `headers`, overwriting anything already set.
    fn apply_static(&self, headers: &mut HeaderMap) {
        for (name, value) in &self.static_headers {
            headers.insert(name.clone(), value.clone());
        }
    }
}

/// Tower layer for adding security headers.
///
/// # Examples
///
/// ```rust,ignore
/// use axum::{Router, routing::get};
/// use http_security_headers::{Preset, SecurityHeadersLayer};
///
/// let app = Router::new()
///     .route("/", get(|| async { "Hello, World!" }))
///     .layer(SecurityHeadersLayer::new(Preset::Strict.build()));
/// ```
#[derive(Clone, Debug)]
pub struct SecurityHeadersLayer {
    prepared: Arc<Prepared>,
}

impl SecurityHeadersLayer {
    /// Creates a new `SecurityHeadersLayer` with the given configuration.
    ///
    /// Accepts either a [`SecurityHeaders`] or an `Arc<SecurityHeaders>`, so an
    /// existing configuration can be shared across several layers without cloning
    /// it.
    ///
    /// # Panics
    ///
    /// Panics if the configuration requests a per-request CSP nonce but the `nonce`
    /// feature is not enabled. This is a startup-time misconfiguration; the
    /// alternative would be to serve a policy that quietly lacks the nonce it was
    /// built around.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_security_headers::{Preset, SecurityHeadersLayer};
    /// use std::sync::Arc;
    ///
    /// let owned = SecurityHeadersLayer::new(Preset::Strict.build());
    /// let shared = SecurityHeadersLayer::new(Arc::new(Preset::Strict.build()));
    /// ```
    pub fn new(headers: impl Into<Arc<SecurityHeaders>>) -> Self {
        Self {
            prepared: Arc::new(Prepared::new(headers.into())),
        }
    }

    /// Returns the configuration this layer applies.
    pub fn config(&self) -> &Arc<SecurityHeaders> {
        &self.prepared.config
    }
}

impl<S> Layer<S> for SecurityHeadersLayer {
    type Service = SecurityHeadersService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SecurityHeadersService {
            inner,
            prepared: self.prepared.clone(),
        }
    }
}

/// Tower service for adding security headers.
#[derive(Clone, Debug)]
pub struct SecurityHeadersService<S> {
    inner: S,
    prepared: Arc<Prepared>,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for SecurityHeadersService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    ResBody: Body,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = SecurityHeadersFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    #[cfg_attr(not(feature = "nonce"), allow(unused_mut))]
    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        #[cfg(feature = "observability")]
        trace!("Security headers middleware: processing request");

        // A nonce must be minted before the handler runs, so the handler can embed
        // the same value in the markup it returns.
        let csp = self.render_csp(&mut req);

        SecurityHeadersFuture {
            future: self.inner.call(req),
            prepared: self.prepared.clone(),
            csp,
        }
    }
}

impl<S> SecurityHeadersService<S> {
    #[cfg(feature = "nonce")]
    fn render_csp<ReqBody>(&self, req: &mut Request<ReqBody>) -> Option<HeaderValue> {
        if !self.prepared.config.needs_nonce() {
            return None;
        }

        let nonce = Nonce::random();
        let rendered = self
            .prepared
            .config
            .csp_with_nonce(&nonce)?
            .expect("SecurityHeadersBuilder::build validated this CSP");

        // Hand the nonce to the handler. In Axum this is `Extension<Nonce>`.
        req.extensions_mut().insert(nonce);

        Some(
            HeaderValue::from_str(&rendered)
                .expect("SecurityHeadersBuilder::build validated this CSP"),
        )
    }

    #[cfg(not(feature = "nonce"))]
    fn render_csp<ReqBody>(&self, _req: &mut Request<ReqBody>) -> Option<HeaderValue> {
        None
    }
}

pin_project! {
    /// Future returned by [`SecurityHeadersService`].
    pub struct SecurityHeadersFuture<F> {
        #[pin]
        future: F,
        prepared: Arc<Prepared>,
        csp: Option<HeaderValue>,
    }
}

impl<F, ResBody, E> Future for SecurityHeadersFuture<F>
where
    F: Future<Output = Result<Response<ResBody>, E>>,
    ResBody: Body,
{
    type Output = Result<Response<ResBody>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();

        match this.future.poll(cx) {
            Poll::Ready(Ok(mut response)) => {
                let headers = response.headers_mut();
                this.prepared.apply_static(headers);

                if let Some(csp) = this.csp.take() {
                    headers.insert(this.prepared.csp_name.clone(), csp);
                }

                #[cfg(feature = "observability")]
                trace!("Security headers middleware: applied headers to response");
                Poll::Ready(Ok(response))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Adds the configured security headers to a response.
///
/// This is the one-shot form of the middleware, for the cases where a Tower layer
/// does not fit. It does **not** handle per-request nonces -- a config built with
/// [`with_nonce`] needs [`SecurityHeadersLayer`], which can mint the nonce before
/// the handler runs.
///
/// # Examples
///
/// ```
/// use http::Response;
/// use http_security_headers::{add_security_headers, Preset};
///
/// let config = Preset::Strict.build();
/// let mut response = Response::new("Hello, World!");
/// add_security_headers(&mut response, &config);
///
/// assert!(response.headers().contains_key("content-security-policy"));
/// ```
///
/// [`with_nonce`]: crate::ContentSecurityPolicy::with_nonce
pub fn add_security_headers<B>(response: &mut Response<B>, config: &SecurityHeaders) {
    #[cfg(feature = "observability")]
    trace!("Adding security headers to response");

    let headers = response.headers_mut();

    for (name, value) in config.header_pairs() {
        let name = HeaderName::from_static(name);
        let value = HeaderValue::from_str(value)
            .expect("SecurityHeadersBuilder::build validated this header value");
        headers.insert(name, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Preset;
    #[cfg(feature = "nonce")]
    use crate::{ContentSecurityPolicy, SecurityHeaders};
    use bytes::Bytes;
    use http::Response;
    use http_body_util::Full;
    use std::convert::Infallible;
    use tower::service_fn;
    use tower::ServiceExt;

    fn ok_service(
    ) -> impl Service<Request<()>, Response = Response<Full<Bytes>>, Error = Infallible> {
        service_fn(|_req: Request<()>| async {
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
        })
    }

    #[test]
    fn test_add_security_headers_strict() {
        let config = Preset::Strict.build();
        let mut response = Response::new("test body");

        add_security_headers(&mut response, &config);

        let headers = response.headers();
        assert!(headers.contains_key(http::header::CONTENT_SECURITY_POLICY));
        assert!(headers.contains_key(http::header::STRICT_TRANSPORT_SECURITY));
        assert!(headers.contains_key(http::header::X_FRAME_OPTIONS));
        assert!(headers.contains_key(http::header::X_CONTENT_TYPE_OPTIONS));
        assert!(headers.contains_key(http::header::REFERRER_POLICY));
        assert!(headers.contains_key("permissions-policy"));
        assert!(headers.contains_key("cross-origin-opener-policy"));
        assert!(headers.contains_key("cross-origin-embedder-policy"));
        assert!(headers.contains_key("cross-origin-resource-policy"));
    }

    #[test]
    fn test_add_security_headers_balanced() {
        let config = Preset::Balanced.build();
        let mut response = Response::new("test body");

        add_security_headers(&mut response, &config);

        let headers = response.headers();
        assert!(headers.contains_key(http::header::CONTENT_SECURITY_POLICY));
        assert!(headers.contains_key(http::header::STRICT_TRANSPORT_SECURITY));
        assert_eq!(
            headers.get(http::header::X_FRAME_OPTIONS).unwrap(),
            "SAMEORIGIN"
        );
    }

    #[test]
    fn test_add_security_headers_relaxed() {
        let config = Preset::Relaxed.build();
        let mut response = Response::new("test body");

        add_security_headers(&mut response, &config);

        let headers = response.headers();
        assert!(headers.contains_key(http::header::STRICT_TRANSPORT_SECURITY));
        assert!(headers.contains_key(http::header::X_FRAME_OPTIONS));
        assert!(headers.contains_key(http::header::X_CONTENT_TYPE_OPTIONS));
        assert!(headers.contains_key(http::header::REFERRER_POLICY));

        // Relaxed doesn't include CSP
        assert!(!headers.contains_key(http::header::CONTENT_SECURITY_POLICY));
    }

    #[tokio::test]
    async fn test_security_headers_layer_applies_headers() {
        let layer = SecurityHeadersLayer::new(Preset::Balanced.build());
        let service = layer.layer(ok_service());

        let response = service.oneshot(Request::new(())).await.unwrap();
        let headers = response.headers();

        assert!(headers.contains_key(http::header::STRICT_TRANSPORT_SECURITY));
        assert!(headers.contains_key(http::header::X_FRAME_OPTIONS));
    }

    #[tokio::test]
    async fn test_layer_accepts_arc_and_owned() {
        // `Arc` was mandatory through 0.2.0; both must work now.
        let from_arc = SecurityHeadersLayer::new(Arc::new(Preset::Relaxed.build()));
        let from_owned = SecurityHeadersLayer::new(Preset::Relaxed.build());

        for layer in [from_arc, from_owned] {
            let response = layer
                .layer(ok_service())
                .oneshot(Request::new(()))
                .await
                .unwrap();
            assert!(response
                .headers()
                .contains_key(http::header::X_FRAME_OPTIONS));
        }
    }

    #[tokio::test]
    async fn test_layer_overwrites_handler_headers() {
        let layer = SecurityHeadersLayer::new(Preset::Relaxed.build());

        let service = layer.layer(service_fn(|_req: Request<()>| async {
            let mut response = Response::new(Full::new(Bytes::from_static(b"ok")));
            response.headers_mut().insert(
                http::header::X_FRAME_OPTIONS,
                HeaderValue::from_static("DENY"),
            );
            Ok::<_, Infallible>(response)
        }));

        let response = service.oneshot(Request::new(())).await.unwrap();
        assert_eq!(
            response
                .headers()
                .get(http::header::X_FRAME_OPTIONS)
                .unwrap(),
            "SAMEORIGIN"
        );
    }

    #[cfg(feature = "nonce")]
    #[tokio::test]
    async fn test_nonce_is_fresh_per_request_and_matches_the_header() {
        let config = SecurityHeaders::builder()
            .content_security_policy(
                ContentSecurityPolicy::new()
                    .default_src(vec!["'self'"])
                    .script_src(vec!["'self'"])
                    .with_nonce(),
            )
            .build()
            .unwrap();

        let layer = SecurityHeadersLayer::new(config);

        // The handler reads the nonce out of the request extensions and echoes it,
        // which is exactly what a template renderer would do.
        let service = layer.layer(service_fn(|req: Request<()>| async move {
            let nonce = req
                .extensions()
                .get::<Nonce>()
                .expect("middleware should supply a nonce")
                .clone();
            let mut response = Response::new(Full::new(Bytes::from(nonce.into_string())));
            response
                .headers_mut()
                .insert("x-echo", HeaderValue::from_static("1"));
            Ok::<_, Infallible>(response)
        }));

        let mut seen = Vec::new();
        for _ in 0..3 {
            let response = service.clone().oneshot(Request::new(())).await.unwrap();

            let csp = response
                .headers()
                .get(http::header::CONTENT_SECURITY_POLICY)
                .unwrap()
                .to_str()
                .unwrap()
                .to_string();

            let body = http_body_util::BodyExt::collect(response.into_body())
                .await
                .unwrap()
                .to_bytes();
            let handler_nonce = String::from_utf8(body.to_vec()).unwrap();

            // The value the handler saw must be the value the browser is told to trust.
            assert!(
                csp.contains(&format!("'nonce-{handler_nonce}'")),
                "handler nonce {handler_nonce} missing from CSP {csp}"
            );
            seen.push(handler_nonce);
        }

        seen.sort();
        seen.dedup();
        assert_eq!(seen.len(), 3, "nonces must not repeat across requests");
    }

    #[cfg(feature = "nonce")]
    #[tokio::test]
    async fn test_no_nonce_extension_when_config_does_not_ask_for_one() {
        let layer = SecurityHeadersLayer::new(Preset::Balanced.build());

        let service = layer.layer(service_fn(|req: Request<()>| async move {
            assert!(req.extensions().get::<Nonce>().is_none());
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
        }));

        service.oneshot(Request::new(())).await.unwrap();
    }
}
