//! Actix-Web middleware integration.
//!
//! Enable the `actix` feature to use the provided middleware that applies
//! `http-security-headers` to every outgoing response.
//!
//! Actix-Web 4 is built on `http` 0.2, so this module keeps its own pre-parsed
//! [`HeaderMap`] rather than sharing the one the Tower middleware builds from
//! `http` 1. Both are rendered once from the same validated
//! [`header_pairs`](SecurityHeaders::header_pairs).

use crate::SecurityHeaders;
use actix_web::body::MessageBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::header::{HeaderMap, HeaderName, HeaderValue};
use actix_web::Error;
use futures_util::future::{ready, LocalBoxFuture, Ready};
use std::sync::Arc;

#[cfg(feature = "nonce")]
use crate::Nonce;
#[cfg(feature = "nonce")]
use actix_web::HttpMessage;

/// The configuration, with its header values pre-parsed into Actix's `http` types.
#[derive(Debug, Clone)]
struct Prepared {
    config: Arc<SecurityHeaders>,
    static_headers: HeaderMap,
    /// When true, a header the inner service already set is left alone.
    if_not_present: bool,
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
            // Validated by `SecurityHeadersBuilder::build`; see the Tower module for
            // why this is an assertion rather than a silently skipped header.
            let name = HeaderName::from_static(name);
            let value = HeaderValue::from_str(value)
                .expect("SecurityHeadersBuilder::build validated this header value");
            static_headers.insert(name, value);
        }

        Self {
            config,
            static_headers,
            if_not_present: false,
        }
    }

    /// Applies one header, honouring the configured overwrite behaviour.
    fn put(&self, headers: &mut HeaderMap, name: &HeaderName, value: &HeaderValue) {
        if self.if_not_present && headers.contains_key(name) {
            return;
        }
        headers.insert(name.clone(), value.clone());
    }

    fn apply_static(&self, headers: &mut HeaderMap) {
        for (name, value) in &self.static_headers {
            self.put(headers, name, value);
        }
    }
}

/// Actix-Web middleware that applies configured security headers to responses.
///
/// # Examples
///
/// ```rust,ignore
/// use actix_web::{web, App, HttpResponse, HttpServer};
/// use http_security_headers::{Preset, SecurityHeadersMiddleware};
///
/// #[actix_web::main]
/// async fn main() -> std::io::Result<()> {
///     HttpServer::new(|| {
///         App::new()
///             .wrap(SecurityHeadersMiddleware::new(Preset::Strict.build()))
///             .route("/", web::get().to(|| async { HttpResponse::Ok().body("Hello") }))
///     })
///     .bind(("127.0.0.1", 3000))?
///     .run()
///     .await
/// }
/// ```
#[derive(Clone, Debug)]
pub struct SecurityHeadersMiddleware {
    prepared: Arc<Prepared>,
}

impl SecurityHeadersMiddleware {
    /// Creates a new Actix middleware from the provided configuration.
    ///
    /// Accepts either a [`SecurityHeaders`] or an `Arc<SecurityHeaders>`.
    ///
    /// # Panics
    ///
    /// Panics if the configuration requests a per-request CSP nonce but the `nonce`
    /// feature is not enabled.
    pub fn new(headers: impl Into<Arc<SecurityHeaders>>) -> Self {
        Self {
            prepared: Arc::new(Prepared::new(headers.into())),
        }
    }

    /// Leaves any header the wrapped service already set on the response alone.
    ///
    /// By default the configured value wins. Switch this on when a route
    /// legitimately sets its own value and the middleware should fill in only
    /// what is missing.
    pub fn if_not_present(mut self) -> Self {
        Arc::make_mut(&mut self.prepared).if_not_present = true;
        self
    }

    /// Returns the configuration this middleware applies.
    pub fn config(&self) -> &Arc<SecurityHeaders> {
        &self.prepared.config
    }
}

impl<S, B> Transform<S, ServiceRequest> for SecurityHeadersMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = SecurityHeadersMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(SecurityHeadersMiddlewareService {
            service,
            prepared: self.prepared.clone(),
        }))
    }
}

/// Inner service that applies headers after the wrapped service completes.
#[derive(Debug)]
pub struct SecurityHeadersMiddlewareService<S> {
    service: S,
    prepared: Arc<Prepared>,
}

impl<S> SecurityHeadersMiddlewareService<S> {
    #[cfg(feature = "nonce")]
    fn nonce_headers(&self, req: &ServiceRequest) -> Vec<(HeaderName, HeaderValue)> {
        if !self.prepared.config.needs_nonce() {
            return Vec::new();
        }

        // One nonce per request, shared by the enforcing and report-only policies.
        let nonce = Nonce::random();
        let rendered = self
            .prepared
            .config
            .nonce_header_pairs(&nonce)
            .expect("SecurityHeadersBuilder::build validated these policies");

        // Handlers reach this with `web::ReqData<Nonce>`.
        req.extensions_mut().insert(nonce);

        rendered
            .into_iter()
            .map(|(name, value)| {
                (
                    HeaderName::from_static(name),
                    HeaderValue::from_str(&value)
                        .expect("SecurityHeadersBuilder::build validated these policies"),
                )
            })
            .collect()
    }

    #[cfg(not(feature = "nonce"))]
    fn nonce_headers(&self, _req: &ServiceRequest) -> Vec<(HeaderName, HeaderValue)> {
        Vec::new()
    }
}

impl<S, B> Service<ServiceRequest> for SecurityHeadersMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let prepared = self.prepared.clone();
        let nonce_headers = self.nonce_headers(&req);
        let fut = self.service.call(req);

        Box::pin(async move {
            let mut res = fut.await?;
            let headers = res.response_mut().headers_mut();

            prepared.apply_static(headers);
            for (name, value) in &nonce_headers {
                prepared.put(headers, name, value);
            }

            Ok(res)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Preset;
    use actix_web::{test, web, App, HttpResponse};

    #[actix_web::test]
    async fn middleware_adds_headers() {
        let app = test::init_service(
            App::new()
                .wrap(SecurityHeadersMiddleware::new(Preset::Balanced.build()))
                .route("/", web::get().to(|| async { HttpResponse::Ok().finish() })),
        )
        .await;

        let req = test::TestRequest::get().uri("/").to_request();
        let res = test::call_service(&app, req).await;
        let headers = res.headers();

        use actix_web::http::header;

        assert!(headers.contains_key(header::STRICT_TRANSPORT_SECURITY));
        assert!(headers.contains_key(header::X_FRAME_OPTIONS));
        assert!(headers.contains_key(header::X_CONTENT_TYPE_OPTIONS));
        assert!(headers.contains_key(header::CONTENT_SECURITY_POLICY));
        assert!(headers.contains_key("permissions-policy"));
    }

    #[actix_web::test]
    async fn middleware_accepts_arc_and_owned() {
        for middleware in [
            SecurityHeadersMiddleware::new(Arc::new(Preset::Relaxed.build())),
            SecurityHeadersMiddleware::new(Preset::Relaxed.build()),
        ] {
            let app = test::init_service(
                App::new()
                    .wrap(middleware)
                    .route("/", web::get().to(|| async { HttpResponse::Ok().finish() })),
            )
            .await;

            let req = test::TestRequest::get().uri("/").to_request();
            let res = test::call_service(&app, req).await;
            assert!(res
                .headers()
                .contains_key(actix_web::http::header::X_FRAME_OPTIONS));
        }
    }

    #[actix_web::test]
    async fn middleware_overwrites_handler_headers() {
        let app = test::init_service(
            App::new()
                .wrap(SecurityHeadersMiddleware::new(Preset::Relaxed.build()))
                .route(
                    "/",
                    web::get().to(|| async {
                        HttpResponse::Ok()
                            .insert_header(("x-frame-options", "DENY"))
                            .finish()
                    }),
                ),
        )
        .await;

        let req = test::TestRequest::get().uri("/").to_request();
        let res = test::call_service(&app, req).await;

        assert_eq!(
            res.headers()
                .get(actix_web::http::header::X_FRAME_OPTIONS)
                .unwrap(),
            "SAMEORIGIN"
        );
    }

    #[actix_web::test]
    async fn if_not_present_keeps_the_handlers_value() {
        let app = test::init_service(
            App::new()
                .wrap(SecurityHeadersMiddleware::new(Preset::Relaxed.build()).if_not_present())
                .route(
                    "/",
                    web::get().to(|| async {
                        HttpResponse::Ok()
                            .insert_header(("x-frame-options", "DENY"))
                            .finish()
                    }),
                ),
        )
        .await;

        let req = test::TestRequest::get().uri("/").to_request();
        let res = test::call_service(&app, req).await;
        let headers = res.headers();

        assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
        assert!(headers.contains_key(actix_web::http::header::STRICT_TRANSPORT_SECURITY));
    }

    #[actix_web::test]
    async fn report_only_header_is_emitted() {
        let config = crate::SecurityHeaders::builder()
            .content_security_policy(crate::ContentSecurityPolicy::new().script_src(vec!["'self'"]))
            .content_security_policy_report_only(
                crate::ContentSecurityPolicy::new().script_src(vec!["'none'"]),
            )
            .build()
            .unwrap();

        let app = test::init_service(
            App::new()
                .wrap(SecurityHeadersMiddleware::new(config))
                .route("/", web::get().to(|| async { HttpResponse::Ok().finish() })),
        )
        .await;

        let req = test::TestRequest::get().uri("/").to_request();
        let res = test::call_service(&app, req).await;

        assert_eq!(
            res.headers()
                .get("content-security-policy-report-only")
                .unwrap(),
            "script-src 'none'"
        );
    }

    #[cfg(feature = "nonce")]
    #[actix_web::test]
    async fn both_csp_headers_share_the_handlers_nonce() {
        let config = crate::SecurityHeaders::builder()
            .content_security_policy(
                crate::ContentSecurityPolicy::new()
                    .script_src(vec!["'self'", "'unsafe-inline'"])
                    .nonce_for(["script-src"]),
            )
            .content_security_policy_report_only(
                crate::ContentSecurityPolicy::new()
                    .script_src(vec!["'self'"])
                    .nonce_for(["script-src"]),
            )
            .build()
            .unwrap();

        let app = test::init_service(
            App::new()
                .wrap(SecurityHeadersMiddleware::new(config))
                .route(
                    "/",
                    web::get().to(|nonce: Option<web::ReqData<Nonce>>| async move {
                        HttpResponse::Ok().body(nonce.unwrap().as_str().to_string())
                    }),
                ),
        )
        .await;

        let req = test::TestRequest::get().uri("/").to_request();
        let res = test::call_service(&app, req).await;

        let enforced = res
            .headers()
            .get("content-security-policy")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let reported = res
            .headers()
            .get("content-security-policy-report-only")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        let body = test::read_body(res).await;
        let handler_nonce = String::from_utf8(body.to_vec()).unwrap();
        let expected = format!("'nonce-{handler_nonce}'");

        assert!(enforced.contains(&expected), "enforced: {enforced}");
        assert!(reported.contains(&expected), "report-only: {reported}");
    }

    #[cfg(feature = "nonce")]
    #[actix_web::test]
    async fn middleware_supplies_a_matching_nonce() {
        let app = test::init_service(
            App::new()
                .wrap(SecurityHeadersMiddleware::new(
                    Preset::BalancedNonce.build(),
                ))
                .route(
                    "/",
                    web::get().to(|nonce: Option<web::ReqData<Nonce>>| async move {
                        let nonce = nonce.expect("middleware should supply a nonce");
                        HttpResponse::Ok().body(nonce.as_str().to_string())
                    }),
                ),
        )
        .await;

        let req = test::TestRequest::get().uri("/").to_request();
        let res = test::call_service(&app, req).await;

        let csp = res
            .headers()
            .get(actix_web::http::header::CONTENT_SECURITY_POLICY)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        let body = test::read_body(res).await;
        let handler_nonce = String::from_utf8(body.to_vec()).unwrap();

        assert!(
            csp.contains(&format!("'nonce-{handler_nonce}'")),
            "handler nonce {handler_nonce} missing from CSP {csp}"
        );
    }
}
