//! Security headers configuration.
//!
//! This module provides the main configuration type and builder for security headers.

use crate::error::{Error, Result};
use crate::policy::*;

/// Canonical header names, so the Tower and Actix paths cannot drift apart.
pub(crate) const CONTENT_SECURITY_POLICY: &str = "content-security-policy";
pub(crate) const STRICT_TRANSPORT_SECURITY: &str = "strict-transport-security";
pub(crate) const X_FRAME_OPTIONS: &str = "x-frame-options";
pub(crate) const X_CONTENT_TYPE_OPTIONS: &str = "x-content-type-options";
pub(crate) const REFERRER_POLICY: &str = "referrer-policy";
pub(crate) const PERMISSIONS_POLICY: &str = "permissions-policy";
pub(crate) const CROSS_ORIGIN_OPENER_POLICY: &str = "cross-origin-opener-policy";
pub(crate) const CROSS_ORIGIN_EMBEDDER_POLICY: &str = "cross-origin-embedder-policy";
pub(crate) const CROSS_ORIGIN_RESOURCE_POLICY: &str = "cross-origin-resource-policy";

/// Main security headers configuration.
///
/// This struct holds all configured security headers and provides a builder pattern
/// for ergonomic construction.
///
/// Header values are rendered once, when [`build`] is called, and reused for every
/// response. Anything that could not be rendered into a legal HTTP header value is a
/// `build()` error rather than a header that silently disappears at request time.
///
/// # Examples
///
/// ```
/// use http_security_headers::SecurityHeaders;
/// use std::time::Duration;
///
/// let headers = SecurityHeaders::builder()
///     .strict_transport_security(Duration::from_secs(31536000), true, false)
///     .x_frame_options_deny()
///     .referrer_policy_no_referrer()
///     .build()
///     .unwrap();
/// ```
///
/// [`build`]: SecurityHeadersBuilder::build
#[derive(Debug, Clone)]
pub struct SecurityHeaders {
    content_security_policy: Option<ContentSecurityPolicy>,
    strict_transport_security: Option<StrictTransportSecurity>,
    x_frame_options: Option<XFrameOptions>,
    x_content_type_options: bool,
    referrer_policy: Option<ReferrerPolicy>,
    permissions_policy: Option<PermissionsPolicy>,
    cross_origin_opener_policy: Option<CrossOriginOpenerPolicy>,
    cross_origin_embedder_policy: Option<CrossOriginEmbedderPolicy>,
    cross_origin_resource_policy: Option<CrossOriginResourcePolicy>,

    /// Every header whose value does not change per request, rendered once.
    ///
    /// When the CSP carries a nonce it is excluded here and rendered per request
    /// instead; [`needs_nonce`](Self::needs_nonce) reports which case applies.
    rendered: Vec<(&'static str, String)>,
}

impl SecurityHeaders {
    /// Creates a new builder for SecurityHeaders.
    pub fn builder() -> SecurityHeadersBuilder {
        SecurityHeadersBuilder::default()
    }

    /// Returns the Content-Security-Policy if configured.
    pub fn content_security_policy(&self) -> Option<&ContentSecurityPolicy> {
        self.content_security_policy.as_ref()
    }

    /// Returns the Strict-Transport-Security policy if configured.
    pub fn strict_transport_security(&self) -> Option<&StrictTransportSecurity> {
        self.strict_transport_security.as_ref()
    }

    /// Returns the X-Frame-Options policy if configured.
    pub fn x_frame_options(&self) -> Option<XFrameOptions> {
        self.x_frame_options
    }

    /// Returns whether X-Content-Type-Options: nosniff is enabled.
    pub fn x_content_type_options_enabled(&self) -> bool {
        self.x_content_type_options
    }

    /// Returns the Referrer-Policy if configured.
    pub fn referrer_policy(&self) -> Option<ReferrerPolicy> {
        self.referrer_policy
    }

    /// Returns the Permissions-Policy if configured.
    pub fn permissions_policy(&self) -> Option<&PermissionsPolicy> {
        self.permissions_policy.as_ref()
    }

    /// Returns the Cross-Origin-Opener-Policy if configured.
    pub fn cross_origin_opener_policy(&self) -> Option<CrossOriginOpenerPolicy> {
        self.cross_origin_opener_policy
    }

    /// Returns the Cross-Origin-Embedder-Policy if configured.
    pub fn cross_origin_embedder_policy(&self) -> Option<CrossOriginEmbedderPolicy> {
        self.cross_origin_embedder_policy
    }

    /// Returns the Cross-Origin-Resource-Policy if configured.
    pub fn cross_origin_resource_policy(&self) -> Option<CrossOriginResourcePolicy> {
        self.cross_origin_resource_policy
    }

    /// Returns whether the configured CSP needs a per-request nonce.
    ///
    /// When this is true the Tower middleware mints a [`Nonce`] for each request,
    /// places it in the request extensions, and renders the CSP with it.
    pub fn needs_nonce(&self) -> bool {
        self.content_security_policy
            .as_ref()
            .is_some_and(ContentSecurityPolicy::requires_nonce)
    }

    /// Returns the pre-rendered `(name, value)` pairs for every static header.
    ///
    /// This is the framework-agnostic escape hatch: it needs no feature flags, and
    /// the values are already validated, so they can be written straight out.
    ///
    /// If [`needs_nonce`](Self::needs_nonce) is true the CSP is **not** included --
    /// use [`csp_with_nonce`](Self::csp_with_nonce) for it.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_security_headers::Preset;
    ///
    /// let headers = Preset::Relaxed.build();
    /// for (name, value) in headers.header_pairs() {
    ///     println!("{name}: {value}");
    /// }
    /// ```
    pub fn header_pairs(&self) -> &[(&'static str, String)] {
        &self.rendered
    }

    /// Renders the Content-Security-Policy for one request, injecting `nonce`.
    ///
    /// Returns `None` if no CSP is configured.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidCsp`] if the policy cannot be rendered. In practice
    /// this cannot happen for a policy that survived `build()`.
    pub fn csp_with_nonce(&self, nonce: &Nonce) -> Option<Result<String>> {
        self.content_security_policy
            .as_ref()
            .map(|csp| csp.to_header_value_with_nonce(nonce))
    }
}

/// Builder for SecurityHeaders.
///
/// Provides a fluent interface for configuring security headers.
#[derive(Debug, Default, Clone)]
pub struct SecurityHeadersBuilder {
    content_security_policy: Option<ContentSecurityPolicy>,
    strict_transport_security: Option<StrictTransportSecurity>,
    x_frame_options: Option<XFrameOptions>,
    x_content_type_options: bool,
    referrer_policy: Option<ReferrerPolicy>,
    permissions_policy: Option<PermissionsPolicy>,
    cross_origin_opener_policy: Option<CrossOriginOpenerPolicy>,
    cross_origin_embedder_policy: Option<CrossOriginEmbedderPolicy>,
    cross_origin_resource_policy: Option<CrossOriginResourcePolicy>,
}

impl SecurityHeadersBuilder {
    /// Sets the Content-Security-Policy.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_security_headers::{SecurityHeaders, ContentSecurityPolicy};
    ///
    /// let csp = ContentSecurityPolicy::new()
    ///     .default_src(vec!["'self'"])
    ///     .script_src(vec!["'self'", "'unsafe-inline'"]);
    ///
    /// let headers = SecurityHeaders::builder()
    ///     .content_security_policy(csp)
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn content_security_policy(mut self, policy: ContentSecurityPolicy) -> Self {
        self.content_security_policy = Some(policy);
        self
    }

    /// Sets the Strict-Transport-Security header.
    ///
    /// # Arguments
    ///
    /// * `max_age` - Duration for the max-age directive
    /// * `include_subdomains` - Whether to include the includeSubDomains directive
    /// * `preload` - Whether to include the preload directive
    ///
    /// # Examples
    ///
    /// ```
    /// use http_security_headers::SecurityHeaders;
    /// use std::time::Duration;
    ///
    /// let headers = SecurityHeaders::builder()
    ///     .strict_transport_security(Duration::from_secs(31536000), true, false)
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn strict_transport_security(
        mut self,
        max_age: std::time::Duration,
        include_subdomains: bool,
        preload: bool,
    ) -> Self {
        let hsts = StrictTransportSecurity::new(max_age)
            .include_subdomains(include_subdomains)
            .preload(preload);
        self.strict_transport_security = Some(hsts);
        self
    }

    /// Sets the Strict-Transport-Security header with a custom policy.
    pub fn strict_transport_security_policy(mut self, policy: StrictTransportSecurity) -> Self {
        self.strict_transport_security = Some(policy);
        self
    }

    /// Sets X-Frame-Options to DENY.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_security_headers::SecurityHeaders;
    ///
    /// let headers = SecurityHeaders::builder()
    ///     .x_frame_options_deny()
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn x_frame_options_deny(mut self) -> Self {
        self.x_frame_options = Some(XFrameOptions::Deny);
        self
    }

    /// Sets X-Frame-Options to SAMEORIGIN.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_security_headers::SecurityHeaders;
    ///
    /// let headers = SecurityHeaders::builder()
    ///     .x_frame_options_sameorigin()
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn x_frame_options_sameorigin(mut self) -> Self {
        self.x_frame_options = Some(XFrameOptions::SameOrigin);
        self
    }

    /// Sets the X-Frame-Options header with a custom value.
    pub fn x_frame_options(mut self, policy: XFrameOptions) -> Self {
        self.x_frame_options = Some(policy);
        self
    }

    /// Enables X-Content-Type-Options: nosniff.
    ///
    /// This is enabled by default in preset configurations.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_security_headers::SecurityHeaders;
    ///
    /// let headers = SecurityHeaders::builder()
    ///     .x_content_type_options_nosniff()
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn x_content_type_options_nosniff(mut self) -> Self {
        self.x_content_type_options = true;
        self
    }

    /// Sets the Referrer-Policy header.
    pub fn referrer_policy(mut self, policy: ReferrerPolicy) -> Self {
        self.referrer_policy = Some(policy);
        self
    }

    /// Sets Referrer-Policy to no-referrer.
    pub fn referrer_policy_no_referrer(mut self) -> Self {
        self.referrer_policy = Some(ReferrerPolicy::NoReferrer);
        self
    }

    /// Sets Referrer-Policy to strict-origin-when-cross-origin.
    pub fn referrer_policy_strict_origin_when_cross_origin(mut self) -> Self {
        self.referrer_policy = Some(ReferrerPolicy::StrictOriginWhenCrossOrigin);
        self
    }

    /// Sets the Permissions-Policy header.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_security_headers::{PermissionsPolicy, SecurityHeaders};
    ///
    /// let headers = SecurityHeaders::builder()
    ///     .permissions_policy(
    ///         PermissionsPolicy::new()
    ///             .deny("camera")
    ///             .deny("microphone")
    ///             .self_only("geolocation"),
    ///     )
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn permissions_policy(mut self, policy: PermissionsPolicy) -> Self {
        self.permissions_policy = Some(policy);
        self
    }

    /// Sets the Cross-Origin-Opener-Policy header.
    pub fn cross_origin_opener_policy(mut self, policy: CrossOriginOpenerPolicy) -> Self {
        self.cross_origin_opener_policy = Some(policy);
        self
    }

    /// Sets the Cross-Origin-Embedder-Policy header.
    pub fn cross_origin_embedder_policy(mut self, policy: CrossOriginEmbedderPolicy) -> Self {
        self.cross_origin_embedder_policy = Some(policy);
        self
    }

    /// Sets the Cross-Origin-Resource-Policy header.
    pub fn cross_origin_resource_policy(mut self, policy: CrossOriginResourcePolicy) -> Self {
        self.cross_origin_resource_policy = Some(policy);
        self
    }

    /// Builds the SecurityHeaders configuration.
    ///
    /// Every header value is rendered and validated here, once, so that applying the
    /// configuration to a response cannot fail.
    ///
    /// # Errors
    ///
    /// Returns an error if no header is configured, or if any policy renders to
    /// something that is not a legal HTTP header value.
    pub fn build(self) -> Result<SecurityHeaders> {
        // Validate that at least one header is configured
        if self.content_security_policy.is_none()
            && self.strict_transport_security.is_none()
            && self.x_frame_options.is_none()
            && !self.x_content_type_options
            && self.referrer_policy.is_none()
            && self.permissions_policy.is_none()
            && self.cross_origin_opener_policy.is_none()
            && self.cross_origin_embedder_policy.is_none()
            && self.cross_origin_resource_policy.is_none()
        {
            return Err(Error::ValidationFailed(
                "At least one security header must be configured".to_string(),
            ));
        }

        let mut rendered: Vec<(&'static str, String)> = Vec::new();

        if let Some(csp) = &self.content_security_policy {
            // Render even when a nonce is in play: it proves the policy is legal
            // now rather than on the first request that reaches production.
            let value = csp.to_header_value()?;
            if !csp.requires_nonce() {
                rendered.push((CONTENT_SECURITY_POLICY, value));
            }
        }

        if let Some(hsts) = &self.strict_transport_security {
            rendered.push((STRICT_TRANSPORT_SECURITY, hsts.to_header_value()?));
        }

        if let Some(xfo) = self.x_frame_options {
            rendered.push((X_FRAME_OPTIONS, xfo.as_str().to_string()));
        }

        if self.x_content_type_options {
            rendered.push((X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()));
        }

        if let Some(rp) = self.referrer_policy {
            rendered.push((REFERRER_POLICY, rp.as_str().to_string()));
        }

        if let Some(pp) = &self.permissions_policy {
            rendered.push((PERMISSIONS_POLICY, pp.to_header_value()?));
        }

        if let Some(coop) = self.cross_origin_opener_policy {
            rendered.push((CROSS_ORIGIN_OPENER_POLICY, coop.as_str().to_string()));
        }

        if let Some(coep) = self.cross_origin_embedder_policy {
            rendered.push((CROSS_ORIGIN_EMBEDDER_POLICY, coep.as_str().to_string()));
        }

        if let Some(corp) = self.cross_origin_resource_policy {
            rendered.push((CROSS_ORIGIN_RESOURCE_POLICY, corp.as_str().to_string()));
        }

        Ok(SecurityHeaders {
            content_security_policy: self.content_security_policy,
            strict_transport_security: self.strict_transport_security,
            x_frame_options: self.x_frame_options,
            x_content_type_options: self.x_content_type_options,
            referrer_policy: self.referrer_policy,
            permissions_policy: self.permissions_policy,
            cross_origin_opener_policy: self.cross_origin_opener_policy,
            cross_origin_embedder_policy: self.cross_origin_embedder_policy,
            cross_origin_resource_policy: self.cross_origin_resource_policy,
            rendered,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_builder_empty_fails() {
        let result = SecurityHeaders::builder().build();
        assert!(result.is_err());
    }

    #[test]
    fn test_builder_with_hsts() {
        let headers = SecurityHeaders::builder()
            .strict_transport_security(Duration::from_secs(31536000), true, false)
            .build()
            .unwrap();

        assert!(headers.strict_transport_security().is_some());
        let hsts = headers.strict_transport_security().unwrap();
        assert_eq!(hsts.max_age(), Duration::from_secs(31536000));
        assert!(hsts.includes_subdomains());
        assert!(!hsts.is_preload());
    }

    #[test]
    fn test_builder_with_frame_options() {
        let headers = SecurityHeaders::builder()
            .x_frame_options_deny()
            .build()
            .unwrap();

        assert_eq!(headers.x_frame_options(), Some(XFrameOptions::Deny));
    }

    #[test]
    fn test_builder_with_referrer_policy() {
        let headers = SecurityHeaders::builder()
            .referrer_policy_no_referrer()
            .build()
            .unwrap();

        assert_eq!(headers.referrer_policy(), Some(ReferrerPolicy::NoReferrer));
    }

    #[test]
    fn test_builder_with_multiple_headers() {
        let csp = ContentSecurityPolicy::new().default_src(vec!["'self'"]);

        let headers = SecurityHeaders::builder()
            .content_security_policy(csp)
            .strict_transport_security(Duration::from_secs(31536000), true, false)
            .x_frame_options_deny()
            .x_content_type_options_nosniff()
            .referrer_policy_no_referrer()
            .permissions_policy(PermissionsPolicy::new().deny("camera"))
            .cross_origin_opener_policy(CrossOriginOpenerPolicy::SameOrigin)
            .cross_origin_embedder_policy(CrossOriginEmbedderPolicy::RequireCorp)
            .cross_origin_resource_policy(CrossOriginResourcePolicy::SameOrigin)
            .build()
            .unwrap();

        assert!(headers.content_security_policy().is_some());
        assert!(headers.strict_transport_security().is_some());
        assert!(headers.x_frame_options().is_some());
        assert!(headers.x_content_type_options_enabled());
        assert!(headers.referrer_policy().is_some());
        assert!(headers.permissions_policy().is_some());
        assert!(headers.cross_origin_opener_policy().is_some());
        assert!(headers.cross_origin_embedder_policy().is_some());
        assert!(headers.cross_origin_resource_policy().is_some());

        assert_eq!(headers.header_pairs().len(), 9);
    }

    #[test]
    fn test_builder_with_empty_csp_fails() {
        let result = SecurityHeaders::builder()
            .content_security_policy(ContentSecurityPolicy::new())
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_builder_rejects_unrenderable_csp() {
        // Through 0.2.0 this built fine and then dropped the CSP header at request
        // time, with no error and no log.
        let result = SecurityHeaders::builder()
            .content_security_policy(
                ContentSecurityPolicy::new().default_src(vec!["https://evil\r\nX-Evil: 1"]),
            )
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_builder_rejects_unrenderable_permissions_policy() {
        let result = SecurityHeaders::builder()
            .permissions_policy(PermissionsPolicy::new().allow("camera", vec!["https://a\"b"]))
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_hsts_preload_is_validated_at_build_time() {
        let result = SecurityHeaders::builder()
            .strict_transport_security(Duration::from_secs(60), true, true)
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_strict_transport_security_respects_false_arguments() {
        let headers = SecurityHeaders::builder()
            .strict_transport_security_policy(
                StrictTransportSecurity::new(Duration::from_secs(600))
                    .include_subdomains(true)
                    .preload(false),
            )
            .strict_transport_security(Duration::from_secs(600), false, false)
            .build()
            .unwrap();

        let hsts = headers.strict_transport_security().unwrap();
        assert!(!hsts.includes_subdomains());
        assert!(!hsts.is_preload());
    }

    #[test]
    fn test_header_pairs_are_prerendered() {
        let headers = SecurityHeaders::builder()
            .x_frame_options_deny()
            .x_content_type_options_nosniff()
            .build()
            .unwrap();

        let pairs = headers.header_pairs();
        assert!(pairs.contains(&("x-frame-options", "DENY".to_string())));
        assert!(pairs.contains(&("x-content-type-options", "nosniff".to_string())));
    }

    #[test]
    fn test_nonce_csp_is_excluded_from_static_pairs() {
        let headers = SecurityHeaders::builder()
            .content_security_policy(
                ContentSecurityPolicy::new()
                    .script_src(vec!["'self'"])
                    .with_nonce(),
            )
            .x_frame_options_deny()
            .build()
            .unwrap();

        assert!(headers.needs_nonce());
        assert!(!headers
            .header_pairs()
            .iter()
            .any(|(name, _)| *name == CONTENT_SECURITY_POLICY));

        let nonce = Nonce::from_encoded("dGVzdA==").unwrap();
        let csp = headers.csp_with_nonce(&nonce).unwrap().unwrap();
        assert_eq!(csp, "script-src 'self' 'nonce-dGVzdA=='");
    }

    #[test]
    fn test_static_csp_is_included_in_pairs() {
        let headers = SecurityHeaders::builder()
            .content_security_policy(ContentSecurityPolicy::new().default_src(vec!["'self'"]))
            .build()
            .unwrap();

        assert!(!headers.needs_nonce());
        assert!(
            headers
                .header_pairs()
                .iter()
                .any(|(name, value)| *name == CONTENT_SECURITY_POLICY
                    && value == "default-src 'self'")
        );
    }
}
