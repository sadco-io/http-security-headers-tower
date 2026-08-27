//! Preset security header configurations.
//!
//! This module provides pre-configured security header sets for common use cases.

use crate::config::SecurityHeaders;
use crate::policy::*;
use std::time::Duration;

/// One year, the value the HSTS preload list requires.
const ONE_YEAR: Duration = Duration::from_secs(31_536_000);
/// Six months.
const SIX_MONTHS: Duration = Duration::from_secs(15_552_000);

/// Security preset levels.
///
/// # Examples
///
/// ```
/// use http_security_headers::Preset;
///
/// let headers = Preset::Strict.build();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Preset {
    /// Strict security configuration.
    ///
    /// Recommended for applications that can enforce strict security policies.
    /// May break functionality if not properly configured.
    ///
    /// Includes:
    /// - CSP: `base-uri 'self'; default-src 'self'; frame-ancestors 'none'; object-src 'none'`
    /// - HSTS: 1 year, includeSubDomains
    /// - X-Frame-Options: DENY
    /// - X-Content-Type-Options: nosniff
    /// - Referrer-Policy: no-referrer
    /// - Permissions-Policy: camera, geolocation, microphone, payment and usb denied
    /// - COOP: same-origin
    /// - COEP: require-corp
    /// - CORP: same-origin
    Strict,

    /// Balanced security configuration.
    ///
    /// Provides good security while maintaining compatibility with most applications.
    ///
    /// Includes:
    /// - CSP: `default-src 'self'; object-src 'none'; script-src 'self' 'unsafe-inline'`
    /// - HSTS: 1 year, includeSubDomains
    /// - X-Frame-Options: SAMEORIGIN
    /// - X-Content-Type-Options: nosniff
    /// - Referrer-Policy: strict-origin-when-cross-origin
    /// - Permissions-Policy: camera, geolocation and microphone denied
    /// - COOP: same-origin-allow-popups
    ///
    /// # This preset does not protect against XSS
    ///
    /// `script-src` carries `'unsafe-inline'`, which permits any inline `<script>`
    /// on the page -- including one an attacker injected. That is the single thing
    /// CSP exists to stop, so treat this preset's CSP as defence in depth for
    /// resource loading, not as an XSS control.
    ///
    /// It is kept permissive because most applications cannot adopt a stricter
    /// policy without changing their templates. When you can, use
    /// [`BalancedNonce`](Self::BalancedNonce), which drops `'unsafe-inline'` in
    /// favour of a per-request nonce and is otherwise identical.
    Balanced,

    /// [`Balanced`](Self::Balanced), with a per-request nonce instead of `'unsafe-inline'`.
    ///
    /// Identical to `Balanced` in every other respect. `script-src` and `style-src`
    /// are set to `'self'` and marked for nonce injection, so the Tower middleware
    /// mints a fresh nonce per request, puts it in the request extensions, and
    /// writes it into the CSP.
    ///
    /// Your templates must stamp the same nonce onto every inline `<script>` and
    /// `<style>` tag; any tag without it will not run.
    ///
    /// Requires the `nonce` feature when used with [`SecurityHeadersLayer`].
    ///
    /// # Examples
    ///
    /// ```
    /// use http_security_headers::Preset;
    ///
    /// let headers = Preset::BalancedNonce.build();
    /// assert!(headers.needs_nonce());
    /// ```
    ///
    /// [`SecurityHeadersLayer`]: crate::SecurityHeadersLayer
    BalancedNonce,

    /// Relaxed security configuration.
    ///
    /// Provides baseline security with minimal restrictions.
    /// Suitable for applications that need maximum compatibility.
    ///
    /// Includes:
    /// - HSTS: 6 months
    /// - X-Frame-Options: SAMEORIGIN
    /// - X-Content-Type-Options: nosniff
    /// - Referrer-Policy: strict-origin-when-cross-origin
    Relaxed,
}

impl Preset {
    /// Builds the SecurityHeaders for this preset.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_security_headers::Preset;
    ///
    /// let headers = Preset::Strict.build();
    /// ```
    pub fn build(self) -> SecurityHeaders {
        match self {
            Self::Strict => Self::build_strict(),
            Self::Balanced => Self::build_balanced(false),
            Self::BalancedNonce => Self::build_balanced(true),
            Self::Relaxed => Self::build_relaxed(),
        }
    }

    fn build_strict() -> SecurityHeaders {
        let csp = ContentSecurityPolicy::new()
            .default_src(vec!["'self'"])
            .object_src(vec!["'none'"])
            .base_uri(vec!["'self'"])
            .frame_ancestors(vec!["'none'"]);

        SecurityHeaders::builder()
            .content_security_policy(csp)
            .strict_transport_security(ONE_YEAR, true, false)
            .x_frame_options_deny()
            .x_content_type_options_nosniff()
            .referrer_policy_no_referrer()
            .permissions_policy(
                PermissionsPolicy::new()
                    .deny("camera")
                    .deny("geolocation")
                    .deny("microphone")
                    .deny("payment")
                    .deny("usb"),
            )
            .cross_origin_opener_policy(CrossOriginOpenerPolicy::SameOrigin)
            .cross_origin_embedder_policy(CrossOriginEmbedderPolicy::RequireCorp)
            .cross_origin_resource_policy(CrossOriginResourcePolicy::SameOrigin)
            .build()
            .expect("strict preset should always be valid")
    }

    fn build_balanced(use_nonce: bool) -> SecurityHeaders {
        let csp = ContentSecurityPolicy::new()
            .default_src(vec!["'self'"])
            .object_src(vec!["'none'"]);

        let csp = if use_nonce {
            csp.script_src(vec!["'self'"])
                .style_src(vec!["'self'"])
                .with_nonce()
        } else {
            csp.script_src(vec!["'self'", "'unsafe-inline'"])
        };

        SecurityHeaders::builder()
            .content_security_policy(csp)
            .strict_transport_security(ONE_YEAR, true, false)
            .x_frame_options_sameorigin()
            .x_content_type_options_nosniff()
            .referrer_policy_strict_origin_when_cross_origin()
            .permissions_policy(
                PermissionsPolicy::new()
                    .deny("camera")
                    .deny("geolocation")
                    .deny("microphone"),
            )
            .cross_origin_opener_policy(CrossOriginOpenerPolicy::SameOriginAllowPopups)
            .build()
            .expect("balanced preset should always be valid")
    }

    fn build_relaxed() -> SecurityHeaders {
        SecurityHeaders::builder()
            .strict_transport_security(SIX_MONTHS, false, false)
            .x_frame_options_sameorigin()
            .x_content_type_options_nosniff()
            .referrer_policy_strict_origin_when_cross_origin()
            .build()
            .expect("relaxed preset should always be valid")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strict_preset() {
        let headers = Preset::Strict.build();

        assert!(headers.content_security_policy().is_some());
        assert!(headers.strict_transport_security().is_some());
        assert_eq!(headers.x_frame_options(), Some(XFrameOptions::Deny));
        assert!(headers.x_content_type_options_enabled());
        assert_eq!(headers.referrer_policy(), Some(ReferrerPolicy::NoReferrer));
        assert!(headers.permissions_policy().is_some());
        assert_eq!(
            headers.cross_origin_opener_policy(),
            Some(CrossOriginOpenerPolicy::SameOrigin)
        );
        assert_eq!(
            headers.cross_origin_embedder_policy(),
            Some(CrossOriginEmbedderPolicy::RequireCorp)
        );
        assert_eq!(
            headers.cross_origin_resource_policy(),
            Some(CrossOriginResourcePolicy::SameOrigin)
        );
    }

    #[test]
    fn test_balanced_preset() {
        let headers = Preset::Balanced.build();

        assert!(headers.content_security_policy().is_some());
        assert!(headers.strict_transport_security().is_some());
        assert_eq!(headers.x_frame_options(), Some(XFrameOptions::SameOrigin));
        assert!(headers.x_content_type_options_enabled());
        assert_eq!(
            headers.referrer_policy(),
            Some(ReferrerPolicy::StrictOriginWhenCrossOrigin)
        );
        assert_eq!(
            headers.cross_origin_opener_policy(),
            Some(CrossOriginOpenerPolicy::SameOriginAllowPopups)
        );
        assert!(!headers.needs_nonce());
    }

    #[test]
    fn test_relaxed_preset() {
        let headers = Preset::Relaxed.build();

        assert!(headers.content_security_policy().is_none());
        assert!(headers.strict_transport_security().is_some());
        assert_eq!(headers.x_frame_options(), Some(XFrameOptions::SameOrigin));
        assert!(headers.x_content_type_options_enabled());
        assert_eq!(
            headers.referrer_policy(),
            Some(ReferrerPolicy::StrictOriginWhenCrossOrigin)
        );

        let hsts = headers.strict_transport_security().unwrap();
        assert_eq!(hsts.max_age(), SIX_MONTHS);
    }

    #[test]
    fn test_balanced_nonce_drops_unsafe_inline() {
        let headers = Preset::BalancedNonce.build();
        let csp = headers.content_security_policy().unwrap();

        assert!(headers.needs_nonce());
        assert!(
            !csp.to_header_value().unwrap().contains("'unsafe-inline'"),
            "the nonce variant exists precisely to avoid 'unsafe-inline'"
        );

        let nonce = Nonce::from_encoded("dGVzdA==").unwrap();
        let rendered = csp.to_header_value_with_nonce(&nonce).unwrap();
        assert!(rendered.contains("script-src 'self' 'nonce-dGVzdA=='"));
        assert!(rendered.contains("style-src 'self' 'nonce-dGVzdA=='"));
    }

    #[test]
    fn test_balanced_variants_differ_only_in_script_and_style() {
        let plain = Preset::Balanced.build();
        let nonced = Preset::BalancedNonce.build();

        assert_eq!(
            plain.strict_transport_security(),
            nonced.strict_transport_security()
        );
        assert_eq!(plain.x_frame_options(), nonced.x_frame_options());
        assert_eq!(plain.referrer_policy(), nonced.referrer_policy());
        assert_eq!(plain.permissions_policy(), nonced.permissions_policy());
        assert_eq!(
            plain.cross_origin_opener_policy(),
            nonced.cross_origin_opener_policy()
        );
    }

    #[test]
    fn test_balanced_documents_its_unsafe_inline() {
        // Guards the doc comment above: if this ever stops being true, the warning
        // on `Preset::Balanced` needs rewriting too.
        let csp = Preset::Balanced.build();
        let value = csp
            .content_security_policy()
            .unwrap()
            .to_header_value()
            .unwrap();
        assert!(value.contains("script-src 'self' 'unsafe-inline'"));
    }

    #[test]
    fn test_every_preset_builds_and_renders() {
        for preset in [
            Preset::Strict,
            Preset::Balanced,
            Preset::BalancedNonce,
            Preset::Relaxed,
        ] {
            let headers = preset.build();
            assert!(
                !headers.header_pairs().is_empty(),
                "{preset:?} rendered no headers"
            );
        }
    }
}
