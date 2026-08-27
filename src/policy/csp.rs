//! Content-Security-Policy (CSP) header configuration.
//!
//! CSP helps prevent cross-site scripting (XSS), clickjacking, and other code injection
//! attacks by specifying which dynamic resources are allowed to load.

use crate::error::{Error, Result};
use crate::policy::Nonce;
use std::collections::{BTreeMap, BTreeSet};

/// Content-Security-Policy configuration.
///
/// Directives are held in a [`BTreeMap`], so the rendered header is byte-identical
/// for two policies configured in different orders.
///
/// # Examples
///
/// ```
/// use http_security_headers::ContentSecurityPolicy;
///
/// let csp = ContentSecurityPolicy::new()
///     .default_src(vec!["'self'"])
///     .script_src(vec!["'self'", "'unsafe-inline'"])
///     .style_src(vec!["'self'", "https://fonts.googleapis.com"])
///     .img_src(vec!["'self'", "data:", "https:"]);
/// ```
///
/// # Nonces
///
/// Mark directives with [`with_nonce`] or [`nonce_for`] and the Tower middleware will
/// mint a fresh nonce for every request, inject it into those directives, and hand it
/// to your handler through the request extensions:
///
/// ```
/// use http_security_headers::ContentSecurityPolicy;
///
/// let csp = ContentSecurityPolicy::new()
///     .default_src(vec!["'self'"])
///     .script_src(vec!["'self'"])
///     .with_nonce();
///
/// assert!(csp.requires_nonce());
/// ```
///
/// [`with_nonce`]: ContentSecurityPolicy::with_nonce
/// [`nonce_for`]: ContentSecurityPolicy::nonce_for
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ContentSecurityPolicy {
    directives: BTreeMap<String, Vec<String>>,
    nonce_directives: BTreeSet<String>,
}

impl ContentSecurityPolicy {
    /// Creates a new empty CSP policy.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the `default-src` directive.
    ///
    /// This serves as a fallback for other fetch directives.
    pub fn default_src<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.set_directive("default-src", sources);
        self
    }

    /// Sets the `script-src` directive.
    ///
    /// Specifies valid sources for JavaScript.
    pub fn script_src<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.set_directive("script-src", sources);
        self
    }

    /// Sets the `style-src` directive.
    ///
    /// Specifies valid sources for stylesheets.
    pub fn style_src<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.set_directive("style-src", sources);
        self
    }

    /// Sets the `img-src` directive.
    ///
    /// Specifies valid sources for images.
    pub fn img_src<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.set_directive("img-src", sources);
        self
    }

    /// Sets the `font-src` directive.
    ///
    /// Specifies valid sources for fonts.
    pub fn font_src<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.set_directive("font-src", sources);
        self
    }

    /// Sets the `connect-src` directive.
    ///
    /// Restricts URLs that can be loaded using script interfaces (fetch, XHR, WebSocket, etc.).
    pub fn connect_src<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.set_directive("connect-src", sources);
        self
    }

    /// Sets the `object-src` directive.
    ///
    /// Specifies valid sources for `<object>`, `<embed>`, and `<applet>` elements.
    pub fn object_src<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.set_directive("object-src", sources);
        self
    }

    /// Sets the `frame-src` directive.
    ///
    /// Specifies valid sources for nested browsing contexts loaded using `<frame>` and `<iframe>`.
    pub fn frame_src<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.set_directive("frame-src", sources);
        self
    }

    /// Sets the `base-uri` directive.
    ///
    /// Restricts the URLs that can be used in a document's `<base>` element.
    pub fn base_uri<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.set_directive("base-uri", sources);
        self
    }

    /// Sets the `form-action` directive.
    ///
    /// Restricts the URLs which can be used as the target of form submissions.
    pub fn form_action<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.set_directive("form-action", sources);
        self
    }

    /// Sets the `frame-ancestors` directive.
    ///
    /// Specifies valid parents that may embed a page using `<frame>`, `<iframe>`, etc.
    pub fn frame_ancestors<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.set_directive("frame-ancestors", sources);
        self
    }

    /// Sets the `report-uri` directive.
    ///
    /// Deprecated in favour of `report-to`, but still the directive most browsers
    /// actually honour. Setting both is the usual advice.
    pub fn report_uri<I, S>(mut self, endpoints: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.set_directive("report-uri", endpoints);
        self
    }

    /// Sets the `report-to` directive, naming a group from the `Reporting-Endpoints` header.
    pub fn report_to(mut self, group: &str) -> Self {
        self.set_directive("report-to", [group]);
        self
    }

    /// Sets the `upgrade-insecure-requests` directive (valueless).
    ///
    /// Instructs browsers to upgrade all insecure requests to HTTPS.
    pub fn upgrade_insecure_requests(mut self) -> Self {
        self.directives
            .insert("upgrade-insecure-requests".to_string(), vec![]);
        self
    }

    /// Sets the `block-all-mixed-content` directive (valueless).
    ///
    /// Prevents loading any mixed content (HTTP resources on HTTPS pages).
    ///
    /// Obsolete: browsers now upgrade or block mixed content by default. Prefer
    /// [`upgrade_insecure_requests`](Self::upgrade_insecure_requests).
    pub fn block_all_mixed_content(mut self) -> Self {
        self.directives
            .insert("block-all-mixed-content".to_string(), vec![]);
        self
    }

    /// Sets a custom directive.
    ///
    /// This allows setting directives not covered by the convenience methods.
    pub fn directive<I, S>(mut self, name: &str, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.set_directive(name, sources);
        self
    }

    /// Requests a per-request nonce for `script-src` and `style-src`.
    ///
    /// Equivalent to `nonce_for(["script-src", "style-src"])`. The directives must
    /// also exist in the policy -- a nonce is added to a directive, it does not
    /// create one.
    pub fn with_nonce(self) -> Self {
        self.nonce_for(["script-src", "style-src"])
    }

    /// Requests a per-request nonce for specific directives.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_security_headers::ContentSecurityPolicy;
    ///
    /// let csp = ContentSecurityPolicy::new()
    ///     .script_src(vec!["'self'"])
    ///     .nonce_for(["script-src"]);
    ///
    /// assert!(csp.requires_nonce());
    /// ```
    pub fn nonce_for<I, S>(mut self, directives: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for directive in directives {
            self.nonce_directives.insert(directive.into());
        }
        self
    }

    /// Adds `'strict-dynamic'` to `script-src`.
    ///
    /// `'strict-dynamic'` tells the browser to trust scripts loaded by an
    /// already-trusted script, and to ignore host allowlists in `script-src`. It is
    /// only meaningful alongside a nonce or a hash.
    pub fn strict_dynamic(mut self) -> Self {
        self.directives
            .entry("script-src".to_string())
            .or_default()
            .push("'strict-dynamic'".to_string());
        self
    }

    /// Returns whether any directive is configured to receive a per-request nonce.
    pub fn requires_nonce(&self) -> bool {
        !self.nonce_directives.is_empty()
    }

    /// Returns whether the policy has no directives.
    pub fn is_empty(&self) -> bool {
        self.directives.is_empty()
    }

    /// Returns the number of configured directives.
    pub fn len(&self) -> usize {
        self.directives.len()
    }

    /// Returns the sources configured for a directive, if it is set.
    pub fn get(&self, directive: &str) -> Option<&[String]> {
        self.directives.get(directive).map(Vec::as_slice)
    }

    /// Helper method to set a directive.
    fn set_directive<I, S>(&mut self, name: &str, sources: I)
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let sources: Vec<String> = sources.into_iter().map(Into::into).collect();
        self.directives.insert(name.to_string(), sources);
    }

    /// Converts the policy to its header value string.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidCsp`] if the policy is empty, or if a directive name
    /// or source contains a character that cannot appear in an HTTP header value.
    ///
    /// If the policy [requires a nonce](Self::requires_nonce), the nonce directives
    /// are rendered without one -- use [`to_header_value_with_nonce`] instead.
    ///
    /// [`to_header_value_with_nonce`]: Self::to_header_value_with_nonce
    pub fn to_header_value(&self) -> Result<String> {
        self.render(None)
    }

    /// Converts the policy to its header value string, injecting `nonce` into every
    /// directive registered with [`nonce_for`](Self::nonce_for).
    ///
    /// # Examples
    ///
    /// ```
    /// use http_security_headers::{ContentSecurityPolicy, Nonce};
    ///
    /// let csp = ContentSecurityPolicy::new()
    ///     .script_src(vec!["'self'"])
    ///     .nonce_for(["script-src"]);
    ///
    /// let nonce = Nonce::from_encoded("dGVzdA==").unwrap();
    /// assert_eq!(
    ///     csp.to_header_value_with_nonce(&nonce).unwrap(),
    ///     "script-src 'self' 'nonce-dGVzdA=='"
    /// );
    /// ```
    pub fn to_header_value_with_nonce(&self, nonce: &Nonce) -> Result<String> {
        self.render(Some(nonce))
    }

    fn render(&self, nonce: Option<&Nonce>) -> Result<String> {
        if self.directives.is_empty() {
            return Err(Error::InvalidCsp("CSP policy is empty".to_string()));
        }

        let mut parts = Vec::with_capacity(self.directives.len());

        for (directive, sources) in &self.directives {
            validate_token(directive, "directive name")?;

            let mut rendered: Vec<&str> = Vec::with_capacity(sources.len() + 1);
            for source in sources {
                validate_token(source, "source")?;
                rendered.push(source);
            }

            let nonce_source;
            if let Some(nonce) = nonce {
                if self.nonce_directives.contains(directive) {
                    nonce_source = nonce.source();
                    rendered.push(&nonce_source);
                }
            }

            if rendered.is_empty() {
                // Valueless directives (upgrade-insecure-requests, block-all-mixed-content)
                parts.push(directive.clone());
            } else {
                parts.push(format!("{directive} {}", rendered.join(" ")));
            }
        }

        Ok(parts.join("; "))
    }

    /// Parses a CSP policy from a header value string.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_security_headers::ContentSecurityPolicy;
    ///
    /// let csp = ContentSecurityPolicy::parse("default-src 'self'; script-src 'unsafe-inline'").unwrap();
    /// ```
    pub fn parse(value: &str) -> Result<Self> {
        let mut csp = Self::new();

        for directive_str in value.split(';').map(str::trim) {
            if directive_str.is_empty() {
                continue;
            }

            let mut parts = directive_str.split_whitespace();
            let Some(directive_name) = parts.next() else {
                continue;
            };

            validate_token(directive_name, "directive name")?;

            let mut sources = Vec::new();
            for source in parts {
                validate_token(source, "source")?;
                sources.push(source.to_string());
            }

            csp.directives.insert(directive_name.to_string(), sources);
        }

        if csp.directives.is_empty() {
            return Err(Error::InvalidCsp("No directives found".to_string()));
        }

        Ok(csp)
    }
}

/// Rejects anything that could not survive `HeaderValue` parsing.
///
/// Without this, a stray control character makes the whole header unparseable, and
/// the middleware would silently ship a response with no CSP at all. Catching it
/// here turns a silent security regression into a `build()` error.
fn validate_token(token: &str, kind: &str) -> Result<()> {
    if token.is_empty() {
        return Err(Error::InvalidCsp(format!("Empty CSP {kind}")));
    }

    if let Some(bad) = token
        .chars()
        .find(|c| c.is_control() || *c == ';' || *c == ',' || !c.is_ascii())
    {
        return Err(Error::InvalidCsp(format!(
            "CSP {kind} '{}' contains an illegal character {bad:?}",
            token.escape_debug()
        )));
    }

    Ok(())
}

impl std::fmt::Display for ContentSecurityPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_header_value().unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let csp = ContentSecurityPolicy::new();
        assert!(csp.is_empty());
    }

    #[test]
    fn test_builder() {
        let csp = ContentSecurityPolicy::new()
            .default_src(vec!["'self'"])
            .script_src(vec!["'self'", "'unsafe-inline'"])
            .style_src(vec!["'self'", "https://fonts.googleapis.com"]);

        assert_eq!(csp.len(), 3);
        assert_eq!(csp.get("default-src").unwrap(), ["'self'"]);
        assert_eq!(
            csp.get("script-src").unwrap(),
            ["'self'", "'unsafe-inline'"]
        );
    }

    #[test]
    fn test_to_header_value() {
        let csp = ContentSecurityPolicy::new()
            .default_src(vec!["'self'"])
            .script_src(vec!["'self'", "'unsafe-inline'"]);

        assert_eq!(
            csp.to_header_value().unwrap(),
            "default-src 'self'; script-src 'self' 'unsafe-inline'"
        );
    }

    #[test]
    fn test_directive_order_is_independent_of_insertion_order() {
        let a = ContentSecurityPolicy::new()
            .script_src(vec!["'self'"])
            .default_src(vec!["'self'"]);
        let b = ContentSecurityPolicy::new()
            .default_src(vec!["'self'"])
            .script_src(vec!["'self'"]);

        assert_eq!(a.to_header_value().unwrap(), b.to_header_value().unwrap());
    }

    #[test]
    fn test_valueless_directives() {
        let csp = ContentSecurityPolicy::new()
            .default_src(vec!["'self'"])
            .upgrade_insecure_requests();

        let header = csp.to_header_value().unwrap();
        assert!(header.contains("upgrade-insecure-requests"));
        assert!(header.contains("default-src 'self'"));
    }

    #[test]
    fn test_empty_policy_error() {
        let csp = ContentSecurityPolicy::new();
        assert!(csp.to_header_value().is_err());
    }

    #[test]
    fn test_parse() {
        let csp =
            ContentSecurityPolicy::parse("default-src 'self'; script-src 'unsafe-inline'").unwrap();

        assert_eq!(csp.len(), 2);
        assert_eq!(csp.get("default-src").unwrap(), ["'self'"]);
        assert_eq!(csp.get("script-src").unwrap(), ["'unsafe-inline'"]);
    }

    #[test]
    fn test_parse_empty() {
        assert!(ContentSecurityPolicy::parse("").is_err());
        assert!(ContentSecurityPolicy::parse("   ").is_err());
    }

    #[test]
    fn test_custom_directive() {
        let csp = ContentSecurityPolicy::new().directive("worker-src", vec!["'self'", "blob:"]);

        assert_eq!(csp.get("worker-src").unwrap(), ["'self'", "blob:"]);
    }

    #[test]
    fn test_source_with_control_character_is_rejected() {
        // Without validation this renders a header value that `HeaderValue` refuses,
        // and the middleware would then ship a response with no CSP at all.
        let csp = ContentSecurityPolicy::new().default_src(vec!["https://evil\r\nX-Evil: 1"]);
        assert!(csp.to_header_value().is_err());
    }

    #[test]
    fn test_source_with_non_ascii_is_rejected() {
        let csp = ContentSecurityPolicy::new().default_src(vec!["https://exämple.com"]);
        assert!(csp.to_header_value().is_err());
    }

    #[test]
    fn test_source_containing_directive_separator_is_rejected() {
        let csp =
            ContentSecurityPolicy::new().default_src(vec!["'self'; script-src 'unsafe-inline'"]);
        assert!(csp.to_header_value().is_err());
    }

    #[test]
    fn test_nonce_injection() {
        let csp = ContentSecurityPolicy::new()
            .default_src(vec!["'self'"])
            .script_src(vec!["'self'"])
            .nonce_for(["script-src"]);

        let nonce = Nonce::from_encoded("dGVzdA==").unwrap();
        assert_eq!(
            csp.to_header_value_with_nonce(&nonce).unwrap(),
            "default-src 'self'; script-src 'self' 'nonce-dGVzdA=='"
        );
    }

    #[test]
    fn test_with_nonce_covers_script_and_style() {
        let csp = ContentSecurityPolicy::new()
            .script_src(vec!["'self'"])
            .style_src(vec!["'self'"])
            .with_nonce();

        let nonce = Nonce::from_encoded("dGVzdA==").unwrap();
        let header = csp.to_header_value_with_nonce(&nonce).unwrap();

        assert!(header.contains("script-src 'self' 'nonce-dGVzdA=='"));
        assert!(header.contains("style-src 'self' 'nonce-dGVzdA=='"));
    }

    #[test]
    fn test_requires_nonce() {
        assert!(!ContentSecurityPolicy::new()
            .script_src(vec!["'self'"])
            .requires_nonce());
        assert!(ContentSecurityPolicy::new()
            .script_src(vec!["'self'"])
            .with_nonce()
            .requires_nonce());
    }

    #[test]
    fn test_nonce_is_omitted_without_one() {
        let csp = ContentSecurityPolicy::new()
            .script_src(vec!["'self'"])
            .nonce_for(["script-src"]);

        assert_eq!(csp.to_header_value().unwrap(), "script-src 'self'");
    }

    #[test]
    fn test_strict_dynamic() {
        let csp = ContentSecurityPolicy::new()
            .script_src(vec!["'self'"])
            .strict_dynamic();

        assert_eq!(
            csp.to_header_value().unwrap(),
            "script-src 'self' 'strict-dynamic'"
        );
    }

    #[test]
    fn test_report_directives() {
        let csp = ContentSecurityPolicy::new()
            .default_src(vec!["'self'"])
            .report_uri(vec!["/csp-report"])
            .report_to("csp-endpoint");

        let header = csp.to_header_value().unwrap();
        assert!(header.contains("report-uri /csp-report"));
        assert!(header.contains("report-to csp-endpoint"));
    }

    #[test]
    fn test_display() {
        let csp = ContentSecurityPolicy::new().default_src(vec!["'self'"]);
        assert_eq!(csp.to_string(), "default-src 'self'");
    }
}
