//! Permissions-Policy header configuration.
//!
//! Permissions-Policy (formerly Feature-Policy) controls which browser features and
//! APIs a document and its embedded frames may use -- camera, microphone, geolocation,
//! payment and so on.
//!
//! The header is a structured-fields dictionary: each feature maps to an allowlist,
//! written as a parenthesised list of origins. The two common cases are `()` -- an
//! empty allowlist, meaning the feature is denied everywhere -- and `(self)`, meaning
//! only the document's own origin may use it.
//!
//! ```text
//! Permissions-Policy: camera=(), geolocation=(self), fullscreen=(self "https://cdn.example.com")
//! ```

use crate::error::{Error, Result};
use std::collections::BTreeMap;

/// Permissions-Policy configuration.
///
/// Directives are stored in a [`BTreeMap`], so [`to_header_value`] emits them in a
/// stable alphabetical order regardless of the order they were configured in.
///
/// # Examples
///
/// ```
/// use http_security_headers::PermissionsPolicy;
///
/// let policy = PermissionsPolicy::new()
///     .deny("camera")
///     .deny("microphone")
///     .self_only("geolocation")
///     .allow("fullscreen", vec!["'self'", "https://player.example.com"]);
///
/// assert_eq!(
///     policy.to_header_value().unwrap(),
///     "camera=(), fullscreen=(self \"https://player.example.com\"), geolocation=(self), microphone=()"
/// );
/// ```
///
/// [`to_header_value`]: PermissionsPolicy::to_header_value
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PermissionsPolicy {
    directives: BTreeMap<String, Allowlist>,
}

/// The allowlist for a single Permissions-Policy feature.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Allowlist {
    /// `*` -- every origin, including cross-origin frames.
    Any,
    /// A parenthesised origin list, possibly empty.
    Origins(Vec<String>),
}

impl PermissionsPolicy {
    /// Creates a new, empty Permissions-Policy.
    pub fn new() -> Self {
        Self::default()
    }

    /// Denies a feature outright by giving it an empty allowlist -- `feature=()`.
    ///
    /// This is the strongest setting: neither the document nor any embedded frame
    /// may use the feature.
    pub fn deny(mut self, feature: &str) -> Self {
        self.directives
            .insert(feature.to_string(), Allowlist::Origins(Vec::new()));
        self
    }

    /// Restricts a feature to the document's own origin -- `feature=(self)`.
    pub fn self_only(mut self, feature: &str) -> Self {
        self.directives.insert(
            feature.to_string(),
            Allowlist::Origins(vec!["self".to_string()]),
        );
        self
    }

    /// Allows a feature for every origin -- `feature=*`.
    ///
    /// Rarely what you want; prefer [`allow`](Self::allow) with an explicit list.
    pub fn any(mut self, feature: &str) -> Self {
        self.directives.insert(feature.to_string(), Allowlist::Any);
        self
    }

    /// Allows a feature for an explicit list of origins.
    ///
    /// The token `self` (with or without the CSP-style surrounding quotes) is
    /// emitted bare, as the structured-fields grammar requires; every other entry is
    /// emitted as a quoted string.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_security_headers::PermissionsPolicy;
    ///
    /// let policy = PermissionsPolicy::new()
    ///     .allow("payment", vec!["self", "https://checkout.example.com"]);
    ///
    /// assert_eq!(
    ///     policy.to_header_value().unwrap(),
    ///     "payment=(self \"https://checkout.example.com\")"
    /// );
    /// ```
    pub fn allow<I, S>(mut self, feature: &str, origins: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let origins: Vec<String> = origins.into_iter().map(Into::into).collect();
        self.directives
            .insert(feature.to_string(), Allowlist::Origins(origins));
        self
    }

    /// Returns whether any feature has been configured.
    pub fn is_empty(&self) -> bool {
        self.directives.is_empty()
    }

    /// Returns the number of configured features.
    pub fn len(&self) -> usize {
        self.directives.len()
    }

    /// Converts the policy to its header value string.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPermissionsPolicy`] if no features are configured, if a
    /// feature name is not a valid structured-fields token, or if an origin contains a
    /// character that cannot appear in a quoted string.
    pub fn to_header_value(&self) -> Result<String> {
        if self.directives.is_empty() {
            return Err(Error::InvalidPermissionsPolicy(
                "Permissions-Policy is empty".to_string(),
            ));
        }

        let mut parts = Vec::with_capacity(self.directives.len());

        for (feature, allowlist) in &self.directives {
            validate_feature_name(feature)?;

            match allowlist {
                Allowlist::Any => parts.push(format!("{feature}=*")),
                Allowlist::Origins(origins) => {
                    let mut rendered = Vec::with_capacity(origins.len());
                    for origin in origins {
                        rendered.push(render_origin(feature, origin)?);
                    }
                    parts.push(format!("{feature}=({})", rendered.join(" ")));
                }
            }
        }

        Ok(parts.join(", "))
    }

    /// Parses a Permissions-Policy from a header value string.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_security_headers::PermissionsPolicy;
    ///
    /// let policy = PermissionsPolicy::parse("camera=(), geolocation=(self)").unwrap();
    /// assert_eq!(policy.len(), 2);
    /// ```
    pub fn parse(value: &str) -> Result<Self> {
        let mut policy = Self::new();

        for entry in split_top_level(value) {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }

            let (feature, allowlist) = entry.split_once('=').ok_or_else(|| {
                Error::InvalidPermissionsPolicy(format!("Missing '=' in directive: '{entry}'"))
            })?;

            let feature = feature.trim();
            validate_feature_name(feature)?;

            let allowlist = allowlist.trim();
            if allowlist == "*" {
                policy
                    .directives
                    .insert(feature.to_string(), Allowlist::Any);
                continue;
            }

            let inner = allowlist
                .strip_prefix('(')
                .and_then(|rest| rest.strip_suffix(')'))
                .ok_or_else(|| {
                    Error::InvalidPermissionsPolicy(format!(
                        "Allowlist for '{feature}' must be '*' or parenthesised, got '{allowlist}'"
                    ))
                })?;

            let origins: Vec<String> = inner
                .split_whitespace()
                .map(|origin| origin.trim_matches('"').to_string())
                .collect();

            policy
                .directives
                .insert(feature.to_string(), Allowlist::Origins(origins));
        }

        if policy.directives.is_empty() {
            return Err(Error::InvalidPermissionsPolicy(
                "No directives found".to_string(),
            ));
        }

        Ok(policy)
    }
}

/// Splits on commas that are not inside a parenthesised allowlist.
fn split_top_level(value: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;

    for (index, ch) in value.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                parts.push(&value[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }

    parts.push(&value[start..]);
    parts
}

/// Feature names are structured-fields tokens: lowercase ASCII, digits and `-`.
fn validate_feature_name(feature: &str) -> Result<()> {
    if feature.is_empty() {
        return Err(Error::InvalidPermissionsPolicy(
            "Feature name is empty".to_string(),
        ));
    }

    if !feature
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '*')
    {
        return Err(Error::InvalidPermissionsPolicy(format!(
            "Invalid feature name: '{feature}'"
        )));
    }

    Ok(())
}

/// Renders one allowlist entry, quoting everything except the bare `self` keyword.
fn render_origin(feature: &str, origin: &str) -> Result<String> {
    // Accept the CSP spelling `'self'` as well, since users move between the two
    // headers constantly and the quoting rules differ.
    let unquoted = origin.trim_matches('\'').trim_matches('"');

    if unquoted.eq_ignore_ascii_case("self") {
        return Ok("self".to_string());
    }

    if unquoted == "*" {
        return Ok("*".to_string());
    }

    if unquoted.is_empty() {
        return Err(Error::InvalidPermissionsPolicy(format!(
            "Empty origin in allowlist for '{feature}'"
        )));
    }

    // A quoted string cannot contain a quote, a backslash, or any control
    // character. Rejecting here means the header can never be silently dropped
    // later by `HeaderValue` parsing.
    if unquoted
        .chars()
        .any(|c| c == '"' || c == '\\' || c.is_control() || !c.is_ascii())
    {
        return Err(Error::InvalidPermissionsPolicy(format!(
            "Origin '{unquoted}' for '{feature}' contains a character that cannot appear in a header"
        )));
    }

    Ok(format!("\"{unquoted}\""))
}

impl std::fmt::Display for PermissionsPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_header_value().unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deny_and_self_only() {
        let policy = PermissionsPolicy::new()
            .deny("camera")
            .self_only("geolocation");

        assert_eq!(
            policy.to_header_value().unwrap(),
            "camera=(), geolocation=(self)"
        );
    }

    #[test]
    fn test_allow_quotes_origins_but_not_self() {
        let policy =
            PermissionsPolicy::new().allow("payment", vec!["self", "https://checkout.example.com"]);

        assert_eq!(
            policy.to_header_value().unwrap(),
            "payment=(self \"https://checkout.example.com\")"
        );
    }

    #[test]
    fn test_allow_accepts_csp_style_self() {
        let policy = PermissionsPolicy::new().allow("fullscreen", vec!["'self'"]);
        assert_eq!(policy.to_header_value().unwrap(), "fullscreen=(self)");
    }

    #[test]
    fn test_any() {
        let policy = PermissionsPolicy::new().any("fullscreen");
        assert_eq!(policy.to_header_value().unwrap(), "fullscreen=*");
    }

    #[test]
    fn test_directives_are_sorted() {
        let a = PermissionsPolicy::new().deny("usb").deny("camera");
        let b = PermissionsPolicy::new().deny("camera").deny("usb");

        assert_eq!(a.to_header_value().unwrap(), b.to_header_value().unwrap());
        assert_eq!(a.to_header_value().unwrap(), "camera=(), usb=()");
    }

    #[test]
    fn test_empty_policy_is_an_error() {
        assert!(PermissionsPolicy::new().to_header_value().is_err());
    }

    #[test]
    fn test_invalid_feature_name_is_rejected() {
        let policy = PermissionsPolicy::new().deny("not a feature");
        assert!(policy.to_header_value().is_err());
    }

    #[test]
    fn test_origin_with_control_character_is_rejected() {
        let policy = PermissionsPolicy::new().allow("camera", vec!["https://evil\r\nX: y"]);
        assert!(policy.to_header_value().is_err());
    }

    #[test]
    fn test_origin_with_quote_is_rejected() {
        let policy = PermissionsPolicy::new().allow("camera", vec!["https://a\"b"]);
        assert!(policy.to_header_value().is_err());
    }

    #[test]
    fn test_parse_round_trip() {
        let original = "camera=(), fullscreen=(self \"https://a.example\"), geolocation=*";
        let parsed = PermissionsPolicy::parse(original).unwrap();
        assert_eq!(parsed.to_header_value().unwrap(), original);
    }

    #[test]
    fn test_parse_does_not_split_inside_allowlist() {
        // The comma-free grammar means a naive split(',') is fine, but an
        // allowlist rendered with commas by a non-conforming peer must not
        // produce two bogus directives.
        let parsed =
            PermissionsPolicy::parse("geolocation=(self \"https://a,b.example\")").unwrap();
        assert_eq!(parsed.len(), 1);
    }

    #[test]
    fn test_parse_rejects_malformed() {
        assert!(PermissionsPolicy::parse("").is_err());
        assert!(PermissionsPolicy::parse("camera").is_err());
        assert!(PermissionsPolicy::parse("camera=self").is_err());
    }

    #[test]
    fn test_display() {
        let policy = PermissionsPolicy::new().deny("camera");
        assert_eq!(policy.to_string(), "camera=()");
    }
}
