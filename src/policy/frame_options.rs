//! X-Frame-Options header configuration.
//!
//! The X-Frame-Options header protects against clickjacking attacks by controlling
//! whether a browser should be allowed to render a page in a `<frame>`, `<iframe>`,
//! `<embed>`, or `<object>`.

use crate::error::{Error, Result};

/// X-Frame-Options header value.
///
/// # Examples
///
/// ```
/// use http_security_headers::XFrameOptions;
///
/// let deny = XFrameOptions::Deny;
/// let sameorigin = XFrameOptions::SameOrigin;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XFrameOptions {
    /// The page cannot be displayed in a frame, regardless of the site attempting to do so.
    Deny,
    /// The page can only be displayed in a frame on the same origin as the page itself.
    SameOrigin,
}

impl XFrameOptions {
    /// Converts the policy to its header value string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Deny => "DENY",
            Self::SameOrigin => "SAMEORIGIN",
        }
    }
}

impl std::str::FromStr for XFrameOptions {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_uppercase().as_str() {
            "DENY" => Ok(Self::Deny),
            "SAMEORIGIN" => Ok(Self::SameOrigin),
            _ => Err(Error::InvalidFrameOptions(format!(
                "Expected 'DENY' or 'SAMEORIGIN', got '{}'",
                s
            ))),
        }
    }
}

impl std::fmt::Display for XFrameOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_as_str() {
        assert_eq!(XFrameOptions::Deny.as_str(), "DENY");
        assert_eq!(XFrameOptions::SameOrigin.as_str(), "SAMEORIGIN");
    }

    #[test]
    fn test_from_str() {
        assert_eq!(
            XFrameOptions::from_str("DENY").unwrap(),
            XFrameOptions::Deny
        );
        assert_eq!(
            XFrameOptions::from_str("deny").unwrap(),
            XFrameOptions::Deny
        );
        assert_eq!(
            XFrameOptions::from_str("SAMEORIGIN").unwrap(),
            XFrameOptions::SameOrigin
        );
        assert_eq!(
            XFrameOptions::from_str("sameorigin").unwrap(),
            XFrameOptions::SameOrigin
        );

        assert!(XFrameOptions::from_str("invalid").is_err());
    }

    #[test]
    fn test_display() {
        assert_eq!(XFrameOptions::Deny.to_string(), "DENY");
        assert_eq!(XFrameOptions::SameOrigin.to_string(), "SAMEORIGIN");
    }
}
