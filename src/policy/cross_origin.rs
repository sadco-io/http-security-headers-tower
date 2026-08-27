//! Cross-Origin policy headers configuration.
//!
//! These headers help protect against Spectre-like attacks and control how resources
//! are shared across origins.

use crate::error::{Error, Result};

/// Cross-Origin-Opener-Policy (COOP) header value.
///
/// COOP allows you to ensure a top-level document does not share a browsing context
/// group with cross-origin documents.
///
/// # Examples
///
/// ```
/// use http_security_headers::CrossOriginOpenerPolicy;
///
/// let policy = CrossOriginOpenerPolicy::SameOrigin;
/// let policy = CrossOriginOpenerPolicy::SameOriginAllowPopups;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrossOriginOpenerPolicy {
    /// Isolates the browsing context exclusively to same-origin documents.
    SameOrigin,
    /// Retains references to newly opened windows or tabs which don't set COOP or opt out
    /// by setting COOP to `unsafe-none`.
    SameOriginAllowPopups,
    /// This is the default value and allows the document to be added to its opener's
    /// browsing context group unless the opener itself has a COOP of `same-origin` or
    /// `same-origin-allow-popups`.
    UnsafeNone,
}

impl CrossOriginOpenerPolicy {
    /// Converts the policy to its header value string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SameOrigin => "same-origin",
            Self::SameOriginAllowPopups => "same-origin-allow-popups",
            Self::UnsafeNone => "unsafe-none",
        }
    }
}

impl std::str::FromStr for CrossOriginOpenerPolicy {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "same-origin" => Ok(Self::SameOrigin),
            "same-origin-allow-popups" => Ok(Self::SameOriginAllowPopups),
            "unsafe-none" => Ok(Self::UnsafeNone),
            _ => Err(Error::InvalidCoop(format!(
                "Unknown Cross-Origin-Opener-Policy: '{}'",
                s
            ))),
        }
    }
}

impl std::fmt::Display for CrossOriginOpenerPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Cross-Origin-Embedder-Policy (COEP) header value.
///
/// COEP prevents a document from loading any cross-origin resources that don't explicitly
/// grant the document permission to be loaded.
///
/// # Examples
///
/// ```
/// use http_security_headers::CrossOriginEmbedderPolicy;
///
/// let policy = CrossOriginEmbedderPolicy::RequireCorp;
/// let policy = CrossOriginEmbedderPolicy::UnsafeNone;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrossOriginEmbedderPolicy {
    /// This is the default value and allows the document to fetch cross-origin resources
    /// without giving explicit permission through the CORS protocol or CORP header.
    UnsafeNone,
    /// A document can only load resources from the same origin, or resources explicitly
    /// marked as loadable from another origin.
    RequireCorp,
    /// A more permissive variant of `require-corp` that reports (but doesn't block)
    /// violations and allows cross-origin resources without CORP headers to load.
    Credentialless,
}

impl CrossOriginEmbedderPolicy {
    /// Converts the policy to its header value string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UnsafeNone => "unsafe-none",
            Self::RequireCorp => "require-corp",
            Self::Credentialless => "credentialless",
        }
    }
}

impl std::str::FromStr for CrossOriginEmbedderPolicy {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "unsafe-none" => Ok(Self::UnsafeNone),
            "require-corp" => Ok(Self::RequireCorp),
            "credentialless" => Ok(Self::Credentialless),
            _ => Err(Error::InvalidCoep(format!(
                "Unknown Cross-Origin-Embedder-Policy: '{}'",
                s
            ))),
        }
    }
}

impl std::fmt::Display for CrossOriginEmbedderPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Cross-Origin-Resource-Policy (CORP) header value.
///
/// CORP allows you to control the set of origins that are empowered to include a resource.
///
/// # Examples
///
/// ```
/// use http_security_headers::CrossOriginResourcePolicy;
///
/// let policy = CrossOriginResourcePolicy::SameOrigin;
/// let policy = CrossOriginResourcePolicy::SameSite;
/// let policy = CrossOriginResourcePolicy::CrossOrigin;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrossOriginResourcePolicy {
    /// Only requests from the same origin can read the resource.
    SameOrigin,
    /// Only requests from the same site can read the resource.
    SameSite,
    /// Requests from any origin can read the resource.
    CrossOrigin,
}

impl CrossOriginResourcePolicy {
    /// Converts the policy to its header value string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SameOrigin => "same-origin",
            Self::SameSite => "same-site",
            Self::CrossOrigin => "cross-origin",
        }
    }
}

impl std::str::FromStr for CrossOriginResourcePolicy {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "same-origin" => Ok(Self::SameOrigin),
            "same-site" => Ok(Self::SameSite),
            "cross-origin" => Ok(Self::CrossOrigin),
            _ => Err(Error::InvalidCorp(format!(
                "Unknown Cross-Origin-Resource-Policy: '{}'",
                s
            ))),
        }
    }
}

impl std::fmt::Display for CrossOriginResourcePolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    // COOP tests
    #[test]
    fn test_coop_as_str() {
        assert_eq!(CrossOriginOpenerPolicy::SameOrigin.as_str(), "same-origin");
        assert_eq!(
            CrossOriginOpenerPolicy::SameOriginAllowPopups.as_str(),
            "same-origin-allow-popups"
        );
        assert_eq!(CrossOriginOpenerPolicy::UnsafeNone.as_str(), "unsafe-none");
    }

    #[test]
    fn test_coop_from_str() {
        assert_eq!(
            CrossOriginOpenerPolicy::from_str("same-origin").unwrap(),
            CrossOriginOpenerPolicy::SameOrigin
        );
        assert_eq!(
            CrossOriginOpenerPolicy::from_str("same-origin-allow-popups").unwrap(),
            CrossOriginOpenerPolicy::SameOriginAllowPopups
        );
        assert_eq!(
            CrossOriginOpenerPolicy::from_str("unsafe-none").unwrap(),
            CrossOriginOpenerPolicy::UnsafeNone
        );
        assert!(CrossOriginOpenerPolicy::from_str("invalid").is_err());
    }

    // COEP tests
    #[test]
    fn test_coep_as_str() {
        assert_eq!(
            CrossOriginEmbedderPolicy::UnsafeNone.as_str(),
            "unsafe-none"
        );
        assert_eq!(
            CrossOriginEmbedderPolicy::RequireCorp.as_str(),
            "require-corp"
        );
        assert_eq!(
            CrossOriginEmbedderPolicy::Credentialless.as_str(),
            "credentialless"
        );
    }

    #[test]
    fn test_coep_from_str() {
        assert_eq!(
            CrossOriginEmbedderPolicy::from_str("unsafe-none").unwrap(),
            CrossOriginEmbedderPolicy::UnsafeNone
        );
        assert_eq!(
            CrossOriginEmbedderPolicy::from_str("require-corp").unwrap(),
            CrossOriginEmbedderPolicy::RequireCorp
        );
        assert_eq!(
            CrossOriginEmbedderPolicy::from_str("credentialless").unwrap(),
            CrossOriginEmbedderPolicy::Credentialless
        );
        assert!(CrossOriginEmbedderPolicy::from_str("invalid").is_err());
    }

    // CORP tests
    #[test]
    fn test_corp_as_str() {
        assert_eq!(
            CrossOriginResourcePolicy::SameOrigin.as_str(),
            "same-origin"
        );
        assert_eq!(CrossOriginResourcePolicy::SameSite.as_str(), "same-site");
        assert_eq!(
            CrossOriginResourcePolicy::CrossOrigin.as_str(),
            "cross-origin"
        );
    }

    #[test]
    fn test_corp_from_str() {
        assert_eq!(
            CrossOriginResourcePolicy::from_str("same-origin").unwrap(),
            CrossOriginResourcePolicy::SameOrigin
        );
        assert_eq!(
            CrossOriginResourcePolicy::from_str("same-site").unwrap(),
            CrossOriginResourcePolicy::SameSite
        );
        assert_eq!(
            CrossOriginResourcePolicy::from_str("cross-origin").unwrap(),
            CrossOriginResourcePolicy::CrossOrigin
        );
        assert!(CrossOriginResourcePolicy::from_str("invalid").is_err());
    }

    #[test]
    fn test_display() {
        assert_eq!(
            CrossOriginOpenerPolicy::SameOrigin.to_string(),
            "same-origin"
        );
        assert_eq!(
            CrossOriginEmbedderPolicy::RequireCorp.to_string(),
            "require-corp"
        );
        assert_eq!(CrossOriginResourcePolicy::SameSite.to_string(), "same-site");
    }
}
