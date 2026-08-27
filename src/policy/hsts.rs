//! HTTP Strict Transport Security (HSTS) configuration.
//!
//! HSTS tells browsers to only connect to the site over HTTPS, preventing
//! protocol downgrade attacks and cookie hijacking.

use crate::error::{Error, Result};
use std::time::Duration;

/// HTTP Strict Transport Security (HSTS) policy.
///
/// # Examples
///
/// ```
/// use http_security_headers::StrictTransportSecurity;
/// use std::time::Duration;
///
/// // One year HSTS with subdomains
/// let hsts = StrictTransportSecurity::new(Duration::from_secs(31536000))
///     .include_subdomains(true);
///
/// // Custom configuration
/// let hsts = StrictTransportSecurity::new(Duration::from_secs(86400))
///     .include_subdomains(false)
///     .preload(true);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrictTransportSecurity {
    max_age: Duration,
    include_subdomains: bool,
    preload: bool,
}

impl StrictTransportSecurity {
    /// Creates a new HSTS policy with the specified max-age.
    ///
    /// # Arguments
    ///
    /// * `max_age` - The time, in seconds, that the browser should remember to only access the site using HTTPS.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_security_headers::StrictTransportSecurity;
    /// use std::time::Duration;
    ///
    /// let hsts = StrictTransportSecurity::new(Duration::from_secs(31536000)); // 1 year
    /// ```
    pub fn new(max_age: Duration) -> Self {
        Self {
            max_age,
            include_subdomains: false,
            preload: false,
        }
    }

    /// Sets whether the rule applies to all subdomains.
    ///
    /// When enabled, this rule applies to all of the site's subdomains as well.
    pub fn include_subdomains(mut self, include: bool) -> Self {
        self.include_subdomains = include;
        self
    }

    /// Sets whether the site wishes to be included in the HSTS preload list.
    ///
    /// Note: Before enabling preload, ensure your site meets the preload list requirements:
    /// <https://hstspreload.org/>
    pub fn preload(mut self, preload: bool) -> Self {
        self.preload = preload;
        self
    }

    /// Gets the max-age duration.
    pub fn max_age(&self) -> Duration {
        self.max_age
    }

    /// Returns whether subdomains are included.
    pub fn includes_subdomains(&self) -> bool {
        self.include_subdomains
    }

    /// Returns whether preload is enabled.
    pub fn is_preload(&self) -> bool {
        self.preload
    }

    /// Converts the policy to its header value string.
    pub fn to_header_value(&self) -> Result<String> {
        let max_age_secs = self.max_age.as_secs();

        if max_age_secs == 0 {
            return Err(Error::InvalidHsts(
                "max-age must be greater than 0".to_string(),
            ));
        }

        if self.preload {
            if !self.include_subdomains {
                return Err(Error::InvalidHsts(
                    "preload requires includeSubDomains to be enabled".to_string(),
                ));
            }

            if max_age_secs < 31_536_000 {
                return Err(Error::InvalidHsts(
                    "preload requires max-age to be at least 31536000 seconds (1 year)".to_string(),
                ));
            }
        }

        let mut value = format!("max-age={}", max_age_secs);

        if self.include_subdomains {
            value.push_str("; includeSubDomains");
        }

        if self.preload {
            value.push_str("; preload");
        }

        Ok(value)
    }

    /// Parses an HSTS policy from a header value string.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_security_headers::StrictTransportSecurity;
    ///
    /// let hsts = StrictTransportSecurity::parse("max-age=31536000; includeSubDomains").unwrap();
    /// ```
    pub fn parse(value: &str) -> Result<Self> {
        let mut max_age = None;
        let mut include_subdomains = false;
        let mut preload = false;

        for directive in value.split(';').map(|s| s.trim()) {
            if directive.starts_with("max-age=") {
                let age_str = directive.trim_start_matches("max-age=");
                let age_secs = age_str.parse::<u64>().map_err(|_| {
                    Error::InvalidHsts(format!("Invalid max-age value: '{}'", age_str))
                })?;
                max_age = Some(Duration::from_secs(age_secs));
            } else if directive.eq_ignore_ascii_case("includeSubDomains") {
                include_subdomains = true;
            } else if directive.eq_ignore_ascii_case("preload") {
                preload = true;
            }
        }

        let max_age =
            max_age.ok_or_else(|| Error::InvalidHsts("Missing max-age directive".to_string()))?;

        if preload && !include_subdomains {
            return Err(Error::InvalidHsts(
                "preload requires the includeSubDomains directive".to_string(),
            ));
        }

        if preload && max_age.as_secs() < 31_536_000 {
            return Err(Error::InvalidHsts(
                "preload requires max-age to be at least 31536000 seconds (1 year)".to_string(),
            ));
        }

        Ok(Self {
            max_age,
            include_subdomains,
            preload,
        })
    }
}

impl std::fmt::Display for StrictTransportSecurity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_header_value().unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let hsts = StrictTransportSecurity::new(Duration::from_secs(31536000));
        assert_eq!(hsts.max_age(), Duration::from_secs(31536000));
        assert!(!hsts.includes_subdomains());
        assert!(!hsts.is_preload());
    }

    #[test]
    fn test_builder() {
        let hsts = StrictTransportSecurity::new(Duration::from_secs(31536000))
            .include_subdomains(true)
            .preload(true);

        assert_eq!(hsts.max_age(), Duration::from_secs(31536000));
        assert!(hsts.includes_subdomains());
        assert!(hsts.is_preload());
    }

    #[test]
    fn test_to_header_value() {
        let hsts = StrictTransportSecurity::new(Duration::from_secs(31536000));
        assert_eq!(hsts.to_header_value().unwrap(), "max-age=31536000");

        let hsts =
            StrictTransportSecurity::new(Duration::from_secs(31536000)).include_subdomains(true);
        assert_eq!(
            hsts.to_header_value().unwrap(),
            "max-age=31536000; includeSubDomains"
        );

        let hsts = StrictTransportSecurity::new(Duration::from_secs(31536000))
            .include_subdomains(true)
            .preload(true);
        assert_eq!(
            hsts.to_header_value().unwrap(),
            "max-age=31536000; includeSubDomains; preload"
        );
    }

    #[test]
    fn test_to_header_value_zero_max_age() {
        let hsts = StrictTransportSecurity::new(Duration::from_secs(0));
        assert!(hsts.to_header_value().is_err());
    }

    #[test]
    fn test_to_header_value_invalid_preload() {
        let hsts = StrictTransportSecurity::new(Duration::from_secs(31536000)).preload(true);
        assert!(hsts.to_header_value().is_err());

        let hsts = StrictTransportSecurity::new(Duration::from_secs(60))
            .include_subdomains(true)
            .preload(true);
        assert!(hsts.to_header_value().is_err());
    }

    #[test]
    fn test_parse() {
        let hsts = StrictTransportSecurity::parse("max-age=31536000").unwrap();
        assert_eq!(hsts.max_age(), Duration::from_secs(31536000));
        assert!(!hsts.includes_subdomains());
        assert!(!hsts.is_preload());

        let hsts = StrictTransportSecurity::parse("max-age=31536000; includeSubDomains").unwrap();
        assert!(hsts.includes_subdomains());

        let hsts =
            StrictTransportSecurity::parse("max-age=31536000; includeSubDomains; preload").unwrap();
        assert!(hsts.includes_subdomains());
        assert!(hsts.is_preload());
    }

    #[test]
    fn test_parse_invalid() {
        assert!(StrictTransportSecurity::parse("invalid").is_err());
        assert!(StrictTransportSecurity::parse("max-age=invalid").is_err());
        assert!(StrictTransportSecurity::parse("").is_err());
    }

    #[test]
    fn test_parse_invalid_preload() {
        assert!(StrictTransportSecurity::parse("max-age=31536000; preload").is_err());
        assert!(StrictTransportSecurity::parse("max-age=100; includeSubDomains; preload").is_err());
    }

    #[test]
    fn test_display() {
        let hsts =
            StrictTransportSecurity::new(Duration::from_secs(31536000)).include_subdomains(true);
        assert_eq!(hsts.to_string(), "max-age=31536000; includeSubDomains");
    }
}
