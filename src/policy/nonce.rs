//! Per-request CSP nonces.
//!
//! A nonce lets a page keep `script-src 'self'` -- no `'unsafe-inline'` -- while
//! still running the inline `<script>` tags it needs. The server emits an
//! unpredictable value in both the CSP header and the `nonce` attribute of every
//! script it trusts, and the browser runs only those scripts.
//!
//! A nonce is only worth anything if it is **unpredictable and used exactly once**.
//! Generating one per request is the whole point; reusing a value across requests,
//! or deriving it from something an attacker can guess, gives no protection at all.

use crate::error::{Error, Result};

/// Number of random bytes behind a generated nonce.
///
/// The CSP specification requires at least 128 bits of entropy.
#[cfg(feature = "nonce")]
const NONCE_BYTES: usize = 16;

#[cfg(feature = "nonce")]
const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// A single-use Content-Security-Policy nonce.
///
/// Cheap to clone -- it wraps a short `String`. Handlers receive one through the
/// request extensions when the Tower middleware is generating nonces; see the
/// [`middleware`](crate::middleware) module.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "nonce")] {
/// use http_security_headers::Nonce;
///
/// let nonce = Nonce::random();
/// assert_eq!(nonce.source(), format!("'nonce-{}'", nonce.as_str()));
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Nonce(String);

impl Nonce {
    /// Generates a fresh nonce from 128 bits of operating-system entropy.
    ///
    /// # Panics
    ///
    /// Panics if the OS entropy source is unavailable. A CSP nonce with no
    /// randomness behind it is worse than no nonce at all -- it would look like a
    /// working defence while providing none -- so this is deliberately not a
    /// recoverable error. In practice `getrandom` fails only on a
    /// catastrophically misconfigured system.
    #[cfg(feature = "nonce")]
    pub fn random() -> Self {
        let mut bytes = [0u8; NONCE_BYTES];
        getrandom::fill(&mut bytes)
            .expect("OS entropy source unavailable; cannot generate a CSP nonce");
        Self(base64_encode(&bytes))
    }

    /// Wraps a nonce value you generated yourself.
    ///
    /// The value must be non-empty and consist only of base64 characters, so that
    /// it can never make the resulting header unparseable.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidCsp`] if the value is empty or contains a character
    /// outside the base64 alphabet.
    ///
    /// # Examples
    ///
    /// ```
    /// use http_security_headers::Nonce;
    ///
    /// assert!(Nonce::from_encoded("dGVzdA==").is_ok());
    /// assert!(Nonce::from_encoded("has spaces").is_err());
    /// ```
    pub fn from_encoded(value: impl Into<String>) -> Result<Self> {
        let value = value.into();

        if value.is_empty() {
            return Err(Error::InvalidCsp("Nonce is empty".to_string()));
        }

        if !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'-' | b'_' | b'='))
        {
            return Err(Error::InvalidCsp(format!(
                "Nonce '{value}' contains characters outside the base64 alphabet"
            )));
        }

        Ok(Self(value))
    }

    /// Returns the raw encoded value, for the `nonce` attribute of a `<script>` tag.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the value formatted as a CSP source expression: `'nonce-<value>'`.
    pub fn source(&self) -> String {
        format!("'nonce-{}'", self.0)
    }

    /// Consumes the nonce, returning the encoded value.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl std::fmt::Display for Nonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Standard padded base64. Sixteen bytes of input, so the encoder does not need to
/// be general -- but it is, and it is small enough not to justify a dependency.
#[cfg(feature = "nonce")]
fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);

    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(BASE64[(triple >> 18) as usize & 0x3F] as char);
        out.push(BASE64[(triple >> 12) as usize & 0x3F] as char);
        out.push(if chunk.len() > 1 {
            BASE64[(triple >> 6) as usize & 0x3F] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            BASE64[triple as usize & 0x3F] as char
        } else {
            '='
        });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "nonce")]
    #[test]
    fn test_base64_matches_known_vectors() {
        // RFC 4648 section 10.
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn test_from_encoded_accepts_base64() {
        assert!(Nonce::from_encoded("dGVzdA==").is_ok());
        assert!(Nonce::from_encoded("abc-_123").is_ok());
    }

    #[test]
    fn test_from_encoded_rejects_injection() {
        assert!(Nonce::from_encoded("").is_err());
        assert!(Nonce::from_encoded("has spaces").is_err());
        assert!(Nonce::from_encoded("a'; script-src *").is_err());
        assert!(Nonce::from_encoded("a\r\nX-Evil: 1").is_err());
    }

    #[test]
    fn test_source_format() {
        let nonce = Nonce::from_encoded("dGVzdA==").unwrap();
        assert_eq!(nonce.source(), "'nonce-dGVzdA=='");
        assert_eq!(nonce.as_str(), "dGVzdA==");
    }

    #[cfg(feature = "nonce")]
    #[test]
    fn test_random_is_valid_and_distinct() {
        let a = Nonce::random();
        let b = Nonce::random();

        assert_ne!(a, b, "two generated nonces must not collide");
        // 16 bytes -> 24 base64 characters including padding.
        assert_eq!(a.as_str().len(), 24);
        // A generated nonce must survive its own validator.
        assert!(Nonce::from_encoded(a.as_str()).is_ok());
    }
}
