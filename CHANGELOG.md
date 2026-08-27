# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-08-26

### Added
- **Permissions-Policy support.** New `PermissionsPolicy` type with `deny`, `self_only`,
  `any` and `allow` builders, plus `parse`. The `Error::InvalidPermissionsPolicy` variant
  has existed since 0.1.0 with nothing behind it; this is what it was waiting for.
  `Strict` and `Balanced` presets now emit the header.
- **Per-request CSP nonces**, behind the new `nonce` feature. `ContentSecurityPolicy::with_nonce()`
  and `nonce_for([...])` mark directives to receive one; the Tower and Actix middleware
  mint a fresh nonce per request, place it in the request extensions (`Extension<Nonce>`
  in Axum, `web::ReqData<Nonce>` in Actix) and write the matching value into the header.
- `Preset::BalancedNonce` — `Balanced` with a per-request nonce instead of `'unsafe-inline'`,
  identical in every other respect.
- `ContentSecurityPolicy`: `strict_dynamic()`, `report_uri()`, `report_to()`, `get()`,
  `len()`, `is_empty()` and `requires_nonce()`.
- `SecurityHeaders::header_pairs()` — the pre-rendered `(name, value)` pairs, available
  with no feature flags, for frameworks this crate has no integration with.
- `SecurityHeaders::needs_nonce()` and `csp_with_nonce()`.
- `SecurityHeadersLayer::config()` and `SecurityHeadersMiddleware::config()`.
- CI (test on stable + beta, feature powerset via `cargo hack`, both MSRV floors, fmt,
  clippy, `cargo package`, `cargo deny`, `cargo machete`), a weekly advisory cron,
  `dependabot.yml`, `deny.toml` and `.gitattributes`. The crate had no CI at all.
- `examples/axum_nonce.rs`, demonstrating a nonced script running and an un-nonced one
  being blocked.
- `tests/nonce_middleware.rs` — end-to-end checks that the nonce a handler receives is
  the nonce the browser is told to trust, and that nonces never repeat.

### Fixed
- **Security headers could silently vanish.** The middleware wrapped every header insert
  in `if let Ok(...)`, so a policy that rendered to something `HeaderValue` rejects — a
  stray control character or non-ASCII byte in a CSP source, say — produced a response
  with that header simply absent, with no error and no log. CSP sources, CSP directive
  names and Permissions-Policy origins are now validated when the policy is rendered, and
  `SecurityHeadersBuilder::build()` renders every header, so an unrepresentable value is
  a `build()` error instead.
- **Header values were re-rendered on every response.** The CSP was re-sorted,
  re-formatted, re-allocated and re-parsed into a `HeaderValue` for each request. Values
  are now rendered once at `build()` time and stored as a ready-made `HeaderMap`; applying
  them is a few refcount bumps.
- `rust-version` was `1.75.0`, which the crate could not build with. It is now `1.85`,
  with the `actix` feature documented and CI-enforced at `1.88`.
- `cargo fmt --check` did not pass on three example files.

### Changed
- **MSRV raised to 1.85** (1.88 with the `actix` feature). See above — the previous
  declaration was not buildable.
- **Removed three features that did nothing.** `validation`, `metrics` and `axum` declared
  `regex`, `metrics` and `axum-core` respectively, and no code referenced any of them.
  Enabling them only added weight to downstream dependency trees. The Tower layer already
  works with Axum; no `axum` feature is needed for it.
- `actix-web` is now depended on with `default-features = false, features = ["macros"]`.
  A header middleware needs none of HTTP/2, compression or cookie handling, and dropping
  them also drops `h2` 0.3 — whose newest release still carries GHSA-q83h-524g-xf6h, with
  the fix only in the 0.4 line that actix-http 3.x cannot use. An application that enables
  actix-web's `http2` itself still resolves `h2` 0.3; this crate is simply no longer the
  reason.
- `SecurityHeadersLayer::new` and `SecurityHeadersMiddleware::new` now accept
  `impl Into<Arc<SecurityHeaders>>`, so an owned `SecurityHeaders` works as well as an
  `Arc`. Existing `Arc` call sites are unaffected.
- `Preset` is now `#[non_exhaustive]`, so future presets are not a breaking change.
- `ContentSecurityPolicy` and `PermissionsPolicy` store directives in a `BTreeMap`, so
  ordering is deterministic by construction rather than by a sort at render time.
- `SecurityHeaders` fields are private; the existing accessors are unchanged.
- `Preset::Balanced` documents plainly that its `'unsafe-inline'` means it is not an XSS
  control, and points at `BalancedNonce`. Its behaviour is unchanged apart from the new
  Permissions-Policy header.
- Packaging allow-list added (`include`); the published crate is 28 files / 46.5 KiB
  compressed.
- Dependency floors raised: tower 0.5.3, http 1.5.0, http-body 1.1.0, pin-project-lite
  0.2.17, actix-web 4.15, futures-util 0.3.34, tracing 0.1.44, thiserror 2.0.20.
  Dev-dependencies: axum 0.8.9, http-body-util 0.1.5, bytes 1.12.1, hyper 1.11.
- Lockfile refreshed; `time` 0.3.44 → 0.3.55 clears RUSTSEC-2026-0009.
- Repository URL corrected to `danielrcurtis/http-security-headers-tower` in `Cargo.toml`,
  the README badge and the changelog links. The crate remains published as
  `http-security-headers`.

### Migration from 0.2

- Drop `features = ["validation"]`, `["metrics"]` or `["axum"]` — they did nothing. For
  Axum, use `features = ["middleware"]`.
- If you match on `Preset`, add a wildcard arm; it is now `#[non_exhaustive]`.
- If you build a CSP or Permissions-Policy from values that are not plain visible ASCII,
  `build()` now returns an error where 0.2 silently dropped the header at request time.
- Rust 1.85 or newer is required (1.88 with `actix`).

## [0.2.0] - 2026-03-30

### Changed
- Bump dependency versions: tower 0.5.2, http-body 1.0.1, pin-project-lite 0.2.16, actix-web 4.11, futures-util 0.3.31, tracing 0.1.41, metrics 0.24.2, regex 1.12.2
- Bump dev-dependency versions: tower 0.5.2, http 1.3.1, http-body-util 0.1.3, bytes 1.10.1, hyper 1.7

### Fixed
- CSP `to_header_value()` now produces deterministic directive ordering (sorted alphabetically)
- HSTS validation now runs at `build()` time — invalid preload configurations are caught immediately instead of being silently dropped at request time
- Populate LICENSE-MIT with full license text

## [0.1.0] - 2025-11-08

### Added
- Initial release
- Type-safe security header configuration
- Builder pattern for ergonomic API
- Preset configurations (Strict, Balanced, Relaxed)
- Support for 8 security headers:
  - Content-Security-Policy (CSP)
  - Strict-Transport-Security (HSTS)
  - X-Frame-Options
  - X-Content-Type-Options
  - Referrer-Policy
  - Cross-Origin-Opener-Policy (COOP)
  - Cross-Origin-Embedder-Policy (COEP)
  - Cross-Origin-Resource-Policy (CORP)
- Tower middleware support
- Comprehensive test suite (36 tests, 100% coverage)
- Documentation and examples
- Feature flags for optional dependencies

[Unreleased]: https://github.com/danielrcurtis/http-security-headers-tower/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/danielrcurtis/http-security-headers-tower/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/danielrcurtis/http-security-headers-tower/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/danielrcurtis/http-security-headers-tower/releases/tag/v0.1.0
