# http-security-headers

[![Crates.io](https://img.shields.io/crates/v/http-security-headers.svg)](https://crates.io/crates/http-security-headers)
[![Documentation](https://docs.rs/http-security-headers/badge.svg)](https://docs.rs/http-security-headers)
[![License](https://img.shields.io/crates/l/http-security-headers.svg)](https://github.com/sadco-io/http-security-headers-tower)

Type-safe, framework-agnostic HTTP security headers for Rust with Tower and Actix-Web integration.

> The crate is published as `http-security-headers`; the repository is
> [`http-security-headers-tower`](https://github.com/sadco-io/http-security-headers-tower).

## Features

- **🔒 Type-safe configuration**: Compile-time guarantees for header values
- **🏗️ Builder pattern**: Ergonomic, fluent API for configuration
- **📦 Preset configurations**: Strict, Balanced and Relaxed security levels
- **🔌 Framework integrations**: Tower middleware (Axum, Tonic, etc.) and Actix-Web support
- **🎲 Per-request CSP nonces**: Drop `'unsafe-inline'` without rewriting your templates
- **⚡ Rendered once**: Header values are built and validated at `build()` time, not per request
- **📝 Well-documented**: Comprehensive docs with examples

## Security Headers Supported

| Header | Description |
|--------|-------------|
| **Content-Security-Policy (CSP)** | Prevents XSS and code injection attacks |
| **Strict-Transport-Security (HSTS)** | Forces HTTPS connections |
| **X-Frame-Options** | Prevents clickjacking attacks |
| **X-Content-Type-Options** | Prevents MIME type sniffing |
| **Referrer-Policy** | Controls referrer information |
| **Permissions-Policy** | Controls access to browser features and APIs |
| **Cross-Origin-Opener-Policy (COOP)** | Isolates browsing contexts |
| **Cross-Origin-Embedder-Policy (COEP)** | Controls cross-origin resource loading |
| **Cross-Origin-Resource-Policy (CORP)** | Controls resource sharing |

## Installation

Core only:

```toml
[dependencies]
http-security-headers = "0.3"
```

With Tower/Axum middleware:

```toml
[dependencies]
http-security-headers = { version = "0.3", features = ["middleware"] }
```

With per-request CSP nonces:

```toml
[dependencies]
http-security-headers = { version = "0.3", features = ["middleware", "nonce"] }
```

With Actix-Web integration:

```toml
[dependencies]
http-security-headers = { version = "0.3", features = ["actix"] }
```

## Quick Start

### Using Presets

```rust
use http_security_headers::Preset;

let headers = Preset::Strict.build();
```

### Custom Configuration

```rust
use http_security_headers::{ContentSecurityPolicy, PermissionsPolicy, SecurityHeaders};
use std::time::Duration;

let csp = ContentSecurityPolicy::new()
    .default_src(vec!["'self'"])
    .script_src(vec!["'self'", "'unsafe-inline'"])
    .style_src(vec!["'self'", "https://fonts.googleapis.com"]);

let headers = SecurityHeaders::builder()
    .content_security_policy(csp)
    .strict_transport_security(Duration::from_secs(31536000), true, false)
    .x_frame_options_deny()
    .x_content_type_options_nosniff()
    .referrer_policy_no_referrer()
    .permissions_policy(PermissionsPolicy::new().deny("camera").deny("microphone"))
    .build()
    .unwrap();
```

Everything is rendered and validated inside `build()`. A policy that cannot become a
legal HTTP header value is an error there, rather than a header that silently goes
missing at request time.

### With Axum

```rust
use axum::{Router, routing::get};
use http_security_headers::{Preset, SecurityHeadersLayer};

let app = Router::new()
    .route("/", get(|| async { "Hello, World!" }))
    .layer(SecurityHeadersLayer::new(Preset::Strict.build()));
```

`SecurityHeadersLayer::new` takes a `SecurityHeaders` or an `Arc<SecurityHeaders>`,
so a configuration can be shared across several layers without cloning it.

### With Actix-Web

```rust
use actix_web::{web, App, HttpResponse, HttpServer};
use http_security_headers::{Preset, SecurityHeadersMiddleware};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .wrap(SecurityHeadersMiddleware::new(Preset::Strict.build()))
            .route("/", web::get().to(|| async { HttpResponse::Ok().body("Hello, World!") }))
    })
    .bind(("127.0.0.1", 3000))?
    .run()
    .await
}
```

## CSP Nonces

`'unsafe-inline'` in `script-src` allows any inline `<script>` on the page — including
one an attacker injected — which is the single thing CSP exists to stop. A nonce is the
way out: the server emits an unpredictable value in both the CSP header and the `nonce`
attribute of every script it trusts, so injected scripts do not run.

Enable the `nonce` feature and mark the directives that should carry one. The middleware
mints a fresh nonce per request, hands it to your handler through the request extensions,
and writes the matching value into the header:

```rust
use axum::{Extension, Router, routing::get};
use http_security_headers::{Nonce, Preset, SecurityHeadersLayer};

async fn index(Extension(nonce): Extension<Nonce>) -> String {
    format!("<script nonce=\"{nonce}\">console.log('hi')</script>")
}

let app = Router::new()
    .route("/", get(index))
    .layer(SecurityHeadersLayer::new(Preset::BalancedNonce.build()));
```

Under Actix-Web the nonce arrives as `web::ReqData<Nonce>`.

To add a nonce to a hand-built policy, use `with_nonce()` (which covers `script-src` and
`style-src`) or `nonce_for([...])` for specific directives:

```rust
use http_security_headers::ContentSecurityPolicy;

let csp = ContentSecurityPolicy::new()
    .default_src(vec!["'self'"])
    .script_src(vec!["'self'"])
    .nonce_for(["script-src"]);
```

A configuration that asks for a nonce while the `nonce` feature is off panics when the
layer is constructed, rather than quietly serving a policy without one.

## Rolling out a stricter policy

`Content-Security-Policy-Report-Only` lets the browser evaluate a policy and report
violations without enforcing it. That is the safe way to tighten a policy against real
traffic: keep the permissive one enforcing, put the intended one in report-only, and
read the reports before swapping them over.

```rust
use http_security_headers::{ContentSecurityPolicy, SecurityHeaders};

let headers = SecurityHeaders::builder()
    // Enforced today.
    .content_security_policy(
        ContentSecurityPolicy::new().script_src(vec!["'self'", "'unsafe-inline'"]),
    )
    // What we intend to enforce once the reports come back clean.
    .content_security_policy_report_only(
        ContentSecurityPolicy::new()
            .script_src(vec!["'self'"])
            .report_uri(vec!["/csp-report"]),
    )
    .build()
    .unwrap();
```

If either policy uses a nonce, both are rendered with the **same** per-request nonce —
the one your handler receives. A dry run is only meaningful if it carries the nonce of
the policy it is rehearsing.

## Letting a route set its own headers

By default the configured value wins, which is what a blanket policy should do. When a
route legitimately sets its own — a page building a bespoke CSP, an endpoint that must be
framable — `if_not_present()` makes the middleware fill in only what is missing:

```rust
use http_security_headers::{Preset, SecurityHeadersLayer};

let layer = SecurityHeadersLayer::new(Preset::Strict.build()).if_not_present();
```

Available on the Actix middleware too.

## Presets

### Strict

Recommended for applications that can enforce strict security policies.

```rust
let headers = Preset::Strict.build();
```

**Includes:**
- CSP: `base-uri 'self'; default-src 'self'; frame-ancestors 'none'; object-src 'none'`
- HSTS: 1 year, includeSubDomains
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- Referrer-Policy: no-referrer
- Permissions-Policy: `camera`, `geolocation`, `microphone`, `payment` and `usb` denied
- COOP: same-origin
- COEP: require-corp
- CORP: same-origin

### Balanced

Good compatibility, and **not an XSS control** — see the warning below.

```rust
let headers = Preset::Balanced.build();
```

**Includes:**
- CSP: `default-src 'self'; object-src 'none'; script-src 'self' 'unsafe-inline'`
- HSTS: 1 year, includeSubDomains
- X-Frame-Options: SAMEORIGIN
- X-Content-Type-Options: nosniff
- Referrer-Policy: strict-origin-when-cross-origin
- Permissions-Policy: `camera`, `geolocation` and `microphone` denied
- COOP: same-origin-allow-popups

> ⚠️ `Balanced` carries `'unsafe-inline'` in `script-src`, which permits any inline
> script on the page. Treat its CSP as defence in depth for resource loading, not as
> protection against XSS. Use `BalancedNonce` when your templates can carry a nonce.

### BalancedNonce

`Balanced`, with a per-request nonce instead of `'unsafe-inline'`. Identical in every
other respect. Requires the `nonce` feature.

```rust
let headers = Preset::BalancedNonce.build();
```

### Relaxed

Baseline security with minimal restrictions.

```rust
let headers = Preset::Relaxed.build();
```

**Includes:**
- HSTS: 6 months
- X-Frame-Options: SAMEORIGIN
- X-Content-Type-Options: nosniff
- Referrer-Policy: strict-origin-when-cross-origin

## Examples

Check out the [examples](examples/) directory:

- **[axum_basic.rs](examples/axum_basic.rs)**: Basic Axum integration with a preset
- **[axum_custom.rs](examples/axum_custom.rs)**: Custom security headers configuration
- **[axum_nonce.rs](examples/axum_nonce.rs)**: Per-request CSP nonces, with a page that
  demonstrates a nonced script running and an un-nonced one being blocked
- **[actix_basic.rs](examples/actix_basic.rs)**: Simple Actix-Web integration

```bash
cargo run --example axum_basic  --features middleware
cargo run --example axum_custom --features middleware
cargo run --example axum_nonce  --features middleware,nonce
cargo run --example actix_basic --features actix
```

## Feature Flags

| Feature | Description |
|---------|-------------|
| `middleware` | Tower `Layer`/`Service` for any Tower-based framework |
| `actix` | Actix-Web middleware (implies `middleware`) |
| `nonce` | Per-request CSP nonce generation (adds `getrandom`) |
| `observability` | `tracing` events in the middleware |

## Minimum Supported Rust Version

**1.85** for the default build and for `middleware`, `nonce` and `observability`.

**1.88** for the `actix` feature — actix-web, actix-http and actix-server all declare
`rust-version = "1.88"`. Both floors are enforced by separate CI jobs.

The MSRV is treated as part of the public API: it is raised only in a minor release.

## A note on the `actix` feature and `h2`

`actix-web` is depended on with `default-features = false`, because a header middleware
needs none of HTTP/2, compression or cookie handling. That also keeps `h2` 0.3 out of the
tree — its newest release (0.3.27) still carries
[GHSA-q83h-524g-xf6h](https://github.com/hyperium/hyper/security/advisories/GHSA-q83h-524g-xf6h),
and the fix exists only in the 0.4 line, which actix-http 3.x cannot use.

This is not a fix for your application: if you enable actix-web's `http2` yourself, Cargo
unions the features and `h2` 0.3 comes back. It means only that this crate is not the
reason it is there.

## Comparison with Other Crates

| Feature | http-security-headers | secure-headers | tower-http |
|---------|---------------------|----------------|------------|
| Type-safe configuration | ✅ | ❌ | Partial |
| Builder pattern | ✅ | ❌ | ❌ |
| Preset configurations | ✅ | ❌ | ❌ |
| Framework-agnostic | ✅ | ❌ | ✅ |
| CSP builder | ✅ | ❌ | ❌ |
| Per-request CSP nonces | ✅ | ❌ | ❌ |
| Full header support | ✅ | Partial | Partial |

## Documentation

Full documentation is available on [docs.rs](https://docs.rs/http-security-headers).

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

Before opening one, `cargo fmt --all`, `cargo clippy --all-features --lib --tests
--examples -- -D warnings` and `cargo test --all-features` should all be clean; CI runs
the same checks plus a feature powerset build, both MSRV floors, `cargo deny` and an
unused-dependency scan.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Acknowledgments

Inspired by:
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
