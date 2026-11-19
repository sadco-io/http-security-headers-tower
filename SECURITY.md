# Security Policy

## Supported Versions

| Version | Supported | Notes |
|---------|-----------|-------|
| `0.6.x` | Yes | Current release line. Before 1.0, only the latest minor release line receives security fixes. |
| `< 0.6` | No | Upgrade to `0.6.x`. |

## Scope

`http-security-headers` constructs and validates HTTP security headers (`Content-Security-Policy`, `Content-Security-Policy-Report-Only`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Embedder-Policy`, and `Cross-Origin-Resource-Policy`) via `SecurityHeaders`, `Preset`, and the optional `middleware` (`SecurityHeadersLayer`), `actix` (`SecurityHeadersMiddleware`), and `nonce` (`Nonce::random()` and per-request nonce generation) features.

- **In scope:** Missing, malformed, or silently dropped headers; weakened header rendering relative to configured options or documented `Preset` definitions (`Strict`, `Balanced`, `BalancedNonce`, `Relaxed`); header or directive injection in `ContentSecurityPolicy` (including `require-trusted-types-for`, `trusted-types`, `parse`, and `Nonce::from_encoded`); predictability or cross-request reuse of `Nonce::random()` values; and panics reachable from untrusted inputs at runtime.
- **Out of scope:** Deliberately permissive caller configurations (such as `Preset::Balanced` with `'unsafe-inline'`, `Preset::Relaxed` omitting CSP, `.if_not_present()` preserving handler-supplied headers, or weak caller-supplied `Nonce::from_encoded` values) and vulnerabilities in dependencies (including `actix-web` or `h2` if HTTP/2 is enabled by the application, which belong to the upstream dependency, though we will release an update when needed).

## Advisories

For each security fix we publish a GitHub Security Advisory for `http-security-headers` and request a RustSec
advisory. Fixed versions are listed in the advisory and in [CHANGELOG.md](CHANGELOG.md).

## Reporting a Vulnerability

If you have discovered a security vulnerability in this project, please report
it privately. **Do not disclose it as a public issue.** This gives us time to
work with you to fix the issue before public exposure, reducing the chance that
the exploit will be used before a patch is released.

Please disclose it at [security advisory](https://github.com/sadco-io/http-security-headers-tower/security/advisories/new).

This project is maintained by a team of volunteers on a reasonable-effort basis.
As such, please give us at least 90 days to work on a fix before public exposure.
