# Changelog & Version History

All notable changes and architectural releases for MBKAuthe are documented here.

---

## [6.0.0] - 2026-09-14

### Major Architecture Overhaul
- **TypeScript 5.x First-Class**: Complete rewrite to modern TypeScript with strict typing, full ESM native support (`"type": "module"`), and generated `.d.ts` declaration maps.
- **Layered Subsystem Structure**: Reorganized codebase into clean, decoupled layers:
  - `core/`: Pure domain logic, errors, domain events, permissions, cryptographic `TokenEngine`, `AuthContext`, validation DTOs.
  - `db/`: Database adapters (`PostgresAdapter`, `SqliteAdapter`), dialects (`PostgresDialect`, `SqliteDialect`), `BaseRepository`, resilient query retries (`dbRetry`), live query logger, and shutdown lifecycle handlers.
  - `services/`: Domain service layer (`AuthService`, `AuthorizationService`, `ApiTokenService`, `CliAuthService`, `OAuthService`, `PermissionSyncService`).
  - `oauth/`: Provider-neutral OAuth 2.0 and OpenID Connect engine with `createAuth` dependency injection factory.
  - `express/`: Express router adapters for OAuth and auth flows.
  - `http/`: Express application routing, auth/security middleware, response formatters, and session management.
  - `diagnostics/`: Real-time health reporting (`getAuthHealthReport`).
- **Provider-Neutral OAuth 2.0 & OIDC**: Modern social and enterprise identity engine supporting Google, GitHub, Microsoft/Entra ID, Discord, Apple, and Custom OIDC. Features automatic discovery via `/.well-known/openid-configuration`, remote JWKS validation with `jose`, default-on PKCE (RFC 7636), and AES-256-GCM token encryption at rest.
- **Decoupled Authentication & Authorization**: Separated authentication concerns (`AuthContext`, `req.auth`, session restoration) from authorization decisions (`AuthorizationService`, `RoleRegistry`, dynamic policies).
- **Dynamic Manifest Permission Engine**: Added declarative `app:service:action` permission catalogs with `definePermissions`, database sync (`syncAppPermissions`), `RoleRegistry`, wildcard matching, and drop-in `sessPerm` / `permChk` middleware.
- **Cryptographic TokenEngine**: Standardized prefixed tokens (`mbk_pat_`, `mbk_cli_`, `mbk_dev_`, `mbk_sess_`) with constant-time verification against SHA-256 hashes.
- **Domain Event Streaming**: Implemented type-safe `authEvents` emitter for login, logout, token creation, CLI approvals, and OAuth security alerts.
- **Dual-Database Resilience**: Added automatic query retries with exponential backoff and jitter (`dbRetry`), `SqliteMutex` for conflict-free SQLite concurrency, and live dev query logging (`dbQueryLogger`).
- **RFC 8628 CLI Device Login**: First-class OAuth 2.0 Device Flow with 8-character user codes and polling endpoints.
- **Clean Subpath Exports**: Added modular exports in `package.json` (`mbkauthe`, `mbkauthe/core`, `mbkauthe/db`, `mbkauthe/repositories`, `mbkauthe/services`, `mbkauthe/oauth`, `mbkauthe/oauth/presets`, `mbkauthe/express`, `mbkauthe/middleware`, `mbkauthe/response`, `mbkauthe/diagnostics`, `mbkauthe/config`).

---

## [5.6.0] - 2026-08-10
- Added initial support for dynamic app permission syncing.
- Improved cookie expiration handling on mobile browsers.
- Bug fixes for OAuth state verification.

---

## [5.0.0] - 2026-04-15
- Introduced multi-session auto-eviction (`MAX_SESSIONS_PER_USER`).
- Added TOTP 2FA trusted device remember tokens.
- SQLite WAL mode support.

---

## [4.0.0] - 2025-11-20
- Added Personal Access Tokens (PAT).
- Added multi-account list cookie support.

---

## [3.0.0] - 2025-06-01
- Added GitHub App and Google OAuth 2.0 social login workflows.

---

## [1.0.0] - 2024-01-10
- Initial release of MBKAuthe with PostgreSQL session authentication.

