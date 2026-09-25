# Changelog & Version History

All notable changes and architectural releases for MBKAuthe are documented here.

---

## [6.2.0] - 2026-09-25

### Service Layer Optimization & Flow Refactoring
- **Centralized Service Layer**: Consolidated business logic from route handlers into dedicated service methods:
  - `AuthService`: Added `listDeviceAccounts()`, `switchDeviceSession()`, `logoutDeviceAccount()`, `logoutAllDeviceAccounts()`, `validateSession()`, `validateSessionWithSid()`, and administrative `terminateAllSessions()`.
  - `ApiTokenService`: Added `verifyToken()` for direct programmatic token validation with automatic last-used tracking, `listTokensForUserAdmin()`, `bulkRevokeTokens()`, and enforced user token quotas (`maxTokensPerUser`).
  - `CliAuthService`: Streamlined RFC 8628 lifecycle with `initiate()`, `poll()`, `approve()`, `deny()`, `findSessionByUserCode()`, and automated stale session expiration.
  - `OAuthFlowService`: Replaced legacy `OAuthService` export with unified `OAuthFlowService` from the provider-neutral OAuth module.
- **Database & Query Enhancements**:
  - `SqliteAdapter`: Added support for positional SQL parameter binding arrays `[...args]` and development query logging hooks.
  - `BaseRepository`: Enhanced JSON array querying with `_isJsonArrayContains` helper for seamless JSON containment checks across PostgreSQL and SQLite.
- **View Engine & Template Migration**:
  - Migrated view templates from `.handlebars` to `.hbs` extension across all pages, modals, and error views.
  - Updated `scripts/publish.js` and build scripts for packaging `.hbs` template assets.
- **Official SQL Schema Definitions**:
  - Added clean standalone DDL files in `docs/schema/postgres.sql` and `docs/schema/sqlite.sql` with full table, index, and trigger specifications.
- **Admin REST API Extensions**:
  - Added `POST /api/admin/api-tokens/bulk-revoke` for bulk token invalidation.
  - Added `GET /api/admin/api-tokens/user/:username` for superadmin user token audits.

---

## [6.1.0] - 2026-09-20

### Device-Based Accounts, Local Protection & Avatar Service
- **Unified Session Store**: Consolidated session storage into `mbkcore_session` table with optimized indices and reduced query overhead.
- **Device-Based Multi-Account Management**: Added first-class support for multi-account switching on shared devices, individual account logouts, and device session enumeration.
- **Local-Only User Guard**: Added `is_local_only` column flag on `mbkcore_users` to restrict test/dev accounts from logging in when `IS_DEPLOYED=true` or in production environments (`LOCAL_USER_PROD_RESTRICTED`).
- **User Avatar Service**: Added built-in `AvatarService` and `/avatar/:username` endpoint supporting initials SVG generation, custom avatars, and SVG caching.
- **Performance Optimizations**: Streamlined session validation query counts (single-query auth checks) and improved response serialization.

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

