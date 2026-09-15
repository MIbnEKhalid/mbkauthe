# Changelog & Version History

All notable changes and architectural releases for MBKAuthe are documented here.

---

## [6.0.0] - 2026-09-14

### Major Architecture Overhaul
- **TypeScript 5.x First-Class**: Complete rewrite to modern TypeScript with strict typing, full ESM native support (`"type": "module"`), and generated `.d.ts` declaration maps.
- **Layered Subsystem Structure**: Reorganized codebase into clean, decoupled layers:
  - `core/`: Pure business logic, errors, domain events, permissions, cryptographic `TokenEngine`, validation DTOs.
  - `db/`: Database adapters (`PostgresAdapter`, `SqliteAdapter`), dialects (`PostgresDialect`, `SqliteDialect`), `BaseRepository`, resilient query retries (`dbRetry`), live query logger, and shutdown lifecycle handlers.
  - `services/`: Domain service layer (`AuthService`, `ApiTokenService`, `CliAuthService`, `OAuthService`, `PermissionSyncService`).
  - `http/`: Express application routing, auth/security middleware, response formatters, and session management.
  - `diagnostics/`: Real-time health reporting (`getAuthHealthReport`).
- **Dynamic Manifest Permission Engine**: Added declarative `app:service:action` permission catalogs with `definePermissions`, database sync (`syncAppPermissions`), `RoleRegistry`, wildcard matching, and drop-in `sessPerm` / `permChk` middleware.
- **Cryptographic TokenEngine**: Standardized prefixed tokens (`mbk_pat_`, `mbk_cli_`, `mbk_dev_`, `mbk_sess_`) with constant-time verification against SHA-256 hashes.
- **Domain Event Streaming**: Implemented type-safe `authEvents` emitter for login, logout, token creation, and CLI approvals.
- **Dual-Database Resilience**: Added automatic query retries with exponential backoff and jitter (`dbRetry`), `SqliteMutex` for conflict-free SQLite concurrency, and live dev query logging (`dbQueryLogger`).
- **RFC 8628 CLI Device Login**: First-class OAuth 2.0 Device Flow with 8-character user codes and polling endpoints.
- **Clean Subpath Exports**: Added modular exports in `package.json` (`mbkauthe`, `mbkauthe/core`, `mbkauthe/db`, `mbkauthe/repositories`, `mbkauthe/services`, `mbkauthe/middleware`, `mbkauthe/response`, `mbkauthe/config`).

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
