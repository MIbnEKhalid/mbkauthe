# MBKAuthe v6 Documentation

> Enterprise-Grade Authentication & Authorization Framework for Node.js and Express

- **Official Live Documentation**: [https://mbkauthe.mbktech.org](https://mbkauthe.mbktech.org)
- **NPM Package**: [https://www.npmjs.com/package/mbkauthe](https://www.npmjs.com/package/mbkauthe)
- **Source Code**: [https://github.com/MIbnEKhalid/mbkauthe](https://github.com/MIbnEKhalid/mbkauthe)

---

## Welcome to MBKAuthe v6

MBKAuthe v6 is a TypeScript-first, ESM authentication and authorization engine designed for modern Node.js applications. It provides end-to-end security primitives, dual-database persistence across PostgreSQL and SQLite, cryptographic token management, manifest-driven RBAC, RFC 8628 CLI device flows, domain event streaming, and resilient database operations.

```bash
npm install mbkauthe
```

---

## Documentation Structure

### 1. Getting Started
- [Overview & Quick Start](guides/getting-started.md) — Prerequisites, installation, and mounting the Express engine in under 15 lines of code.
- [Environment Configuration](guides/configuration.md) — Configuration schema, environment variables, validation rules, and the typed `mbkautheVar` object.
- [Dual-Database Setup](guides/database.md) — PostgreSQL connection pooling and embedded SQLite (WAL mode + FIFO mutex) setup and table creation.
- [Database Architecture & Repositories](guides/dual-database-guide.md) — BaseRepository patterns, SQL dialect translation, transparent query retries, and live query logging.

### 2. Authentication & Core Engine
- [Session Engine & Multi-Session](guides/authentication.md) — Encrypted cookies, session restoration middleware, multi-account device switching, and concurrent session limits (`MAX_SESSIONS_PER_USER`).
- [Role-Based Access Control (RBAC)](guides/rbac.md) — Role hierarchies (`superadmin`, `admin`, `normaluser`, `guest`), `RoleRegistry`, and role enforcement middleware (`roleChk`, `sessRole`).
- [Dynamic Permission Catalogs](guides/permissions.md) — Declarative `app:service:action` manifests, `definePermissions`, `syncAppPermissions`, and `sessPerm` / `permChk` middleware.
- [Social OAuth (GitHub & Google)](guides/oauth.md) — GitHub App and Google OAuth 2.0 social login, account linking, and shared credentials.
- [Two-Factor Authentication (2FA)](guides/2fa.md) — RFC 6238 TOTP authentication, QR code generation, and trusted device tokens.

### 3. Tokens & Developer Tooling
- [API Tokens & TokenEngine](guides/api-tokens.md) — Cryptographic `TokenEngine`, prefixed Personal Access Tokens (`mbk_pat_`), SHA-256 constant-time verification, and scoped permissions.
- [RFC 8628 CLI Device Login](guides/cli-auth.md) — OAuth 2.0 Device Authorization Grant for terminal tools with 8-character user codes and `mbk_cli_` tokens.
- [Production Deployment](guides/deployment.md) — Production checklist, domain cookie sharing, HTTPS enforcement, reverse proxies, and serverless deployment.

### 4. API & Developer Reference
- [API Overview](reference/api.md) — High-level REST API architecture, HTTP status codes, headers, and rate limiting.
- [REST Endpoints Catalog](reference/api/endpoints.md) — Complete specification of all authentication, session, token, admin, CLI, and diagnostic endpoints.
- [Middleware Reference](reference/api/middleware.md) — Comprehensive guide for `sessVal`, `roleChk`, `sessRole`, `sessPerm`, `permChk`, `reloadSessionUser`, `strictValidateSession`, and security middleware.
- [Events, Health & Diagnostics](reference/api/operations.md) — Domain event streaming via `authEvents`, real-time system health checks (`getAuthHealthReport`), and query monitoring.
- [Error Codes Directory](reference/error-codes.md) — Complete error codes reference with error categories, causes, and client recovery hints.
- [Code Examples & Recipes](reference/api/examples.md) — Copyable TypeScript code recipes, custom repository implementations, and client integration snippets.

### 5. Architecture & Guidelines
- [Database Schema & DDL](schema/database-schema.md) — Full SQL DDL definitions for PostgreSQL and SQLite.
- [Documentation & Coding Guide](STYLE.md) — Style standards, module rules, and contribution guidelines.
- [Changelog & Release Notes](reference/changelog.md) — Version history, feature additions, and the v6.0.0 architecture release.

---

## Subpath Exports

MBKAuthe provides clean TypeScript subpath exports for modular tree-shaking and layer separation:

| Subpath Export | Content |
|---|---|
| `mbkauthe` | Main Express router, middleware, validation DTOs, and top-level helpers. |
| `mbkauthe/core` | Core domain logic: `TokenEngine`, `RoleRegistry`, `authEvents`, `MbkAuthError`, `ErrorCodes`. |
| `mbkauthe/db` | Database layer: `PostgresAdapter`, `SqliteAdapter`, `dblogin`, `dialect`, `wrapPoolWithRetry`. |
| `mbkauthe/repositories` | Typed data repositories: `UserRepository`, `SessionRepository`, `AuthRepository`, `PermissionRepository`, etc. |
| `mbkauthe/services` | Domain services: `AuthService`, `ApiTokenService`, `CliAuthService`, `OAuthService`, `PermissionSyncService`. |
| `mbkauthe/middleware` | HTTP middleware: `validateSession`, `checkPermission`, `securityHeadersMiddleware`, `corsMiddleware`. |
| `mbkauthe/response` | Response formatters & handlers: `sendSuccess`, `sendError`, `renderPage`, `renderError`, `isJsonRequest`. |
| `mbkauthe/config` | Configuration & security: `mbkautheVar`, `hashPassword`, `verifyPassword`, `encryptSessionId`. |
