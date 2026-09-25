# MBKAuthe v6 Documentation

> Enterprise-Grade Authentication & Authorization Framework for Node.js and Express

- **Official Live Documentation**: [https://mbkauthe.mbktech.org](https://mbkauthe.mbktech.org)
- **NPM Package**: [https://www.npmjs.com/package/mbkauthe](https://www.npmjs.com/package/mbkauthe)
- **Source Code**: [https://github.com/MIbnEKhalid/mbkauthe](https://github.com/MIbnEKhalid/mbkauthe)

---

## Welcome to MBKAuthe v6

MBKAuthe v6 is a TypeScript-first, ESM authentication and authorization engine designed for modern Node.js applications. It provides end-to-end security primitives, dual-database persistence across PostgreSQL and SQLite, provider-neutral OAuth 2.0 & OIDC, cryptographic token management, manifest-driven RBAC, decoupled authorization policies, RFC 8628 CLI device flows, domain event streaming, and resilient database operations.

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
- [Provider-Neutral OAuth & OIDC](guides/oauth.md) — Google, GitHub, Microsoft, Discord, Apple, and Custom OIDC social login, account linking, and token encryption.
- [WebAuthn & Passkeys](guides/passkeys.md) — FIDO2 biometric authentication (Touch ID, Face ID, Windows Hello) and security keys.
- [OAuth Architecture Reference](oauth.md) — In-depth architectural breakdown of provider-neutral OAuth, PKCE, JWKS, and `createAuth` dependency injection.
- [Custom OIDC Integration](oauth-custom-oidc.md) — Complete guide to integrating Keycloak, Auth0, Okta, and generic OIDC providers.
- [OAuth Migration Guide](oauth-migration.md) — Upgrading from Passport or legacy OAuth to MBKAuthe v6.
- [Two-Factor Authentication (2FA)](guides/2fa.md) — RFC 6238 TOTP authentication and QR code generation.

### 3. Tokens & Developer Tooling
- [API Tokens & TokenEngine](guides/api-tokens.md) — Cryptographic `TokenEngine`, prefixed Personal Access Tokens (`mbk_pat_`), SHA-256 constant-time verification, and scoped permissions.
- [RFC 8628 CLI Device Login](guides/cli-auth.md) — OAuth 2.0 Device Authorization Grant for terminal tools with 8-character user codes and `mbk_cli_` tokens.
- [Production Deployment](guides/deployment.md) — Production checklist, domain cookie sharing, HTTPS enforcement, reverse proxies, and cloud deployment.

### 4. API & Developer Reference
- [API Overview](reference/api.md) — High-level REST API architecture, HTTP status codes, headers, and rate limiting.
- [REST Endpoints Catalog](reference/api/endpoints.md) — Complete specification of all authentication, session, token, admin, CLI, OAuth, and diagnostic endpoints.
- [Middleware Reference](reference/api/middleware.md) — Comprehensive guide for `sessVal`, `roleChk`, `sessRole`, `sessPerm`, `permChk`, `authenticate`, `reloadSessionUser`, `strictValidateSession`, and security middleware.
- [Events, Health & Diagnostics](reference/api/operations.md) — Domain event streaming via `authEvents`, real-time system health checks (`getAuthHealthReport`), and query monitoring.
- [Error Codes Directory](reference/error-codes.md) — Complete error codes reference with error categories, causes, and client recovery hints.
- [Code Examples & Recipes](reference/api/examples.md) — Copyable TypeScript code recipes, custom repository implementations, and client integration snippets.

### 5. Architecture & Guidelines
- [System Architecture & Flows](guides/architecture.md) — Comprehensive architectural specifications, subsystem relationships, and sequence flows with Mermaid diagrams.
- [Database Schema & DDL](schema/database-schema.md) — Full SQL DDL definitions for PostgreSQL and SQLite.
- [Documentation & Coding Guide](STYLE.md) — Style standards, module rules, and contribution guidelines.
- [Changelog & Release Notes](reference/changelog.md) — Version history, feature additions, and the v6.0.0 architecture release.

---

## Subpath Exports

MBKAuthe provides clean TypeScript subpath exports for modular tree-shaking and layer separation:

| Subpath Export | Content |
|---|---|
| `mbkauthe` | Main Express router, middleware, validation DTOs, and top-level helpers. |
| `mbkauthe/core` | Core domain logic: `TokenEngine`, `RoleRegistry`, `AuthorizationService`, `AuthContext`, `authEvents`, `MbkAuthError`, `ErrorCodes`. |
| `mbkauthe/db` | Database layer: `PostgresAdapter`, `SqliteAdapter`, `dblogin`, `dialect`, `wrapPoolWithRetry`, `BaseRepository`. |
| `mbkauthe/repositories` | Typed data repositories: `UserRepository`, `SessionRepository`, `PasskeyRepository`, `AuthRepository`, `PermissionRepository`, `ApiTokenRepository`, `OAuthAccountRepository`. |
| `mbkauthe/services` | Domain services: `AuthService`, `PasskeyService`, `ApiTokenService`, `CliAuthService`, `OAuthFlowService`, `AvatarService`, `PermissionSyncService`. |
| `mbkauthe/oauth` | Provider-neutral OAuth/OIDC engine: `createOAuthFlowService`, `OAuthStateStore`, `OAuthTokenEncryption`. |
| `mbkauthe/oauth/presets` | Built-in identity provider presets: `googleProvider`, `githubProvider`, `microsoftProvider`, `discordProvider`, `appleProvider`, `customOIDCProvider`. |
| `mbkauthe/express` | Express router adapter: `createOAuthRouter`. |
| `mbkauthe/middleware` | HTTP middleware: `validateSession`, `checkPermission`, `securityHeadersMiddleware`, `corsMiddleware`. |
| `mbkauthe/response` | Response formatters & handlers: `sendSuccess`, `sendError`, `renderPage`, `renderError`, `isJsonRequest`. |
| `mbkauthe/diagnostics` | Real-time diagnostic reporting: `getAuthHealthReport`, `AuthHealthStatus`. |
| `mbkauthe/config` | Configuration & security: `mbkautheVar`, `hashPassword`, `verifyPassword`, `encryptSessionId`, `decryptSessionId`. |
