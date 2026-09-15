<div align="center">

# MBKAuthe v6

**Enterprise-Grade Authentication & Authorization Framework for Node.js & Express**

<p align="center">
  <img src="https://skillicons.dev/icons?i=ts,js,nodejs,express,postgres,sqlite,vitest,git" alt="TypeScript, Node.js, Express, PostgreSQL, SQLite, Vitest, Git" />
</p>

# MBKAuthe - Node.js Authentication System


[![npm version](https://img.shields.io/npm/v/mbkauthe.svg?style=flat-square&color=0284c7)](https://www.npmjs.com/package/mbkauthe)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x_ESM-3178c6.svg?style=flat-square)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-emerald.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![Website](https://img.shields.io/badge/website-mbkauthe.mbktech.org-0284c7.svg?style=flat-square)](https://mbkauthe.mbktech.org)
[![Tests](https://img.shields.io/badge/tests-297_passed-success.svg?style=flat-square)](https://github.com/MIbnEKhalid/mbkauthe)
[![Downloads](https://img.shields.io/npm/dm/mbkauthe.svg)](https://www.npmjs.com/package/mbkauthe)
[![Check npm version](https://github.com/MIbnEKhalid/mbkauthe/actions/workflows/checkLatestVersion.yml/badge.svg)](https://github.com/MIbnEKhalid/mbkauthe/actions/workflows/checkLatestVersion.yml)

[Official Website](https://mbkauthe.mbktech.org) • [Interactive Docs](https://mbkauthe.mbktech.org/docs) • [API Reference](https://mbkauthe.mbktech.org/api-reference) • [Examples](https://mbkauthe.mbktech.org/examples)

</div>

---

## Overview

**MBKAuthe v6** is a modular, developer-first authentication and authorization engine built natively in TypeScript ESM for Node.js and Express applications.

Designed for high reliability and defense-in-depth security, MBKAuthe provides dual-database persistence across PostgreSQL and embedded SQLite, encrypted multi-session management, dynamic manifest-driven permissions, cryptographic token generation, RFC 8628 CLI device login, social OAuth integrations, domain event streaming, and resilient query retries.

---

## Key Features

- **Dual-Database Persistence**: First-class support for **PostgreSQL** (connection pooling) and embedded **SQLite** (via `better-sqlite3` with WAL mode and FIFO `SqliteMutex`).
- **Encrypted Multi-Session Engine**: Client-side AES cookie encryption, automatic database session validation, session restoration, and concurrent session pruning (`MAX_SESSIONS_PER_USER`).
- **Dynamic Manifest-Driven RBAC**: Declarative `app:service:action` permission manifests (`definePermissions`), database catalog sync (`syncAppPermissions`), `RoleRegistry`, and drop-in middleware (`sessVal`, `sessRole`, `sessPerm`, `roleChk`, `permChk`).
- **Cryptographic TokenEngine**: Standardized prefixed tokens (`mbk_pat_`, `mbk_cli_`, `mbk_dev_`, `mbk_sess_`) with constant-time SHA-256 verification and last-used tracking.
- **RFC 8628 CLI Device Login**: OAuth 2.0 Device Authorization Grant allowing command-line tools to authenticate seamlessly via the browser with 8-character user codes.
- **Social OAuth & Account Linking**: Built-in GitHub App and Google OAuth 2.0 authentication with unified user account linking.
- **TOTP Two-Factor Authentication**: RFC 6238 Time-based One-Time Passwords with QR code setup and trusted device tokens.
- **Domain Event Streaming**: Type-safe `authEvents` emitter for audit logs, webhooks, and analytics (`auth:login:success`, `auth:logout`, `auth:token:created`, etc.).
- **Health & Observability**: Real-time diagnostic reporting (`getAuthHealthReport`) and live in-memory database query logging.

---

## Installation

```bash
npm install mbkauthe express
```

**Prerequisites**:
- Node.js `>= 18.0.0`
- PostgreSQL 13+ (optional if using SQLite)

---

## Quick Start (Express + TypeScript)

```typescript
import express from "express";
import mbkauthe, { sessVal, roleChk, sessPerm } from "mbkauthe";
import { definePermissions } from "mbkauthe/core";
import { syncAppPermissions } from "mbkauthe/services";

const app = express();

// 1. Define App Permissions
const AppPermissions = definePermissions({
  appKey: "portal",
  permissions: {
    dashboard: { view: "View main dashboard" },
    admin: { manage: "Manage system configuration" },
  },
  roles: {
    superadmin: ["portal:*"],
    normaluser: ["portal:dashboard:view"],
  },
});

// 2. Mount Authentication Router (/mbkauthe/*)
app.use(mbkauthe);

// 3. Protected User Route
app.get("/dashboard", sessVal, (req, res) => {
  res.json({
    message: `Welcome back, ${req.session.user.username}!`,
    user: req.session.user,
  });
});

// 4. Role-Protected Admin Route
app.get("/admin", sessRole("superadmin"), (req, res) => {
  res.json({ message: "Welcome to the Superadmin Panel" });
});

// 5. Permission-Protected Route
app.get("/admin/config", sessPerm(AppPermissions.admin.manage), (req, res) => {
  res.json({ config: { maintenanceMode: false } });
});

// 6. Start Server and Sync Permissions
app.listen(3000, async () => {
  await syncAppPermissions(AppPermissions);
  console.log("Server listening on http://localhost:3000");
});
```

---

## Configuration (`.env`)

Create a `.env` file in your application root:

```env
APP_NAME=portal
DOMAIN=localhost
IS_DEPLOYED=false
MAIN_SECRET_TOKEN=a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
SESSION_SECRET_KEY=f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5
DB_TYPE=sqlite
SQLITE_PATH=./data/mbkauthe.sqlite
COOKIE_EXPIRE_TIME=2
LOGIN_REDIRECT_URL=/dashboard
MAX_SESSIONS_PER_USER=5
```

---

## Subpath Modular Exports

MBKAuthe provides modular TypeScript subpath exports:

```typescript
// 1. Top-Level Engine & Express Middleware
import mbkauthe, { sessVal, roleChk, sessPerm, sessRole, permChk } from "mbkauthe";

// 2. Core Domain Models, Tokens & Events
import { TokenEngine, RoleRegistry, authEvents, definePermissions, ErrorCodes } from "mbkauthe/core";

// 3. Database Adapters, Pools & Query Retry
import { dblogin, dialect, applySchema, withQueryRetry, BaseRepository } from "mbkauthe/db";

// 4. Typed Repositories
import { userRepository, sessionRepository, authRepository } from "mbkauthe/repositories";

// 5. Domain Services
import { authService, apiTokenService, cliAuthService, syncAppPermissions } from "mbkauthe/services";

// 6. Response Formatters & Envelopes
import { sendSuccess, sendError, renderPage, renderError, isJsonRequest } from "mbkauthe/response";

// 7. Configuration & Security Hashing
import { mbkautheVar, hashPassword, verifyPassword, encryptSessionId } from "mbkauthe/config";
```

---

## Domain Event Listeners

Subscribe to typed auth lifecycle events for real-time audit logging and metrics:

```typescript
import { authEvents } from "mbkauthe/core";

authEvents.on("auth:login:success", (evt) => {
  console.log(`[Audit] ${evt.username} logged in from ${evt.ip} via ${evt.authMethod}`);
});

authEvents.on("auth:token:created", (evt) => {
  console.log(`[Audit] API Token "${evt.name}" created for user ${evt.userId}`);
});

authEvents.on("auth:cli:approved", (evt) => {
  console.log(`[Audit] User ${evt.userId} approved CLI user code: ${evt.userCode}`);
});
```

---

## REST Endpoints Overview

| Method | Path | Description | Authentication |
|---|---|---|---|
| `POST` | `/mbkauthe/api/login` | Authenticate with username & password | Public |
| `POST` | `/mbkauthe/api/logout` | Terminate active session | Session Cookie |
| `POST` | `/mbkauthe/api/logout-all` | Terminate all user sessions across devices | Session Cookie |
| `POST` | `/mbkauthe/api/checkSession` | Verify session validity | Session Cookie / Token |
| `POST` | `/mbkauthe/api/verify-2fa` | Complete 2FA TOTP verification | Session Cookie |
| `GET` | `/mbkauthe/api/tokens` | List Personal Access Tokens | Session Cookie |
| `POST` | `/mbkauthe/api/tokens` | Create Personal Access Token | Session Cookie |
| `DELETE` | `/mbkauthe/api/tokens/:id` | Revoke Personal Access Token | Session Cookie |
| `POST` | `/mbkauthe/api/cli-auth/device-code` | Request CLI device code | Public |
| `POST` | `/mbkauthe/api/cli-auth/poll` | Poll CLI authorization status | Public |
| `GET` | `/mbkauthe/api/health` | System health diagnostic status | Public |

---

## Documentation

Full interactive guides, recipes, and detailed API references are available at [https://mbkauthe.mbktech.org](https://mbkauthe.mbktech.org).

- [Getting Started Guide](docs/guides/getting-started.md)
- [Environment Configuration Reference](docs/guides/configuration.md)
- [Dual-Database Engine Setup](docs/guides/database.md)
- [Database Repositories Guide](docs/guides/dual-database-guide.md)
- [Dynamic Permissions & RBAC](docs/guides/permissions.md)
- [TokenEngine & API Tokens](docs/guides/api-tokens.md)
- [RFC 8628 CLI Device Login](docs/guides/cli-auth.md)
- [Social OAuth (GitHub & Google)](docs/guides/oauth.md)
- [REST Endpoints Catalog](docs/reference/api/endpoints.md)
- [Express Middleware Reference](docs/reference/api/middleware.md)
- [Error Codes Directory](docs/reference/error-codes.md)
- [Changelog](docs/reference/changelog.md)

---

## License

MIT License. Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors.
