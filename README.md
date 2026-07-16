# MBKAuthe - Node.js Authentication System

[![Version](https://img.shields.io/npm/v/mbkauthe.svg)](https://www.npmjs.com/package/mbkauthe)
[![License](https://img.shields.io/badge/License-LGPL--3.0-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen.svg)](https://nodejs.org/)
[![Publish](https://github.com/MIbnEKhalid/mbkauthe/actions/workflows/publish.yml/badge.svg?branch=main)](https://github.com/MIbnEKhalid/mbkauthe/actions/workflows/publish.yml)
[![Downloads](https://img.shields.io/npm/dm/mbkauthe.svg)](https://www.npmjs.com/package/mbkauthe)

<p align="center">
  <img height="64px" src="./public/logo.png" alt="MBKAuthe" />
</p>

**MBKAuthe** is an open source authentication package for Node.js and Express, backed by PostgreSQL or SQLite. It handles login, session validation, role/app access checks, optional TOTP 2FA, OAuth login, API token authentication, and multi-session management.

> **Note:** MBKAuthe is intentionally focused on authentication and session validation. The broader user, permission, and dashboard management system is a separate MBKTech product named **MBKCore**(closed source for now).

## Features

- Express middleware for session validation and role checks
- PostgreSQL or SQLite storage for users, sessions, 2FA, trusted devices, and API tokens
- Secure password authentication with PBKDF2
- Optional TOTP 2FA with trusted devices
- GitHub App and Google OAuth login flows
- API token authentication with read-only/write scopes
- Configurable multi-session support per user
- CSRF protection, rate limiting, secure cookies, and session fixation prevention
- Customizable Handlebars views
- Vercel/serverless-friendly deployment support
- Dev-only DB Query Monitor with callsite, timing, request context, and pool stats

## Installation

```bash
npm install mbkauthe
```

## Quick Start

1. Copy the environment template.

```powershell
Copy-Item .env.example .env
```

2. Configure environment values.

See the [configuration guide](docs/guides/configuration.md) for `mbkautheVar`, `mbkauthShared`, OAuth settings, session settings, and deployment flags.

3. Choose a database backend.

MBKAuthe supports two backends, selected with `DB_TYPE` in `mbkautheVar`:

- **PostgreSQL** (default) - set `LOGIN_DB` to a connection string. Recommended for production and multi-instance deployments.
- **SQLite** - set `DB_TYPE` to `sqlite` and `SQLITE_PATH` to a file path (created if missing). No database server required - convenient for development, tests, and small single-instance deployments. Uses `better-sqlite3` with WAL mode; expect `-wal`/`-shm` side files next to the database file. See the [SQLite backend notes](docs/guides/database.md#sqlite-backend-notes) in the database guide.

4. Create database tables.

```bash
npm run create-tables
```

The script applies [docs/schema/db.sql](docs/schema/db.sql) (PostgreSQL) or [docs/schema/db.sqlite.sql](docs/schema/db.sqlite.sql) (SQLite) to the configured backend. You can also run the matching SQL file yourself.

The schema includes a default SuperAdmin user (`support` / `12345678`). Change that password immediately. See the [database guide](docs/guides/database.md).

5. Mount MBKAuthe in Express.

```javascript
import express from "express";
import dotenv from "dotenv";
import mbkauthe, { sessVal, roleChk, sessRole } from "mbkauthe";

dotenv.config();

const app = express();

app.use(mbkauthe);

app.get("/dashboard", sessVal, (req, res) => {
  res.send(`Welcome ${req.session.user.username}!`);
});

app.get("/admin", sessVal, roleChk("SuperAdmin"), (req, res) => {
  res.send("Admin Panel");
});

// Or combine session and role checks into one middleware:
app.get("/admin", sessRole("SuperAdmin"), (req, res) => {
  res.send("Admin Panel");
});

app.listen(3000);
```

## Common Exports

- `sessVal` / `validateSession` - require a valid session or API token.
- `roleChk` / `checkRolePermission` - require a role after session validation.
- `sessRole` / `validateSessionAndRole` - combine session and role checks.
- `strictValidateSession` - require cookie session authentication only.
- `strictValidateSessionAndRole` - strict cookie session plus role check.
- `authenticate(token)` - protect server-to-server routes with a static bearer token.
- `dblogin` - access the configured database pool (`pg.Pool` or the SQLite adapter, per `DB_TYPE`).
- `dbType` - the active backend: `"postgres"` or `"sqlite"`.

See the [API reference](docs/reference/api.md) for endpoints, middleware, examples, security notes, and rate limits.

## JSON Error Responses

Browser page routes usually render HTML errors, while API/AJAX-style requests receive JSON. MBKAuthe treats a request as JSON when any of these are true:

- The path starts with `/mbkauthe/api/` or `/api/`
- `X-Requested-With: XMLHttpRequest`
- `Accept` prefers JSON and does not explicitly prefer `text/html`
- `User-Agent` looks like a non-browser client such as `curl`, `wget`, or `Postman`
- `User-Agent: json`

```bash
curl -i -H "User-Agent: json" http://localhost:3000/mbkauthe/test
```

## Development

```bash
npm test
npm run test:watch
npm run dev
```

Development-only diagnostics are mounted when `process.env.env === "dev"`:

- `/mbkauthe/db` - DB Query Monitor UI
- `/mbkauthe/db.json` - DB Query Monitor JSON
- `/mbkauthe/db/reset` - reset diagnostic query logs
- `/mbkauthe/validate-superadmin` - SuperAdmin validation check

## Documentation

- [Documentation index](docs/README.md)
- [Configuration guide](docs/guides/configuration.md)
- [Database guide](docs/guides/database.md)
- [API reference](docs/reference/api.md)
- [Authentication and sessions](docs/reference/api/authentication.md)
- [Endpoints](docs/reference/api/endpoints.md)
- [Middleware](docs/reference/api/middleware.md)
- [Code examples](docs/reference/api/examples.md)
- [Operational reference](docs/reference/api/operations.md)
- [Error codes](docs/reference/error-codes.md)
- [Documentation style guide](docs/STYLE.md)

## Deployment Checklist

- Set `IS_DEPLOYED=true`
- Use strong `SESSION_SECRET_KEY` and `Main_SECRET_TOKEN` values
- Enable HTTPS
- Set the correct `DOMAIN`
- Set an appropriate `COOKIE_EXPIRE_TIME`
- Store secrets in environment variables
- Configure OAuth credentials only when the matching provider is enabled
- If using the SQLite backend, put `SQLITE_PATH` on persistent disk (not ephemeral/serverless storage) and back up the database together with its `-wal`/`-shm` side files

Vercel deployments can use shared OAuth credentials through `mbkauthShared`.

## License

LGPL v3.0 - see [LICENSE](LICENSE).

## Author

**Muhammad Bin Khalid**  
[support@mbktech.org](mailto:support@mbktech.org) | [chmuhammadbinkhalid28@gmail.com](mailto:chmuhammadbinkhalid28@gmail.com)  
[GitHub @MIbnEKhalid](https://github.com/MIbnEKhalid)

## Links

- [npm](https://www.npmjs.com/package/mbkauthe)
- [GitHub](https://github.com/MIbnEKhalid/mbkauthe)
- [Support](https://github.com/MIbnEKhalid/mbkauthe/issues)

---

Made with love by [MBKTech.org](https://mbktech.org).
