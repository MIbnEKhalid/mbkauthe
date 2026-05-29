# MBKAuthe - Node.js Authentication System

[![Version](https://img.shields.io/npm/v/mbkauthe.svg)](https://www.npmjs.com/package/mbkauthe)
[![License](https://img.shields.io/badge/License-GPL--2.0-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D14.0.0-brightgreen.svg)](https://nodejs.org/)
[![Publish](https://github.com/MIbnEKhalid/mbkauthe/actions/workflows/publish.yml/badge.svg?branch=main)](https://github.com/MIbnEKhalid/mbkauthe/actions/workflows/publish.yml)
[![Downloads](https://img.shields.io/npm/dm/mbkauthe.svg)](https://www.npmjs.com/package/mbkauthe)


<p align="center">
  <img height="64px" src="./public/logo.png" alt="MBKAuthe" />
</p>

**MBKAuthe** is an open source package focused on login, authentication, and validating sessions for your desired apps in Node.js with Express and PostgreSQL. It provides secure login, session validation, 2FA, role/app access checks, OAuth (GitHub & Google), multi-session support, and related authentication flows.

> **Note:** MBKAuthe is intentionally limited to authentication and session validation. The full user/permission/dashboard management system is a separate product called **MBKCore**, developed by MBKTech and not currently open source. Access to MBKCore is currently available only to the MBKTech team, and we may refine it and consider open sourcing it in the future.

## Todo
- Currently, for every request to a protected page, a database query is made to retrieve authentication information (allowed apps, username, session ID, role, etc.). We should implement a caching mechanism to reduce this overhead, but also find a way to allow administrators to log users out and update permissions in near real-time.

## ✨ Key Features

- Compatible With Serverless Function (Vercel)
- Secure password authentication (PBKDF2)
- PostgreSQL session management
- Multi-session support (configurable concurrent sessions per user)
- Optional TOTP-based 2FA with trusted devices
- Social login (GitHub App & Google OAuth)
- Role-based access: SuperAdmin, NormalUser, Guest, member
- CSRF protection & rate limiting
- Easy Express.js integration
- Customizable Handlebars templates
- Session fixation prevention
- Dynamic profile picture routing with session caching
- Modern responsive UI with desktop two-column layout
- Dev-only DB Query Monitor with callsite, timing, and request context

## 📦 Installation

```bash
npm install mbkauthe
```

## 🚀 Quick Start

**1. Configure Environment**

```bash
Copy-Item .env.example .env
```
See [docs/env.md](docs/env.md).

**2. Set Up Database**
Run [docs/db.sql](docs/db.sql) to create tables and a default SuperAdmin (`support` / `12345678`). Change the password immediately. See [docs/db.md](docs/db.md).

**3. Integrate with Express**

```javascript
import express from 'express';
import mbkauthe, { sessVal, roleChk } from 'mbkauthe';
import dotenv from 'dotenv';
dotenv.config();

const app = express();
app.use(mbkauthe);

app.get('/dashboard', sessVal, (req, res) => res.send(`Welcome ${req.session.user.username}!`));
app.get('/admin', sessVal, roleChk(['SuperAdmin']), (req, res) => res.send('Admin Panel'));

app.listen(3000);
```

## 🧪 Testing

```bash
npm test
npm run test:watch
npm run dev
```

## 🔧 Core API

- **Session Validation:** `validateSession`
- **Role Check:** `checkRolePermission(['Role'])`/`roleChk(['Role'])`
- **Combined:** `validateSessionAndRole(['SuperAdmin', 'NormalUser'])`/`sessRole(['SuperAdmin', 'NormalUser'])`
- **API Token Auth:** `authenticate(process.env.API_TOKEN)`

## 🧾 JSON Responses (HTML vs JSON)

Most browser page routes render HTML on auth errors, while API/AJAX-style requests receive JSON error responses.

MBKAuthe treats a request as **JSON** (and returns JSON errors) when any of the following apply:

- URL/path starts with `/mbkauthe/api/` or `/api/`
- `X-Requested-With: XMLHttpRequest`
- `Accept` indicates JSON (e.g., `application/json`) and does not explicitly prefer `text/html`
- `User-Agent` looks like a non-browser client (e.g., `curl`, `wget`, `Postman`)
- `User-Agent: json` (explicitly forces JSON responses)

**Example (force JSON errors):**
```bash
curl -i -H "User-Agent: json" http://localhost:3000/mbkauthe/test
```

## 🧰 Diagnostics (dev only)

These are only mounted when `process.env.env === "dev"`:

- **DB Query Monitor (HTML):** `/mbkauthe/db`
- **DB Query Monitor (JSON):** `/mbkauthe/db.json`
- **SuperAdmin check:** `/mbkauthe/validate-superadmin`

## 🔐 Security

- Rate limiting, CSRF protection, secure cookies
- Password hashing (PBKDF2, 100k iterations)
- PostgreSQL-backed sessions with automatic cleanup
- OAuth with state validation and secure callbacks

## 📱 Two-Factor Authentication

Enable via `MBKAUTH_TWO_FA_ENABLE=true`. Trusted devices can skip 2FA for a set duration.

## 🔄 Social Login Integration

**GitHub App / Google OAuth:** Configure credentials via `.env` or `mbkautheVar`. Users must link accounts before login.

## 🎨 Customization

- **Redirect URL:** `mbkautheVar={"loginRedirectURL":"/dashboard"}`
- **Custom Views:** `views/loginmbkauthe.handlebars`, `2fa.handlebars`, `Error/dError.handlebars`
- **Database Access:** `import { dblogin } from 'mbkauthe'; const result = await dblogin.query('SELECT * FROM "Users"');`

## 📄 API Reference

- Full endpoint list and details: [docs/api.md](docs/api.md)

## 🧰 Diagnostics (dev only)

- **DB Query Monitor (HTML):** `/mbkauthe/db`
- **DB Query Monitor (JSON):** `/mbkauthe/db.json`
- **SuperAdmin check:** `/mbkauthe/debug/validate-superadmin`

These routes are only mounted when `process.env.env === "dev"`. They expose query timing, status/error, pool stats, request context, and callsite data for troubleshooting.

## 🚢 Deployment

Checklist for production:
- `IS_DEPLOYED=true`
- Strong secrets for SESSION_SECRET_KEY & Main_SECRET_TOKEN
- HTTPS enabled
- Correct DOMAIN & COOKIE_EXPIRE_TIME
- Use environment variables for all secrets

**Vercel:** Supports shared OAuth credentials via `mbkauthShared`.

## 📚 Documentation

- [API Reference](docs/api.md)
- [Database Schema](docs/db.md)
- [Environment Config](docs/env.md)
- [Error Codes](docs/error-messages.md)

## 📝 License

GPL v2.0 — see [LICENSE](LICENSE)

## 👨‍💻 Author

**Muhammad Bin Khalid**  
📧 [support@mbktech.org](mailto:support@mbktech.org) | [chmuhammadbinkhalid28@gmail.com](mailto:chmuhammadbinkhalid28@gmail.com)  
🔗 [GitHub @MIbnEKhalid](https://github.com/MIbnEKhalid)

## 🔗 Links

- [npm](https://www.npmjs.com/package/mbkauthe)
- [GitHub](https://github.com/MIbnEKhalid/mbkauthe)
- [Support](https://github.com/MIbnEKhalid/mbkauthe/issues)

---

Made with ❤️ by [MBKTech.org](https://mbktech.org)