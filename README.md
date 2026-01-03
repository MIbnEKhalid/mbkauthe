# MBKAuthe - Node.js Authentication System

[![Version](https://img.shields.io/npm/v/mbkauthe.svg)](https://www.npmjs.com/package/mbkauthe)
[![License](https://img.shields.io/badge/License-GPL--2.0-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D14.0.0-brightgreen.svg)](https://nodejs.org/)
[![Publish](https://github.com/MIbnEKhalid/mbkauthe/actions/workflows/publish.yml/badge.svg?branch=main)](https://github.com/MIbnEKhalid/mbkauthe/actions/workflows/publish.yml)

<p align="center">
  <img height="64px" src="./public/icon.svg" alt="MBKAuthe" />
</p>

**MBKAuthe** is a production-ready authentication system for Node.js with Express and PostgreSQL. Features include secure login, 2FA, role-based access, OAuth (GitHub & Google), multi-session support, and multi-app user management.

## ✨ Key Features

- Secure password authentication (PBKDF2)
- PostgreSQL session management
- Multi-session support (configurable concurrent sessions per user)
- Optional TOTP-based 2FA with trusted devices
- OAuth login (GitHub & Google)
- Role-based access: SuperAdmin, NormalUser, Guest
- CSRF protection & rate limiting
- Easy Express.js integration
- Customizable Handlebars templates
- Session fixation prevention
- Dynamic profile picture routing with session caching
- Modern responsive UI with desktop two-column layout

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
import mbkauthe, { validateSession, checkRolePermission } from 'mbkauthe';
import dotenv from 'dotenv';
dotenv.config();

const app = express();
app.use(mbkauthe);

app.get('/dashboard', validateSession, (req, res) => res.send(`Welcome ${req.session.user.username}!`));
app.get('/admin', validateSession, checkRolePermission(['SuperAdmin']), (req, res) => res.send('Admin Panel'));

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
- **Role Check:** `checkRolePermission(['Role'])`
- **Combined:** `validateSessionAndRole(['SuperAdmin', 'NormalUser'])`
- **API Token Auth:** `authenticate(process.env.API_TOKEN)`

## 🔐 Security

- Rate limiting, CSRF protection, secure cookies
- Password hashing (PBKDF2, 100k iterations)
- PostgreSQL-backed sessions with automatic cleanup
- OAuth with state validation and secure callbacks

## 📱 Two-Factor Authentication

Enable via `MBKAUTH_TWO_FA_ENABLE=true`. Trusted devices can skip 2FA for a set duration.

## 🔄 OAuth Integration

**GitHub / Google OAuth:** Configure apps and credentials via `.env` or `mbkautheVar`. Users must link accounts before login.

## 🎨 Customization

- **Redirect URL:** `mbkautheVar={"loginRedirectURL":"/dashboard"}`
- **Custom Views:** `views/loginmbkauthe.handlebars`, `2fa.handlebars`, `Error/dError.handlebars`
- **Database Access:** `import { dblogin } from 'mbkauthe'; const result = await dblogin.query('SELECT * FROM "Users"');`

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