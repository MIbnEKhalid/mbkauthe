# Production Deployment Checklist

[Back to docs index](../README.md) | [Back to project README](../../README.md)

This guide covers essential deployment steps, security checklists, and domain configuration when launching applications running MBKAuthe in production.

---

## 1. Production Environment Variables

Ensure all required production environment variables are properly configured:

```env
APP_NAME=portal
IS_DEPLOYED=true
DOMAIN=mbktech.org
LOGIN_DB=postgresql://dbuser:securepassword@db-host:5432/mbkauth_prod
SESSION_SECRET_KEY=9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a
MAIN_SECRET_TOKEN=strong-cryptographic-token-for-internal-apis
MBKAUTH_TWO_FA_ENABLE=true
COOKIE_EXPIRE_TIME=7
MAX_SESSIONS_PER_USER=5
```

---

## 2. Cookie Domain Scoping

When `IS_DEPLOYED=true`:
- `DOMAIN` must be set to the **root domain** (e.g. `mbktech.org`, NOT `portal.mbktech.org`).
- MBKAuthe automatically scopes session cookies to `.mbktech.org`.
- This enables **Single Sign-On (SSO)** across all subdomains (`portal.mbktech.org`, `mbkauthe.mbktech.org`, `api.mbktech.org`).
- In local development (`IS_DEPLOYED=false`), `DOMAIN=localhost` isolates cookies to the local port.

---

## 3. HTTPS & Reverse Proxy Configuration

MBKAuthe sets `Secure` and `SameSite=Lax` flags on session cookies in production. This requires HTTPS:

### Express Proxy Trust

If your app is running behind a reverse proxy (e.g., Nginx, Cloudflare, AWS ALB, Traefik), enable `trust proxy` in Express:

```javascript
import express from "express";

const app = express();
app.set("trust proxy", 1); // Trust first proxy hop
```

---

## 4. Connection Pooling & Graceful Shutdown

Always register database pools for graceful termination to avoid hanging connections during rolling deployments:

```javascript
import { registerGracefulShutdown } from "mbkauthe";
import { pool } from "./src/db/connection.js";

registerGracefulShutdown(pool);
```

---

## 5. Security Checklist

- [ ] `IS_DEPLOYED` is set to `"true"`.
- [ ] `SESSION_SECRET_KEY` is at least 32 cryptographically random characters.
- [ ] Default `support` password in `mbkcore_users` has been changed.
- [ ] Database credentials and secrets are kept out of version control.
- [ ] SSL/TLS certificates are active and valid.
- [ ] Rate limits are active on authentication routes.
