# Environment Configuration in MBKAuthe v6

MBKAuthe v6 features a configuration system that validates, normalizes, and proxies environment variables. Configuration is automatically loaded on initialization and exposed via the typed `mbkautheVar` export.

---

## Configuration Sources & Priority

MBKAuthe loads configuration values in the following order of precedence (highest to lowest):

1. **Direct Environment Variables**: `APP_NAME`, `DOMAIN`, `SESSION_SECRET_KEY`, etc.
2. **JSON-Encoded Objects**: `process.env.mbkautheVar` or `process.env.mbkauthShared` (parsed as JSON).
3. **Prefixed Environment Variables**: `mbkautheVar.APP_NAME`, `mbkautheVar_APP_NAME`, `mbkauthShared.DOMAIN`.
4. **Built-in Defaults**: Fallback default values for optional settings.

---

## Configuration Reference

| Environment Variable | Type | Default | Description |
|---|---|---|---|
| `APP_NAME` | `string` | **Required** | Identifier for your application (e.g. `mbkcore`, `portal`). Normalized to lowercase. |
| `DOMAIN` | `string` | **Required** | Base cookie domain (e.g. `localhost` or `mbktech.org`). Must not contain protocols or ports. |
| `MAIN_SECRET_TOKEN` | `string` | **Required** | 32-byte secret hex token used for internal API verification and administrative calls. |
| `SESSION_SECRET_KEY` | `string` | **Required** | 32-byte secret key used for session cookie AES encryption and password peppering. |
| `IS_DEPLOYED` | `boolean` | `"false"` | When `"true"`, cookies use `Secure` and `SameSite=None/Lax` cross-subdomain policies. |
| `DB_TYPE` | `string` | `"postgres"` | Database engine: `"postgres"` or `"sqlite"`. |
| `LOGIN_DB` | `string` | `undefined` | PostgreSQL connection string URL (`postgres://user:pass@host:5432/dbname`). |
| `SQLITE_PATH` | `string` | `"./mbkauthe.sqlite"` | Filesystem path for SQLite database file when `DB_TYPE=sqlite`. |
| `MBKAUTH_TWO_FA_ENABLE` | `boolean` | `"false"` | Enables TOTP Two-Factor Authentication across the login flow. |
| `COOKIE_EXPIRE_TIME` | `number` | `2` | Session cookie lifespan in hours. |
| `DEVICE_TRUST_DURATION_DAYS` | `number` | `7` | Duration in days to remember a trusted 2FA device. |
| `LOGIN_REDIRECT_URL` | `string` | `"/dashboard"` | Relative path to redirect users after successful login. Must start with `/`. |
| `MAX_SESSIONS_PER_USER` | `number` | `5` | Maximum active concurrent sessions allowed per user before oldest session eviction. |
| `CLI_AUTH_ENABLED` | `boolean` | `"false"` | Enables the RFC 8628 CLI Device Login endpoints. |
| `CLI_AUTH_BASE_URL` | `string` | `undefined` | Custom base verification URL displayed to CLI users. |
| `GITHUB_LOGIN_ENABLED` | `boolean` | `"false"` | Enables GitHub OAuth / GitHub App login flow. |
| `GITHUB_APP_CLIENT_ID` | `string` | `undefined` | GitHub App Client ID. |
| `GITHUB_APP_CLIENT_SECRET` | `string` | `undefined` | GitHub App Client Secret. |
| `GITHUB_CLIENT_ID` | `string` | `undefined` | Legacy GitHub OAuth Client ID (if not using GitHub App). |
| `GITHUB_CLIENT_SECRET` | `string` | `undefined` | Legacy GitHub OAuth Client Secret. |
| `GOOGLE_LOGIN_ENABLED` | `boolean` | `"false"` | Enables Google OAuth2 login flow. |
| `GOOGLE_CLIENT_ID` | `string` | `undefined` | Google Cloud OAuth 2.0 Client ID. |
| `GOOGLE_CLIENT_SECRET` | `string` | `undefined` | Google Cloud OAuth 2.0 Client Secret. |

---

## Example `.env` Files

### Local Development with SQLite

```env
APP_NAME=my_service
DOMAIN=localhost
IS_DEPLOYED=false
MAIN_SECRET_TOKEN=a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
SESSION_SECRET_KEY=f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5
DB_TYPE=sqlite
SQLITE_PATH=./data/auth.sqlite
COOKIE_EXPIRE_TIME=2
LOGIN_REDIRECT_URL=/dashboard
MAX_SESSIONS_PER_USER=5
```

### Production with PostgreSQL & OAuth

```env
APP_NAME=portal
DOMAIN=mbktech.org
IS_DEPLOYED=true
MAIN_SECRET_TOKEN=3f8d9b1c7a2e4f5a6b8c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a
SESSION_SECRET_KEY=9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d
DB_TYPE=postgres
LOGIN_DB=postgres://mbkauth_user:SuperSecretPassword123@db.prod.internal:5432/mbkauth_prod?sslmode=require
COOKIE_EXPIRE_TIME=24
DEVICE_TRUST_DURATION_DAYS=30
LOGIN_REDIRECT_URL=/app/overview
MAX_SESSIONS_PER_USER=10
MBKAUTH_TWO_FA_ENABLE=true
GITHUB_LOGIN_ENABLED=true
GITHUB_APP_CLIENT_ID=Iv1.8392019384920192
GITHUB_APP_CLIENT_SECRET=3891028394019283019283019283019283019283
GOOGLE_LOGIN_ENABLED=true
GOOGLE_CLIENT_ID=123456789012-abc123xyz.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-abc123xyz_example_secret
```

---

## Programmatic Access & Validation

You can inspect and validate configuration in code:

```typescript
import { mbkautheVar, validateConfiguration } from "mbkauthe/config";

// Read case-insensitively via proxy
console.log("App Name:", mbkautheVar.APP_NAME); // or mbkautheVar.app_name
console.log("DB Type:", mbkautheVar.DB_TYPE);

// Strict validation (throws descriptive Error if required keys are missing)
try {
  const config = validateConfiguration();
  console.log("Configuration is valid.");
} catch (err) {
  console.error("Configuration validation failed:", err.message);
}
```
