# Environment Configuration in MBKAuthe v6

MBKAuthe v6 features a configuration system that validates, normalizes, and proxies environment variables. Configuration is automatically loaded on initialization and exposed via the typed `mbkautheVar` export.

---

## Configuration Sources & Priority

MBKAuthe loads configuration values in the following order of precedence (highest to lowest):

1. **Direct Environment Variables**: `APP_NAME`, `DOMAIN`, `SESSION_SECRET_KEY`, `OAUTH_PROVIDERS`, etc.
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
| `OAUTH_PROVIDERS` | `object` \| `JSON string` | `{}` | Unified OAuth/OIDC providers configuration (GitHub, Google, Microsoft, Discord, Apple, Custom OIDC). |

---

## Unified OAuth Configuration (`OAUTH_PROVIDERS`)

MBKAuthe replaces scattered OAuth environment variables with a structured, provider-neutral configuration object.

### Example in `mbkautheVar`:

```json
{
  "APP_NAME": "portal",
  "MAIN_SECRET_TOKEN": "...",
  "SESSION_SECRET_KEY": "...",
  "IS_DEPLOYED": "true",
  "DOMAIN": "mbktech.org",
  "GITHUB": {
    "LOGIN_ENABLED": "true",
    "CLIENT_ID": "gh-app-client-id",
    "CLIENT_SECRET": "gh-app-client-secret"
  },
  "GOOGLE": {
    "LOGIN_ENABLED": "true",
    "CLIENT_ID": "google-client-id.apps.googleusercontent.com",
    "CLIENT_SECRET": "google-client-secret"
  },
  "MICROSOFT": {
    "LOGIN_ENABLED": "true",
    "CLIENT_ID": "azure-client-id",
    "CLIENT_SECRET": "azure-client-secret",
    "TENANT": "common"
  }
}
```

Or nested under `OAUTH_PROVIDERS`:

```json
{
  "OAUTH_PROVIDERS": {
    "github": {
      "login_enabled": true,
      "client_id": "gh-id",
      "client_secret": "gh-sec"
    },
    "google": {
      "login_enabled": true,
      "client_id": "gg-id",
      "client_secret": "gg-sec"
    },
    "keycloak": {
      "type": "oidc",
      "name": "Enterprise SSO",
      "issuer": "https://sso.example.com/realms/main",
      "client_id": "portal-client",
      "client_secret": "sso-secret"
    }
  }
}
```

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

### Production with PostgreSQL & Unified OAuth Providers

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
OAUTH_PROVIDERS='{"github":{"login_enabled":true,"client_id":"gh_id","client_secret":"gh_secret"},"google":{"login_enabled":true,"client_id":"gg_id","client_secret":"gg_secret"}}'
```

---

## Programmatic Access & Validation

You can inspect and validate configuration in code:

```typescript
import { mbkautheVar, validateConfiguration } from "mbkauthe/config";

// Read case-insensitively via proxy
console.log("App Name:", mbkautheVar.APP_NAME); // or mbkautheVar.app_name
console.log("DB Type:", mbkautheVar.DB_TYPE);
console.log("OAuth Providers:", mbkautheVar.OAUTH_PROVIDERS);

// Strict validation (throws descriptive Error if required keys are missing)
try {
  const config = validateConfiguration();
  console.log("Configuration is valid.");
} catch (err) {
  console.error("Configuration validation failed:", err.message);
}
```
