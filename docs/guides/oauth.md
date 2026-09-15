# Social OAuth & OIDC Authentication in MBKAuthe v6

MBKAuthe v6 provides unified social and enterprise authentication for **GitHub**, **Google**, **Microsoft / Entra ID**, **Discord**, **Apple**, and **Custom OIDC** providers. Accounts are linked to user records in the database, allowing users to sign in interchangeably via passwords or social identity providers.

---

## 1. Unified Environment Configuration

Instead of having to manually configure OAuth providers in every single application, MBKAuthe allows setting secrets directly in your environment configuration object (`mbkautheVar`, `mbkauthShared`, or `OAUTH_PROVIDERS`).

### Format Example (`mbkautheVar` / `.env`):

```json
{
  "GITHUB": {
    "LOGIN_ENABLED": "true",
    "CLIENT_ID": "Iv1.8392019384920192",
    "CLIENT_SECRET": "3891028394019283019283019283019283019283"
  },
  "GOOGLE": {
    "LOGIN_ENABLED": "true",
    "CLIENT_ID": "123456789012-abc123xyz.apps.googleusercontent.com",
    "CLIENT_SECRET": "GOCSPX-abc123xyz_example_secret"
  },
  "MICROSOFT": {
    "LOGIN_ENABLED": "true",
    "CLIENT_ID": "azure-client-uuid",
    "CLIENT_SECRET": "azure-client-secret-val",
    "TENANT": "common"
  }
}
```

Or standalone `OAUTH_PROVIDERS` JSON environment variable:

```env
OAUTH_PROVIDERS='{"github":{"login_enabled":true,"client_id":"...","client_secret":"..."},"google":{"login_enabled":true,"client_id":"...","client_secret":"..."}}'
```

---

## 2. Callback URLs

Configure your identity providers with the following standard callback URLs:

| Provider | Callback URL |
|---|---|
| **Modern OAuth Router** | `https://<YOUR_DOMAIN>/auth/oauth/:provider/callback` |
| **Legacy Compatibility** | `https://<YOUR_DOMAIN>/mbkauthe/api/:provider/login/callback` |

---

## 3. Account Linking & Social Login Endpoints

MBKAuthe provides both modern REST endpoints and legacy routes:

- **Modern Initiation**: `GET /auth/oauth/:provider/begin`
- **Modern Callback**: `GET /auth/oauth/:provider/callback`
- **Account Linking**: `POST /auth/oauth/:provider/link`
- **Account Unlinking**: `DELETE /auth/oauth/accounts/:id`
- **Legacy Initiation**: `GET /mbkauthe/api/:provider/login`
- **Legacy Callback**: `GET /mbkauthe/api/:provider/login/callback`

When an OAuth user authenticates:
1. `OAuthFlowService` searches `mbkcore_oauth_accounts` for a matching `provider` and `provider_user_id`.
2. If found, the existing account logs in directly.
3. If not found and `allowAutoLinkByEmail` is enabled with a verified email address matching an existing user, it links securely.
4. Otherwise, a new user account is provisioned or linked via settings.
