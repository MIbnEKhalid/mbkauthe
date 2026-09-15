# Provider-Neutral OAuth & OIDC in MBKAuthe v6

MBKAuthe v6 provides unified social and enterprise authentication for **Google**, **GitHub**, **Microsoft / Entra ID**, **Discord**, **Apple**, and **Custom OIDC** providers. Accounts are linked to user records in the database, allowing users to sign in interchangeably via passwords or social identity providers.

---

## 1. OAuth Architecture & Specialized Guides

For in-depth architectural details, refer to the dedicated guides:
- [OAuth Architecture Reference](../oauth.md) — Comprehensive explanation of PKCE, jose JWKS verification, state store, and token encryption.
- [Custom OIDC Integration Guide](../oauth-custom-oidc.md) — Step-by-step setup for Keycloak, Auth0, Okta, and enterprise OpenID Connect servers.
- [OAuth Migration Guide](../oauth-migration.md) — Guide for migrating existing applications to MBKAuthe v6.

---

## 2. Configuration via `createAuth` (Recommended)

MBKAuthe supports declarative, dependency-injected configuration without polluting global state:

```typescript
import { createAuth } from "mbkauthe";
import {
  googleProvider,
  githubProvider,
  microsoftProvider,
  discordProvider,
  appleProvider,
  customOIDCProvider,
} from "mbkauthe/oauth/presets";

const auth = createAuth({
  appName: "portal",
  oauth: {
    stateTtlSeconds: 600, // 10 minutes
    allowAutoLinkByEmail: true,
    encryptionKey: process.env.OAUTH_ENCRYPTION_KEY,
    providers: [
      googleProvider({
        clientId: process.env.GOOGLE_CLIENT_ID!,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
      }),
      githubProvider({
        clientId: process.env.GITHUB_CLIENT_ID!,
        clientSecret: process.env.GITHUB_CLIENT_SECRET!,
      }),
      microsoftProvider({
        clientId: process.env.AZURE_CLIENT_ID!,
        clientSecret: process.env.AZURE_CLIENT_SECRET!,
        tenantId: "common",
      }),
      discordProvider({
        clientId: process.env.DISCORD_CLIENT_ID!,
        clientSecret: process.env.DISCORD_CLIENT_SECRET!,
      }),
      customOIDCProvider({
        id: "keycloak",
        name: "Enterprise SSO",
        issuer: "https://sso.example.com/realms/main",
        clientId: "portal-client",
        clientSecret: process.env.KEYCLOAK_SECRET!,
      }),
    ],
  },
});

export default auth;
```

---

## 3. Environment Variable Configuration (`OAUTH_PROVIDERS`)

You can also configure providers using the `OAUTH_PROVIDERS` JSON environment variable or `mbkautheVar`:

```env
OAUTH_PROVIDERS='{"github":{"login_enabled":true,"client_id":"...","client_secret":"..."},"google":{"login_enabled":true,"client_id":"...","client_secret":"..."}}'
```

---

## 4. Callback URLs & Routing

Configure your identity provider consoles with the following callback URLs:

| Provider | Callback URL |
|---|---|
| **Modern OAuth Router** | `https://<YOUR_DOMAIN>/auth/oauth/:provider/callback` (or `/mbkauthe/oauth/:provider/callback`) |
| **Legacy Compatibility** | `https://<YOUR_DOMAIN>/mbkauthe/api/:provider/login/callback` |

---

## 5. Account Linking & Social Login Endpoints

MBKAuthe provides REST endpoints for social login and account management:

- `GET /mbkauthe/oauth/providers` — List enabled OAuth providers for UI rendering.
- `GET /mbkauthe/oauth/:provider/begin` — Generate PKCE/state and redirect to IDP.
- `GET /mbkauthe/oauth/:provider/callback` — Handle IDP callback, verify PKCE/JWKS, and establish session.
- `POST /mbkauthe/oauth/:provider/link` — Link social identity to currently authenticated user.
- `DELETE /mbkauthe/oauth/accounts/:id` — Disconnect a linked social account.
- `GET /mbkauthe/oauth/accounts` — List all connected social accounts for the user.

When an OAuth user authenticates:
1. `OAuthFlowService` searches `mbkcore_oauth_accounts` for matching `provider` and `provider_user_id`.
2. If found, logs in the existing linked user account.
3. If not found and `allowAutoLinkByEmail` is enabled with a verified email matching an existing account, links automatically.
4. Otherwise, provisions a new user or redirects to account completion.

