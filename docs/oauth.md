# Provider-Neutral OAuth & OIDC Architecture in MBKAuthe

MBKAuthe v6 replaces Passport with a modern, framework-agnostic **provider-neutral OAuth 2.0 and OpenID Connect (OIDC)** engine. The core architecture is decoupled from HTTP frameworks, with Express provided as a thin adapter layer.

---

## Key Features

1. **Framework-Agnostic Core (`mbkauthe/oauth`)**:
   - Zero dependencies on Express or Passport in core.
   - Works in Node.js, serverless runtimes, microservices, and background jobs.
2. **Native OIDC Discovery & Cryptographic Verification (`jose`)**:
   - Automatically resolves endpoints from `/.well-known/openid-configuration`.
   - Validates ID Token signatures against remote JWKS (`jose.createRemoteJWKSet`).
   - Validates `iss`, `aud`, `exp`, and cryptographic `nonce`.
3. **PKCE Default-On (RFC 7636)**:
   - S256 code challenge generation and validation on every authorization flow.
4. **Token Encryption at Rest**:
   - Access tokens, refresh tokens, and ID tokens are encrypted using **AES-256-GCM** before database storage.
5. **Dependency Injection (`createAuth`)**:
   - Pure dependency injection with zero global singletons and zero `process.env` pollution in core modules.
6. **Built-in Presets**:
   - Google (`googleProvider`)
   - GitHub (`githubProvider`)
   - Microsoft / Entra ID (`microsoftProvider`)
   - Discord (`discordProvider`)
   - Apple (`appleProvider`)
   - Custom OIDC (`customOIDCProvider`)

---

## Architecture Overview

```mermaid
graph TD
    Client[Web / Mobile / CLI] --> ExpressAdapter[Express Router Adapter (/auth/oauth)]
    ExpressAdapter --> FlowService[OAuthFlowService]
    FlowService --> StateStore[OAuthStateStore (PKCE, State, Nonce)]
    FlowService --> Provider[OAuthProvider / OIDCProvider]
    FlowService --> Repo[OAuthAccountRepository (Postgres/SQLite)]
    FlowService --> Crypto[AES-256-GCM Encryptor]
    FlowService --> EventBus[Domain Events (oauth.*)]
    Provider --> HttpClient[OAuthHttpClient (Native fetch)]
    Provider --> Jose[jose (JWKS & JWT Verification)]
```

---

## Configuration with `createAuth`

Configure OAuth providers without global environment variables:

```typescript
import { createAuth } from "mbkauthe";
import {
  googleProvider,
  githubProvider,
  microsoftProvider,
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
      customOIDCProvider({
        id: "keycloak",
        name: "Keycloak SSO",
        issuer: "https://auth.company.com/realms/main",
        clientId: "company-app",
        clientSecret: process.env.KEYCLOAK_SECRET!,
      }),
    ],
  },
});

export default auth;
```

---

## Express Adapter Integration

Mount the OAuth router in your Express application:

```typescript
import express from "express";
import auth from "./auth.config.js";

const app = express();

// Mount OAuth endpoints at /auth/oauth
app.use("/auth/oauth", auth.createOAuthRouter({
  defaultRedirectUrl: "/dashboard",
}));
```

### Mounted REST Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/auth/oauth/providers` | Lists all enabled OAuth providers. |
| `GET` | `/auth/oauth/:provider/begin` | Generates state/PKCE and redirects to IDP authorization URL. |
| `GET` | `/auth/oauth/:provider/callback` | Handles callback from IDP, validates state, creates session. |
| `POST` | `/auth/oauth/:provider/link` | Initiates linking a social provider to the logged-in user. |
| `DELETE` | `/auth/oauth/accounts/:id` | Unlinks a social account by ID or provider name. |
| `GET` | `/auth/oauth/accounts` | Lists linked accounts for the current authenticated user. |

---

## Normalized User Profile Shape

Every provider returns an identical `OAuthUserProfile` shape:

```typescript
export interface OAuthUserProfile {
  provider: string;           // "google" | "github" | "microsoft" | etc.
  id: string;                 // Unique user ID from IDP
  email: string | null;       // Primary user email
  emailVerified: boolean;     // Whether email is verified by IDP
  name: string | null;        // Full display name
  username: string | null;    // Preferred username/handle
  avatarUrl: string | null;   // Profile picture URL
  raw: Record<string, any>;   // Original raw claims / JSON
}
```

---

## Domain Audit Events

The OAuth engine emits structured domain events:

- `oauth.begin`: OAuth authorization flow started.
- `oauth.callback.success`: Successful OAuth login.
- `oauth.callback.failure`: OAuth callback failed.
- `oauth.account.linked`: Social account linked to existing user.
- `oauth.account.unlinked`: Social account disconnected.
- `oauth.new_user.created`: New user provisioned via social login.
- `oauth.suspicious`: Security anomaly detected (state tampering, replay, CSRF attempt).

```typescript
import { authEvents } from "mbkauthe";

authEvents.on("oauth.suspicious", (event) => {
  console.warn(`[SECURITY ALERT] Suspicious OAuth activity from IP ${event.ip}: ${event.reason}`);
});
```
