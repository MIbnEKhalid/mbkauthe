# Connecting Custom OIDC Identity Providers

MBKAuthe v6 allows connecting **any standard OpenID Connect (OIDC) compliant Identity Provider** (e.g., Keycloak, Okta, Auth0, Authentik, Zitadel, Google Workspace, Azure AD) purely via configuration without custom code.

---

## 1. Discovery-Driven OIDC (Recommended)

When using an OIDC server that exposes `/.well-known/openid-configuration`, MBKAuthe automatically discovers authorization endpoints, token endpoints, userinfo endpoints, and JWKS public keys.

```typescript
import { createAuth } from "mbkauthe";
import { customOIDCProvider } from "mbkauthe/oauth/presets";

export const auth = createAuth({
  oauth: {
    providers: [
      customOIDCProvider({
        id: "keycloak",
        name: "Enterprise Keycloak SSO",
        issuer: "https://auth.company.com/realms/production",
        clientId: "portal-client-id",
        clientSecret: process.env.KEYCLOAK_CLIENT_SECRET!,
        defaultScopes: ["openid", "profile", "email", "roles"],
      }),
    ],
  },
});
```

---

## 2. Manual Endpoint Overrides

If your identity provider does not support standard discovery or is behind an internal proxy, you can specify endpoints manually:

```typescript
import { customOIDCProvider } from "mbkauthe/oauth/presets";

const internalIdp = customOIDCProvider({
  id: "internal-idp",
  name: "Internal SSO",
  clientId: "internal-app",
  clientSecret: process.env.INTERNAL_IDP_SECRET!,
  authorizationEndpoint: "https://sso.internal.corp/oauth2/v1/authorize",
  tokenEndpoint: "https://sso.internal.corp/oauth2/v1/token",
  userinfoEndpoint: "https://sso.internal.corp/oauth2/v1/userinfo",
  jwksUri: "https://sso.internal.corp/oauth2/v1/keys",
  usePkce: true,
});
```

---

## 3. Custom Claim Mapping (`profileParser`)

If your IDP returns custom claim fields (such as nested roles, organization IDs, or employee numbers), use `profileParser`:

```typescript
import { customOIDCProvider } from "mbkauthe/oauth/presets";

const oktaProvider = customOIDCProvider({
  id: "okta",
  name: "Okta Enterprise",
  issuer: "https://company.okta.com",
  clientId: "okta-client-id",
  clientSecret: process.env.OKTA_CLIENT_SECRET!,
  profileParser: (raw, tokens) => {
    return {
      provider: "okta",
      id: raw.sub,
      email: raw.email,
      emailVerified: Boolean(raw.email_verified),
      name: raw.name || `${raw.firstName} ${raw.lastName}`,
      username: raw.preferred_username || raw.email.split("@")[0],
      avatarUrl: raw.profile_picture_url || null,
      raw, // Raw claims preserved for auditing
    };
  },
});
```

---

## 4. End-to-End Security Guarantees

1. **JWKS Key Rotation**: Remote JWKS keys are fetched on demand via `jose.createRemoteJWKSet` and cached with standard cache policies.
2. **Cryptographic Nonce**: Every authorization request generates an unguessable nonce which is verified against the received ID Token `nonce` claim.
3. **Audience & Issuer Check**: ID tokens are strictly validated to ensure `aud === clientId` and `iss === issuer`.
4. **Token Encryption**: Tokens stored in `mbkcore_oauth_accounts` are encrypted with AES-256-GCM.
