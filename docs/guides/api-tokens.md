# API Tokens & TokenEngine in MBKAuthe v6

MBKAuthe v6 features a cryptographic **TokenEngine** and **ApiTokenService** for managing scoped Personal Access Tokens (PATs). Tokens are stored as SHA-256 hashes and evaluated with constant-time equality checks.

---

## 1. TokenEngine & Prefixes

The `TokenEngine` creates cryptographically secure tokens with standard prefixes:

| Token Type | Prefix | Entropy | Description |
|---|---|---|---|
| `pat` | `mbk_pat_` | 32 bytes (64 hex) | Personal Access Token for API clients and automations. |
| `cli` | `mbk_cli_` | 32 bytes (64 hex) | CLI Device Authorization session token. |
| `device` | `mbk_dev_` | 32 bytes (64 hex) | 2FA trusted device remember token. |
| `session` | `mbk_sess_` | 32 bytes (64 hex) | Encrypted user session identifier. |

### Generating Tokens Programmatically

```typescript
import { TokenEngine } from "mbkauthe/core";

// Create Personal Access Token
const rawToken = TokenEngine.createApiToken();
console.log("New PAT:", rawToken); // "mbk_pat_a8f7c9e12..."

// Hash token for database storage
const hash = TokenEngine.hashToken(rawToken);

// Constant-time token verification
const matches = TokenEngine.verifyToken(rawToken, hash);
console.log("Token matches hash:", matches); // true
```

---

## 2. Managing API Tokens via `ApiTokenService`

```typescript
import { apiTokenService } from "mbkauthe/services";

// Create a new API token for a user
const { token, record } = await apiTokenService.createToken({
  userId: 42,
  name: "GitHub Actions CI",
  scopes: ["portal:build:trigger", "portal:deploy:write"],
  expiresInDays: 90,
});

console.log("Raw Bearer Token (display once):", token);
console.log("Token Record ID:", record.id);
```

---

## 3. Authenticating API Requests

Clients pass the token in the standard `Authorization` header:

```http
GET /api/deployments HTTP/1.1
Host: api.mbktech.org
Authorization: Bearer mbk_pat_a8f7c9e12...
```

### Validating API Tokens with `validateApiSession`

Use `validateApiSession` or `validateSession` (which supports both session cookies and Bearer tokens transparently):

```typescript
import express from "express";
import { sessVal, permChk } from "mbkauthe";

const app = express();

// Authenticate via either Session Cookie or Bearer API Token
app.get("/api/deployments", sessVal, permChk("portal:deploy:write"), (req, res) => {
  res.json({ status: "deployed", user: (req as any).auth?.user || req.session.user });
});
```
