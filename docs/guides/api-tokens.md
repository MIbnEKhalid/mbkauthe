# API Tokens & TokenEngine in MBKAuthe v6

MBKAuthe v6 features a cryptographic **TokenEngine** and **ApiTokenService** for managing scoped Personal Access Tokens (PATs). Tokens are stored as SHA-256 hashes and evaluated with constant-time equality checks.

---

## 1. TokenEngine & Prefixes

The `TokenEngine` creates cryptographically secure tokens with standard prefixes:

| Token Type | Prefix | Entropy | Description |
|---|---|---|---|
| `pat` | `mbk_pat_` | 32 bytes (64 hex) | Personal Access Token for API clients and automations. |
| `cli` | `mbk_cli_` | 32 bytes (64 hex) | CLI Device Authorization session token. |
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

// Parse token prefix and entropy
const parsed = TokenEngine.parseToken(rawToken);
console.log("Token type:", parsed.type); // "pat"
```

---

## 2. Managing API Tokens via `ApiTokenService`

```typescript
import { apiTokenService } from "mbkauthe/services";

// 1. Create a new API token for a user with optional role/limit options
const { token, tokenRecord } = await apiTokenService.createToken(
  "alice",
  {
    name: "GitHub Actions CI",
    scopes: ["portal:build:trigger", "portal:deploy:write"],
    expiresInDays: 90,
  },
  {
    userRole: "normaluser",
    maxTokensPerUser: 10,
  }
);

console.log("Raw Bearer Token (display once):", token);
console.log("Token Record ID:", tokenRecord.id);

// 2. Programmatically verify an incoming raw Bearer token
const verified = await apiTokenService.verifyToken(token);
console.log("Valid:", verified.valid, "User:", verified.username, "Permissions:", verified.permissions);

// 3. List user tokens
const tokens = await apiTokenService.listUserTokens("alice");

// 4. Revoke a token
await apiTokenService.revokeToken(tokenRecord.id, "alice");

// 5. Admin: List tokens for a specific user
const userTokens = await apiTokenService.listTokensForUserAdmin("alice");

// 6. Admin: Bulk revoke multiple tokens
const revokedCount = await apiTokenService.bulkRevokeTokens([1, 2, 3]);
```

---

## 3. Authenticating API Requests

Clients pass the token in the standard `Authorization` header:

```http
GET /api/deployments HTTP/1.1
Host: api.mbktech.org
Authorization: Bearer mbk_pat_a8f7c9e12...
```

### Validating API Tokens with `sessVal` or `validateApiSession`

MBKAuthe's `validateSession` (`sessVal`) middleware transparently supports both browser session cookies and Bearer tokens:

```typescript
import express from "express";
import { sessVal, permChk } from "mbkauthe";

const app = express();

// Authenticate via either Session Cookie or Bearer API Token
app.get("/api/deployments", sessVal, permChk("portal:deploy:write"), (req, res) => {
  res.json({
    status: "deployed",
    user: (req as any).auth?.user || req.session.user,
    authContext: (req as any).auth,
  });
});
```

---

## 4. User and Admin REST Endpoints

MBKAuthe provides comprehensive REST endpoints for token management:

### User Endpoints
- `GET /user/api-tokens`: List active tokens for the logged-in user.
- `POST /api/token`: Create a new PAT with name, scopes, and expiration.
- `DELETE /api/tokens/:id`: Revoke a PAT owned by the user.
- `POST /api/tokens/verify`: Test PAT validity and view associated scopes.

### Admin Endpoints (Superadmin Only)
- `GET /dashboard/admin/api-tokens`: Admin dashboard listing all tokens.
- `GET /api/admin/api-tokens/stats`: Token metrics (total, active, expired).
- `GET /api/admin/api-tokens/user/:username`: List tokens for a specific user.
- `DELETE /api/admin/api-tokens/:id`: Revoke any token by ID.
- `POST /api/admin/api-tokens/bulk-revoke`: Bulk revoke multiple tokens by ID array (`{ "token_ids": [1, 2, 3] }`).
- `DELETE /api/admin/api-tokens/user/:username`: Revoke all tokens for a user.


