# Authentication and Sessions

[Back to API index](../api.md) | [Back to docs index](../../README.md) | [Back to project README](../../../README.md)

## Authentication

MBKAuthe supports two authentication methods:

1. **Session-based Authentication** - Cookie-based sessions for web applications
2. **Token-based Authentication** - Persistent API keys for server-to-server communication

### Token-based Authentication

For API clients and external services, use a Bearer token in the `Authorization` header.

**Header Format:**
```
Authorization: Bearer <your_api_token>
```
*Token format: `mbk_` followed by 64 hexadecimal characters.*

**Behavior:**
- **Stateless:** Validates against the `ApiTokens` table on every request.
- **Expiration:** Tokens can have an optional expiration date.
- **Permissions:** API tokens inherit the permissions of the user who created them.
- **Scopes:** Tokens have a scope (`read-only` or `write`) that controls which HTTP methods are allowed:
  - `read-only`: Only GET, HEAD, and OPTIONS requests (safe, read-only operations)
  - `write`: All HTTP methods (GET, POST, PUT, DELETE, PATCH, etc.)
- **Usage Tracking:** The system updates the `LastUsed` timestamp on every successful request.

**Errors:**
- `401 Unauthorized` (Code 1005: `INVALID_AUTH_TOKEN`): Token is malformed or not found.
- `401 Unauthorized` (Code 1006: `API_TOKEN_EXPIRED`): Token exists but has passed its expiration date.
- `403 Forbidden` (Code 1007: `TOKEN_SCOPE_INSUFFICIENT`): Token scope doesn't allow this HTTP method.

**Example Usage:**

**1. Backend Implementation (Express):**

Even when using API tokens, the `validateSession`/`sessVal` middleware hydrates `req.session.user` for consistency, allowing you to use the same route logic for both browser and API clients.

```javascript
import { sessVal } from 'mbkauthe';

app.get('/api/protected-resource', sessVal, (req, res) => {
  // Access user info populated from the token
  const user = req.session.user; // { id, username, role, ... }
  
  res.json({ 
    message: `Hello ${user.username}`,
    role: user.role
  });
});
```

**2. Client Request Examples:**

*cURL:*
```bash
curl -X GET https://api.yourdomain.com/api/protected-resource \
  -H "Authorization: Bearer mbk_7f83a92b1dc..."
```

*JavaScript (Fetch):*
```javascript
const response = await fetch('https://api.yourdomain.com/api/protected-resource', {
  headers: {
    'Authorization': 'Bearer mbk_7f83a92b1dc...'
  }
});
const data = await response.json();
```

**Output:**
```json
{
  "message": "Hello john.doe",
  "role": "NormalUser"
}
```

---

## Session Management

### Session Cookie

When a user logs in, MBKAuthe creates a session and sets the following cookies:

| Cookie Name | Description | HttpOnly | Secure | SameSite |
|------------|-------------|----------|--------|----------|
| `mbkauthe.sid` | Session identifier | ✓ | Auto* | lax |
| `sessionId` | Encrypted session token (AES-256-GCM). This cookie is encrypted and treated as an opaque value by clients; do not attempt to parse or rely on the raw cookie contents. Use server endpoints (e.g., `GET /mbkauthe/api/checkSession`, `POST /mbkauthe/api/checkSession` (body) or `POST /mbkauthe/api/verifySession`) to validate or query session information. | ✓ | Auto* | lax |
| `username` | Username | ✗ | Auto* | lax |

\* `secure` flag is automatically set to `true` in production when `IS_DEPLOYED=true`

### Session Lifetime

- Default: 2 days (configurable via `COOKIE_EXPIRE_TIME`)
- Application sessions are stored in the `Sessions` table in PostgreSQL
- Sessions persist across subdomains in production

---

