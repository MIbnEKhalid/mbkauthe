# REST Endpoints Catalog

Comprehensive specification of all HTTP routes and API endpoints in MBKAuthe v6.

---

## 1. Authentication & Session Endpoints

### `POST /mbkauthe/api/login`
Authenticates user with username and password.
- **Rate Limit**: 8 requests per minute.
- **Request Body**:
  ```json
  {
    "username": "alice",
    "password": "mySecurePassword123",
    "redirect": "/dashboard"
  }
  ```
- **Response (200 OK - Standard Login)**:
  ```json
  {
    "success": true,
    "user": {
      "user_id": 1,
      "username": "alice",
      "full_name": "Alice Smith",
      "role": "normaluser",
      "allowed_apps": ["portal"]
    },
    "redirect_url": "/dashboard"
  }
  ```
- **Response (200 OK - 2FA Required)**:
  ```json
  {
    "success": true,
    "two_factor_required": true,
    "redirect_url": "/dashboard"
  }
  ```

### `POST /mbkauthe/api/logout`
Logs out active session and clears session cookies.

### `POST /mbkauthe/api/logout-all`
Destroys all active sessions across all devices for the authenticated user.

### `POST /mbkauthe/api/switch-session`
Switches active account on a multi-session device.
- **Request Body**:
  ```json
  {
    "target_username": "bob",
    "target_sid": "98a7b6c5-4321-..."
  }
  ```

### `GET /mbkauthe/api/account-sessions`
Lists all active remembered accounts stored in the device cookie.

### `POST /mbkauthe/api/logout-account`
Logs out a specific remembered account from the device without affecting other accounts.

### `POST /mbkauthe/api/checkSession` or `POST /mbkauthe/api/verifySession`
Validates a session token or current cookie session.
- **Request Body** (optional): `{ "sessionId": "..." }`
- **Response (200 OK)**:
  ```json
  {
    "valid": true,
    "user": {
      "username": "alice",
      "role": "normaluser",
      "full_name": "Alice Smith"
    }
  }
  ```

---

## 2. Two-Factor Authentication (2FA)

### `POST /mbkauthe/api/verify-2fa`
Submits TOTP 6-digit code after password verification.
- **Rate Limit**: 5 requests per minute.
- **Request Body**:
  ```json
  {
    "token": "123456"
  }
  ```

---

## 3. WebAuthn / FIDO2 Passkeys

Mounted under `/mbkauthe/api/passkey/*`:

### `POST /mbkauthe/api/passkey/register-options`
Generates WebAuthn registration options and challenge for an authenticated user.
- **Auth Required**: Session Cookie.
- **Response (200 OK)**:
  ```json
  {
    "challenge": "e8a9...b4c2",
    "rp": { "name": "portal", "id": "localhost" },
    "user": { "id": "1", "name": "alice", "displayName": "Alice Smith" },
    "pubKeyCredParams": [{ "alg": -7, "type": "public-key" }, { "alg": -257, "type": "public-key" }],
    "excludeCredentials": []
  }
  ```

### `POST /mbkauthe/api/passkey/register-verify`
Verifies WebAuthn attestation response and stores the passkey.
- **Auth Required**: Session Cookie.
- **Request Body**:
  ```json
  {
    "registrationResponse": { "id": "...", "rawId": "...", "response": { ... }, "type": "public-key" },
    "name": "My MacBook Touch ID"
  }
  ```
- **Response (200 OK)**:
  ```json
  {
    "success": true,
    "passkey": {
      "id": 1,
      "name": "My MacBook Touch ID",
      "device_type": "multiDevice",
      "created_at": "2026-09-15T12:00:00.000Z"
    }
  }
  ```

### `POST /mbkauthe/api/passkey/login-options`
Generates WebAuthn assertion options and challenge for passwordless sign-in.
- **Auth Required**: Public.
- **Request Body** (optional): `{ "username": "alice" }`
- **Response (200 OK)**:
  ```json
  {
    "challenge": "f1d2...c3b4",
    "rpId": "localhost",
    "timeout": 60000,
    "userVerification": "preferred"
  }
  ```

### `POST /mbkauthe/api/passkey/login-verify`
Verifies WebAuthn assertion signature, checks counter anti-replay, and mints authenticated session.
- **Auth Required**: Public.
- **Request Body**:
  ```json
  {
    "authenticationResponse": { "id": "...", "rawId": "...", "response": { ... }, "type": "public-key" },
    "redirect": "/dashboard"
  }
  ```
- **Response (200 OK)**:
  ```json
  {
    "success": true,
    "user": {
      "user_id": 1,
      "username": "alice",
      "full_name": "Alice Smith",
      "role": "normaluser"
    },
    "redirect_url": "/dashboard"
  }
  ```

### `GET /mbkauthe/api/passkey/list`
Lists all registered passkeys for the active user.
- **Auth Required**: Session Cookie.

### `PATCH /mbkauthe/api/passkey/:id`
Renames an existing registered passkey.
- **Auth Required**: Session Cookie.
- **Request Body**: `{ "name": "Office YubiKey 5C" }`

### `DELETE /mbkauthe/api/passkey/:id`
Deletes a registered passkey.
- **Auth Required**: Session Cookie.

---

## 4. Provider-Neutral OAuth & OIDC Endpoints

Mounted under `/mbkauthe/oauth/*` (or `/auth/oauth/*` via Express adapter):

| Method | Path | Description | Authentication |
|---|---|---|---|
| `GET` | `/mbkauthe/oauth/providers` | Lists configured social providers | Public |
| `GET` | `/mbkauthe/oauth/:provider/begin` | Generates state & PKCE, redirects to IDP | Public |
| `GET` | `/mbkauthe/oauth/:provider/callback` | Validates IDP response, logs in / links user | Public |
| `POST` | `/mbkauthe/oauth/:provider/link` | Initiates linking provider to logged-in user | Session Cookie |
| `DELETE` | `/mbkauthe/oauth/accounts/:id` | Unlinks connected social identity | Session Cookie |
| `GET` | `/mbkauthe/oauth/accounts` | Lists connected social accounts | Session Cookie |

---

## 5. Personal Access Tokens (PAT)

### `GET /user/api-tokens`
Lists active API tokens created by the current logged-in user.

### `POST /api/token`
Generates a new Personal Access Token (`mbk_pat_...`).
- **Request Body**:
  ```json
  {
    "name": "Deployment CI",
    "scopes": ["portal:build:trigger"],
    "expiresInDays": 30
  }
  ```
- **Response (200 OK)**:
  ```json
  {
    "success": true,
    "token": "mbk_pat_9a8b7c...",
    "id": 42,
    "name": "Deployment CI"
  }
  ```

### `DELETE /api/tokens/:id`
Revokes an active Personal Access Token owned by the user.

### `POST /api/tokens/verify`
Tests token validity and returns token user info.

---

## 6. Admin API Token Management

Accessible to `superadmin` users:

- `GET /dashboard/admin/api-tokens`: Renders token administration dashboard.
- `GET /api/admin/api-tokens/stats`: Returns token metrics (total, active, expired).
- `GET /api/admin/api-tokens/:username`: Lists all tokens created by a specific user.
- `DELETE /api/admin/api-tokens/:id`: Revokes any token by ID.
- `DELETE /api/admin/api-tokens/user/:username`: Revokes all tokens for a user.

---

## 7. RFC 8628 CLI Device Login

### `POST /api/cli/device`
Initiates a new CLI device authorization session.
- **Request Body**: `{ "client_name": "My CLI Tool" }`
- **Response (200 OK)**:
  ```json
  {
    "device_code": "d8f7e6...",
    "user_code": "RRR2-L9QJ",
    "verification_uri": "https://auth.mbktech.org/mbkauthe/cli-auth/verify",
    "expires_in": 900,
    "interval": 5
  }
  ```

### `POST /api/cli/device/token`
CLI polls for authorization status using `device_code`.
- **Response (200 OK)**:
  - `{ "status": "pending" }` (User hasn't approved yet)
  - `{ "status": "approved", "token": "mbk_cli_...", "user": { ... } }`
  - `{ "status": "denied" }`

### `POST /api/cli/device/approve`
Approves the CLI session from the browser interface.

---

## 8. Diagnostics & Operations

### `GET /mbkauthe/api/health`
Returns real-time health diagnostic status of MBKAuthe and database connectivity.

### `GET /mbkauthe/db` / `GET /mbkauthe/db.json`
Development endpoint (requires `ENV=dev` and `DB_LOGS=true`) to inspect live database query execution metrics.

