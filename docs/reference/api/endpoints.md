# REST Endpoints Catalog

Comprehensive specification of all HTTP routes and API endpoints in MBKAuthe v6.

---

## 1. Authentication & Session Endpoints

### `POST /mbkauthe/api/login`
Authenticates user with username/email and password.
- **Request Body**:
  ```json
  {
    "username": "alice",
    "password": "mySecurePassword123"
  }
  ```
- **Response (200 OK)**:
  ```json
  {
    "success": true,
    "user": {
      "id": 1,
      "username": "alice",
      "email": "alice@example.com",
      "role": "normaluser"
    }
  }
  ```

### `POST /mbkauthe/api/logout`
Logs out current active session and clears session cookies.

### `POST /mbkauthe/api/logout-all`
Destroys all active sessions across all devices for the current user.

### `POST /mbkauthe/api/checkSession` or `POST /mbkauthe/api/verifySession`
Validates a session token or current cookie session.
- **Request Body** (optional): `{ "sessionId": "..." }`
- **Response (200 OK)**: `{ "valid": true, "user": { ... } }`

---

## 2. Two-Factor Authentication (2FA)

### `POST /mbkauthe/api/verify-2fa`
Submits TOTP 6-digit code after password verification.
- **Request Body**:
  ```json
  {
    "token": "123456",
    "trustDevice": true
  }
  ```

---

## 3. Personal Access Tokens (PAT)

### `GET /mbkauthe/api/tokens`
Lists all active API tokens created by the current logged-in user.

### `POST /mbkauthe/api/tokens`
Generates a new Personal Access Token (`mbk_pat_...`).
- **Request Body**:
  ```json
  {
    "name": "Deployment Automation",
    "scopes": ["portal:build:trigger"],
    "expiresInDays": 30
  }
  ```
- **Response (201 Created)**:
  ```json
  {
    "success": true,
    "token": "mbk_pat_9a8b7c...",
    "id": 42,
    "name": "Deployment Automation"
  }
  ```

### `DELETE /mbkauthe/api/tokens/:id`
Revokes an active Personal Access Token by ID.

---

## 4. RFC 8628 CLI Device Login

### `POST /mbkauthe/api/cli-auth/device-code`
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

### `POST /mbkauthe/api/cli-auth/poll`
CLI polls for authorization status using `device_code`.
- **Response (200 OK)**:
  - `{ "status": "pending" }` (User hasn't approved yet)
  - `{ "status": "approved", "token": "mbk_cli_...", "user": { ... } }`
  - `{ "status": "denied" }`

---

## 5. Diagnostics & Logs

### `GET /mbkauthe/api/health`
Returns real-time health diagnostic status of MBKAuthe and database connectivity.

### `GET /mbkauthe/db-logs`
Development endpoint (requires `ENV=dev` and `DB_LOGS=true`) to inspect live database query execution metrics.
