# Session Engine & Authentication in MBKAuthe v6

MBKAuthe v6 features a multi-session engine with client-side encrypted cookies, automatic session restoration, unified authentication context (`req.auth` and `req.session`), multi-device tracking, and concurrent session limits (`MAX_SESSIONS_PER_USER`).

---

## 1. How Authentication Works

```
┌─────────────────────────────────────────────────────────────┐
│ 1. User Submits Credentials (POST /mbkauthe/api/login)      │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│ 2. AuthService Validates Password (PBKDF2/Argon2id + Pepper)│
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│ 3. Check App Authorization & Enforce MAX_SESSIONS_PER_USER   │
│    (Evict oldest session if limit exceeded)                 │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│ 4. Issue Encrypted session_id Cookie & Multi-Account List   │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│ 5. SessionRestoration Middleware Rebuilds req.session & auth│
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Password Hashing & Security

MBKAuthe hashes user passwords using cryptographically secure PBKDF2/Argon2id hybrid mechanics with:
- **Per-User Unique Salts**: 32-byte cryptographically random hex salt.
- **Server-Side Secret Pepper**: Injected from `SESSION_SECRET_KEY` so database compromises alone cannot be cracked offline.
- **Constant-Time Verification**: Comparison via `crypto.timingSafeEqual`.

```typescript
import { hashPassword, verifyPassword } from "mbkauthe/config";

// Hash a new user password
const hash = await hashPassword("superSecretP@ssword123", "alice");

// Verify password
const isValid = await verifyPassword("superSecretP@ssword123", "alice", hash);
console.log("Password valid:", isValid);
```

---

## 3. Session Validation Middleware (`sessVal`)

To protect any Express route, apply the `validateSession` (`sessVal`) middleware:

```typescript
import express from "express";
import { sessVal, reloadSessionUser } from "mbkauthe";

const router = express.Router();

// Protect a route with session cookie or API token
router.get("/profile", sessVal, (req, res) => {
  // Legacy session object
  const user = req.session.user;
  
  // Unified AuthContext domain model
  const auth = (req as any).auth;
  
  res.json({
    id: user.user_id || user.id,
    username: user.username,
    role: user.role,
    permissions: req.session.permissions,
    authPrincipal: auth?.principal,
    authMethod: auth?.authMethod,
  });
});

// Refresh user permissions/roles from database on demand
router.get("/refresh-profile", sessVal, reloadSessionUser, (req, res) => {
  res.json({ message: "User refreshed from database", user: req.session.user });
});
```

---

## 4. Multi-Session Management & Auto-Pruning

MBKAuthe tracks all active sessions in the database (`mbkcore_session` unified session table).

- When a user logs in, the engine checks their total active session count.
- If it exceeds `MAX_SESSIONS_PER_USER` (default: `5`), the oldest active sessions are automatically destroyed.
- Users can log out of the current device, a specific remembered account, or all devices simultaneously via `POST /mbkauthe/api/logout-all`.

---

## 5. Device-Based Account Management (`AuthService`)

MBKAuthe provides comprehensive device session management via `AuthService` and client cookies:

```typescript
import { authService } from "mbkauthe/services";

// 1. List all active accounts on a specific device
const { accounts, current_session_id } = await authService.listDeviceAccounts(deviceId, currentSid);

// 2. Switch device session to a specific remembered account
const switched = await authService.switchDeviceSession(deviceId, targetSid, currentUserId);

// 3. Logout a single account on this device
await authService.logoutDeviceAccount(deviceId, targetSid);

// 4. Logout all accounts from this device
await authService.logoutAllDeviceAccounts(deviceId);

// 5. Check session validity programmatically
const status = await authService.validateSession(sessionId);
console.log("Valid:", status.valid, "Expires:", status.expiry);
```

### Switching Active Session via REST API

Send a `POST` request to `/mbkauthe/api/switch-session`:

```json
{
  "target_sid": "98a7b6c5-4321-4def-9abc-1234567890ab"
}
```

---

## 6. Local-Only User Guard

For development and staging workflows, test accounts can be flagged with `is_local_only = true` in the database.

When `IS_DEPLOYED=true` or in production environments:
- Local-only accounts are **strictly blocked** from authenticating or switching sessions.
- Login attempts immediately return HTTP 403 with `LOCAL_USER_PROD_RESTRICTED` error code.
- This prevents accidental leakage or usage of mock/developer credentials in production deployments.

---

## 7. User Avatar Service (`AvatarService`)

MBKAuthe includes a built-in avatar generation and proxy service:

- **Endpoint**: `GET /avatar/:username`
- If the user has a custom profile image URL, it redirects to the image or delivers the cached asset.
- If no image is configured, `AvatarService` generates a crisp, personalized SVG avatar using the user's initials with consistent background hashing.

```typescript
import { avatarService } from "mbkauthe/services";

// Generate SVG string directly
const svg = avatarService.generateInitialsSvg("Alice Smith", 96);
```
