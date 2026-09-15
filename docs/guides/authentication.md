# Session Engine & Authentication in MBKAuthe v6

MBKAuthe v6 features a multi-session engine with client-side encrypted cookies, automatic session restoration, multi-device tracking, and concurrent session limits (`MAX_SESSIONS_PER_USER`).

---

## 1. How Authentication Works

```
┌─────────────────────────────────────────────────────────────┐
│ 1. User Submits Credentials (POST /mbkauthe/api/login)      │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│ 2. AuthService Validates Password (Argon2id/PBKDF2+Pepper)   │
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
│ 5. SessionRestoration Middleware Rebuilds Session on Request│
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
const hash = await hashPassword("superSecretP@ssword123");

// Verify password
const isValid = await verifyPassword("superSecretP@ssword123", hash);
console.log("Password valid:", isValid);
```

---

## 3. Session Validation Middleware (`sessVal`)

To protect any Express route, apply the `validateSession` (`sessVal`) middleware:

```typescript
import express from "express";
import { sessVal, reloadSessionUser } from "mbkauthe";

const router = express.Router();

// Protect a route
router.get("/profile", sessVal, (req, res) => {
  const user = req.session.user;
  res.json({
    id: user.id,
    username: user.username,
    role: user.role,
    permissions: req.session.permissions,
  });
});

// Refresh user permissions/roles from database on demand
router.get("/refresh-profile", sessVal, reloadSessionUser, (req, res) => {
  res.json({ message: "User refreshed from database", user: req.session.user });
});
```

---

## 4. Multi-Session Management & Auto-Pruning

MBKAuthe tracks all active sessions in the database (`app_sessions` / `sessions` table).

- When a user logs in, the engine checks their total active session count.
- If it exceeds `MAX_SESSIONS_PER_USER` (default: `5`), the oldest active sessions are automatically destroyed.
- Users can log out of the current device, a specific remembered account, or all devices simultaneously via `POST /mbkauthe/api/logout-all`.

---

## 5. Multi-Account Cookie Management

MBKAuthe supports multiple active accounts on a single browser device via the `mbkauth_accounts` cookie:

```typescript
import {
  readAccountListFromCookie,
  upsertAccountListCookie,
  removeAccountFromCookie,
} from "mbkauthe";

// Inspect active accounts on device
const accounts = readAccountListFromCookie(req);
console.log("Active accounts on device:", accounts);
```
