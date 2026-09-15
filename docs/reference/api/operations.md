# Events, Observability & Operations

MBKAuthe v6 provides observability tools including type-safe domain event streaming (`authEvents`), comprehensive health reporting (`getAuthHealthReport`), and live database query logging.

---

## 1. Domain Event Streaming (`authEvents`)

MBKAuthe emits typed domain events throughout the authentication and authorization lifecycle. You can subscribe to these events for audit logging, analytics, webhooks, or alerting:

```typescript
import { authEvents } from "mbkauthe/core";

// 1. Successful Login
authEvents.on("auth:login:success", (evt) => {
  console.log(`[Audit] User ${evt.username} (ID: ${evt.userId}) logged in from IP ${evt.ip}`);
});

// 2. Failed Login Attempt
authEvents.on("auth:login:failed", (evt) => {
  console.warn(`[Security Alert] Failed login for ${evt.username}: ${evt.reason} (IP: ${evt.ip})`);
});

// 3. User Logout
authEvents.on("auth:logout", (evt) => {
  console.log(`[Audit] User ${evt.userId} logged out (All devices: ${evt.allDevices})`);
});

// 4. API Token Created
authEvents.on("auth:token:created", (evt) => {
  console.log(`[Audit] API Token "${evt.name}" created for user ${evt.userId} with scopes: ${evt.scopes.join(", ")}`);
});

// 5. CLI Device Flow Approved
authEvents.on("auth:cli:approved", (evt) => {
  console.log(`[Audit] User ${evt.userId} approved CLI device code ${evt.userCode}`);
});
```

### Supported Event Names

| Event Name | Payload Interface | Trigger |
|---|---|---|
| `auth:login:success` | `AuthLoginSuccessEvent` | Successful login via password, OAuth, or 2FA. |
| `auth:login:failed` | `AuthLoginFailedEvent` | Incorrect password, inactive account, or invalid 2FA. |
| `auth:logout` | `AuthLogoutEvent` | Single or all-device session termination. |
| `auth:token:created` | `AuthTokenCreatedEvent` | New Personal Access Token generated. |
| `auth:token:revoked` | `AuthTokenRevokedEvent` | Token deletion / revocation. |
| `auth:account:switched`| `AuthAccountSwitchedEvent` | Multi-account device account switch. |
| `auth:cli:approved` | `AuthCliApprovedEvent` | RFC 8628 CLI login approval in browser. |
| `auth:cli:denied` | `AuthCliDeniedEvent` | CLI login rejection by user. |

---

## 2. Health & Diagnostics (`getAuthHealthReport`)

Use `getAuthHealthReport()` for Kubernetes readiness/liveness probes or status pages:

```typescript
import { getAuthHealthReport } from "mbkauthe";

const health = await getAuthHealthReport();
console.log("System Health:", health);
```

### Sample Health Output
```json
{
  "status": "healthy",
  "version": "6.0.0",
  "dialect": "postgres",
  "database": {
    "connected": true,
    "latencyMs": 4
  },
  "config": {
    "valid": true,
    "missingRequired": [],
    "warnings": []
  },
  "timestamp": "2026-09-14T06:00:00.000Z"
}
```

---

## 3. Rate Limiting & Abuse Prevention

MBKAuthe applies IP-based rate limiting to sensitive routes by default:
- Login endpoints: 15 requests per 15-minute window.
- 2FA verification: 10 attempts per 15-minute window.
- CLI device code requests: 20 per hour.
