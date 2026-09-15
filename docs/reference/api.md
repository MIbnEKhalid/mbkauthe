# REST API Reference Overview

MBKAuthe v6 provides RESTful API endpoints for authentication, session verification, personal access token management, CLI device authorizations, OAuth callbacks, and system diagnostics.

---

## Base Path & Content Negotiation

All authentication and session endpoints are mounted under the `/mbkauthe` prefix by default (or the custom router mount path in your Express application).

### Content Negotiation
- **JSON Requests**: If `Accept: application/json` or `Content-Type: application/json` is sent, MBKAuthe responds with JSON envelopes `{ success: boolean, ... }`.
- **HTML Requests**: Standard browser navigation requests return rendered HTML views with appropriate HTTP status codes.

---

## Standard Response Envelopes

### Success Response
```json
{
  "success": true,
  "statusCode": 200,
  "message": "Operation completed successfully",
  "data": { ... }
}
```

### Error Response
```json
{
  "success": false,
  "statusCode": 401,
  "errorCode": 601,
  "error": {
    "code": 601,
    "message": "The username or password you entered is incorrect. Please try again.",
    "details": "Check your spelling and make sure Caps Lock is off"
  },
  "message": "The username or password you entered is incorrect. Please try again.",
  "hint": "Check your spelling and make sure Caps Lock is off",
  "timestamp": "2026-09-14T06:00:00.000Z"
}
```

---

## Authentication Schemes

1. **Session Cookie**: Encrypted `session_id` cookie sent with browser requests.
2. **Bearer Token**: Standard HTTP Header `Authorization: Bearer mbk_pat_...` or `Authorization: Bearer mbk_cli_...`.
3. **Internal Secret**: `Authorization: Bearer <MAIN_SECRET_TOKEN>` for internal service-to-service calls.

---

## Endpoint Categories

- [REST Endpoints Catalog](api/endpoints.md) — Comprehensive list of all endpoints.
- [Middleware Reference](api/middleware.md) — Express middleware documentation.
- [Events & Diagnostics](api/operations.md) — Observability, health reports, and query monitoring.
- [Error Codes Directory](error-codes.md) — Exact error codes and recovery hints.
