# Environment Configuration Guide

[← Back to README](README.md)
This document describes the environment variables MBKAuth expects and keeps brief usage notes for each parameter. Validation and defaults are implemented in `lib/config/index.js` (it parses `mbkautheVar`, applies optional `mbkauthShared` fallbacks, normalizes values, and throws on validation failures).

## How configuration is provided
- Primary payload: `mbkautheVar` — a JSON string with app-specific keys.
- Optional shared defaults: `mbkauthShared` — a JSON string used only for missing or empty keys.
- Example: `mbkautheVar={"APP_NAME":"mbkauthe", ...}`

---

## Parameters (short descriptions)

- APP_NAME
  - Description: Application identifier used for access control.
  - Example: `"APP_NAME":"mbkauthe"`
  - Required: Yes

- Main_SECRET_TOKEN
  - Description: Primary token used for internal auth and validations.
  - Example: `"Main_SECRET_TOKEN":"my-secret-token"`
  - Required: Yes

- SESSION_SECRET_KEY
  - Description: Cryptographic key for sessions/cookies. Use a long random string.
  - Example: `"SESSION_SECRET_KEY":"<32+ random chars>"`
  - Required: Yes

- IS_DEPLOYED
  - Description: Deployment mode flag; affects cookie domain and localhost behavior.
  - Values: `true` / `false` / `f` (normalized to strings)
  - Example: `"IS_DEPLOYED":"false"`
  - Required: Yes

- DOMAIN
  - Description: App domain (e.g., `localhost` or `yourdomain.com`). Required when deployed.
  - Example: `"DOMAIN":"localhost"`
  - Required: Yes

- LOGIN_DB
  - Description: PostgreSQL connection string for auth (must start with `postgresql://` or `postgres://`).
  - Example: `"LOGIN_DB":"postgresql://user:pass@localhost:5432/mbkauth"`
  - Required: Yes

- MBKAUTH_TWO_FA_ENABLE
  - Description: Enable Two-Factor Authentication.
  - Values: `true` / `false` / `f`
  - Example: `"MBKAUTH_TWO_FA_ENABLE":"true"`
  - Required: Yes

- EncPass
  - Description: When `true`, use hashed password column (`PasswordEnc`) instead of plain `Password`.
  - Default: `false` (recommended `true` in production)
  - Example: `"EncPass":"true"`
  - Required: No

- COOKIE_EXPIRE_TIME
  - Description: Session cookie lifetime (days).
  - Default: `2`
  - Example: `"COOKIE_EXPIRE_TIME":7`
  - Required: No

- DEVICE_TRUST_DURATION_DAYS
  - Description: Days a device remains trusted (skips some auth steps).
  - Default: `7`
  - Example: `"DEVICE_TRUST_DURATION_DAYS":30`
  - Required: No

- loginRedirectURL
  - Description: Post-login redirect path.
  - Default: `/dashboard`
  - Example: `"loginRedirectURL":"/dashboard"`
  - Required: No

- GITHUB_LOGIN_ENABLED / GOOGLE_LOGIN_ENABLED
  - Description: Enable OAuth providers.
  - Default: `false`
  - If `true`, corresponding `*_CLIENT_ID` and `*_CLIENT_SECRET` are required.

- GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET / GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET
  - Description: OAuth credentials (put in `mbkautheVar` preferred, or `mbkauthShared`).
  - Required when provider enabled.

---

## Quick examples
Development (.env):

```env
mbkautheVar={"APP_NAME":"mbkauthe","Main_SECRET_TOKEN":"dev-token","SESSION_SECRET_KEY":"dev-secret","IS_DEPLOYED":"false","DOMAIN":"localhost","EncPass":"false","LOGIN_DB":"postgresql://user:pass@localhost:5432/mbkauth_dev","MBKAUTH_TWO_FA_ENABLE":"false"}
mbkauthShared={"GITHUB_LOGIN_ENABLED":"false"}
```

Production (short):

```env
mbkautheVar={"APP_NAME":"mbkauthe","Main_SECRET_TOKEN":"prod-token","SESSION_SECRET_KEY":"prod-secret","IS_DEPLOYED":"true","DOMAIN":"yourdomain.com","EncPass":"true","LOGIN_DB":"postgresql://dbuser:secure@db:5432/mbkauth_prod","MBKAUTH_TWO_FA_ENABLE":"true"}
```

---

## Rules & best practices
- Boolean-like fields: use `"true"`, `"false"`, or `"f"` (the parser accepts booleans too and normalizes to strings).
- Numeric fields: must be positive numbers (e.g., `COOKIE_EXPIRE_TIME`, `DEVICE_TRUST_DURATION_DAYS`).
- `LOGIN_DB` must start with `postgresql://` or `postgres://`.
- Never commit `.env` to source control and use HTTPS in production (when `IS_DEPLOYED=true`).
- Use a >=32-char `SESSION_SECRET_KEY` and rotate secrets regularly.

For the exact validation messages and default application, consult `lib/config/index.js` (it will throw a comprehensive error if validation fails at startup).
