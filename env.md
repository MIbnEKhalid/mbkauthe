# Configuration Guide

[<- Back](README.md)

## Application Settings

```properties
APP_NAME=mbkauthe
```

> **APP_NAME**: Specifies the name of the application. This is used to distinguish one project from another and is critical for ensuring users are restricted to specific apps. It corresponds to the `AllowedApp` column in the Users table.

## reCAPTCHA Settings

```properties
RECAPTCHA_ENABLED=true
RECAPTCHA_SECRET_KEY=your-secret-key
BYPASS_USERS=["demo", "user1"]
```

> **RECAPTCHA_ENABLED**: Set to `true` to enable reCAPTCHA verification.

> **RECAPTCHA_SECRET_KEY**: Provide the secret key obtained from the [Google reCAPTCHA Admin Console](https://www.google.com/recaptcha/admin).

> **BYPASS_USERS**: Specify an array of usernames (e.g., `["demo", "user1"]`) that will bypass reCAPTCHA verification.

> **Note**: Ensure `RECAPTCHA_SECRET_KEY` is set when `RECAPTCHA_ENABLED=true`.


## Session Settings
```properties
SESSION_SECRET_KEY=123
IS_DEPLOYED=true
DOMAIN=mbktechstudio.com
```
> **SESSION_SECRET_KEY**: Generate a secure key using [Generate Secret](https://generate-secret.vercel.app/32).

> **IS_DEPLOYED**:

> - `true`: For deployed environments. Sessions are shared across all subDOMAINs of `.mbktechstudio.com` or the DOMAIN specified in `DOMAIN`.

> - `false`: For local development.

> - Important: If set to `true`, login functionality will not work on `localhost`. Use a valid DOMAIN for proper operation.

> **DOMAIN**:

> - Set `DOMAIN` to your DOMAIN

> - If you don't have a DOMAIN, set `IS_DEPLOYED=false`.


## Database Settings

```properties
LOGIN_DB=postgresql://username:password@server.DOMAIN/db_name
```
> Replace the placeholder with your PostgreSQL connection string.


## Two-Factor Authentication (2FA)
```properties
MBKAUTH_TWO_FA_ENABLE=false
```
> MBKAUTH_TWO_FA_ENABLE: Set to `true` to enable Two-Factor Authentication.


## Cookie Settings

```properties
COOKIE_EXPIRE_TIME=5
```
> Cookie expiration time in days. Default is `2 days`.