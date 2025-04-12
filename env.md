# Configuration Guide

[<- Back](README.md)

## reCAPTCHA Settings
```properties
RECAPTCHA_SECRET_KEY=123
```
> Note: Obtain your secret key from Google reCAPTCHA Admin Console.


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