# Social OAuth Integration (GitHub & Google)

[Back to docs index](../README.md) | [Back to project README](../../README.md)

MBKAuthe includes first-class support for **OAuth2 Social Sign-In** via **GitHub Apps** and **Google OAuth2**.

---

## 1. Overview

OAuth authentication allows users to log into your applications using their existing GitHub or Google accounts. MBKAuthe manages:

- CSRF state parameters and OAuth redirect handshakes
- Automatic account linking with `mbkcore_users`
- Linking multiple OAuth providers to a single primary account
- Unified session creation and cookie encryption

---

## 2. GitHub App OAuth Setup

### Step 1: Create a GitHub App or OAuth App

1. Go to **GitHub Settings → Developer Settings → GitHub Apps** (or OAuth Apps).
2. Set **Homepage URL** to your domain (e.g., `https://mbktech.org`).
3. Set **Authorization callback URL** to:
   ```
   https://yourdomain.com/mbkauthe/api/github/login/callback
   ```
4. Generate a Client Secret.

### Step 2: Configure Environment Variables

```env
# Enable GitHub Login
GITHUB_LOGIN_ENABLED=true

# GitHub App Credentials
GITHUB_APP_CLIENT_ID=your_github_client_id
GITHUB_APP_CLIENT_SECRET=your_github_client_secret
```

---

## 3. Google OAuth Setup

### Step 1: Create Google Cloud Credentials

1. Go to the [Google Cloud Console](https://console.cloud.google.com/).
2. Navigate to **APIs & Services → Credentials → Create Credentials → OAuth client ID**.
3. Set Application Type to **Web application**.
4. Add Authorized redirect URI:
   ```
   https://yourdomain.com/mbkauthe/api/google/login/callback
   ```

### Step 2: Configure Environment Variables

```env
# Enable Google Login
GOOGLE_LOGIN_ENABLED=true

# Google OAuth Credentials
GOOGLE_CLIENT_ID=your_google_client_id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your_google_client_secret
```

---

## 4. Shared OAuth Configuration Across Microservices

When deploying multiple apps under the same root domain (e.g. `portal.mbktech.org`, `api.mbktech.org`), you can share OAuth credentials across services via `mbkauthShared`:

```env
mbkauthShared={"GITHUB_LOGIN_ENABLED":"true","GITHUB_APP_CLIENT_ID":"...","GITHUB_APP_CLIENT_SECRET":"...","GOOGLE_LOGIN_ENABLED":"true","GOOGLE_CLIENT_ID":"...","GOOGLE_CLIENT_SECRET":"..."}
```

---

## 5. Endpoints & Flow

| Provider | Initiation Route | Callback Route |
| :--- | :--- | :--- |
| **GitHub** | `GET /mbkauthe/api/github/login` | `GET /mbkauthe/api/github/login/callback` |
| **Google** | `GET /mbkauthe/api/google/login` | `GET /mbkauthe/api/google/login/callback` |

Users are redirected to their chosen provider, authorize the application, and return with an authenticated session cookie scoped to your root domain.
