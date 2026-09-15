# Social OAuth Authentication in MBKAuthe v6

MBKAuthe v6 provides unified social authentication for **GitHub App** and **Google OAuth 2.0**. Accounts are linked to user records in the database, allowing users to sign in interchangeably via passwords or social providers.

---

## 1. GitHub OAuth Configuration

MBKAuthe supports GitHub App credentials (preferred) as well as OAuth App keys.

Set the following in `.env`:

```env
GITHUB_LOGIN_ENABLED=true
GITHUB_APP_CLIENT_ID=Iv1.8392019384920192
GITHUB_APP_CLIENT_SECRET=3891028394019283019283019283019283019283
```

### GitHub Callback URL
Configure your GitHub App authorization callback URL to:
```
https://<YOUR_DOMAIN>/mbkauthe/api/github/callback
```

---

## 2. Google OAuth 2.0 Configuration

Set the following in `.env`:

```env
GOOGLE_LOGIN_ENABLED=true
GOOGLE_CLIENT_ID=123456789012-abc123xyz.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-abc123xyz_example_secret
```

### Google Callback URL
Configure your Google Cloud Console Authorized redirect URI to:
```
https://<YOUR_DOMAIN>/mbkauthe/api/google/callback
```

---

## 3. Account Linking & Social Login Endpoints

MBKAuthe mounts social login initiation and callback routes:

- **GitHub Login**: `GET /mbkauthe/api/github/login` (Redirects user to GitHub)
- **GitHub Callback**: `GET /mbkauthe/api/github/callback` (Validates code, creates session)
- **Google Login**: `GET /mbkauthe/api/google/login` (Redirects user to Google consent)
- **Google Callback**: `GET /mbkauthe/api/google/callback` (Validates code, creates session)

When an OAuth user authenticates:
1. `OAuthService` searches `users` for a matching `github_id` or `google_id`.
2. If found, the existing account logs in directly.
3. If not found, a matching email links the profile or prompts account registration according to application settings.
