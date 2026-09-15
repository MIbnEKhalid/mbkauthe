# Two-Factor Authentication (TOTP 2FA) in MBKAuthe v6

MBKAuthe v6 includes RFC 6238 Time-based One-Time Password (TOTP) two-factor authentication, compatible with Google Authenticator, Authy, Microsoft Authenticator, 1Password, and Apple Keychain.

---

## 1. Enabling 2FA

Enable 2FA globally in `.env`:

```env
MBKAUTH_TWO_FA_ENABLE=true
```

---

## 2. 2FA Setup Flow

1. User initiates 2FA setup in user security settings.
2. Server generates a base32 secret and `otpauth://` URI using `speakeasy`.
3. Server returns QR code data or setup key to the frontend.
4. User enters the 6-digit confirmation code from their authenticator app.
5. Server verifies the code and sets `two_factor_enabled = true` on the user record.

---

## 3. 2FA Login Flow

When a user with 2FA enabled logs in with username and password:

1. `POST /mbkauthe/api/login` verifies password credentials.
2. Server responds with `200 OK` and `{ success: true, two_factor_required: true, redirect_url: "/dashboard" }`.
3. User submits their current 6-digit code to `POST /mbkauthe/api/verify-2fa`.
4. If valid, the session is created and promoted to fully authenticated status.

---

## 4. Modern Passwordless Alternative: Passkeys

For users seeking seamless, phishing-resistant authentication without entering one-time codes on every sign-in, MBKAuthe provides full **FIDO2 / WebAuthn Passkey** support.

Users can register platform biometric authenticators (Touch ID, Face ID, Windows Hello) or security keys to sign in with a single touch. See the [WebAuthn & Passkeys Guide](passkeys.md) for full details.
