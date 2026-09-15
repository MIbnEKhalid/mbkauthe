# Two-Factor Authentication (TOTP 2FA) in MBKAuthe v6

MBKAuthe v6 includes RFC 6238 Time-based One-Time Password (TOTP) two-factor authentication, compatible with Google Authenticator, Authy, 1Password, and Apple Keychain.

---

## 1. Enabling 2FA

Enable 2FA globally in `.env`:

```env
MBKAUTH_TWO_FA_ENABLE=true
DEVICE_TRUST_DURATION_DAYS=7
```

---

## 2. 2FA Setup Flow

1. User initiates 2FA setup in settings.
2. Server generates a base32 secret and `otpauth://` URI using `speakeasy`.
3. Server returns QR code data or setup key to the frontend.
4. User enters the 6-digit confirmation code.
5. Server verifies code and sets `two_factor_enabled = true` on the user record.

---

## 3. 2FA Login Flow & Device Trust

When a user with 2FA enabled logs in with username and password:

1. `POST /mbkauthe/api/login` verifies password credentials.
2. Server responds with `200 OK` and `{ requires2FA: true }` (or renders the 2FA verification screen).
3. User submits 6-digit code to `POST /mbkauthe/api/verify-2fa`.
4. If valid, the session is promoted to fully authenticated status.
5. If user checks **"Trust this device"**, MBKAuthe issues an `mbk_dev_` cookie valid for `DEVICE_TRUST_DURATION_DAYS` (default: 7 days). Subsequent logins on that device bypass the 2FA challenge until expiry.
