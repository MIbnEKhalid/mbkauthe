# RFC 8628 CLI Device Login in MBKAuthe v6

MBKAuthe v6 provides an implementation of the **OAuth 2.0 Device Authorization Grant (RFC 8628)**. This allows command-line interfaces (CLIs), terminal tools, and embedded headless devices to authenticate users securely via a standard web browser.

---

## 1. How the CLI Device Flow Works

```
┌────────────────────────────────────────────────────────┐
│ 1. CLI requests authorization code                     │
│    POST /mbkauthe/api/cli-auth/device-code             │
└──────────────────────────┬─────────────────────────────┘
                           │ Returns: device_code, user_code (e.g. RRR2-L9QJ), verification_uri
┌──────────────────────────▼─────────────────────────────┐
│ 2. User opens browser to verification_uri and enters   │
│    user_code to review requested client name & scopes. │
└──────────────────────────┬─────────────────────────────┘
                           │
┌──────────────────────────▼─────────────────────────────┐
│ 3. CLI polls POST /mbkauthe/api/cli-auth/poll          │
│    with device_code every 3-5 seconds.                 │
└──────────────────────────┬─────────────────────────────┘
                           │
┌──────────────────────────▼─────────────────────────────┐
│ 4. User approves in browser -> CLI poll returns token: │
│    { status: "approved", token: "mbk_cli_...", user }  │
└────────────────────────────────────────────────────────┘
```

---

## 2. Enabling CLI Auth

Set `CLI_AUTH_ENABLED=true` in your `.env` file:

```env
CLI_AUTH_ENABLED=true
CLI_AUTH_BASE_URL=https://auth.mbktech.org/mbkauthe/cli-auth/verify
```

---

## 3. Reference CLI Client Implementation

Here is a complete, runnable Node.js CLI login script:

```typescript
import fetch from "node-fetch";

const AUTH_HOST = "https://auth.mbktech.org";

async function loginCLI() {
  console.log("Initiating CLI login...");

  // 1. Request device authorization
  const initRes = await fetch(`${AUTH_HOST}/mbkauthe/api/cli-auth/device-code`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ client_name: "MBK Developer CLI" }),
  });
  const { device_code, user_code, verification_uri, interval = 5, expires_in } = await initRes.json();

  console.log(`\n👉 Please open your browser: ${verification_uri}`);
  console.log(`🔑 Enter code: ${user_code}\n`);

  // 2. Poll for authorization
  const deadline = Date.now() + expires_in * 1000;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, interval * 1000));

    const pollRes = await fetch(`${AUTH_HOST}/mbkauthe/api/cli-auth/poll`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ device_code }),
    });
    const pollData = await pollRes.json();

    if (pollData.status === "approved") {
      console.log("✅ Authentication successful!");
      console.log(`Welcome, ${pollData.user.username}`);
      console.log(`API Token: ${pollData.token}`);
      return pollData.token;
    } else if (pollData.status === "denied") {
      console.error("❌ Authentication was denied by user.");
      return null;
    }
  }

  console.error("⌛ Device code expired. Please try again.");
}

loginCLI();
```
