#!/usr/bin/env node
/**
 * mbkcli.mjs — MBKAuthe browser-based CLI login demo (Node.js).
 *
 * On every run:
 *   1. If a saved token exists, verify it against the server.
 *   2. If it's valid, use it straight away.
 *   3. If there's no token (or it's invalid), start a browser-based device
 *      login, wait for approval, then save the new token.
 *   4. Finally call a protected API with the token (Bearer) to confirm it works.
 *
 * Requires Node 18+ (uses the built-in fetch). No third-party dependencies.
 *
 * Run:
 *   node scripts/mbkcli.mjs
 *   MBKCLI_BASE_URL=http://172.19.208.1:5001 node scripts/mbkcli.mjs   # e.g. from WSL
 */
import { homedir } from "node:os";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { spawn } from "node:child_process";

// ============================ Predefined config ============================
const CONFIG = {
  // Override the server URL at runtime with: MBKCLI_BASE_URL=http://host:port
  // NOTE: default is 127.0.0.1 (not localhost) because Node resolves localhost to
  // ::1 on some systems, while the server listens on IPv4 only -> ECONNREFUSED.
  baseUrl: process.env.MBKCLI_BASE_URL || "http://localhost:5555",
  clientName: process.env.MBKCLI_CLIENT_NAME || "mbkbucket-cli", // this CLI's name (shown in the browser)
  // Public random key (>= 6 chars) of the API Token Profile to request.
  // Find it on the admin page: /dashboard/admin/api-token-profiles
  profileKey: process.env.MBKCLI_PROFILE_KEY || "1362403658a3",
  // Deprecated fallback: numeric profile id (MBKCLI_PROFILE_ID).
  profileId: process.env.MBKCLI_PROFILE_ID ? Number(process.env.MBKCLI_PROFILE_ID) : null,
  tokenFile: process.env.MBKCLI_TOKEN_FILE || join(homedir(), ".mbkcli_token"), // where the token is saved
  protectedMethod: "GET", // method for the protected API call
  protectedRoute: "/mbkauthe/test.json", // protected API route to test
};
// ===========================================================================

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Run an HTTP request. Returns { httpStatus, data, raw }. Exits on network failure. */
async function api(method, path, { token = null, body = null } = {}) {
  const headers = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body) headers["Content-Type"] = "application/json";

  let res;
  try {
    res = await fetch(`${CONFIG.baseUrl}${path}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch (err) {
    console.error(`ERROR: Could not reach ${CONFIG.baseUrl}${path}`);
    console.error(`       ${err.cause?.code || err.message}`);
    console.error("       Is the server running? From WSL with the server on Windows,");
    console.error("       set MBKCLI_BASE_URL to the Windows host IP, e.g. http://172.19.208.1:5001");
    process.exit(1);
  }

  const raw = await res.text();
  let data = {};
  try {
    data = JSON.parse(raw);
  } catch {
    /* non-JSON response (e.g. HTML error page) — keep raw */
  }
  return { httpStatus: res.status, data, raw };
}

/** Best-effort open of the verification URL in the default browser. */
function openBrowser(url) {
  try {
    const { platform } = process;
    if (platform === "win32") {
      spawn("cmd", ["/c", "start", "", url], { stdio: "ignore", detached: true }).unref();
    } else if (platform === "darwin") {
      spawn("open", [url], { stdio: "ignore", detached: true }).unref();
    } else {
      spawn("xdg-open", [url], { stdio: "ignore", detached: true }).unref();
    }
  } catch {
    /* ignore — opening the browser is best-effort */
  }
}

function readToken() {
  if (!existsSync(CONFIG.tokenFile)) return null;
  const raw = readFileSync(CONFIG.tokenFile, "utf8").trim();
  return raw || null;
}

function saveToken(token) {
  writeFileSync(CONFIG.tokenFile, `${token}\n`, { mode: 0o600 });
  console.log(`==> Verified and saved token to ${CONFIG.tokenFile}`);
}

/** Step 2: run the browser-based device login and return the issued token. */
async function deviceLogin() {
  const profileRef = CONFIG.profileKey
    ? { profileKey: CONFIG.profileKey }
    : CONFIG.profileId
      ? { profileId: CONFIG.profileId }
      : null;
  if (!profileRef) {
    console.error("ERROR: No API Token Profile configured.");
    console.error("       Set MBKCLI_PROFILE_KEY to a profile key (see /dashboard/admin/api-token-profiles),");
    console.error("       or MBKCLI_PROFILE_ID as a fallback (deprecated).");
    process.exit(1);
  }

  console.log(
    `\n==> Requesting login (${CONFIG.clientName}, profile ${CONFIG.profileKey || CONFIG.profileId}) from ${CONFIG.baseUrl}`
  );

  const start = await api("POST", "/api/cli/device", {
    body: { clientName: CONFIG.clientName, ...profileRef },
  });
  const { verificationUrl, userCode, deviceCode, interval, expiresIn } = start.data;
  if (!verificationUrl || !deviceCode) {
    console.error("ERROR: Could not start login. Server responded:");
    console.error(start.raw || JSON.stringify(start.data));
    process.exit(1);
  }

  console.log("\n=== ACTION REQUIRED ===");
  console.log(`Open this URL in a browser and approve (code: ${userCode}):`);
  console.log(`\n    ${verificationUrl}\n`);
  openBrowser(verificationUrl);

  const pollEvery = interval || 5;
  const maxAttempts = Math.floor((expiresIn || 900) / pollEvery) + 2;
  console.log(`==> Waiting for approval (polling every ${pollEvery}s)...`);

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const poll = await api("POST", "/api/cli/device/token", {
      body: { deviceCode },
    });
    const { status, token } = poll.data;

    if (status === "approved" && token) {
      console.log(`    Approved as '${poll.data.username}' — token received.`);
      return token;
    }
    if (status === "pending") {
      process.stdout.write(
        `    [${attempt}/${maxAttempts}] still pending... (Ctrl-C to cancel)\r`
      );
      await sleep(pollEvery * 1000);
      continue;
    }
    if (["denied", "expired", "completed", "invalid"].includes(status)) {
      console.error(`\nERROR: Login ${status}.`);
      console.error(poll.raw || JSON.stringify(poll.data));
      process.exit(1);
    }
    process.stdout.write(`    [${attempt}/${maxAttempts}] unexpected response, retrying...\n`);
    console.error(poll.raw || JSON.stringify(poll.data));
    await sleep(pollEvery * 1000);
  }

  console.error("\nERROR: Timed out waiting for approval.");
  process.exit(1);
}

/** Step 3: call the protected API with the Bearer token and report the result. */
async function checkProtected(token) {
  console.log(
    `\n==> Checking protected API: ${CONFIG.protectedMethod} ${CONFIG.protectedRoute}`
  );
  const r = await api(CONFIG.protectedMethod, CONFIG.protectedRoute, { token });
  const ok = r.httpStatus >= 200 && r.httpStatus < 300;
  console.log(`    ${ok ? "OK" : "FAILED"} (HTTP ${r.httpStatus})`);
  console.log("\n=== Protected API response ===");
  console.log(typeof r.data === "object" && Object.keys(r.data).length ? JSON.stringify(r.data, null, 2) : r.raw);
}

async function main() {
  // 1. Load the saved token (if any) and check it is still valid.
  let token = readToken();
  if (token) {
    const v = await api("POST", "/api/tokens/verify", { token });
    if (v.data.success) {
      console.log(`Using saved token (valid for ${v.data.username}).`);
    } else {
      console.log("Saved token is invalid/expired — requesting a new login.");
      token = null;
    }
  } else {
    console.log("No saved token yet.");
  }

  // 2. If needed, do a browser-based device login, then verify + save.
  if (!token) {
    token = await deviceLogin();
    const verify = await api("POST", "/api/tokens/verify", { token });
    if (!verify.data.success) {
      console.error("ERROR: New token failed verification.");
      console.error(verify.raw || JSON.stringify(verify.data));
      process.exit(1);
    }
    saveToken(token);
  }

  // 3. Check that a protected API works with the Bearer token.
  await checkProtected(token);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
