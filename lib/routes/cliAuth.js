// CLI / device-flow auth routes (RFC 8628-style browser login).
//
// Customized token provisioning:
//   1. POST /api/cli/device                  — CLI requests a login (clientName + profileId)
//   2. GET  /mbkauthe/cli/device/:userCode   — browser page to approve/deny (session)
//   3. POST /api/cli/device/approve          — user approves/denies (session)
//   4. POST /api/cli/device/token            — CLI polls for the issued token
//
// On approval, MBKAuthe reads the API Token Profile (MBKCore-owned table) for
// the requested ProfileId and issues an API token built from that template
// (scope, allowed apps, expiration policy). The raw token is delivered exactly
// once to the polling CLI.
//
// Security notes:
//   - The device code is a high-entropy secret: only its SHA-256 hash is stored.
//   - The user code is short but single-use; only its hash is stored.
//   - The raw token is staged in "PendingToken" only between approval and the
//     CLI's next poll, then cleared on delivery. Pollers race for delivery via
//     an atomic status transition, so the token can never be handed out twice.
//   - The approve endpoint is a same-origin JSON POST; cross-site JSON requests
//     are blocked by CORS + SameSite=Lax cookies (consistent with POST /api/token).

import express from "express";
import crypto from "crypto";
import rateLimit from "express-rate-limit";
import { sessRole } from "../middleware/auth.js";
import { renderPage } from "#response.js";
import { hashApiToken, generatePrefixedToken, generateRandomHex } from "../config/security.js";
import { cliAuthSessionRepository } from "../db/CliAuthSessionRepository.js";
import { apiTokenRepository } from "../db/ApiTokenRepository.js";
import { mbkautheVar } from "#config.js";

const router = express.Router();

// --- Tunables ---
const DEVICE_CODE_TTL_MS = 15 * 60 * 1000; // 15 minutes
const POLL_INTERVAL_SECONDS = 5;
const MAX_API_TOKEN_LIMIT = 10; // non-SuperAdmin token limit (matches POST /api/token)

// User-code alphabet: unambiguous (no 0/O, 1/I/L).
const USER_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const USER_CODE_LENGTH = 8;

function generateUserCode() {
  let code = "";
  for (let i = 0; i < USER_CODE_LENGTH; i += 1) {
    code += USER_CODE_ALPHABET[crypto.randomInt(USER_CODE_ALPHABET.length)];
  }
  return `${code.slice(0, 4)}-${code.slice(4)}`;
}

// --- Rate limiting ---
const createCliLimit = (max, windowMs = 60 * 1000) =>
  rateLimit({
    windowMs,
    max,
    message: { success: false, message: "Too many requests, please try again later" },
    standardHeaders: true,
    legacyHeaders: false,
    validate: { xForwardedForHeader: false, trustProxy: false },
    keyGenerator: (req) =>
      req.ip || req.connection?.remoteAddress || req.socket?.remoteAddress || "unknown",
  });

const deviceRequestLimit = createCliLimit(20);
const devicePollLimit = createCliLimit(60);
const deviceApproveLimit = createCliLimit(30);

// --- Verification URL helpers ---
function getBaseUrl(req) {
  if (mbkautheVar.CLI_AUTH_BASE_URL) {
    return String(mbkautheVar.CLI_AUTH_BASE_URL).replace(/\/+$/, "");
  }
  if (mbkautheVar.IS_DEPLOYED === "true" && mbkautheVar.DOMAIN) {
    return `https://${mbkautheVar.DOMAIN}`;
  }
  const host = req.get("host") || "localhost";
  const proto = (req.protocol || "http");
  return `${proto}://${host}`;
}

function buildVerificationUrl(req, userCode) {
  return `${getBaseUrl(req)}/mbkauthe/cli/device/${userCode}`;
}

// ---------------------------------------------------------------------------
// 1. CLI requests a login
// ---------------------------------------------------------------------------
router.post("/api/cli/device", deviceRequestLimit, async (req, res) => {
  try {
    const { clientName, profileId, profileKey } = req.body || {};

    if (!clientName || typeof clientName !== "string" || !clientName.trim()) {
      return res.status(400).json({ success: false, message: "clientName is required" });
    }
    if (clientName.trim().length > 255) {
      return res.status(400).json({ success: false, message: "clientName must be 255 characters or less" });
    }

    // A profile is referenced by its public ProfileKey (>= 6 chars, preferred) or,
    // for backwards compatibility, by its numeric id.
    let profile = null;
    if (profileKey && typeof profileKey === "string" && profileKey.trim().length >= 6) {
      profile = await cliAuthSessionRepository.getActiveProfileByKey(profileKey.trim());
    } else if (profileId !== undefined && profileId !== null) {
      const parsedProfileId = parseInt(profileId, 10);
      if (Number.isInteger(parsedProfileId) && parsedProfileId > 0) {
        profile = await cliAuthSessionRepository.getActiveProfileById(parsedProfileId);
      }
    }

    if (!profile) {
      return res.status(400).json({
        success: false,
        message: "A valid profileKey (or profileId) for an active API token profile is required",
      });
    }

    const deviceCode = generateRandomHex(24);
    const userCode = generateUserCode();
    const expiresAt = new Date(Date.now() + DEVICE_CODE_TTL_MS);

    await cliAuthSessionRepository.create({
      deviceCodeHash: hashApiToken(deviceCode),
      userCodeHash: hashApiToken(userCode),
      clientName: clientName.trim(),
      profileId: profile.id,
      expiresAt,
    });

    return res.status(201).json({
      success: true,
      verificationUrl: buildVerificationUrl(req, userCode),
      userCode,
      deviceCode,
      expiresIn: Math.floor(DEVICE_CODE_TTL_MS / 1000),
      interval: POLL_INTERVAL_SECONDS,
      clientName: clientName.trim(),
      profile: {
        id: profile.id,
        key: profile.ProfileKey,
        name: profile.Name,
        scope: profile.Scope,
        allowedApps: profile.AllowedApps ?? null,
        expiresInDays: profile.ExpiresInDays,
      },
    });
  } catch (err) {
    console.error("Error creating CLI auth session:", err);
    return res.status(500).json({ success: false, message: "Failed to start CLI login" });
  }
});

// ---------------------------------------------------------------------------
// 2. Browser approval page
// ---------------------------------------------------------------------------
router.get("/mbkauthe/cli/device/:userCode", sessRole("any"), async (req, res) => {
  try {
    const userCode = String(req.params.userCode || "").trim().toUpperCase();
    if (!userCode || !/^[A-Z2-9]{4}-[A-Z2-9]{4}$/.test(userCode)) {
      return renderCliError(res, req, "This login request could not be found. The code may be invalid or already used.");
    }

    const session = await cliAuthSessionRepository.findByUserCodeHash(hashApiToken(userCode));
    if (!session) {
      return renderCliError(res, req, "This login request could not be found. It may have expired or already been used.");
    }

    if (session.Status === "pending" && new Date(session.ExpiresAt) <= new Date()) {
      await cliAuthSessionRepository.markExpired(session.id);
      session.Status = "expired";
    }

    let profile = null;
    if (session.ProfileId) {
      profile = await cliAuthSessionRepository.getProfileById(session.ProfileId);
    }

    const expiresAt = session.ExpiresAt instanceof Date ? session.ExpiresAt : new Date(session.ExpiresAt);
    const expiresInSeconds = Math.max(0, Math.floor((expiresAt.getTime() - Date.now()) / 1000));

    return renderPage(req, res, "cli/device-approval.handlebars", false, {
      pagename: "Approve CLI Login",
      pageTitle: "Approve CLI Login",
      ogUrl: `/mbkauthe/cli/device/${userCode}`,
      userCode,
      status: session.Status,
      clientName: session.ClientName,
      profile: profile
        ? {
            name: profile.Name,
            scope: profile.Scope,
            allowedApps: profile.AllowedApps ?? null,
            expiresInDays: profile.ExpiresInDays,
          }
        : null,
      expiresInSeconds,
      username: req.session.user.username,
    });
  } catch (err) {
    console.error("Error rendering CLI approval page:", err);
    return renderCliError(res, req, "Something went wrong while loading this login request.");
  }
});

// ---------------------------------------------------------------------------
// 3. User approves / denies (browser, session-authenticated)
// ---------------------------------------------------------------------------
router.post("/api/cli/device/approve", deviceApproveLimit, sessRole("any"), async (req, res) => {
  try {
    const { userCode, action } = req.body || {};
    if (!userCode || typeof userCode !== "string") {
      return res.status(400).json({ success: false, message: "userCode is required" });
    }

    const session = await cliAuthSessionRepository.findByUserCodeHash(hashApiToken(userCode.trim().toUpperCase()));
    if (!session) {
      return res.status(404).json({ success: false, message: "Login request not found" });
    }

    if (session.Status !== "pending") {
      return res.status(409).json({ success: false, status: session.Status, message: `This request is already ${session.Status}` });
    }

    if (new Date(session.ExpiresAt) <= new Date()) {
      await cliAuthSessionRepository.markExpired(session.id);
      return res.status(410).json({ success: false, status: "expired", message: "This login request has expired" });
    }

    if (action === "deny") {
      await cliAuthSessionRepository.markDenied(session.id);
      return res.json({ success: true, status: "denied", message: "Login request denied" });
    }

    if (action !== "approve") {
      return res.status(400).json({ success: false, message: "Invalid action. Use 'approve' or 'deny'." });
    }

    // Load the profile template (MBKCore-owned) and issue a token from it.
    const profile = await cliAuthSessionRepository.getActiveProfileById(session.ProfileId);
    if (!profile) {
      await cliAuthSessionRepository.markDenied(session.id);
      return res.status(400).json({
        success: false,
        status: "denied",
        message: "The requested API token profile is no longer available or is inactive. The login was cancelled.",
      });
    }

    const username = req.session.user.username;

    // Enforce the per-user token limit (parity with POST /api/token).
    if (req.session.user.role !== "SuperAdmin") {
      const count = await apiTokenRepository.countForUser(username);
      if (count >= MAX_API_TOKEN_LIMIT) {
        return res.status(403).json({
          success: false,
          message: `Token limit reached (max ${MAX_API_TOKEN_LIMIT}). Delete an existing token and try again.`,
        });
      }
    }

    const rawToken = generatePrefixedToken();
    const tokenHash = hashApiToken(rawToken);
    const prefix = rawToken.substring(0, 8);
    const permissions = JSON.stringify({ scope: profile.Scope, allowedApps: profile.AllowedApps ?? null });

    let expiresAt = null;
    const profileExpiry = parseInt(profile.ExpiresInDays, 10);
    if (Number.isInteger(profileExpiry) && profileExpiry > 0) {
      expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + profileExpiry);
    }

    const tokenName = `${session.ClientName} (CLI)`.slice(0, 255);
    const meta = await apiTokenRepository.insert(username, tokenName, tokenHash, prefix, permissions, expiresAt);

    const approved = await cliAuthSessionRepository.markApproved(session.id, {
      userName: username,
      tokenId: meta.id,
      pendingToken: rawToken,
    });

    if (!approved) {
      // Another request already approved this session — revoke the token we just created.
      await apiTokenRepository.deleteById(meta.id).catch(() => {});
      return res.status(409).json({ success: false, status: "approved", message: "This request was already approved." });
    }

    return res.json({ success: true, status: "approved", message: "Login approved. The CLI will receive the token momentarily." });
  } catch (err) {
    console.error("Error approving CLI login:", err);
    return res.status(500).json({ success: false, message: "Failed to approve login" });
  }
});

// ---------------------------------------------------------------------------
// 4. CLI polls for the issued token
// ---------------------------------------------------------------------------
router.post("/api/cli/device/token", devicePollLimit, async (req, res) => {
  try {
    const { deviceCode } = req.body || {};
    if (!deviceCode || typeof deviceCode !== "string") {
      return res.status(400).json({ success: false, message: "deviceCode is required" });
    }

    const session = await cliAuthSessionRepository.findByDeviceCodeHash(hashApiToken(deviceCode));
    if (!session) {
      return res.status(404).json({ success: false, status: "invalid", message: "Invalid device code" });
    }

    // Opportunistic cleanup of stale sessions.
    await cliAuthSessionRepository.expireStale();

    if (session.Status === "pending") {
      if (new Date(session.ExpiresAt) <= new Date()) {
        await cliAuthSessionRepository.markExpired(session.id);
        return res.json({ success: false, status: "expired", message: "Login request expired" });
      }
      return res.json({ success: false, status: "pending", interval: POLL_INTERVAL_SECONDS });
    }

    if (session.Status === "approved") {
      const delivered = await cliAuthSessionRepository.completeDelivery(session.id);
      if (delivered && session.PendingToken) {
        return res.json({
          success: true,
          status: "approved",
          token: session.PendingToken,
          tokenPrefix: session.PendingToken.substring(0, 8),
          username: session.UserName,
          message: "Login approved",
        });
      }
      return res.json({ success: false, status: "completed", message: "Token already delivered" });
    }

    if (session.Status === "completed") {
      return res.json({ success: false, status: "completed", message: "Token already delivered" });
    }

    if (session.Status === "denied") {
      return res.json({ success: false, status: "denied", message: "Login request denied" });
    }

    return res.json({ success: false, status: "expired", message: "Login request expired" });
  } catch (err) {
    console.error("Error polling CLI login:", err);
    return res.status(500).json({ success: false, message: "Failed to poll login" });
  }
});

function renderCliError(res, req, message) {
  return renderPage(req, res, "cli/device-approval.handlebars", false, {
    pagename: "Approve CLI Login",
    pageTitle: "Approve CLI Login",
    status: "notfound",
    error: message,
  });
}

export default router;
