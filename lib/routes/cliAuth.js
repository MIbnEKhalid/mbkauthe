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

const DEVICE_CODE_TTL_MS = 15 * 60 * 1000;
const POLL_INTERVAL_SECONDS = 5;
const MAX_API_TOKEN_LIMIT = 10;
const USER_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

function generateUserCode() {
  let code = "";
  for (let i = 0; i < 8; i += 1) {
    code += USER_CODE_ALPHABET[crypto.randomInt(USER_CODE_ALPHABET.length)];
  }
  return `${code.slice(0, 4)}-${code.slice(4)}`;
}

const createCliLimit = (max, windowMs = 60 * 1000) =>
  rateLimit({
    windowMs,
    max,
    message: { success: false, message: "Too many requests, please try again later" },
    standardHeaders: true,
    legacyHeaders: false,
    validate: { xForwardedForHeader: false, trustProxy: false },
    keyGenerator: (req) => req.ip || req.connection?.remoteAddress || req.socket?.remoteAddress || "unknown",
  });

const deviceRequestLimit = createCliLimit(20);
const devicePollLimit = createCliLimit(60);
const deviceApproveLimit = createCliLimit(30);

function getBaseUrl(req) {
  if (mbkautheVar.CLI_AUTH_BASE_URL) return String(mbkautheVar.CLI_AUTH_BASE_URL).replace(/\/+$/, "");
  if (mbkautheVar.IS_DEPLOYED === "true" && mbkautheVar.DOMAIN) return `https://${mbkautheVar.DOMAIN}`;
  return `${req.protocol || "http"}://${req.get("host") || "localhost"}`;
}

const buildVerificationUrl = (req, user_code) => `${getBaseUrl(req)}/mbkauthe/cli/device/${user_code}`;

const renderCliError = (res, req, message) =>
  renderPage(req, res, "cli/device-approval.handlebars", false, {
    pagename: "Approve CLI Login",
    pageTitle: "Approve CLI Login",
    status: "notfound",
    error: message,
  });

router.post("/api/cli/device", deviceRequestLimit, async (req, res) => {
  try {
    const { client_name, profile_id, profile_key } = req.body || {};

    if (!client_name || typeof client_name !== "string" || !client_name.trim()) {
      return res.status(400).json({ success: false, message: "client_name is required" });
    }
    if (client_name.trim().length > 255) {
      return res.status(400).json({ success: false, message: "client_name must be 255 characters or less" });
    }

    let profile = null;
    if (profile_key && typeof profile_key === "string" && profile_key.trim().length >= 6) {
      profile = await cliAuthSessionRepository.getActiveProfileByKey(profile_key.trim());
    } else if (profile_id !== undefined && profile_id !== null) {
      const parsedProfileId = parseInt(profile_id, 10);
      if (Number.isInteger(parsedProfileId) && parsedProfileId > 0) {
        profile = await cliAuthSessionRepository.getActiveProfileById(parsedProfileId);
      }
    }

    if (!profile) {
      return res.status(400).json({
        success: false,
        message: "A valid profile_key (or profile_id) for an active API token profile is required",
      });
    }

    const device_code = generateRandomHex(24);
    const user_code = generateUserCode();
    const expires_at = new Date(Date.now() + DEVICE_CODE_TTL_MS);

    await cliAuthSessionRepository.create({
      device_code_hash: hashApiToken(device_code),
      user_code_hash: hashApiToken(user_code),
      client_name: client_name.trim(),
      profile_id: profile.id,
      expires_at,
    });

    return res.status(201).json({
      success: true,
      verification_url: buildVerificationUrl(req, user_code),
      user_code,
      device_code,
      expires_in: Math.floor(DEVICE_CODE_TTL_MS / 1000),
      interval: POLL_INTERVAL_SECONDS,
      client_name: client_name.trim(),
      profile: {
        id: profile.id,
        key: profile.profile_key,
        name: profile.name,
        scope: profile.scope,
        allowed_apps: profile.allowed_apps ?? null,
        expires_in_days: profile.expires_in_days,
      },
    });
  } catch (err) {
    console.error("Error creating CLI auth session:", err);
    return res.status(500).json({ success: false, message: "Failed to start CLI login" });
  }
});

router.get("/mbkauthe/cli/device/:user_code", sessRole("any"), async (req, res) => {
  try {
    const user_code = String(req.params.user_code || "").trim().toUpperCase();
    if (!user_code || !/^[A-Z2-9]{4}-[A-Z2-9]{4}$/.test(user_code)) {
      return renderCliError(res, req, "This login request could not be found. The code may be invalid or already used.");
    }

    const session = await cliAuthSessionRepository.findByUserCodeHash(hashApiToken(user_code));
    if (!session) {
      return renderCliError(res, req, "This login request could not be found. It may have expired or already been used.");
    }

    if (session.status === "pending" && new Date(session.expires_at) <= new Date()) {
      await cliAuthSessionRepository.markExpired(session.id);
      session.status = "expired";
    }

    const profile = session.profile_id ? await cliAuthSessionRepository.getProfileById(session.profile_id) : null;
    const expires_at = session.expires_at instanceof Date ? session.expires_at : new Date(session.expires_at);
    const expires_in_seconds = Math.max(0, Math.floor((expires_at.getTime() - Date.now()) / 1000));

    return renderPage(req, res, "cli/device-approval.handlebars", false, {
      pagename: "Approve CLI Login",
      pageTitle: "Approve CLI Login",
      ogUrl: `/mbkauthe/cli/device/${user_code}`,
      user_code,
      status: session.status,
      client_name: session.client_name,
      profile: profile ? {
        name: profile.name,
        scope: profile.scope,
        allowed_apps: profile.allowed_apps ?? null,
        expires_in_days: profile.expires_in_days,
      } : null,
      expires_in_seconds,
      username: req.session.user.username,
    });
  } catch (err) {
    console.error("Error rendering CLI approval page:", err);
    return renderCliError(res, req, "Something went wrong while loading this login request.");
  }
});

router.post("/api/cli/device/approve", deviceApproveLimit, sessRole("any"), async (req, res) => {
  try {
    const { user_code, action } = req.body || {};
    if (!user_code || typeof user_code !== "string") {
      return res.status(400).json({ success: false, message: "user_code is required" });
    }

    const session = await cliAuthSessionRepository.findByUserCodeHash(hashApiToken(user_code.trim().toUpperCase()));
    if (!session) return res.status(404).json({ success: false, message: "Login request not found" });

    if (session.status !== "pending") {
      return res.status(409).json({ success: false, status: session.status, message: `This request is already ${session.status}` });
    }

    if (new Date(session.expires_at) <= new Date()) {
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

    const profile = await cliAuthSessionRepository.getActiveProfileById(session.profile_id);
    if (!profile) {
      await cliAuthSessionRepository.markDenied(session.id);
      return res.status(400).json({
        success: false,
        status: "denied",
        message: "The requested API token profile is no longer available or is inactive. The login was cancelled.",
      });
    }

    const { username, role } = req.session.user;

    if (role !== "superadmin") {
      const count = await apiTokenRepository.countForUser(username);
      if (count >= MAX_API_TOKEN_LIMIT) {
        return res.status(403).json({
          success: false,
          message: `Token limit reached (max ${MAX_API_TOKEN_LIMIT}). Delete an existing token and try again.`,
        });
      }
    }

    const raw_token = generatePrefixedToken();
    const token_hash = hashApiToken(raw_token);
    const prefix = raw_token.substring(0, 8);
    const permissions = JSON.stringify({ scope: profile.scope, allowed_apps: profile.allowed_apps ?? null });

    let expires_at = null;
    const profile_expiry = parseInt(profile.expires_in_days, 10);
    if (Number.isInteger(profile_expiry) && profile_expiry > 0) {
      expires_at = new Date();
      expires_at.setDate(expires_at.getDate() + profile_expiry);
    }

    const token_name = `${session.client_name} (CLI)`.slice(0, 255);
    const meta = await apiTokenRepository.insert(username, token_name, token_hash, prefix, permissions, expires_at);

    const approved = await cliAuthSessionRepository.markApproved(session.id, {
      username,
      token_id: meta.id,
      pending_token: raw_token,
    });

    if (!approved) {
      await apiTokenRepository.deleteById(meta.id).catch(() => {});
      return res.status(409).json({ success: false, status: "approved", message: "This request was already approved." });
    }

    return res.json({ success: true, status: "approved", message: "Login approved. The CLI will receive the token momentarily." });
  } catch (err) {
    console.error("Error approving CLI login:", err);
    return res.status(500).json({ success: false, message: "Failed to approve login" });
  }
});

router.post("/api/cli/device/token", devicePollLimit, async (req, res) => {
  try {
    const { device_code } = req.body || {};
    if (!device_code || typeof device_code !== "string") {
      return res.status(400).json({ success: false, message: "device_code is required" });
    }

    const session = await cliAuthSessionRepository.findByDeviceCodeHash(hashApiToken(device_code));
    if (!session) {
      return res.status(404).json({ success: false, status: "invalid", message: "Invalid device code" });
    }

    await cliAuthSessionRepository.expireStale();

    if (session.status === "pending") {
      if (new Date(session.expires_at) <= new Date()) {
        await cliAuthSessionRepository.markExpired(session.id);
        return res.json({ success: false, status: "expired", message: "Login request expired" });
      }
      return res.json({ success: false, status: "pending", interval: POLL_INTERVAL_SECONDS });
    }

    if (session.status === "approved") {
      const delivered = await cliAuthSessionRepository.completeDelivery(session.id);
      if (delivered && session.pending_token) {
        return res.json({
          success: true,
          status: "approved",
          token: session.pending_token,
          token_prefix: session.pending_token.substring(0, 8),
          username: session.username,
          message: "Login approved",
        });
      }
      return res.json({ success: false, status: "completed", message: "Token already delivered" });
    }

    if (session.status === "completed") {
      return res.json({ success: false, status: "completed", message: "Token already delivered" });
    }

    if (session.status === "denied") {
      return res.json({ success: false, status: "denied", message: "Login request denied" });
    }

    return res.json({ success: false, status: "expired", message: "Login request expired" });
  } catch (err) {
    console.error("Error polling CLI login:", err);
    return res.status(500).json({ success: false, message: "Failed to poll login" });
  }
});

export default router;
