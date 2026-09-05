import express from "express";
import { renderError, renderPage } from "#response.js";
import { sessRole, sessVal } from "../middleware/auth.js";
import { hashApiToken, generatePrefixedToken } from "../config/security.js";
import { apiTokenRepository } from "../db/ApiTokenRepository.js";

const router = express.Router();

function parseAvailableApps() {
  if (!process.env.APPS) return ["markdown-editor", "bucket-manager", "api-viewer", "webhook-manager"];
  try {
    return JSON.parse(process.env.APPS);
  } catch {
    return process.env.APPS.split(",").map((a) => a.trim()).filter(Boolean);
  }
}

router.get("/user/api-tokens", sessRole("any"), async (req, res) => {
  try {
    const { username } = req.session.user;
    const tokens = await apiTokenRepository.listForUser(username);
    renderPage(req, res, "settings/api-tokens.handlebars", true, {
      page: "API Tokens",
      tokens,
      username,
      availableApps: parseAvailableApps(),
    });
  } catch (error) {
    console.error("Error fetching API tokens:", error);
    renderError(res, req, {
      layout: false,
      code: 500,
      error: "Internal Server Error",
      message: "Failed to load API tokens.",
      details: error,
      pagename: "API Tokens",
      page: "/user/api-tokens",
    });
  }
});

router.post("/api/token", sessVal, async (req, res) => {
  if (!req.body) return res.status(400).json({ success: false, message: "Request body is missing" });

  const { name, expires_days, scope } = req.body;
  if (!name || typeof name !== "string") return res.status(400).json({ success: false, message: "Token name is required" });
  if (name.length > 255) return res.status(400).json({ success: false, message: "Token name must be 255 characters or less" });

  const token_scope = scope || "read-only";
  if (!["read-only", "write"].includes(token_scope)) return res.status(400).json({ success: false, message: "Invalid scope." });

  const { username, role } = req.session.user;

  try {
    if (role !== "superadmin") {
      const token_count = await apiTokenRepository.countForUser(username);
      if (token_count >= 10) return res.status(403).json({ success: false, message: "Token limit reached (max 10)." });
    }

    const raw_token = generatePrefixedToken();
    const token_hash = hashApiToken(raw_token);
    const prefix = raw_token.substring(0, 8);

    let expires_at = null;
    if (expires_days && parseInt(expires_days, 10) > 0) {
      expires_at = new Date();
      expires_at.setDate(expires_at.getDate() + parseInt(expires_days, 10));
    }

    let allowed_apps = null;
    const incoming_apps = req.body.allowed_apps;
    if (incoming_apps) {
      const raw_apps = typeof incoming_apps === "string" ? incoming_apps.split(",") : incoming_apps;
      allowed_apps = (Array.isArray(raw_apps) ? raw_apps : []).map((a) => a?.trim?.()).filter(Boolean);
      if (!allowed_apps.length) allowed_apps = null;
    }

    const permissions = JSON.stringify({ scope: token_scope, allowed_apps });
    const meta = await apiTokenRepository.insert(username, name.trim(), token_hash, prefix, permissions, expires_at);

    res.json({ success: true, token: raw_token, meta, message: "Token created. Copy it now - you won't see it again!" });
  } catch (err) {
    console.error("Error creating API token:", err);
    res.status(500).json({ success: false, message: "Failed to create token", error: err.message });
  }
});

router.delete("/api/tokens/:id", sessRole("any"), async (req, res) => {
  try {
    const token_id = parseInt(req.params.id, 10);
    if (Number.isNaN(token_id)) return res.status(400).json({ success: false, message: "Invalid token ID" });

    const result = await apiTokenRepository.deleteByIdAndUsername(token_id, req.session.user.username);
    if (result.rowCount === 0) return res.status(404).json({ success: false, message: "Token not found or not owned." });

    res.json({ success: true, message: `Token "${result.rows[0].name}" deleted.` });
  } catch (err) {
    console.error("Error deleting API token:", err);
    res.status(500).json({ success: false, message: "Failed to delete token" });
  }
});

router.post("/api/tokens/verify", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) {
      return res.status(401).json({ success: false, message: "No token provided" });
    }

    const token_hash = hashApiToken(authHeader.split(" ")[1]);
    const rows = await apiTokenRepository.findByTokenHash(token_hash);
    if (rows.length === 0) return res.status(401).json({ success: false, message: "Invalid token" });

    const token_data = rows[0];
    if (token_data.expires_at && new Date(token_data.expires_at) < new Date()) {
      return res.status(401).json({ success: false, message: "Token expired" });
    }

    await apiTokenRepository.updateLastUsedByHash(token_hash).catch(() => {});

    res.json({
      success: true,
      username: token_data.username,
      scope: token_data.scope,
      allowed_apps: token_data.allowed_apps,
      message: "Token is valid",
    });
  } catch (error) {
    console.error("Token verification error:", error);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

export default router;
