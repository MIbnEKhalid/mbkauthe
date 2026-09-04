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

  const { name, expiresDays, scope } = req.body;
  if (!name || typeof name !== "string") return res.status(400).json({ success: false, message: "Token name is required" });
  if (name.length > 255) return res.status(400).json({ success: false, message: "Token name must be 255 characters or less" });

  const tokenScope = scope || "read-only";
  if (!["read-only", "write"].includes(tokenScope)) return res.status(400).json({ success: false, message: "Invalid scope." });

  const { username, role } = req.session.user;

  try {
    if (role !== "SuperAdmin") {
      const tokenCount = await apiTokenRepository.countForUser(username);
      if (tokenCount >= 10) return res.status(403).json({ success: false, message: "Token limit reached (max 10)." });
    }

    const rawToken = generatePrefixedToken();
    const tokenHash = hashApiToken(rawToken);
    const prefix = rawToken.substring(0, 8);

    let expiresAt = null;
    if (expiresDays && parseInt(expiresDays, 10) > 0) {
      expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + parseInt(expiresDays, 10));
    }

    let allowedApps = null;
    if (req.body.allowedApps) {
      const rawApps = typeof req.body.allowedApps === "string" ? req.body.allowedApps.split(",") : req.body.allowedApps;
      allowedApps = (Array.isArray(rawApps) ? rawApps : []).map((a) => a?.trim?.()).filter(Boolean);
      if (!allowedApps.length) allowedApps = null;
    }

    const permissions = JSON.stringify({ scope: tokenScope, allowedApps });
    const meta = await apiTokenRepository.insert(username, name.trim(), tokenHash, prefix, permissions, expiresAt);

    res.json({ success: true, token: rawToken, meta, message: "Token created. Copy it now - you won't see it again!" });
  } catch (err) {
    console.error("Error creating API token:", err);
    res.status(500).json({ success: false, message: "Failed to create token", error: err.message });
  }
});

router.delete("/api/tokens/:id", sessRole("any"), async (req, res) => {
  try {
    const tokenId = parseInt(req.params.id, 10);
    if (Number.isNaN(tokenId)) return res.status(400).json({ success: false, message: "Invalid token ID" });

    const result = await apiTokenRepository.deleteByIdAndUsername(tokenId, req.session.user.username);
    if (result.rowCount === 0) return res.status(404).json({ success: false, message: "Token not found or not owned." });

    res.json({ success: true, message: `Token "${result.rows[0].Name}" deleted.` });
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

    const tokenHashVal = hashApiToken(authHeader.split(" ")[1]);
    const rows = await apiTokenRepository.findByTokenHash(tokenHashVal);
    if (rows.length === 0) return res.status(401).json({ success: false, message: "Invalid token" });

    const tokenData = rows[0];
    if (tokenData.ExpiresAt && new Date(tokenData.ExpiresAt) < new Date()) {
      return res.status(401).json({ success: false, message: "Token expired" });
    }

    await apiTokenRepository.updateLastUsedByHash(tokenHashVal).catch(() => {});

    res.json({
      success: true,
      username: tokenData.UserName,
      scope: tokenData.Scope,
      allowedApps: tokenData.AllowedApps,
      message: "Token is valid",
    });
  } catch (error) {
    console.error("Token verification error:", error);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

export default router;
