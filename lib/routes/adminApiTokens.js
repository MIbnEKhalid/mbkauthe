// API token management routes (admin).
//
// Mounted by the host application (e.g. mbkcore at the root). The admin page
// view (dashboard/admin/api-tokens) is provided by the host app; only the
// backend lives here.

import express from "express";
import { renderPage } from "#response.js";
import { sessRole } from "../middleware/auth.js";
import { apiTokenRepository } from "../db/ApiTokenRepository.js";

const router = express.Router();

function parseAvailableApps() {
  let availableApps = ["markdown-editor", "bucket-manager", "api-viewer", "webhook-manager"];
  if (process.env.APPS) {
    try {
      availableApps = JSON.parse(process.env.APPS);
    } catch {
      availableApps = process.env.APPS.split(",").map((a) => a.trim()).filter(Boolean);
    }
  }
  return availableApps;
}

// Admin page to view all API tokens
router.get("/dashboard/admin/api-tokens", sessRole("SuperAdmin"), async (req, res) => {
  try {
    const tokens = await apiTokenRepository.listAll();

    renderPage(req, res, "dashboard/admin/api-tokens.handlebars", true, {
      page: "Admin API Tokens",
      tokens,
      totalTokens: tokens.length,
      availableApps: parseAvailableApps(),
    });
  } catch (error) {
    console.error("Error fetching API tokens:", error);
    renderPage(req, res, "dashboard/admin/api-tokens.handlebars", true, {
      page: "Admin API Tokens",
      tokens: [],
      totalTokens: 0,
      error: "Failed to load API tokens",
    });
  }
});

// Admin API to get token statistics (MUST be before :username route)
router.get("/api/admin/api-tokens/stats", sessRole("SuperAdmin"), async (req, res) => {
  try {
    const stats = await apiTokenRepository.stats();
    res.json({ success: true, stats });
  } catch (error) {
    console.error("Error fetching token statistics:", error);
    res.status(500).json({ success: false, message: "Failed to fetch statistics", error: error.message });
  }
});

// Admin API to get tokens for a specific user
router.get("/api/admin/api-tokens/:username", sessRole("SuperAdmin"), async (req, res) => {
  try {
    const username = req.params.username;
    const tokens = await apiTokenRepository.listForUserAdmin(username);
    res.json({ success: true, tokens });
  } catch (error) {
    console.error("Error fetching user tokens:", error);
    res.status(500).json({ success: false, message: "Failed to fetch tokens", error: error.message });
  }
});

// Admin API to bulk revoke (delete) multiple tokens
// Registered BEFORE the /:id route so "/bulk" is not captured as an id.
router.delete("/api/admin/api-tokens/bulk", sessRole("SuperAdmin"), async (req, res) => {
  try {
    let rawIds = req.body?.ids;
    if (typeof rawIds === "string") {
      rawIds = rawIds.split(",").map((s) => s.trim()).filter(Boolean);
    }
    const ids = (Array.isArray(rawIds) ? rawIds : [])
      .map((id) => parseInt(id, 10))
      .filter((id) => Number.isInteger(id) && id > 0);
    if (ids.length === 0) {
      return res.status(400).json({ success: false, message: "No valid token IDs provided" });
    }

    const result = await apiTokenRepository.deleteByIds(ids);
    res.json({
      success: true,
      message: `Successfully revoked ${result.rowCount} token(s)`,
      count: result.rowCount,
    });
  } catch (error) {
    console.error("Error bulk revoking API tokens:", error);
    res.status(500).json({ success: false, message: "Failed to revoke tokens", error: error.message });
  }
});

// Admin API to revoke (delete) any token
router.delete("/api/admin/api-tokens/:id", sessRole("SuperAdmin"), async (req, res) => {
  try {
    const tokenId = parseInt(req.params.id);
    if (isNaN(tokenId)) {
      return res.status(400).json({ success: false, message: "Invalid token ID" });
    }

    // Get token info before deleting for logging
    const tokenInfo = await apiTokenRepository.findInfoById(tokenId);
    if (!tokenInfo) {
      return res.status(404).json({ success: false, message: "Token not found" });
    }

    const result = await apiTokenRepository.deleteById(tokenId);
    if (result.rowCount === 0) {
      return res.status(404).json({ success: false, message: "Token not found" });
    }

    console.log(`[Admin] Token revoked by ${req.session.user.username}: ${tokenInfo.Name} (User: ${tokenInfo.UserName})`);

    res.json({ success: true, message: "Token revoked successfully" });
  } catch (error) {
    console.error("Error revoking API token:", error);
    res.status(500).json({ success: false, message: "Failed to revoke token", error: error.message });
  }
});

// Admin API to revoke all tokens for a user
router.delete("/api/admin/api-tokens/user/:username", sessRole("SuperAdmin"), async (req, res) => {
  try {
    const username = req.params.username;
    const result = await apiTokenRepository.deleteAllByUsername(username);

    console.log(`[Admin] All tokens revoked for user ${username} by ${req.session.user.username} (${result.rowCount} tokens)`);

    res.json({
      success: true,
      message: `Successfully revoked ${result.rowCount} token(s)`,
      count: result.rowCount,
    });
  } catch (error) {
    console.error("Error revoking user tokens:", error);
    res.status(500).json({ success: false, message: "Failed to revoke tokens", error: error.message });
  }
});

export default router;
