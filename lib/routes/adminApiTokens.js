import express from "express";
import { renderPage } from "#response.js";
import { sessRole } from "../middleware/auth.js";
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

router.get("/dashboard/admin/api-tokens", sessRole("superadmin"), async (req, res) => {
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

router.get("/api/admin/api-tokens/stats", sessRole("superadmin"), async (req, res) => {
  try {
    const stats = await apiTokenRepository.stats();
    res.json({ success: true, stats });
  } catch (error) {
    console.error("Error fetching token statistics:", error);
    res.status(500).json({ success: false, message: "Failed to fetch statistics", error: error.message });
  }
});

router.get("/api/admin/api-tokens/:username", sessRole("superadmin"), async (req, res) => {
  try {
    const tokens = await apiTokenRepository.listForUserAdmin(req.params.username);
    res.json({ success: true, tokens });
  } catch (error) {
    console.error("Error fetching user tokens:", error);
    res.status(500).json({ success: false, message: "Failed to fetch tokens", error: error.message });
  }
});

router.delete("/api/admin/api-tokens/bulk", sessRole("superadmin"), async (req, res) => {
  try {
    let raw_ids = req.body?.ids;
    if (typeof raw_ids === "string") {
      raw_ids = raw_ids.split(",").map((s) => s.trim()).filter(Boolean);
    }
    const ids = (Array.isArray(raw_ids) ? raw_ids : [])
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

router.delete("/api/admin/api-tokens/:id", sessRole("superadmin"), async (req, res) => {
  try {
    const token_id = parseInt(req.params.id, 10);
    if (Number.isNaN(token_id)) return res.status(400).json({ success: false, message: "Invalid token ID" });

    const token_info = await apiTokenRepository.findInfoById(token_id);
    if (!token_info) return res.status(404).json({ success: false, message: "Token not found" });

    const result = await apiTokenRepository.deleteById(token_id);
    if (result.rowCount === 0) return res.status(404).json({ success: false, message: "Token not found" });

    console.log(`[Admin] Token revoked by ${req.session.user.username}: ${token_info.name} (User: ${token_info.username})`);
    res.json({ success: true, message: "Token revoked successfully" });
  } catch (error) {
    console.error("Error revoking API token:", error);
    res.status(500).json({ success: false, message: "Failed to revoke token", error: error.message });
  }
});

router.delete("/api/admin/api-tokens/user/:username", sessRole("superadmin"), async (req, res) => {
  try {
    const { username } = req.params;
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
