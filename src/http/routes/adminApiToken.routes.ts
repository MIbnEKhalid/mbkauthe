import express from "express";
import { renderPage } from "../response/formatters.js";
import { sessRole } from "../middleware/authMiddleware.js";
import { apiTokenService } from "../../services/ApiTokenService.js";

const router = express.Router();

router.get("/dashboard/admin/api-tokens", sessRole("superadmin"), async (req, res) => {
  try {
    const tokens = await apiTokenService.listAllTokens();
    renderPage(req, res, "dashboard/admin/api-tokens.handlebars", true, {
      page: "Admin API Tokens",
      tokens,
      totalTokens: tokens.length,
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
    const stats = await apiTokenService.getTokenStats();
    res.json({ success: true, stats });
  } catch (error: any) {
    console.error("Error fetching token statistics:", error);
    res.status(500).json({ success: false, message: "Failed to fetch statistics", error: error.message });
  }
});

router.get("/api/admin/api-tokens/:username", sessRole("superadmin"), async (req, res) => {
  try {
    const username = Array.isArray(req.params.username) ? req.params.username[0] : req.params.username;
    const tokens = await apiTokenService.listTokensForUserAdmin(String(username));
    res.json({ success: true, tokens });
  } catch (error: any) {
    console.error("Error fetching user tokens:", error);
    res.status(500).json({ success: false, message: "Failed to fetch tokens", error: error.message });
  }
});

router.delete("/api/admin/api-tokens/bulk", sessRole("superadmin"), async (req, res) => {
  try {
    let raw_ids = req.body?.ids;
    if (typeof raw_ids === "string") raw_ids = raw_ids.split(",").map((s: string) => s.trim()).filter(Boolean);
    const ids = (Array.isArray(raw_ids) ? raw_ids : []).map((id: any) => parseInt(id, 10)).filter((id: number) => Number.isInteger(id) && id > 0);

    if (ids.length === 0) return res.status(400).json({ success: false, message: "No valid token IDs provided" });

    const count = await apiTokenService.bulkRevokeTokens(ids);
    res.json({
      success: true,
      message: `Successfully revoked ${count} token(s)`,
      count,
    });
  } catch (error: any) {
    console.error("Error bulk revoking API tokens:", error);
    res.status(500).json({ success: false, message: "Failed to revoke tokens", error: error.message });
  }
});

router.delete("/api/admin/api-tokens/:id", sessRole("superadmin"), async (req, res) => {
  try {
    const rawId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
    const token_id = parseInt(String(rawId), 10);
    if (Number.isNaN(token_id)) return res.status(400).json({ success: false, message: "Invalid token ID" });

    const success = await apiTokenService.adminDeleteToken(token_id);
    if (!success) return res.status(404).json({ success: false, message: "Token not found" });

    console.log(`[Admin] Token revoked by ${(req as any).session?.user?.username || "unknown"}: ID ${token_id}`);
    res.json({ success: true, message: "Token revoked successfully" });
  } catch (error: any) {
    console.error("Error revoking API token:", error);
    res.status(500).json({ success: false, message: "Failed to revoke token", error: error.message });
  }
});

router.delete("/api/admin/api-tokens/user/:username", sessRole("superadmin"), async (req, res) => {
  try {
    const rawUsername = Array.isArray(req.params.username) ? req.params.username[0] : req.params.username;
    const username = String(rawUsername);
    const count = await apiTokenService.revokeAllUserTokens(username);

    console.log(`[Admin] All tokens revoked for user ${username} by ${(req as any).session?.user?.username || "unknown"} (${count} tokens)`);
    res.json({
      success: true,
      message: `Successfully revoked ${count} token(s)`,
      count,
    });
  } catch (error: any) {
    console.error("Error revoking user tokens:", error);
    res.status(500).json({ success: false, message: "Failed to revoke tokens", error: error.message });
  }
});

export const adminApiTokensRouter = router;
export default router;
