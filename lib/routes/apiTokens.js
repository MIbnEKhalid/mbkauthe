import express from "express";
import { renderError, renderPage } from "#response.js";
import { sessRole, sessVal } from "../middleware/auth.js";
import { hashApiToken, generatePrefixedToken } from "../config/security.js";
import { apiTokenRepository } from "../db/ApiTokenRepository.js";
import { permissionRepository } from "../db/PermissionRepository.js";
import { hasPermission, normalizePermission } from "../permissions.js";

const router = express.Router();

/** Normalize an incoming `permissions` payload into a clean, unique, lowercase list. */
function normalizeRequestedPermissions(value) {
  let list = [];
  if (Array.isArray(value)) list = value;
  else if (typeof value === "string") list = value.split(",");
  return [...new Set(list.map(normalizePermission).filter(Boolean))];
}

/**
 * Which catalog permissions may this user hand to a token?
 *
 * SuperAdmins may grant any active catalog permission; everyone else is capped
 * to their own effective permissions (a token can never exceed its owner).
 *
 * @returns {Promise<{ active: Array, grantable: Array, effective: object }>}
 */
async function loadGrantablePermissions(user) {
  const active = await permissionRepository.listActiveCatalog();
  if (user.role === "superadmin") {
    return { active, grantable: active, effective: { allows: [], denies: [] } };
  }
  const effective = await permissionRepository.computeEffectiveForUser(user.username);
  const allowedUser = { permissions: effective };
  const grantable = active.filter((perm) => hasPermission(allowedUser, perm.permission));
  return { active, grantable, effective };
}

/** Group catalog rows into app -> service -> [permission] for the picker UI. */
function groupPermissions(rows) {
  const apps = new Map();
  for (const row of rows) {
    if (!apps.has(row.app_key)) apps.set(row.app_key, new Map());
    const services = apps.get(row.app_key);
    if (!services.has(row.service_key)) services.set(row.service_key, []);
    services.get(row.service_key).push({ permission: row.permission, label: row.label });
  }
  return [...apps.entries()].map(([appKey, services]) => ({
    appKey,
    services: [...services.entries()].map(([serviceKey, permissions]) => ({ serviceKey, permissions })),
  }));
}

router.get("/user/api-tokens", sessRole("any"), async (req, res) => {
  try {
    const user = req.session.user;
    const { username } = user;
    const tokens = await apiTokenRepository.listForUser(username);

    let permissionGroups = [];
    try {
      const { grantable } = await loadGrantablePermissions(user);
      permissionGroups = groupPermissions(grantable);
    } catch (permErr) {
      console.error("Error loading grantable permissions:", permErr);
    }

    renderPage(req, res, "settings/api-tokens.handlebars", true, {
      page: "API Tokens",
      tokens,
      username,
      permissionGroups,
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

  const { name, expires_days } = req.body;
  if (!name || typeof name !== "string") return res.status(400).json({ success: false, message: "Token name is required" });
  if (name.length > 255) return res.status(400).json({ success: false, message: "Token name must be 255 characters or less" });

  const requested = normalizeRequestedPermissions(req.body.permissions);
  if (requested.length === 0) {
    return res.status(400).json({ success: false, message: "Select at least one permission for this token." });
  }

  const { username, role } = req.session.user;

  try {
    const { active, grantable } = await loadGrantablePermissions(req.session.user);
    const activeSet = new Set(active.map((p) => p.permission));
    const grantableSet = new Set(grantable.map((p) => p.permission));

    const unknown = requested.filter((p) => !activeSet.has(p));
    if (unknown.length > 0) {
      return res.status(400).json({ success: false, message: `Unknown permission(s): ${unknown.join(", ")}` });
    }

    const forbidden = requested.filter((p) => !grantableSet.has(p));
    if (forbidden.length > 0) {
      return res.status(403).json({
        success: false,
        message: `You cannot grant permission(s) you do not hold: ${forbidden.join(", ")}`,
      });
    }

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

    const permissions = JSON.stringify({ permissions: requested });
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
      permissions: token_data.token_permissions || [],
      message: "Token is valid",
    });
  } catch (error) {
    console.error("Token verification error:", error);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

export default router;
