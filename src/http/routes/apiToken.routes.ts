import express from "express";
import { renderError, renderPage } from "mbkutils";
import { sessRole, sessPerm } from "../middleware/authMiddleware.js";
import { apiTokenRepository } from "../../db/repositories/ApiTokenRepository.js";
import { apiTokenService } from "../../services/ApiTokenService.js";
import { permissionRepository } from "../../db/repositories/PermissionRepository.js";
import { MbkAuthError } from "../../core/errors/MbkAuthError.js";

const router = express.Router();

function normalizeRequestedPermissions(value: unknown): string[] {
  let list: any[] = [];
  if (Array.isArray(value)) list = value;
  else if (typeof value === "string") list = value.split(",");
  return Array.from(new Set(list.map((s) => String(s).trim().toLowerCase()).filter(Boolean)));
}

function parseJsonObject(val: any): Record<string, any> {
  if (!val) return {};
  if (typeof val === "object" && !Array.isArray(val)) return val;
  if (typeof val === "string") {
    try {
      const parsed = JSON.parse(val);
      return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
    } catch {
      return {};
    }
  }
  return {};
}

async function computeLiveUserMasks(username: string, fallbackPerms: Record<string, number> = {}): Promise<{ isSuperadmin: boolean; masks: Record<string, number> }> {
  try {
    const userRes = await (apiTokenRepository as any).execute(
      `SELECT role, extra_roles, perm_overrides FROM mbkcore_users WHERE LOWER(username) = LOWER($1) LIMIT 1`,
      [username]
    );
    const userRow = userRes?.rows?.[0];
    if (!userRow) return { isSuperadmin: false, masks: fallbackPerms };

    const primaryRole = String(userRow.role || "normaluser").trim().toLowerCase();
    let extraRoles: string[] = [];
    if (Array.isArray(userRow.extra_roles)) {
      extraRoles = userRow.extra_roles;
    } else if (typeof userRow.extra_roles === "string") {
      try {
        const parsed = JSON.parse(userRow.extra_roles);
        if (Array.isArray(parsed)) extraRoles = parsed;
      } catch {}
    }

    const allRoles = Array.from(new Set([primaryRole, ...extraRoles.map((r) => String(r).trim().toLowerCase())].filter(Boolean)));
    if (allRoles.includes("superadmin")) {
      return { isSuperadmin: true, masks: {} };
    }

    const combinedMasks: Record<string, number> = {};
    for (const roleName of allRoles) {
      const roleRes = await (apiTokenRepository as any).execute(
        `SELECT permissions FROM mbkcore_roles WHERE LOWER(name) = LOWER($1) LIMIT 1`,
        [roleName]
      );
      const rolePerms = parseJsonObject(roleRes?.rows?.[0]?.permissions);
      for (const [resKey, maskVal] of Object.entries(rolePerms)) {
        const numMask = Number(maskVal) || 0;
        if (numMask > 0) {
          const cleanKey = resKey.trim().toLowerCase();
          combinedMasks[cleanKey] = (combinedMasks[cleanKey] || 0) | numMask;
        }
      }
    }

    const rawOverrides = parseJsonObject(userRow.perm_overrides);
    const allows = parseJsonObject(rawOverrides.allows);
    const denies = parseJsonObject(rawOverrides.denies);

    for (const [resKey, maskVal] of Object.entries(allows)) {
      const numMask = Number(maskVal) || 0;
      if (numMask > 0) {
        const cleanKey = resKey.trim().toLowerCase();
        combinedMasks[cleanKey] = (combinedMasks[cleanKey] || 0) | numMask;
      }
    }
    for (const [resKey, maskVal] of Object.entries(denies)) {
      const numMask = Number(maskVal) || 0;
      if (numMask > 0) {
        const cleanKey = resKey.trim().toLowerCase();
        combinedMasks[cleanKey] = (combinedMasks[cleanKey] || 0) & ~numMask;
      }
    }

    return { isSuperadmin: false, masks: combinedMasks };
  } catch (err) {
    try {
      const effective = await permissionRepository.computeEffectiveForUser(username);
      return { isSuperadmin: false, masks: effective?.masks || fallbackPerms };
    } catch {
      return { isSuperadmin: false, masks: fallbackPerms };
    }
  }
}

async function loadGrantablePermissions(user: any) {
  const catalogRes = await (apiTokenRepository as any).execute(
    `SELECT permission AS id, app_key, service_key, action_key, label, mask, is_active
     FROM mbkcore_permission_catalog
     WHERE is_active = TRUE
       AND app_key IS NOT NULL AND BTRIM(app_key) <> ''
       AND service_key IS NOT NULL AND BTRIM(service_key) <> ''
     ORDER BY app_key ASC, service_key ASC, mask ASC`
  );

  const active = (catalogRes?.rows || []).map((r: any) => ({
    id: String(r.id).trim().toLowerCase(),
    app_key: String(r.app_key || "portal").trim().toLowerCase(),
    service_key: String(r.service_key || "general").trim().toLowerCase(),
    action_key: String(r.action_key || "access").trim().toLowerCase(),
    label: r.label || r.id,
    mask: Number(r.mask) || 1,
  }));

  if (user?.role === "superadmin") {
    return { active, grantable: active, effective: user.perms || {} };
  }

  const { isSuperadmin, masks } = await computeLiveUserMasks(user?.username, user?.perms || {});
  if (isSuperadmin) {
    return { active, grantable: active, effective: masks };
  }

  const grantable = active.filter((row: any) => {
    if (row.id === "global:basic:access") return true;
    const svcMask = Number(masks[row.service_key] || 0);
    return (svcMask & row.mask) !== 0;
  });

  return { active, grantable, effective: masks };
}

function groupPermissions(rows: any[]) {
  const apps = new Map<string, Map<string, any[]>>();
  for (const row of rows) {
    const { id, app_key, service_key, action_key, label, mask } = row;
    if (!apps.has(app_key)) apps.set(app_key, new Map());
    const services = apps.get(app_key)!;
    if (!services.has(service_key)) services.set(service_key, []);
    services.get(service_key)!.push({
      id,
      permission: id,
      key: id,
      app_key,
      service_key,
      action_key,
      label,
      mask,
    });
  }
  return [...apps.entries()].map(([appKey, services]) => ({
    appKey,
    services: [...services.entries()].map(([serviceKey, permissions]) => ({
      serviceKey,
      permissions,
    })),
  }));
}

router.get("/user/api-tokens", sessRole("any"), async (req, res) => {
  try {
    const { username } = (req as any).session.user;
    const tokens = await apiTokenService.listUserTokens(username);

    let permissionGroups: any[] = [];
    try {
      const { grantable } = await loadGrantablePermissions((req as any).session.user);
      permissionGroups = groupPermissions(grantable);
    } catch (permErr) {
      console.error("Error loading grantable permissions:", permErr);
    }

    renderPage(req, res, "settings/api-tokens.hbs", true, {
      page: "API Tokens",
      tokens,
      username,
      permissionGroups,
    });
  } catch (error) {
    console.error("Error fetching API tokens:", error);
    renderError(res, req, {
      code: 500,
      error: "Internal Server Error",
      message: "Failed to load API tokens.",
      details: error,
      pagename: "API Tokens",
      page: "/user/api-tokens",
    });
  }
});

router.post("/api/token", sessPerm("basic.access"), async (req, res) => {
  if (!req.body) return res.status(400).json({ success: false, message: "Request body is missing" });

  const { name, expires_days } = req.body;
  if (!name || typeof name !== "string") return res.status(400).json({ success: false, message: "Token name is required" });
  if (name.length > 255) return res.status(400).json({ success: false, message: "Token name must be 255 characters or less" });

const rawPermsInput = req.body.permissions ?? req.body.scopes ?? req.body.permission_ids;
  const requested = normalizeRequestedPermissions(rawPermsInput);
  if (requested.length === 0) {
    return res.status(400).json({ success: false, message: "Select at least one permission for this token." });
  }

  const { username, role } = (req as any).session.user;

  try {
    const { active, grantable } = await loadGrantablePermissions((req as any).session.user);
    const activeSet = new Set(active.map((p: any) => p.id));
    const grantableSet = new Set(grantable.map((p: any) => p.id));

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

    const expiresInDays = expires_days && parseInt(expires_days, 10) > 0 ? parseInt(expires_days, 10) : null;
    const { token: raw_token, tokenRecord: meta } = await apiTokenService.createToken(
      username,
      {
        name: name.trim(),
        scopes: requested,
        expiresInDays,
      },
      { userRole: role }
    );

    res.json({ success: true, token: raw_token, meta, message: "Token created. Copy it now - you won't see it again!" });
  } catch (err: any) {
    if (err instanceof MbkAuthError) {
      return res.status(err.statusCode).json({ success: false, message: err.message });
    }
    console.error("Error creating API token:", err);
    res.status(500).json({ success: false, message: "Failed to create token", error: err.message });
  }
});

router.delete("/api/tokens/:id", sessRole("any"), async (req, res) => {
  try {
    const rawId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
    const token_id = parseInt(String(rawId), 10);
    if (Number.isNaN(token_id)) return res.status(400).json({ success: false, message: "Invalid token ID" });

    const username = (req as any).session.user.username;
    const success = await apiTokenService.revokeToken(token_id, username);
    if (!success) return res.status(404).json({ success: false, message: "Token not found or not owned." });

    res.json({ success: true, message: "Token deleted successfully." });
  } catch (err) {
    console.error("Error deleting API token:", err);
    res.status(500).json({ success: false, message: "Failed to delete token" });
  }
});

router.post("/api/tokens/verify", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    const rawToken = authHeader?.startsWith("Bearer ")
      ? authHeader.split(" ")[1]
      : (typeof req.body?.token === "string" ? req.body.token : null);

    if (!rawToken) {
      return res.status(401).json({ success: false, message: "No token provided" });
    }

    const result = await apiTokenService.verifyToken(rawToken);

    res.json({
      success: true,
      username: result.username,
      permissions: result.permissions,
      message: "Token is valid",
    });
  } catch (error: any) {
    if (error instanceof MbkAuthError) {
      return res.status(error.statusCode).json({ success: false, message: error.message });
    }
    console.error("Token verification error:", error);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

export const apiTokensRouter = router;
export default router;