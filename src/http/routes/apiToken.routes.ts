import express from "express";
import { renderError, renderPage } from "../response/formatters.js";
import { sessRole, sessPerm } from "../middleware/authMiddleware.js";
import { apiTokenRepository } from "../../db/repositories/ApiTokenRepository.js";
import { apiTokenService } from "../../services/ApiTokenService.js";
import { permissionRepository } from "../../db/repositories/PermissionRepository.js";
import { normalizePermission } from "../../core/permissions/matcher.js";
import { hasPermission } from "../../core/permissions/roleRegistry.js";
import { MbkAuthError } from "../../core/errors/MbkAuthError.js";

const router = express.Router();

function normalizeRequestedPermissions(value: unknown): string[] {
  let list: string[] = [];
  if (Array.isArray(value)) list = value as string[];
  else if (typeof value === "string") list = value.split(",");
  return [...new Set(list.map(normalizePermission).filter(Boolean))];
}

async function loadGrantablePermissions(user: any) {
  const active = await permissionRepository.listActiveCatalog();
  if (user.role === "superadmin") {
    return { active, grantable: active, effective: { allows: [], denies: [] } };
  }
  const effective = await permissionRepository.computeEffectiveForUser(user.username);
  const grantable = active.filter((perm) => hasPermission({ permissions: effective.effective }, perm.permission));
  return { active, grantable, effective };
}

function groupPermissions(rows: any[]) {
  const apps = new Map<string, Map<string, any[]>>();
  for (const { app_key, service_key, permission, label } of rows) {
    if (!apps.has(app_key)) apps.set(app_key, new Map());
    const services = apps.get(app_key)!;
    if (!services.has(service_key)) services.set(service_key, []);
    services.get(service_key)!.push({ permission, label });
  }
  return [...apps.entries()].map(([appKey, services]) => ({
    appKey,
    services: [...services.entries()].map(([serviceKey, permissions]) => ({ serviceKey, permissions })),
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

  const requested = normalizeRequestedPermissions(req.body.permissions);
  if (requested.length === 0) {
    return res.status(400).json({ success: false, message: "Select at least one permission for this token." });
  }

  const { username, role } = (req as any).session.user;

  try {
    const { active, grantable } = await loadGrantablePermissions((req as any).session.user);
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
