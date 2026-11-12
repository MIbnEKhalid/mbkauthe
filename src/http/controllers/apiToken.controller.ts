/**
 * MBKAuthe — API Token Controller
 * User and Admin API Token controller handlers.
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 */

import type { Request, Response } from "express";
import { renderError, renderPage } from "mbkutils";
import { apiTokenService } from "../../services/ApiTokenService.js";
import { permissionRepository } from "../../db/repositories/PermissionRepository.js";
import { evaluatePermission } from "../../core/permissions/evaluator.js";
import { MbkAuthError } from "../../core/errors/MbkAuthError.js";

export function normalizeRequestedPermissions(value: unknown): string[] {
  let list: any[] = [];
  if (Array.isArray(value)) list = value;
  else if (typeof value === "string") list = value.split(",");
  return Array.from(new Set(list.map((s) => String(s).trim()).filter(Boolean)));
}

export async function loadGrantablePermissions(user: any) {
  const active = await permissionRepository.listActiveCatalog();
  const isSuper = user?.role === "superadmin" || (Array.isArray(user?.roles) && user.roles.includes("superadmin"));
  if (isSuper) {
    return { active, grantable: active, effective: user?.perms || {} };
  }
  const effective = await permissionRepository.computeEffectiveForUser(user.username, user.role);
  const context = {
    isSuperadmin: false,
    role: user.role,
    roles: effective.roles || [user.role],
    masks: effective.masks || {},
  };
  const grantable = active.filter((perm: any) => {
    return evaluatePermission(context, perm.permission || perm.service_key, perm.mask);
  });
  return { active, grantable, effective: effective.masks };
}

export function groupPermissions(rows: any[]) {
  const apps = new Map<string, Map<string, any[]>>();
  for (const row of rows) {
    const appKey = row.app_key || "portal";
    const serviceKey = row.service_key || "general";
    const permKey = row.permission || `${appKey}:${serviceKey}:${row.action_key || row.id}`;
    const label = row.label || `${serviceKey} ${row.action_key || ""}`.trim();

    if (!apps.has(appKey)) apps.set(appKey, new Map());
    const services = apps.get(appKey)!;
    if (!services.has(serviceKey)) services.set(serviceKey, []);
    services.get(serviceKey)!.push({
      id: row.id,
      label,
      permission: permKey,
      action_key: row.action_key,
      mask: row.mask,
    });
  }
  return [...apps.entries()].map(([appKey, services]) => ({
    appKey,
    services: [...services.entries()].map(([serviceKey, permissions]) => ({ serviceKey, permissions })),
  }));
}

export function matchesPermission(reqPerm: string, p: any): boolean {
  const cleanReq = String(reqPerm || "").trim().toLowerCase();
  if (!cleanReq) return false;
  if (String(p.id) === cleanReq) return true;
  if (p.permission && p.permission.toLowerCase() === cleanReq) return true;
  if (p.service_key && p.action_key && `${p.service_key}:${p.action_key}`.toLowerCase() === cleanReq) return true;
  if (p.permission) {
    const partsP = p.permission.toLowerCase().split(":");
    const partsReq = cleanReq.split(":");
    if (partsP.length === 3 && partsReq.length === 2 && partsP[1] === partsReq[0] && partsP[2] === partsReq[1]) {
      return true;
    }
    if (partsP.length === 2 && partsReq.length === 3 && partsReq[1] === partsP[0] && partsReq[2] === partsP[1]) {
      return true;
    }
  }
  return false;
}

// ============================================================================
// User API Tokens Controller Handlers
// ============================================================================

export async function renderUserApiTokensPage(req: Request, res: Response): Promise<void> {
  try {
    const { username } = (req as any).session?.user || {};
    if (!username) {
      return renderError(res, req, {
        code: 401,
        error: "Unauthorized",
        message: "You must be logged in to view API tokens.",
        pagename: "API Tokens",
        page: "/user/api-tokens",
      });
    }

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
}

export async function createUserApiToken(req: Request, res: Response): Promise<any> {
  if (!req.body) return res.status(400).json({ success: false, message: "Request body is missing" });

  const { name, expires_days } = req.body;
  if (!name || typeof name !== "string") return res.status(400).json({ success: false, message: "Token name is required" });
  if (name.length > 255) return res.status(400).json({ success: false, message: "Token name must be 255 characters or less" });

  const requested = normalizeRequestedPermissions(req.body.permissions);
  if (requested.length === 0) {
    return res.status(400).json({ success: false, message: "Select at least one permission for this token." });
  }

  const { username, role } = (req as any).session?.user || {};
  if (!username) return res.status(401).json({ success: false, message: "Unauthorized" });

  try {
    const { active, grantable } = await loadGrantablePermissions((req as any).session.user);

    if (active.length > 0) {
      const unknown = requested.filter((p) => !active.some((item) => matchesPermission(p, item)));
      if (unknown.length > 0) {
        return res.status(400).json({ success: false, message: `Unknown permission(s): ${unknown.join(", ")}` });
      }
    }

    if (grantable.length > 0) {
      const forbidden = requested.filter((p) => !grantable.some((item) => matchesPermission(p, item)));
      if (forbidden.length > 0) {
        return res.status(403).json({
          success: false,
          message: `You cannot grant permission(s) you do not hold: ${forbidden.join(", ")}`,
        });
      }
    }

    const canonicalScopes = requested.map((reqPerm) => {
      const found = active.find((p) => matchesPermission(reqPerm, p));
      return found?.permission || reqPerm;
    });

    const expiresInDays = expires_days && parseInt(expires_days, 10) > 0 ? parseInt(expires_days, 10) : null;
    const { token: raw_token, tokenRecord: meta } = await apiTokenService.createToken(
      username,
      {
        name: name.trim(),
        scopes: canonicalScopes,
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
}

export async function deleteUserApiToken(req: Request, res: Response): Promise<any> {
  try {
    const rawId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
    const token_id = parseInt(String(rawId), 10);
    if (Number.isNaN(token_id)) return res.status(400).json({ success: false, message: "Invalid token ID" });

    const username = (req as any).session?.user?.username;
    if (!username) return res.status(401).json({ success: false, message: "Unauthorized" });

    const success = await apiTokenService.revokeToken(token_id, username);
    if (!success) return res.status(404).json({ success: false, message: "Token not found or not owned." });

    res.json({ success: true, message: "Token deleted successfully." });
  } catch (err) {
    console.error("Error deleting API token:", err);
    res.status(500).json({ success: false, message: "Failed to delete token" });
  }
}

export async function verifyApiToken(req: Request, res: Response): Promise<any> {
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
}

// ============================================================================
// Admin API Tokens Controller Handlers
// ============================================================================

export async function renderAdminApiTokensPage(req: Request, res: Response): Promise<void> {
  try {
    const tokens = await apiTokenService.listAllTokens();
    renderPage(req, res, "dashboard/admin/api-tokens.hbs", true, {
      page: "Admin API Tokens",
      tokens,
      totalTokens: tokens.length,
    });
  } catch (error) {
    console.error("Error fetching API tokens:", error);
    renderPage(req, res, "dashboard/admin/api-tokens.hbs", true, {
      page: "Admin API Tokens",
      tokens: [],
      totalTokens: 0,
      error: "Failed to load API tokens",
    });
  }
}

export async function getAdminApiTokenStats(req: Request, res: Response): Promise<any> {
  try {
    const stats = await apiTokenService.getTokenStats();
    res.json({ success: true, stats });
  } catch (error: any) {
    console.error("Error fetching token statistics:", error);
    res.status(500).json({ success: false, message: "Failed to fetch statistics", error: error.message });
  }
}

export async function getAdminUserApiTokens(req: Request, res: Response): Promise<any> {
  try {
    const username = Array.isArray(req.params.username) ? req.params.username[0] : req.params.username;
    const tokens = await apiTokenService.listTokensForUserAdmin(String(username));
    res.json({ success: true, tokens });
  } catch (error: any) {
    console.error("Error fetching user tokens:", error);
    res.status(500).json({ success: false, message: "Failed to fetch tokens", error: error.message });
  }
}

export async function bulkRevokeAdminApiTokens(req: Request, res: Response): Promise<any> {
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
}

export async function deleteAdminApiToken(req: Request, res: Response): Promise<any> {
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
}

export async function revokeAllUserApiTokensAdmin(req: Request, res: Response): Promise<any> {
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
}

export const apiTokenController = {
  renderUserApiTokensPage,
  createUserApiToken,
  deleteUserApiToken,
  verifyApiToken,
};

export const adminApiTokenController = {
  renderAdminApiTokensPage,
  getAdminApiTokenStats,
  getUserApiTokens: getAdminUserApiTokens,
  bulkRevokeAdminApiTokens,
  deleteAdminApiToken,
  revokeAllUserApiTokens: revokeAllUserApiTokensAdmin,
};

