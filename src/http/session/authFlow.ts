import express from "express";
import { mbkautheVar, isProductionEnvironment } from "../../config/index.js";
import { getCookieOptions, getClearCookieOptions, getOrCreateDeviceId } from "../../config/cookies.js";
import { authRepository } from "../../db/repositories/AuthRepository.js";
import { attachSessionPermissions } from "./sessionPermissions.js";
import { createLogger } from "../../utils/logger.js";
import { ErrorCodes, ErrorMessages } from "../../core/errors/catalog.js";
import { isLocalOnlyUser } from "../../core/types/user.types.js";

const logAuth = createLogger("auth");
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const isUuid = (val: unknown): val is string => typeof val === "string" && UUID_REGEX.test(val);

export function extractRequestOrigin(req: express.Request): string {
  try {
    const rawOrigin = (req.headers.origin || req.headers.referer) as string | undefined;
    if (typeof rawOrigin === "string" && rawOrigin.trim()) {
      try {
        const parsed = new URL(rawOrigin);
        if (parsed.host) return parsed.host;
      } catch {
        // Not a valid URL format, continue
      }
    }
    const forwardedHost = req.headers["x-forwarded-host"] as string | undefined;
    if (typeof forwardedHost === "string" && forwardedHost.trim()) {
      return forwardedHost.split(",")[0].trim();
    }
    const hostHeader = req.get ? req.get("host") : (req.headers.host as string | undefined);
    if (typeof hostHeader === "string" && hostHeader.trim()) {
      return hostHeader.split(",")[0].trim();
    }
  } catch {
    // Ignore error and fall through
  }
  return "Unknown";
}

import { avatarService } from "../../services/AvatarService.js";

export function invalidateAvatarCache(username: string) {
  if (username) avatarService.invalidateAvatarCache(username);
}

export async function fetchActiveSession(session_id: string) {
  if (!isUuid(session_id)) return null;
  const row: any = await authRepository.fetchActiveSession(session_id);
  if (!row) return null;
  if (!row.is_active) return null;
  const isLocalOnly = isLocalOnlyUser(row.is_local_only);
  if (isLocalOnly && isProductionEnvironment()) return null;
  if (row.role !== "superadmin") {
    const allowed = row.allowed_apps;
    if (!Array.isArray(allowed) || !allowed.some((app: any) => app?.toLowerCase() === mbkautheVar.APP_NAME)) return null;
  }
  return row;
}

export async function invalidateDbSession(session_id: string) {
  if (!isUuid(session_id)) return;
  try {
    await authRepository.deleteAppSessionById(session_id);
  } catch (err) {
    console.error(`[mbkauthe] Error invalidating session:`, err);
  }
}

export async function completeLoginProcess(
  req: express.Request,
  res: express.Response,
  user: any,
  redirect_url: string | null = null,
  method: string | null = null
) {
  try {
    const username = user.username;
    if (!username) throw new Error("Username is required in user object");

    const isLocalOnly = isLocalOnlyUser(user.is_local_only);
    if (isLocalOnly && isProductionEnvironment()) {
      logAuth(`Login rejected for user "${username}": account is restricted to local environments`);
      const errDetail = ErrorMessages[ErrorCodes.LOCAL_USER_PROD_RESTRICTED];
      return res.status(403).json({
        success: false,
        error: errDetail.message,
        errorCode: ErrorCodes.LOCAL_USER_PROD_RESTRICTED,
        userMessage: errDetail.userMessage,
        hint: errDetail.hint,
      });
    }

    const originDomain = extractRequestOrigin(req);
    const deviceId = getOrCreateDeviceId(req, res);

    await new Promise<void>((resolve, reject) => (req as any).session.regenerate((err: any) => (err ? reject(err) : resolve())));

    const configuredMax = parseInt(String(mbkautheVar.MAX_SESSIONS_PER_USER), 10);
    const MAX_SESSIONS = Number.isInteger(configuredMax) && configuredMax > 0 ? configuredMax : 5;
    const cookieOpts = getCookieOptions();
    const expiresAt = new Date(Date.now() + (cookieOpts.maxAge || 0));
    const meta = JSON.stringify({
      ip: req.ip,
      ua: req.headers["user-agent"] || null,
      origin: originDomain,
      domain: originDomain,
    });

    const inserted = await authRepository.createAppSessionWithPruning({
      username,
      expiresAt,
      meta,
      maxSessions: MAX_SESSIONS,
      sid: req.sessionID,
      device_id: deviceId,
    });
    const dbSessionId = inserted.id;

    const userFullName = (typeof user.full_name === "string" && user.full_name.trim()) ? user.full_name : username;
    const userImage = (typeof user.image === "string" && user.image.trim()) ? user.image : null;

    (req as any).session.user = {
      session_id: dbSessionId,
      user_id: user.user_id || undefined,
      username,
      full_name: userFullName,
      role: user.role,
      allowed_apps: user.allowed_apps,
      image: userImage || undefined,
      is_local_only: isLocalOnly,
      origin: originDomain,
      domain: originDomain,
      device_id: deviceId,
    };

    invalidateAvatarCache(username);

    if ((req as any).session.pre_auth_user) delete (req as any).session.pre_auth_user;

    await attachSessionPermissions((req as any).session.user, username, user.role);

    (req as any).session.save(async (saveErr: any) => {
      if (saveErr) {
        console.error(`[mbkauthe] Session save error:`, saveErr);
        return res.status(500).json({ success: false, message: "Internal Server Error" });
      }

      const activeCookieOpts = getCookieOptions();
      res.cookie("username", username, { ...activeCookieOpts, httpOnly: false });
      res.cookie("full_name", (req as any).session.user.full_name || username, { ...activeCookieOpts, httpOnly: false });

      if (typeof method === "string") {
        try { res.cookie("last_login_method", method, { ...activeCookieOpts, httpOnly: false }); } catch {}
      }

      (req as any).session.pre_auth_user = null;

      logAuth(`User "${username}" logged in successfully via ${method || "password"} on device "${deviceId}" (last_login updated)`);

      const responsePayload: Record<string, any> = { success: true, message: "Login successful", username };
      if (redirect_url) responsePayload.redirect_url = redirect_url;
      res.status(200).json(responsePayload);
    });
  } catch (err) {
    console.error(`[mbkauthe] Error during login completion:`, err);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
}
