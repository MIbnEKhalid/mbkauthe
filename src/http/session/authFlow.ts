import express from "express";
import { mbkautheVar } from "../../config/index.js";
import { cachedCookieOptions, cachedClearCookieOptions, encryptSessionId } from "../../config/cookies.js";
import { upsertAccountListCookie } from "./accountCookies.js";
import { authRepository } from "../../db/repositories/AuthRepository.js";
import { attachSessionPermissions } from "./sessionPermissions.js";
import { createLogger } from "../../utils/logger.js";

const logAuth = createLogger("auth");
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const isUuid = (val: unknown): val is string => typeof val === "string" && UUID_REGEX.test(val);

export function clearProfilePicCache(req: express.Request, username: string) {
  if (!(req as any)?.res || !username) return;
  if ((req as any).cookies?.profile_image_user && (req as any).cookies.profile_image_user !== username) return;
  (req as any).res.clearCookie("profile_image_url", cachedClearCookieOptions);
  (req as any).res.clearCookie("profile_image_user", cachedClearCookieOptions);
}

export async function fetchActiveSession(session_id: string) {
  if (!session_id || typeof session_id !== "string") return null;
  const row = await authRepository.fetchActiveSession(session_id);
  if (!row || (row.expires_at && new Date(row.expires_at) <= new Date()) || !row.is_active) return null;
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

    await authRepository.deleteSessionBySid(req.sessionID);
    await new Promise<void>((resolve, reject) => (req as any).session.regenerate((err: any) => (err ? reject(err) : resolve())));

    const configuredMax = parseInt(String(mbkautheVar.MAX_SESSIONS_PER_USER), 10);
    const MAX_SESSIONS = Number.isInteger(configuredMax) && configuredMax > 0 ? configuredMax : 5;
    const expiresAt = new Date(Date.now() + (cachedCookieOptions.maxAge || 0));
    const meta = JSON.stringify({ ip: req.ip, ua: req.headers["user-agent"] || null });

    const inserted = await authRepository.createAppSessionWithPruning({
      username,
      expiresAt,
      meta,
      maxSessions: MAX_SESSIONS,
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
    };

    clearProfilePicCache(req, username);

    if ((req as any).session.pre_auth_user) delete (req as any).session.pre_auth_user;

    await attachSessionPermissions((req as any).session.user, username, user.role);

    (req as any).session.save(async (saveErr: any) => {
      if (saveErr) {
        console.error(`[mbkauthe] Session save error:`, saveErr);
        return res.status(500).json({ success: false, message: "Internal Server Error" });
      }

      const encryptedSessionId = encryptSessionId(dbSessionId);
      if (encryptedSessionId) res.cookie("session_id", encryptedSessionId, cachedCookieOptions);

      res.cookie("full_name", (req as any).session.user.full_name || username, { ...cachedCookieOptions, httpOnly: false });

      if (typeof method === "string") {
        try { res.cookie("last_login_method", method, { ...cachedCookieOptions, httpOnly: false }); } catch {}
      }

      upsertAccountListCookie(req, res, {
        session_id: dbSessionId,
        username,
        full_name: (req as any).session.user.full_name || username,
        image: userImage || null,
      });

      (req as any).session.pre_auth_user = null;

      logAuth(`User "${username}" logged in successfully via ${method || "password"} (last_login updated)`);

      const responsePayload: Record<string, any> = { success: true, message: "Login successful", username };
      if (redirect_url) responsePayload.redirect_url = redirect_url;
      res.status(200).json(responsePayload);
    });
  } catch (err) {
    console.error(`[mbkauthe] Error during login completion:`, err);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
}
