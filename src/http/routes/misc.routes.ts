import express from "express";
import rateLimit from "express-rate-limit";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
import { mbkautheVar, packageJson, appVersion } from "../../config/index.js";
import { renderError, renderPage } from "../response/formatters.js";
import { authenticate, sessPerm, sessRole } from "../middleware/authMiddleware.js";
import { ErrorCodes, ErrorMessages, createErrorResponse } from "../../core/errors/catalog.js";
import { decryptSessionId, getCookieDomain, clearSessionCookies } from "../../config/cookies.js";
import { authRepository } from "../../db/repositories/AuthRepository.js";
import { isSafeFetchUrl } from "../utils/urlSafety.js";
import { createLogger } from "../../utils/logger.js";
import { getAuthHealthReport } from "../../diagnostics/index.js";
import { ensureSession } from "../middleware/security.js";
import { avatarService } from "../../services/AvatarService.js";

dotenv.config();

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const router = express.Router();
const logMisc = createLogger("misc");

const LATEST_VERSION_CACHE_TTL_MS = 10 * 60 * 1000;
const LATEST_VERSION_FAILURE_CACHE_TTL_MS = 60 * 1000;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const isUuid = (val: unknown): val is string => typeof val === "string" && UUID_RE.test(val);

const latestVersionCache: { value: string | null; expiresAt: number; pending: Promise<string | null> | null } = {
  value: null,
  expiresAt: 0,
  pending: null,
};

const LoginLimit = rateLimit({
  windowMs: 60 * 1000,
  max: 8,
  message: { success: false, message: "Too many attempts, please try again later" } as any,
  skip: (req) => Boolean((req as any).session?.user),
  validate: { trustProxy: false, xForwardedForHeader: false },
});

const AdminOperationLimit = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 3,
  message: { success: false, message: "Too many admin operations, please try again later" } as any,
  validate: { trustProxy: false, xForwardedForHeader: false },
});

let mainJsSource: string | null = null;
const getMainJsSource = () => (mainJsSource ??= fs.readFileSync(path.join(__dirname, "..", "..", "..", "public", "main.js"), "utf8"));

router.get("/main.js", (req, res) => {
  const clientConfig = JSON.stringify({
    cookieDomain: getCookieDomain() || null,
    domain: mbkautheVar.DOMAIN,
    isDeployed: mbkautheVar.IS_DEPLOYED === "true",
  });
  res.setHeader("Cache-Control", "public, max-age=31536000");
  res.type("application/javascript").send(`window.mbkautheConfig=${clientConfig};\n${getMainJsSource()}`);
});

router.get("/main.css", (req, res) => {
  res.setHeader("Cache-Control", "public, max-age=31536000");
  res.sendFile(path.join(__dirname, "..", "..", "..", "public", "main.css"));
});

router.get("/bg.webp", (req, res) => {
  res.setHeader("Content-Type", "image/webp");
  res.setHeader("Cache-Control", "public, max-age=31536000");
  fs.createReadStream(path.join(__dirname, "..", "..", "..", "public", "bg.webp"))
    .on("error", () => res.status(404).send("Image not found"))
    .pipe(res);
});

const AVATAR_USERNAME_REGEX = /^[a-zA-Z0-9_.-]{1,64}$/;

router.get("/avatar/:username", async (req, res) => {
  const rawParam = req.params.username;
  let targetUsername: string | null = null;
  let isMe = false;

  if (rawParam === "me") {
    isMe = true;
    const sessionUser = (req as any).session?.user || (req as any).auth?.user;
    targetUsername = sessionUser?.username ? sessionUser.username.trim().toLowerCase() : null;
  } else if (typeof rawParam === "string" && AVATAR_USERNAME_REGEX.test(rawParam.trim())) {
    targetUsername = rawParam.trim().toLowerCase();
  }

  // If "me" was requested without an active session, or invalid username provided
  if (!targetUsername) {
    const result = await avatarService.getAvatarImage("default");
    res.setHeader("Content-Type", result.contentType);
    res.setHeader("Cache-Control", isMe ? "private, no-cache" : "public, max-age=300, stale-while-revalidate=86400");
    if (result.etag) res.setHeader("ETag", result.etag);
    if (req.headers["if-none-match"] === result.etag) {
      return res.status(304).end();
    }
    return res.status(200).send(result.buffer);
  }

  // If logged-in session user matches the target and has image, prime cache
  const sessionUser = (req as any).session?.user || (req as any).auth?.user;
  if (sessionUser?.username?.toLowerCase() === targetUsername && sessionUser.image) {
    avatarService.warmCache(targetUsername, sessionUser.image);
  }

  try {
    const meta = await avatarService.getAvatarMetadata(targetUsername);

    // Fast-path 304 response on ETag match
    if (req.headers["if-none-match"] === meta.etag) {
      res.setHeader("ETag", meta.etag);
      res.setHeader("Cache-Control", "public, max-age=300, stale-while-revalidate=86400");
      return res.status(304).end();
    }

    const result = await avatarService.getAvatarImage(targetUsername, meta);
    res.setHeader("Content-Type", result.contentType);
    res.setHeader("Cache-Control", "public, max-age=300, stale-while-revalidate=86400");
    res.setHeader("ETag", result.etag);
    return res.status(200).send(result.buffer);
  } catch (err) {
    console.warn(`[mbkauthe] Error serving avatar for ${targetUsername}:`, err);
    const result = await avatarService.getAvatarImage("default");
    res.setHeader("Content-Type", result.contentType);
    res.setHeader("Cache-Control", "public, max-age=60");
    return res.status(200).send(result.buffer);
  }
});

if (process.env.env === "dev") {
  router.get(["/validate-superadmin"], sessRole("superadmin"), LoginLimit, async (req, res) => {
    try {
      const user = (req as any).session?.user || null;
      return res.json({
        success: true,
        message: "superadmin access granted",
        user: user ? { user_id: user.user_id, username: user.username, role: user.role, session_id: user.session_id } : null,
      });
    } catch {
      return res.status(500).json(createErrorResponse(500, ErrorCodes.INTERNAL_SERVER_ERROR));
    }
  });
}

const buildTestViewData = (req: express.Request) => {
  const user = (req as any).session?.user || (req as any).user || (req as any).authContext?.principal || {};
  const { username, full_name, role, user_id, session_id, allowed_apps, permissions } = user;
  const session_expiry = (req as any).session?.cookie?.expires ? new Date((req as any).session.cookie.expires).toISOString() : null;

  const authContext = (req as any).authContext;
  const authMethod = authContext?.authMethod || (req.headers.authorization ? "api-token" : "session");
  const loginMethod = (req as any).cookies?.last_login_method || "password";

  let auth_type_label = "Session (Cookie)";
  let auth_type_icon = "fa-cookie-bite";
  if (authMethod === "api-token") {
    auth_type_label = "API Token (PAT)";
    auth_type_icon = "fa-key";
  } else if (authMethod === "passkey" || loginMethod === "passkey") {
    auth_type_label = "Passkey (WebAuthn)";
    auth_type_icon = "fa-fingerprint";
  } else if (authMethod === "oauth" || ["github", "google", "discord", "microsoft"].includes(loginMethod)) {
    auth_type_label = `OAuth (${loginMethod})`;
    auth_type_icon = "fa-brands fa-" + (loginMethod === "microsoft" ? "windows" : loginMethod);
  }

  return {
    username,
    full_name: full_name || "N/A",
    role,
    user_id: user_id || "N/A",
    session_id,
    session_id_short: session_id ? session_id.slice(0, 8) : "",
    profile_pic_url: encodeURIComponent(username),
    display_name: full_name || username,
    initial: (full_name && full_name[0]) || (username && username[0]) || "U",
    allowed_apps: Array.isArray(allowed_apps) ? allowed_apps.join(", ") : (allowed_apps || "N/A"),
    session_expiry,
    permissions,
    auth_type: authMethod,
    auth_type_label,
    auth_type_icon,
    login_method: loginMethod,
  };
};

router.get(["/test", "/"], sessPerm("basic.access"), LoginLimit, async (req, res) => {
  return renderPage(req, res, "pages/test.handlebars", false, buildTestViewData(req));
});

router.get("/test.json", sessPerm("basic.access"), LoginLimit, async (req, res) => {
  return res.json(buildTestViewData(req));
});

router.post("/test", sessPerm("basic.access"), LoginLimit, async (req, res) => {
  const user = (req as any).session?.user || (req as any).user || (req as any).authContext?.principal;
  if (user) return res.json({ success: true, message: "You are logged in" });
  return res.status(401).json({ success: false, message: "Authentication required" });
});

router.get("/api/checkSession", ensureSession, LoginLimit, async (req, res) => {
  try {
    if (!(req as any).session?.user?.session_id) {
      (req as any).session?.destroy?.(() => {});
      clearSessionCookies(res);
      return res.status(200).json({ session_valid: false, expiry: null });
    }

    const row = await authRepository.getSessionValidity((req as any).session.user.session_id, req.sessionID, "check-session-validity");
    if (!row || (row.expires_at && new Date(row.expires_at) <= new Date()) || !row.is_active) {
      (req as any).session.destroy(() => {});
      clearSessionCookies(res);
      return res.status(200).json({ session_valid: false, expiry: null });
    }

    const expiry_source = row.expires_at || row.connect_expire || null;
    return res.status(200).json({ session_valid: true, expiry: expiry_source ? new Date(expiry_source).toISOString() : null });
  } catch (err) {
    console.error(`[mbkauthe] checkSession error:`, err);
    return res.status(200).json({ session_valid: false, expiry: null });
  }
});

function normalizeSessionIdFromBody(body: any = {}) {
  const raw_session_id = body.session_id;
  const is_encrypt = body.is_encrypt;
  if (!raw_session_id) return { session_id: null, error: "MISSING" };
  if (!(is_encrypt === true || is_encrypt === "true")) {
    return { session_id: raw_session_id, error: null };
  }

  let to_decrypt = String(raw_session_id);
  try { to_decrypt = decodeURIComponent(to_decrypt); } catch {}
  const decrypted = decryptSessionId(to_decrypt);
  return decrypted && isUuid(decrypted) ? { session_id: decrypted, error: null } : { session_id: null, error: "INVALID" };
}

const isSessionRowValid = (row: any) => Boolean(row && !((row.expires_at && new Date(row.expires_at) <= new Date()) || !row.is_active));

router.post("/api/checkSession", LoginLimit, async (req, res) => {
  try {
    const { session_id, error } = normalizeSessionIdFromBody(req.body || {});
    if (error === "MISSING") return res.status(400).json(createErrorResponse(400, ErrorCodes.MISSING_REQUIRED_FIELD));
    if (error === "INVALID" || !session_id || !isUuid(session_id)) return res.status(400).json(createErrorResponse(400, ErrorCodes.SESSION_INVALID));

    const row = await authRepository.getSessionValidationRow(session_id, "check-session-validity-by-id");
    if (!isSessionRowValid(row)) return res.status(200).json({ session_valid: false, expiry: null });

    return res.status(200).json({ session_valid: true, expiry: row.expires_at ? new Date(row.expires_at).toISOString() : null });
  } catch (err) {
    console.error(`[mbkauthe] checkSession (body) error:`, err);
    return res.status(200).json({ session_valid: false, expiry: null });
  }
});

router.post("/api/verifySession", LoginLimit, async (req, res) => {
  try {
    const { session_id, error } = normalizeSessionIdFromBody(req.body || {});
    if (error === "MISSING") return res.status(400).json(createErrorResponse(400, ErrorCodes.MISSING_REQUIRED_FIELD));
    if (error === "INVALID" || !session_id || !isUuid(session_id)) return res.status(400).json(createErrorResponse(400, ErrorCodes.SESSION_INVALID));

    const row = await authRepository.getSessionValidationRow(session_id, "verify-session");
    if (!isSessionRowValid(row)) return res.status(200).json({ valid: false, expiry: null });

    return res.status(200).json({ valid: true, expiry: row.expires_at ? new Date(row.expires_at).toISOString() : null });
  } catch (err) {
    console.error(`[mbkauthe] verifySession error:`, err);
    return res.status(200).json({ valid: false, expiry: null });
  }
});

router.get("/ErrorCode", ensureSession, (req, res) => {
  try {
    const getErrorName = (code: number) => Object.keys(ErrorCodes).find((key) => (ErrorCodes as any)[key] === code) || "UNKNOWN_ERROR";
    const errorCategories = [
      { name: "Authentication Errors", icon: "🔑", range: "(600-699)", category: "authentication", codes: [601, 602, 603, 604, 605] },
      { name: "Two-Factor Authentication Errors", icon: "📱", range: "(700-799)", category: "2fa", codes: [701, 702, 703, 704] },
      { name: "Session Management Errors", icon: "🔄", range: "(800-899)", category: "session", codes: [801, 802, 803] },
      { name: "Authorization Errors", icon: "🛡️", range: "(900-999)", category: "authorization", codes: [901, 902] },
      { name: "Input Validation Errors", icon: "✏️", range: "(1000-1099)", category: "validation", codes: [1001, 1002, 1003, 1004, 1005, 1006, 1007] },
      { name: "Rate Limiting Errors", icon: "⏱️", range: "(1100-1199)", category: "ratelimit", codes: [1101] },
      { name: "Server Errors", icon: "⚠️", range: "(1200-1299)", category: "server", codes: [1201, 1202, 1203] },
      { name: "OAuth Errors", icon: "🔗", range: "(1300-1399)", category: "oauth", codes: [1301, 1302, 1303] },
    ];

    const categoriesWithErrors = errorCategories
      .map((cat) => ({ ...cat, errors: cat.codes.filter((code) => ErrorMessages[code]).map((code) => ({ code, name: getErrorName(code), ...ErrorMessages[code] })) }))
      .filter((cat) => cat.errors.length > 0);

    const totalErrors = categoriesWithErrors.reduce((acc, cat) => acc + cat.errors.length, 0);

    return renderPage(req, res, "pages/errorCodes.handlebars", false, {
      pageTitle: "Error Codes",
      appName: mbkautheVar.APP_NAME,
      errorCategories: categoriesWithErrors,
      totalErrors,
      totalCategories: categoriesWithErrors.length,
    });
  } catch (err) {
    console.error(`[mbkauthe] Error rendering error codes page:`, err);
    return renderError(res, req, { code: 500, error: "Internal Server Error", message: "Could not load error codes page.", pagename: "Error Codes", page: "/mbkauthe/info" });
  }
});

export async function getLatestVersion({ forceRefresh = false }: { forceRefresh?: boolean } = {}): Promise<string | null> {
  const now = Date.now();
  if (!forceRefresh && latestVersionCache.expiresAt > now) return latestVersionCache.value;
  if (!forceRefresh && latestVersionCache.pending) return latestVersionCache.pending;

  latestVersionCache.pending = (async () => {
    try {
      const response = await fetch("https://raw.githubusercontent.com/MIbnEKhalid/mbkauthe/main/package.json");
      if (!response.ok) {
        latestVersionCache.value = null;
        latestVersionCache.expiresAt = Date.now() + LATEST_VERSION_FAILURE_CACHE_TTL_MS;
        return null;
      }
      const latestPackageJson: any = await response.json();
      const latestVersion = typeof latestPackageJson.version === "string" ? latestPackageJson.version : null;
      latestVersionCache.value = latestVersion;
      latestVersionCache.expiresAt = Date.now() + LATEST_VERSION_CACHE_TTL_MS;
      return latestVersion;
    } catch {
      latestVersionCache.value = null;
      latestVersionCache.expiresAt = Date.now() + LATEST_VERSION_FAILURE_CACHE_TTL_MS;
      return null;
    } finally {
      latestVersionCache.pending = null;
    }
  })();

  return latestVersionCache.pending;
}

export async function checkVersion(): Promise<void> {
  try {
    const latestVersion = await getLatestVersion();
    const hasValidLatest = typeof latestVersion === "string" && /^\d+\.\d+\.\d+/.test(latestVersion);
    if (hasValidLatest && latestVersion !== packageJson.version) {
      console.warn(`[mbkauthe] Current version (${packageJson.version}) is outdated. Latest version: ${latestVersion}. Consider updating mbkauthe.`);
    } else if (hasValidLatest) {
      logMisc(`Running latest version (${packageJson.version}).`);
    }
  } catch (error: any) {
    console.warn(`[mbkauthe] Failed to check for updates: ${error.message}`);
  }
}

const { APP_NAME, DOMAIN, IS_DEPLOYED } = mbkautheVar;
const loginRedirectUrl = mbkautheVar.LOGIN_REDIRECT_URL || "/dashboard";
const safe_mbkautheVar = { APP_NAME, DOMAIN, IS_DEPLOYED, login_redirect_url: loginRedirectUrl };

router.get(["/info", "/i"], ensureSession, LoginLimit, async (req, res) => {
  let latestVersion: string | null = null;
  try { latestVersion = await getLatestVersion(); } catch {}
  try {
    renderPage(req, res, "pages/info_mbkauthe.handlebars", false, {
      mbkautheVar: safe_mbkautheVar,
      CurrentVersion: packageJson.version,
      APP_VERSION: appVersion,
      latestVersion,
    });
  } catch {
    res.status(500).send(`<html><head><title>Error</title></head><body><h1>Error</h1><p>Failed to fetch version information. Please try again later.</p></body></html>`);
  }
});

router.get(["/info.json", "/i.json"], LoginLimit, async (req, res) => {
  let latestVersion: string | null = null;
  try { latestVersion = await getLatestVersion(); } catch {}
  try {
    res.json({ mbkautheVar: safe_mbkautheVar, CurrentVersion: packageJson.version, APP_VERSION: appVersion, latestVersion });
  } catch {
    res.status(500).json({ success: false, message: "Failed to fetch version information" });
  }
});

router.get(["/api/health", "/health", "/health.json", "/api/health.json"], async (req, res) => {
  try {
    const report = await getAuthHealthReport();
    const isOk = report.status === "healthy" || report.status === "degraded";
    return res.status(isOk ? 200 : 503).json({
      success: report.status !== "unhealthy",
      ...report,
    });
  } catch (err: any) {
    return res.status(503).json({
      success: false,
      status: "unhealthy",
      error: err?.message || String(err),
      timestamp: new Date().toISOString(),
    });
  }
});

router.post("/api/terminateAllSessions", AdminOperationLimit, authenticate(mbkautheVar.MAIN_SECRET_TOKEN), async (req, res) => {
  try {
    await Promise.all([
      authRepository.deleteAllAppSessions("terminate-all-app-sessions"),
      authRepository.deleteActiveSessionStoreRows("terminate-all-db-sessions"),
    ]);

    if (typeof (req as any).session?.destroy === "function") {
      (req as any).session.destroy((err: any) => {
        if (err) return res.status(500).json({ success: false, message: "Failed to terminate sessions" });
        clearSessionCookies(res);
        logMisc(`All sessions terminated successfully`);
        res.status(200).json({ success: true, message: "All sessions terminated successfully" });
      });
    } else {
      clearSessionCookies(res);
      logMisc(`All sessions terminated successfully`);
      res.status(200).json({ success: true, message: "All sessions terminated successfully" });
    }
  } catch (err) {
    console.error(`[mbkauthe] Database query error during session termination:`, err);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});

export const miscRouter = router;
export default router;
