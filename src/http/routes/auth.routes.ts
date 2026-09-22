import express from "express";
import csurf from "csurf";
import speakeasy from "speakeasy";
import rateLimit from "express-rate-limit";
import { mbkautheVar, isProductionEnvironment, packageJson } from "../../config/index.js";
import { verifyPassword } from "../../core/security/password.js";
import { getCookieOptions, getCookieDomain, clearSessionCookies, getOrCreateDeviceId, setActiveSessionCookie } from "../../config/cookies.js";
import { ErrorCodes, createErrorResponse, logError } from "../../core/errors/catalog.js";
import { MbkAuthError } from "../../core/errors/MbkAuthError.js";
import { isLocalOnlyUser } from "../../core/types/user.types.js";
import { authRepository } from "../../db/repositories/AuthRepository.js";
import { authService } from "../../services/AuthService.js";
import { passkeyService } from "../../services/PasskeyService.js";
import { attachSessionPermissions } from "../session/sessionPermissions.js";
import { completeLoginProcess, invalidateAvatarCache, fetchActiveSession, invalidateDbSession, isUuid } from "../session/authFlow.js";
import { createLogger } from "../../utils/logger.js";
import { isOAuthProviderConfigured, getEnabledOAuthProvidersUI } from "../../oauth/providers/loader.js";
import { ensureSession } from "../middleware/security.js";
import { renderPage } from "../response/formatters.js";

const router = express.Router();

const authSessionPaths = [
  "/api/passkey",
  "/api/login",
  "/2fa",
  "/api/verify-2fa",
  "/api/logout",
  "/api/accounts",
  "/api/accounts/switch",
  "/api/accounts/logout",
  "/api/accounts/logout-all",
  "/api/account-sessions",
  "/api/logout-account",
  "/api/switch-session",
  "/api/logout-all",
  "/login",
  "/accounts",
];
router.use(authSessionPaths, ensureSession);

const logAuth = createLogger("auth");
const csrfProtection = csurf({ cookie: true });

export { completeLoginProcess };

const LoginLimit = rateLimit({
  windowMs: 60 * 1000,
  max: 8,
  message: { success: false, message: "Too many attempts, please try again later" } as any,
  skip: (req) => Boolean((req as any).session?.user),
  validate: { trustProxy: false, xForwardedForHeader: false },
});

const LogoutLimit = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { success: false, message: "Too many logout attempts, please try again later" } as any,
  validate: { trustProxy: false, xForwardedForHeader: false },
});

const TwoFALimit = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  message: { success: false, message: "Too many 2FA attempts, please try again later" } as any,
  validate: { trustProxy: false, xForwardedForHeader: false },
});

// ============================================
// Passkey Public / Authentication Endpoints
// ============================================

router.post("/api/passkey/login-options", LoginLimit, async (req, res) => {
  try {
    const { username } = req.body || {};
    const trimmedUsername = typeof username === "string" && username.trim() ? username.trim() : undefined;
    const reqHostname = req.hostname || (req.headers.host ? req.headers.host.split(":")[0] : undefined);
    const options = await passkeyService.generateAuthenticationOptions(trimmedUsername, reqHostname);
    (req as any).session.current_webauthn_challenge = options.challenge;
    return res.json({ success: true, options });
  } catch (err: any) {
    logAuth("Error generating passkey login options: %O", err);
    return res.status(500).json(createErrorResponse(500, ErrorCodes.INTERNAL_SERVER_ERROR, { message: "Failed to generate passkey login options" }));
  }
});

router.post("/api/passkey/login-verify", LoginLimit, async (req, res) => {
  const { response, redirect } = req.body || {};
  const expectedChallenge = (req as any).session?.current_webauthn_challenge;

  if (!response || !response.id) {
    return res.status(400).json(createErrorResponse(400, ErrorCodes.MISSING_REQUIRED_FIELD, { message: "Passkey response is required" }));
  }

  if (!expectedChallenge) {
    return res.status(400).json(createErrorResponse(400, ErrorCodes.SESSION_EXPIRED, { message: "WebAuthn challenge expired or not found. Please try again." }));
  }

  try {
    const origin = (req.headers.origin as string) || (req.headers.host ? `${req.protocol}://${req.headers.host}` : undefined);
    const reqHostname = req.hostname || (req.headers.host ? req.headers.host.split(":")[0] : undefined);
    const result = await passkeyService.verifyAuthentication(response, expectedChallenge, origin, {
      ip: req.ip,
      userAgent: req.headers["user-agent"],
      appKey: mbkautheVar.APP_NAME,
      reqHostname,
    });

    delete (req as any).session.current_webauthn_challenge;

    const requested_redirect = typeof redirect === "string" && redirect.startsWith("/") && !redirect.startsWith("//") ? redirect : null;
    const user = result.user;
    const isLocalOnly = isLocalOnlyUser(user.is_local_only);
    const user_for_session = {
      user_id: user.user_id || undefined,
      username: user.username,
      role: user.role,
      allowed_apps: user.allowed_apps,
      full_name: user.full_name,
      image: user.image,
      is_local_only: isLocalOnly,
    };

    return completeLoginProcess(req, res, user_for_session, requested_redirect, "passkey");
  } catch (err: any) {
    logAuth("Error during passkey authentication verification: %O", err);
    if (err instanceof MbkAuthError) {
      return res.status(err.statusCode).json(createErrorResponse(err.statusCode, err.errorCode, { message: err.message }));
    }
    return res.status(500).json(createErrorResponse(500, ErrorCodes.INTERNAL_SERVER_ERROR, { message: "Passkey verification failed" }));
  }
});

// ============================================
// Passkey Authenticated / Registration Endpoints
// ============================================

router.post("/api/passkey/register-options", async (req, res) => {
  const user = (req as any).session?.user;
  if (!user || !user.username) {
    return res.status(401).json(createErrorResponse(401, ErrorCodes.SESSION_NOT_FOUND, { message: "Authentication required" }));
  }

  try {
    const reqHostname = req.hostname || (req.headers.host ? req.headers.host.split(":")[0] : undefined);
    const options = await passkeyService.generateRegistrationOptions(user.username, user.full_name, reqHostname);
    (req as any).session.current_webauthn_challenge = options.challenge;
    return res.json({ success: true, options });
  } catch (err: any) {
    logAuth("Error generating passkey registration options: %O", err);
    return res.status(500).json(createErrorResponse(500, ErrorCodes.INTERNAL_SERVER_ERROR, { message: "Failed to generate passkey registration options" }));
  }
});

router.post("/api/passkey/register-verify", async (req, res) => {
  const user = (req as any).session?.user;
  if (!user || !user.username) {
    return res.status(401).json(createErrorResponse(401, ErrorCodes.SESSION_NOT_FOUND, { message: "Authentication required" }));
  }

  const { response, name } = req.body || {};
  const expectedChallenge = (req as any).session?.current_webauthn_challenge;

  if (!response || !response.id) {
    return res.status(400).json(createErrorResponse(400, ErrorCodes.MISSING_REQUIRED_FIELD, { message: "Passkey registration response is required" }));
  }

  if (!expectedChallenge) {
    return res.status(400).json(createErrorResponse(400, ErrorCodes.SESSION_EXPIRED, { message: "Registration challenge expired or missing" }));
  }

  try {
    const origin = (req.headers.origin as string) || (req.headers.host ? `${req.protocol}://${req.headers.host}` : undefined);
    const reqHostname = req.hostname || (req.headers.host ? req.headers.host.split(":")[0] : undefined);
    const result = await passkeyService.verifyRegistration(user.username, response, expectedChallenge, name, origin, reqHostname);
    delete (req as any).session.current_webauthn_challenge;
    return res.json({ success: true, message: "Passkey registered successfully", passkeyId: result.passkeyId });
  } catch (err: any) {
    logAuth("Error during passkey registration verification: %O", err);
    if (err instanceof MbkAuthError) {
      return res.status(err.statusCode).json(createErrorResponse(err.statusCode, err.errorCode, { message: err.message }));
    }
    return res.status(500).json(createErrorResponse(500, ErrorCodes.INTERNAL_SERVER_ERROR, { message: err?.message || "Failed to verify passkey registration" }));
  }
});

router.get("/api/passkey/list", async (req, res) => {
  const user = (req as any).session?.user;
  if (!user || !user.username) {
    return res.status(401).json(createErrorResponse(401, ErrorCodes.SESSION_NOT_FOUND, { message: "Authentication required" }));
  }

  try {
    const passkeys = await passkeyService.listUserPasskeys(user.username);
    return res.json({ success: true, passkeys });
  } catch (err: any) {
    logAuth("Error listing user passkeys: %O", err);
    return res.status(500).json(createErrorResponse(500, ErrorCodes.INTERNAL_SERVER_ERROR));
  }
});

router.patch("/api/passkey/:id", async (req, res) => {
  const user = (req as any).session?.user;
  if (!user || !user.username) {
    return res.status(401).json(createErrorResponse(401, ErrorCodes.SESSION_NOT_FOUND, { message: "Authentication required" }));
  }

  const { name } = req.body || {};
  try {
    const updated = await passkeyService.renamePasskey(req.params.id, user.username, name);
    if (!updated) return res.status(404).json(createErrorResponse(404, ErrorCodes.RESOURCE_NOT_FOUND, { message: "Passkey not found" }));
    return res.json({ success: true, message: "Passkey renamed successfully" });
  } catch (err: any) {
    logAuth("Error renaming passkey: %O", err);
    if (err instanceof MbkAuthError) {
      return res.status(err.statusCode).json(createErrorResponse(err.statusCode, err.errorCode, { message: err.message }));
    }
    return res.status(500).json(createErrorResponse(500, ErrorCodes.INTERNAL_SERVER_ERROR));
  }
});

router.delete("/api/passkey/:id", async (req, res) => {
  const user = (req as any).session?.user;
  if (!user || !user.username) {
    return res.status(401).json(createErrorResponse(401, ErrorCodes.SESSION_NOT_FOUND, { message: "Authentication required" }));
  }

  try {
    const deleted = await passkeyService.deletePasskey(req.params.id, user.username);
    if (!deleted) return res.status(404).json(createErrorResponse(404, ErrorCodes.RESOURCE_NOT_FOUND, { message: "Passkey not found" }));
    return res.json({ success: true, message: "Passkey deleted successfully" });
  } catch (err: any) {
    logAuth("Error deleting passkey: %O", err);
    return res.status(500).json(createErrorResponse(500, ErrorCodes.INTERNAL_SERVER_ERROR));
  }
});

// ============================================
// Password Login & 2FA
// ============================================

router.post("/api/login", LoginLimit, async (req, res) => {
  logAuth(`Login request received`);
  const { username, password, redirect } = req.body || {};

  if (!username || !password) {
    logError("Login attempt", ErrorCodes.MISSING_REQUIRED_FIELD, { username: username || "missing" });
    return res.status(400).json(createErrorResponse(400, ErrorCodes.MISSING_REQUIRED_FIELD, { message: "Username and password are required" }));
  }

  if (typeof username !== "string" || username.trim().length === 0 || username.length > 255) {
    logError("Login attempt", ErrorCodes.INVALID_USERNAME_FORMAT, { username });
    return res.status(400).json(createErrorResponse(400, ErrorCodes.INVALID_USERNAME_FORMAT));
  }

  if (typeof password !== "string" || password.length < 8 || password.length > 255) {
    logError("Login attempt", ErrorCodes.INVALID_PASSWORD_LENGTH, { username: username.trim() });
    return res.status(400).json(createErrorResponse(400, ErrorCodes.INVALID_PASSWORD_LENGTH));
  }

  const trimmedUsername = username.trim();
  logAuth(`Login attempt for username: ${trimmedUsername}`);

  try {
    const user = await authRepository.getUserWithTwoFA(trimmedUsername);
    if (!user) {
      logError("Login attempt", ErrorCodes.USER_NOT_FOUND, { username: trimmedUsername });
      return res.status(401).json(createErrorResponse(401, ErrorCodes.INVALID_CREDENTIALS));
    }

    const { password_hash, username: auth_username, is_active, is_local_only, role, allowed_apps, user_id, is_enabled, full_name, image } = user;
    const password_matches = password_hash ? await verifyPassword(password, auth_username, password_hash) : false;

    if (!password_matches) {
      logError("Login attempt", ErrorCodes.INCORRECT_PASSWORD, { username: trimmedUsername });
      return res.status(401).json(createErrorResponse(401, ErrorCodes.INCORRECT_PASSWORD));
    }

    if (!is_active) {
      logError("Login attempt", ErrorCodes.ACCOUNT_INACTIVE, { username: trimmedUsername });
      return res.status(403).json(createErrorResponse(403, ErrorCodes.ACCOUNT_INACTIVE));
    }

    const isLocalOnly = isLocalOnlyUser(is_local_only);
    if (isLocalOnly && isProductionEnvironment()) {
      logError("Login attempt", ErrorCodes.LOCAL_USER_PROD_RESTRICTED, { username: trimmedUsername });
      return res.status(403).json(createErrorResponse(403, ErrorCodes.LOCAL_USER_PROD_RESTRICTED));
    }

    if (role !== "superadmin") {
      if (!Array.isArray(allowed_apps) || !allowed_apps.some((app: any) => app?.toLowerCase() === mbkautheVar.APP_NAME)) {
        logError("Login attempt", ErrorCodes.APP_NOT_AUTHORIZED, { username: auth_username, app: mbkautheVar.APP_NAME });
        return res.status(403).json(createErrorResponse(403, ErrorCodes.APP_NOT_AUTHORIZED, {
          message: `You are not authorized to access ${mbkautheVar.APP_NAME}`,
          app: mbkautheVar.APP_NAME,
        }));
      }
    }

    const is_2fa_enabled = String(mbkautheVar.MBKAUTH_TWO_FA_ENABLE || "").toLowerCase() === "true" && Boolean(is_enabled);
    const requested_redirect = typeof redirect === "string" && redirect.startsWith("/") && !redirect.startsWith("//") ? redirect : null;
    const user_for_session = { user_id: user_id || undefined, username: auth_username, role, allowed_apps, full_name, image, is_local_only: isLocalOnly };

    if (is_2fa_enabled) {
      (req as any).session.pre_auth_user = { ...user_for_session, redirect_url: requested_redirect };
      logAuth(`2FA required for user: ${trimmedUsername}`);
      return res.json({ success: true, two_factor_required: true, redirect_url: requested_redirect });
    }

    return completeLoginProcess(req, res, user_for_session, requested_redirect, "password");
  } catch (err) {
    console.error(`[mbkauthe] Error during login process:`, err);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});

router.get("/2fa", csrfProtection, (req, res) => {
  if (!(req as any).session?.pre_auth_user) return res.redirect("/mbkauthe/login");

  let redirectToUse = (req as any).query?.redirect || (req as any).session.pre_auth_user.redirect_url || mbkautheVar.LOGIN_REDIRECT_URL || "/dashboard";
  if (!(typeof redirectToUse === "string" && redirectToUse.startsWith("/") && !redirectToUse.startsWith("//"))) {
    redirectToUse = mbkautheVar.LOGIN_REDIRECT_URL || "/dashboard";
  }

  return renderPage(req, res, "pages/2fa.handlebars", false, {
    customURL: redirectToUse,
    csrfToken: (req as any).csrfToken ? (req as any).csrfToken() : "",
    appName: mbkautheVar.APP_NAME,
    version: packageJson.version,
  });
});

router.post("/api/verify-2fa", TwoFALimit, csrfProtection, async (req, res) => {
  if (!(req as any).session?.pre_auth_user) {
    return res.status(401).json(createErrorResponse(401, ErrorCodes.SESSION_NOT_FOUND, { message: "Please log in first" }));
  }

  const { token } = req.body || {};
  const { username, role, user_id, allowed_apps, full_name, image } = (req as any).session.pre_auth_user;

  if (!token || typeof token !== "string") {
    return res.status(400).json(createErrorResponse(400, ErrorCodes.MISSING_REQUIRED_FIELD, { message: "2FA token is required" }));
  }

  const sanitized_token = token.trim();
  if (!/^\d{6}$/.test(sanitized_token)) {
    return res.status(400).json(createErrorResponse(400, ErrorCodes.INVALID_TOKEN_FORMAT));
  }

  try {
    const two_fa_record = await authRepository.getTwoFASecret(username);
    if (!two_fa_record?.two_fa_secret) {
      return res.status(500).json(createErrorResponse(500, ErrorCodes.TWO_FA_NOT_CONFIGURED));
    }

    const token_validates = speakeasy.totp.verify({
      secret: two_fa_record.two_fa_secret,
      encoding: "base32",
      token: sanitized_token,
      window: 1,
    });

    if (!token_validates) {
      logError("2FA verification", ErrorCodes.TWO_FA_INVALID_TOKEN, { username });
      return res.status(401).json(createErrorResponse(401, ErrorCodes.TWO_FA_INVALID_TOKEN));
    }

    let redirect_from_session = (req as any).session.pre_auth_user.redirect_url;
    if (!(typeof redirect_from_session === "string" && redirect_from_session.startsWith("/") && !redirect_from_session.startsWith("//"))) {
      redirect_from_session = null;
    }
    const redirect_url = redirect_from_session || mbkautheVar.LOGIN_REDIRECT_URL || "/dashboard";
    const method_to_use = (req as any).session.pre_auth_user.login_method || "password";

    delete (req as any).session.pre_auth_user;
    await completeLoginProcess(req, res, { user_id, username, role, allowed_apps, full_name, image }, redirect_url, method_to_use);
  } catch (err) {
    console.error(`[mbkauthe] Error during 2FA verification:`, err);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});

router.post("/api/logout", LogoutLimit, async (req, res) => {
  if (!(req as any).session?.user) return res.status(400).json({ success: false, message: "Not logged in" });

  try {
    const { username, session_id } = (req as any).session.user;
    invalidateAvatarCache(username);

    const operations = [];
    if (session_id) operations.push(authRepository.deleteAppSessionById(session_id, "logout-delete-app-session"));
    if (req.sessionID) operations.push(authRepository.deleteSessionBySid(req.sessionID, "logout-delete-session"));
    await Promise.all(operations);

    (req as any).session.destroy((err: any) => {
      if (err) {
        console.error(`[mbkauthe] Error destroying session:`, err);
        return res.status(500).json({ success: false, message: "Logout failed" });
      }
      clearSessionCookies(res);
      logAuth(`User "${username}" logged out successfully`);
      res.status(200).json({ success: true, message: "Logout successful" });
    });
  } catch (err) {
    console.error(`[mbkauthe] Database query error during logout:`, err);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});

router.get(["/api/accounts", "/api/account-sessions"], LoginLimit, async (req, res) => {
  const deviceId = getOrCreateDeviceId(req, res);
  const current_session_id = req.sessionID || (req as any).session?.user?.session_id || null;

  try {
    const sessionRows = await authRepository.findSessionsByDeviceId(deviceId);
    const validated = [];

    for (const row of sessionRows) {
      const expired = row.expires_at && new Date(row.expires_at) <= new Date();
      const isLocalOnly = isLocalOnlyUser(row.is_local_only);
      const authorized = Boolean(row.is_active && !(isLocalOnly && isProductionEnvironment()) && (
        row.role === "superadmin" ||
        (Array.isArray(row.allowed_apps) && row.allowed_apps.some((app: any) => app?.toLowerCase() === mbkautheVar.APP_NAME))
      ));

      if (expired || !authorized) {
        await invalidateDbSession(row.sid);
        continue;
      }

      let parsedMeta: any = {};
      if (typeof row.meta === "string") {
        try { parsedMeta = JSON.parse(row.meta); } catch {}
      } else if (row.meta && typeof row.meta === "object") {
        parsedMeta = row.meta;
      }

      validated.push({
        session_id: row.sid,
        username: row.username,
        full_name: row.full_name || row.username,
        image: row.image?.trim() ? row.image : null,
        role: row.role || "user",
        origin: parsedMeta.origin || null,
        last_activity: row.last_activity || null,
        expires_at: row.expires_at || null,
        is_current: Boolean(current_session_id && row.sid === current_session_id),
      });
    }

    return res.json({ accounts: validated, current_session_id });
  } catch (err) {
    console.error(`[mbkauthe] Error retrieving device accounts:`, err);
    return res.status(500).json(createErrorResponse(500, ErrorCodes.INTERNAL_SERVER_ERROR));
  }
});

router.post(["/api/accounts/logout", "/api/logout-account"], LoginLimit, async (req, res) => {
  const { session_id } = req.body || {};
  const target_session_id = session_id;

  if (!isUuid(target_session_id)) {
    return res.status(400).json(createErrorResponse(400, ErrorCodes.INVALID_TOKEN_FORMAT, { message: "Invalid session id" }));
  }

  const deviceId = getOrCreateDeviceId(req, res);

  try {
    const deleted = await authRepository.deleteDeviceSession(deviceId, target_session_id);
    if (!deleted) {
      return res.status(403).json(createErrorResponse(403, ErrorCodes.SESSION_NOT_FOUND, { message: "Account not available on this device" }));
    }

    const isCurrent = req.sessionID === target_session_id || (req as any).session?.user?.session_id === target_session_id;
    if (isCurrent) {
      clearSessionCookies(res);
      (req as any).session?.destroy?.(() => {});
    }

    logAuth(`Device "${deviceId}" logged out session "${target_session_id}"`);
    return res.json({ success: true, message: "Account logged out successfully", is_current_logged_out: isCurrent });
  } catch (err) {
    console.error(`[mbkauthe] Error during single account logout:`, err);
    return res.status(500).json(createErrorResponse(500, ErrorCodes.INTERNAL_SERVER_ERROR));
  }
});

router.post(["/api/accounts/switch", "/api/switch-session"], LoginLimit, async (req, res) => {
  const { session_id, redirect } = req.body || {};
  const target_session_id = session_id;

  if (!isUuid(target_session_id)) {
    return res.status(400).json(createErrorResponse(400, ErrorCodes.INVALID_TOKEN_FORMAT, { message: "Invalid session id" }));
  }

  const deviceId = getOrCreateDeviceId(req, res);

  try {
    const targetSession = await authRepository.findDeviceSession(deviceId, target_session_id);
    if (!targetSession) {
      return res.status(403).json(createErrorResponse(403, ErrorCodes.SESSION_NOT_FOUND, { message: "Account not available on this device" }));
    }

    if (!targetSession.is_active) {
      return res.status(401).json(createErrorResponse(401, ErrorCodes.ACCOUNT_INACTIVE));
    }

    const isLocalOnly = isLocalOnlyUser(targetSession.is_local_only);
    if (isLocalOnly && isProductionEnvironment()) {
      return res.status(403).json(createErrorResponse(403, ErrorCodes.LOCAL_USER_PROD_RESTRICTED));
    }

    if (targetSession.role !== "superadmin") {
      const allowed = targetSession.allowed_apps;
      if (!Array.isArray(allowed) || !allowed.some((app: any) => app?.toLowerCase() === mbkautheVar.APP_NAME)) {
        return res.status(401).json(createErrorResponse(401, ErrorCodes.APP_NOT_AUTHORIZED));
      }
    }

    // Touch last activity on target session in database
    await authRepository.touchSessionActivity(targetSession.sid);

    // Set the active session cookie directly to targetSession.sid!
    setActiveSessionCookie(res, targetSession.sid);

    const fullName = targetSession.full_name || targetSession.username;
    res.cookie("full_name", fullName, { ...getCookieOptions(), httpOnly: false });

    logAuth(`Device "${deviceId}" switched active session to user "${targetSession.username}" (${targetSession.sid})`);

    const safe_redirect = typeof redirect === "string" && redirect.startsWith("/") && !redirect.startsWith("//")
      ? redirect
      : mbkautheVar.LOGIN_REDIRECT_URL || "/dashboard";

    return res.json({
      success: true,
      username: targetSession.username,
      full_name: fullName,
      redirect: safe_redirect,
      session_id: targetSession.sid,
    });
  } catch (err) {
    console.error(`[mbkauthe] Error during session switch:`, err);
    return res.status(500).json(createErrorResponse(500, ErrorCodes.INTERNAL_SERVER_ERROR));
  }
});

router.post(["/api/accounts/logout-all", "/api/logout-all"], LoginLimit, async (req, res) => {
  const deviceId = getOrCreateDeviceId(req, res);

  try {
    await authRepository.deleteAllDeviceSessions(deviceId);
    clearSessionCookies(res);
    (req as any).session?.destroy?.(() => {});

    logAuth(`Device "${deviceId}" logged out all sessions`);
    return res.json({ success: true, message: "All accounts logged out" });
  } catch (err) {
    console.error(`[mbkauthe] Error during logout-all:`, err);
    return res.status(500).json(createErrorResponse(500, ErrorCodes.INTERNAL_SERVER_ERROR));
  }
});

router.get("/login", LoginLimit, csrfProtection, (req, res) => {
  const lastLogin = typeof (req as any).cookies?.last_login_method === "string" ? (req as any).cookies.last_login_method : null;
  const oauthProviders = mbkautheVar.OAUTH_PROVIDERS || mbkautheVar.oauth_providers;
  const githubEnabled = isOAuthProviderConfigured("github", oauthProviders) ? "true" : "false";
  const googleEnabled = isOAuthProviderConfigured("google", oauthProviders) ? "true" : "false";
  const enabledOAuthProviders = getEnabledOAuthProvidersUI(oauthProviders, lastLogin);
  const isAddAccount = req.query.prompt === "add_account";

  return res.render("pages/loginmbkauthe.handlebars", {
    layout: false,
    githubLoginEnabled: githubEnabled,
    googleLoginEnabled: googleEnabled,
    enabledOAuthProviders,
    hasOAuthProviders: enabledOAuthProviders.length > 0,
    customURL: mbkautheVar.LOGIN_REDIRECT_URL || "/dashboard",
    cookieDomain: getCookieDomain() || "",
    userLoggedIn: isAddAccount ? false : Boolean((req as any).session?.user),
    username: isAddAccount ? "" : ((req as any).session?.user?.username || ""),
    isAddAccount,
    version: packageJson.version,
    appName: mbkautheVar.APP_NAME,
    csrfToken: (req as any).csrfToken ? (req as any).csrfToken() : "",
    lastLoginMethod: lastLogin,
    lastLoginPassword: lastLogin === "password",
    lastLoginGithub: lastLogin === "github",
    lastLoginGoogle: lastLogin === "google",
    showLoggedOutMessage: req.query.reason === "logged_out",
    redirectTarget: req.query.redirect || null,
  });
});

router.get("/accounts", LoginLimit, csrfProtection, (req, res) => {
  const redirectFromQuery = typeof req.query.redirect === "string" ? req.query.redirect : null;
  const safeRedirect = redirectFromQuery && redirectFromQuery.startsWith("/") && !redirectFromQuery.startsWith("//")
    ? redirectFromQuery
    : mbkautheVar.LOGIN_REDIRECT_URL || "/dashboard";

  return res.render("pages/accountSwitch.handlebars", {
    layout: false,
    customURL: safeRedirect,
    version: packageJson.version,
    appName: mbkautheVar.APP_NAME,
    csrfToken: (req as any).csrfToken ? (req as any).csrfToken() : "",
    userLoggedIn: Boolean((req as any).session?.user),
    username: (req as any).session?.user?.username,
    full_name: (req as any).session?.user?.full_name,
    role: (req as any).session?.user?.role,
  });
});

export const authRouter = router;
export default router;
