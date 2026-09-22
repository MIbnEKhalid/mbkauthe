import type { Request, Response, NextFunction } from "express";
import { mbkautheVar, isProductionEnvironment } from "../../config/env.js";
import { hashApiToken } from "../../config/security.js";
import { renderError } from "../response/formatters.js";
import { isJsonRequest } from "../response/contentNegotiation.js";
import { getCookieOptions, encryptSessionId, decryptSessionId, clearSessionCookies } from "../../config/cookies.js";
import { ErrorCodes, createErrorResponse } from "../../core/errors/catalog.js";
import { extractAuthorizationToken, timingSafeTokenMatch } from "../../core/tokens/index.js";
import { authRepository } from "../../db/repositories/AuthRepository.js";
import { permissionRepository } from "../../db/repositories/PermissionRepository.js";
import { defaultRoleRegistry, GlobalPermissions, resolvePermission } from "../../core/permissions/index.js";
import { authorizationService } from "../../core/permissions/AuthorizationService.js";
import { AuthContext, createSessionAuthContext, createTokenAuthContext, createAnonymousContext, principalFromUser } from "../../core/context/AuthContext.js";
import { attachSessionPermissions, hasNoSessionPermissions } from "../session/sessionPermissions.js";
import { createLogger } from "../../utils/logger.js";
import { type AuthUser, isLocalOnlyUser } from "../../core/types/user.types.js";
import { ensureSessionAsync } from "./security.js";

// Re-export AuthContext for backwards compatibility
export { AuthContext };

const IS_DEV = process.env.env === "dev" || process.env.test === "dev" || process.env.NODE_ENV === "development";
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const isUuid = (val: unknown): val is string => typeof val === "string" && UUID_RE.test(val);
const MAX_API_TOKEN_LENGTH = 4096;
const API_TOKEN_LAST_USED_INTERVAL_MS = 15 * 60 * 1000;
const apiTokenLastUsedCache = new Map<string | number, number>();
const logAuth = createLogger("auth");
const DEFAULT_PERMISSION = GlobalPermissions.basic.access;

function describeRequirement(values: unknown, label: string): string {
  const items = (Array.isArray(values) ? values : [values])
    .filter((v) => v !== undefined && v !== null && String(v).trim() !== "")
    .map(String);
  return items.length ? `Required ${label}: ${items.join(" or ")}` : "";
}

function pruneApiTokenLastUsedCache(now: number): void {
  if (apiTokenLastUsedCache.size < 10000) return;
  const staleBefore = now - API_TOKEN_LAST_USED_INTERVAL_MS * 2;
  for (const [tokenId, lastTouchedAt] of apiTokenLastUsedCache) {
    if (lastTouchedAt < staleBefore) apiTokenLastUsedCache.delete(tokenId);
  }
}

function updateApiTokenLastUsedThrottled(tokenId: string | number): void {
  if (!tokenId) return;
  const now = Date.now();
  const lastTouchedAt = apiTokenLastUsedCache.get(tokenId) || 0;
  if (now - lastTouchedAt < API_TOKEN_LAST_USED_INTERVAL_MS) return;

  pruneApiTokenLastUsedCache(now);
  apiTokenLastUsedCache.set(tokenId, now);
  authRepository.updateApiTokenLastUsed(tokenId).catch((e: any) => {
    apiTokenLastUsedCache.delete(tokenId);
    console.error(`[mbkauthe] Failed to update token usage:`, e);
  });
}

function parseTokenPermissionList(raw: unknown): string[] {
  let list: unknown[] = [];
  if (Array.isArray(raw)) {
    list = raw;
  } else if (raw && typeof raw === "object") {
    list = Array.isArray((raw as any).permissions) ? (raw as any).permissions : [];
  } else if (typeof raw === "string") {
    try {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) list = parsed;
      else if (parsed && Array.isArray(parsed.permissions)) list = parsed.permissions;
    } catch {
      /* ignore */
    }
  }
  return [...new Set(list.map((p) => (typeof p === "string" ? p.trim().toLowerCase() : "")).filter(Boolean))];
}

/**
 * Derives an AuthContext from the Express Request object if not already attached.
 */
export function getOrDeriveAuthContext(req: Request): AuthContext {
  if ((req as any).authContext instanceof AuthContext) {
    return (req as any).authContext;
  }
  if ((req as any).auth instanceof AuthContext) {
    return (req as any).auth;
  }

  const rawUser = (req as any).auth?.user || (req as any).session?.user || (req as any).user;
  if (rawUser && rawUser.username) {
    const isToken = (req as any).auth?.type === "api-token";
    return isToken ? createTokenAuthContext(rawUser) : createSessionAuthContext(rawUser);
  }

  return createAnonymousContext(mbkautheVar.APP_NAME);
}

interface AuthenticateTokenResult {
  ok: boolean;
  context?: AuthContext;
  errorCode?: number;
  statusCode?: number;
}

/**
 * Authenticates an API token from Authorization Header.
 * Pure Authentication: resolves token to an AuthContext without evaluating role/route authorization.
 */
async function authenticateToken(req: Request): Promise<AuthenticateTokenResult> {
  const authHeader = req.headers.authorization;
  if (!authHeader) return { ok: false, errorCode: ErrorCodes.INVALID_AUTH_TOKEN, statusCode: 401 };

  const parts = authHeader.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer") {
    return { ok: false, errorCode: ErrorCodes.INVALID_AUTH_TOKEN, statusCode: 401 };
  }
  const token = parts[1];

  if (!token.startsWith("mbk_")) {
    return { ok: false, errorCode: ErrorCodes.INVALID_AUTH_TOKEN, statusCode: 401 };
  }
  if (token.length > MAX_API_TOKEN_LENGTH) {
    return { ok: false, errorCode: ErrorCodes.INVALID_AUTH_TOKEN, statusCode: 401 };
  }

  const row = await authRepository.getApiTokenByHash(hashApiToken(token));
  if (!row) {
    return { ok: false, errorCode: ErrorCodes.INVALID_AUTH_TOKEN, statusCode: 401 };
  }
  if (row.expires_at && new Date(row.expires_at) <= new Date()) {
    return { ok: false, errorCode: ErrorCodes.API_TOKEN_EXPIRED, statusCode: 401 };
  }
  if (row.is_active === false) {
    return { ok: false, errorCode: ErrorCodes.ACCOUNT_INACTIVE, statusCode: 401 };
  }

  const token_permissions = parseTokenPermissionList(row.permissions);
  updateApiTokenLastUsedThrottled(row.id);

  const hasExplicitPermissions = token_permissions.length > 0;
  const effectiveRole = hasExplicitPermissions ? null : row.role;

  const principal = principalFromUser({
    user_id: row.user_id || undefined,
    username: row.username,
    full_name: row.full_name,
    role: effectiveRole,
    owner_role: row.role,
    session_id: "api-token-session",
    is_active: row.is_active,
    ...(hasExplicitPermissions ? { overrides: { allows: token_permissions, denies: [] }, permissions: { allows: token_permissions, denies: [] } } : {}),
  });

  const context = new AuthContext({
    isAuthenticated: true,
    authMethod: "api-token",
    principal,
    token: {
      id: row.id,
      name: row.name,
      scopes: token_permissions,
      expiresAt: row.expires_at,
    },
    permissions: hasExplicitPermissions ? principal.overrides : null,
  });

  return { ok: true, context };
}

function attachAuthContextToRequest(req: Request, context: AuthContext): void {
  (req as any).authContext = context;
  (req as any).auth = context;
  (req as any).user = context.principal;
  (req as any).userRole = context.principal?.role || (context.principal as any)?.owner_role || "";

  if (!(req as any).session) {
    (req as any).session = {};
  }
  if (!(req as any).session.user && context.principal) {
    (req as any).session.user = context.principal;
  }
}

function destroySessionCookies(req: Request, res: Response) {
  (req as any).session?.destroy?.(() => {});
  clearSessionCookies(res);
}

function respondSessionFailure(req: Request, res: Response, { prefersJson, code, errorCode, error, message, page, pagename = "Login" }: any) {
  destroySessionCookies(req, res);
  if (prefersJson) return res.status(code).json(createErrorResponse(code, errorCode));
  return renderError(res, req, { code, error, message, pagename, page });
}

/**
 * Validates cookie session authentication.
 */
async function validateCookieSession(req: Request, res: Response, next: NextFunction, { prefersJson }: { prefersJson: boolean }) {
  await ensureSessionAsync(req, res);
  const session_id = (req as any).session?.user?.session_id;
  const username = (req as any).session?.user?.username;

  const loginRedirect = `/mbkauthe/login?redirect=${encodeURIComponent(req.originalUrl)}`;

  if (!session_id) {
    const rawCookieHeader = (req.headers && req.headers.cookie) ? String(req.headers.cookie) : "";
    const presentedSessionCookie = Boolean(
      (req as any).cookies?.["mbkauthe.sid"] ||
      (req as any).signedCookies?.["mbkauthe.sid"] ||
      rawCookieHeader.includes("mbkauthe.sid=")
    );

    if (presentedSessionCookie) {
      logAuth(`Presented session cookie not found or invalid in store`);
      return respondSessionFailure(req, res, {
        prefersJson,
        code: 401,
        errorCode: ErrorCodes.SESSION_INVALID,
        error: "Session Expired",
        message: "Your Session Has Expired. Please Log In Again.",
        page: loginRedirect,
      });
    }

    if (IS_DEV) {
      logAuth(`User not authenticated (no session)`);
      logAuth(`req.session.user: %O`, (req as any).session?.user);
    }
    if (prefersJson) return res.status(401).json(createErrorResponse(401, ErrorCodes.SESSION_NOT_FOUND));
    return res.redirect(302, `/mbkauthe/login?${new URLSearchParams({ redirect: req.originalUrl, reason: "logged_out" }).toString()}`);
  }

  if (!isUuid(session_id)) {
    console.warn(`[mbkauthe] Missing or invalid session_id for user "${username || "unknown"}"`);
    return respondSessionFailure(req, res, {
      prefersJson,
      code: 401,
      errorCode: ErrorCodes.SESSION_EXPIRED,
      error: "Session Expired",
      message: "Your Session Has Expired. Please Log In Again.",
      page: loginRedirect,
    });
  }

  try {
    const liveAuth = (req as any).session?._liveAuth;
    const sessionRow = liveAuth !== undefined
      ? liveAuth
      : await authRepository.getSessionAuthData(session_id, prefersJson ? "validate-app-session-for-api" : "validate-app-session");

    if (!sessionRow) {
      logAuth(`Session not found for session_id "${session_id}"`);
      return respondSessionFailure(req, res, {
        prefersJson,
        code: 401,
        errorCode: prefersJson ? ErrorCodes.SESSION_INVALID : ErrorCodes.SESSION_EXPIRED,
        error: "Session Expired",
        message: "Your Session Has Expired. Please Log In Again.",
        page: loginRedirect,
      });
    }

    if (sessionRow.expires_at) {
      const expiresMs = sessionRow.expires_at instanceof Date ? sessionRow.expires_at.getTime() : Date.parse(String(sessionRow.expires_at));
      if (!Number.isNaN(expiresMs) && expiresMs <= Date.now()) {
        logAuth(`Session invalidated (expired) for user "${sessionRow.username || username}"`);
        return respondSessionFailure(req, res, {
          prefersJson,
          code: 401,
          errorCode: ErrorCodes.SESSION_EXPIRED,
          error: "Session Expired",
          message: "Your Session Has Expired. Please Log In Again.",
          page: loginRedirect,
        });
      }
    }

    if (!sessionRow.is_active) {
      logAuth(`Account is inactive for user "${sessionRow.username || username}"`);
      return respondSessionFailure(req, res, {
        prefersJson,
        code: 401,
        errorCode: ErrorCodes.ACCOUNT_INACTIVE,
        error: "Account Inactive",
        message: "Your Account Is Inactive. Please Contact Support.",
        pagename: "Support",
        page: "https://mbktech.org/Support",
      });
    }

    const isLocalOnly = isLocalOnlyUser(sessionRow.is_local_only);
    if (isLocalOnly && isProductionEnvironment()) {
      logAuth(`Account restricted to local environments for user "${sessionRow.username || username}" on production`);
      return respondSessionFailure(req, res, {
        prefersJson,
        code: 403,
        errorCode: ErrorCodes.LOCAL_USER_PROD_RESTRICTED,
        error: "User Restricted To Local",
        message: "This account is restricted to local development/testing environments and cannot log into production.",
        page: loginRedirect,
      });
    }

    const userForSession = {
      session_id: String(session_id),
      user_id: sessionRow.user_id || undefined,
      username: sessionRow.username || username || "unknown",
      full_name: (typeof sessionRow.full_name === "string" && sessionRow.full_name.trim()) || (sessionRow.username || username || "unknown"),
      role: sessionRow.role,
      allowed_apps: sessionRow.allowed_apps,
      image: sessionRow.image || undefined,
      is_local_only: isLocalOnly,
    };

    const isSuper = sessionRow.role === "superadmin";

    if ((req as any).session) {
      const existingUser = (req as any).session.user || {};
      (req as any).session.user = {
        ...existingUser,
        ...userForSession,
      };

      if (isSuper) {
        (req as any).session.user.roles = ["superadmin"];
        (req as any).session.user.overrides = { allows: ["*"], denies: [] };
        (req as any).session.user.permissions = { allows: ["*"], denies: [] };
      } else if (hasNoSessionPermissions((req as any).session.user) || existingUser.role !== sessionRow.role) {
        await attachSessionPermissions((req as any).session.user, userForSession.username, sessionRow.role);
      }
    } else {
      if (isSuper) {
        (userForSession as any).roles = ["superadmin"];
        (userForSession as any).overrides = { allows: ["*"], denies: [] };
        (userForSession as any).permissions = { allows: ["*"], denies: [] };
      } else {
        await attachSessionPermissions(userForSession, userForSession.username, sessionRow.role);
      }
    }

    const sessionUser = (req as any).session?.user || userForSession;

    // Build unified AuthContext with fresh DB session data taking precedence
    const context = createSessionAuthContext(
      sessionUser,
      {
        id: session_id,
        expiresAt: sessionRow.expires_at,
        appKey: mbkautheVar.APP_NAME,
      }
    );

    // Authorization check: App boundary access
    if (!authorizationService.canAccessApp(context)) {
      console.warn(`[mbkauthe] User "${sessionRow.username || username}" is not authorized to use the application "${mbkautheVar.APP_NAME}"`);
      return respondSessionFailure(req, res, {
        prefersJson,
        code: 401,
        errorCode: ErrorCodes.APP_NOT_AUTHORIZED,
        error: "Unauthorized",
        message: `You Are Not Authorized To Use The Application "${mbkautheVar.APP_NAME}"`,
        pagename: "Home",
        page: mbkautheVar.LOGIN_REDIRECT_URL || "/dashboard",
      });
    }

    attachAuthContextToRequest(req, context);
    return next();
  } catch (err) {
    console.error(`[mbkauthe] Session validation error:`, err);
    return res.status(500).json(createErrorResponse(500, ErrorCodes.INTERNAL_SERVER_ERROR));
  }
}

/**
 * Validates request authentication (Session or Token).
 */
export async function validateSession(req: Request, res: Response, next: NextFunction, strictTokenValidation: boolean = false): Promise<any> {
  if (req.headers.authorization) {
    if (strictTokenValidation) {
      return res.status(401).json(
        createErrorResponse(401, ErrorCodes.INVALID_AUTH_TOKEN, {
          message: "Token-based authentication not allowed for this endpoint",
          hint: "Use session-based authentication (cookies) instead",
        })
      );
    }

    try {
      const result = await authenticateToken(req);
      if (!result.ok) {
        const statusCode = result.statusCode || 401;
        const errorCode = result.errorCode || ErrorCodes.INVALID_AUTH_TOKEN;
        return res.status(statusCode).json(createErrorResponse(statusCode, errorCode));
      }
      if (result.context) {
        attachAuthContextToRequest(req, result.context);
      }
      return next();
    } catch (err) {
      console.error(`[mbkauthe] Token validation error:`, err);
      return res.status(500).json(createErrorResponse(500, ErrorCodes.INTERNAL_SERVER_ERROR));
    }
  }

  return validateCookieSession(req, res, next, { prefersJson: isJsonRequest(req) });
}

export async function validateApiSession(req: Request, res: Response, next: NextFunction): Promise<any> {
  return req.headers.authorization ? validateSession(req, res, next) : validateCookieSession(req, res, next, { prefersJson: true });
}

export async function reloadSessionUser(req: Request, res: Response): Promise<boolean> {
  if (!(req as any).session?.user?.username) return false;
  try {
    const { session_id } = (req as any).session.user;
    if (!session_id) {
      destroySessionCookies(req, res);
      return false;
    }

    const row = await authRepository.getSessionWithUserForReload(String(session_id), "reload-session-user");
    if (!row || (row.expires_at && new Date(row.expires_at) <= new Date()) || !row.is_active) {
      destroySessionCookies(req, res);
      return false;
    }

    const isLocalOnly = isLocalOnlyUser(row.is_local_only);
    if (isLocalOnly && isProductionEnvironment()) {
      destroySessionCookies(req, res);
      return false;
    }

    if (!authorizationService.canAccessApp(row, mbkautheVar.APP_NAME)) {
      destroySessionCookies(req, res);
      return false;
    }

    (req as any).session.user.username = row.username;
    (req as any).session.user.role = row.role;
    (req as any).session.user.allowed_apps = row.allowed_apps;
    (req as any).session.user.user_id = row.user_id || undefined;

    if (typeof row.full_name === "string" && row.full_name.trim() !== "") {
      (req as any).session.user.full_name = row.full_name;
    } else if (typeof (req as any).cookies?.full_name === "string") {
      (req as any).session.user.full_name = (req as any).cookies.full_name;
    }

    await attachSessionPermissions((req as any).session.user, row.username, row.role);
    await new Promise<void>((resolve, reject) => (req as any).session.save((err: any) => (err ? reject(err) : resolve())));

    try {
      res.cookie("full_name", (req as any).session.user.full_name || (req as any).session.user.username, { ...getCookieOptions(), httpOnly: false });
      const encryptedSid = encryptSessionId((req as any).session.user.session_id);
      if (encryptedSid) res.cookie("session_id", encryptedSid, getCookieOptions());
    } catch (cookieErr) {
      console.error(`[mbkauthe] Error syncing cookies during reload:`, cookieErr);
    }

    return true;
  } catch (err) {
    console.error(`[mbkauthe] reloadSessionUser error:`, err);
    return false;
  }
}

/**
 * Pure Authorization Middleware: checks role requirements against the AuthContext.
 */
export const checkRolePermission = (requiredRoles: string | string[], notAllowed?: string | null) => async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<any> => {
  try {
    if (!(req as any).authContext && !(req as any).session?.user) {
      await ensureSessionAsync(req, res);
    }
    const authContext = getOrDeriveAuthContext(req);
    if (!authContext.isAuthenticated || !authContext.username) {
      logAuth(`User not authenticated`);
      if (isJsonRequest(req)) return res.status(401).json(createErrorResponse(401, ErrorCodes.SESSION_NOT_FOUND));
      return renderError(res, req, {
        code: 401,
        error: "Not Logged In",
        message: "You Are Not Logged In. Please Log In To Continue.",
        pagename: "Login",
        page: `/mbkauthe/login?redirect=${encodeURIComponent(req.originalUrl)}`,
      });
    }

    if (authorizationService.isSuperadmin(authContext)) return next();

    const homeRedirect = mbkautheVar.LOGIN_REDIRECT_URL || "/dashboard";

    if (notAllowed && authorizationService.isRoleDenied(authContext, notAllowed)) {
      const requirement = `Not permitted role: ${notAllowed.toLowerCase()}`;
      if (isJsonRequest(req)) {
        return res.status(403).json(
          createErrorResponse(403, ErrorCodes.ROLE_NOT_ALLOWED, {
            notAllowedRole: notAllowed.toLowerCase(),
            message: `You are not allowed to access this resource. ${requirement}`,
          })
        );
      }
      return renderError(res, req, {
        code: 403,
        error: "Access Denied",
        message: `You are not allowed to access this resource. ${requirement}`,
        pagename: "Home",
        page: homeRedirect,
      });
    }

    if (authorizationService.hasAnyRole(authContext, requiredRoles)) {
      return next();
    }

    const rolesArray = (Array.isArray(requiredRoles) ? requiredRoles : [requiredRoles]).map((r) => (typeof r === "string" ? r.toLowerCase() : r));
    const requiredRoleNames = rolesArray.filter((r) => typeof r === "string" && r !== "any" && r !== "*");
    const requirement = describeRequirement(requiredRoleNames, "role");

    if (isJsonRequest(req)) {
      return res.status(403).json(
        createErrorResponse(403, ErrorCodes.INSUFFICIENT_PERMISSIONS, {
          requiredRole: requiredRoleNames.length === 1 ? requiredRoleNames[0] : requiredRoleNames,
          message: `You do not have permission to access this resource${requirement ? `. ${requirement}` : ""}`,
        })
      );
    }

    return renderError(res, req, {
      code: 403,
      error: "Access Denied",
      message: `You do not have permission to access this resource${requirement ? `. ${requirement}` : ""}`,
      pagename: "Home",
      page: homeRedirect,
    });
  } catch (err) {
    console.error(`[mbkauthe] Permission check error:`, err);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
};

/**
 * Pure Authorization Middleware: checks permission requirements against the AuthContext.
 */
export const checkPermission = (permission: any = DEFAULT_PERMISSION) => async (req: Request, res: Response, next: NextFunction): Promise<any> => {
  try {
    if (!(req as any).authContext && !(req as any).session?.user) {
      await ensureSessionAsync(req, res);
    }
    const authContext = getOrDeriveAuthContext(req);
    if (!authContext.isAuthenticated || !authContext.username) {
      logAuth(`User not authenticated`);
      if (isJsonRequest(req)) return res.status(401).json(createErrorResponse(401, ErrorCodes.SESSION_NOT_FOUND));
      return renderError(res, req, {
        code: 401,
        error: "Not Logged In",
        message: "You Are Not Logged In. Please Log In To Continue.",
        pagename: "Login",
        page: `/mbkauthe/login?redirect=${encodeURIComponent(req.originalUrl)}`,
      });
    }

    // Superadmin bypass: instant return, zero DB lookups, zero permission comparison
    if (authorizationService.isSuperadmin(authContext)) return next();

    if (defaultRoleRegistry.roles.size === 0) {
      await permissionRepository.loadAllRolesIntoRegistry(defaultRoleRegistry).catch(() => {});
    }

    const resolvedPermission = resolvePermission(permission);
    if (authorizationService.hasPermission(authContext, resolvedPermission)) {
      return next();
    }

    const homeRedirect = mbkautheVar.LOGIN_REDIRECT_URL || "/dashboard";
    if (isJsonRequest(req)) {
      return res.status(403).json(
        createErrorResponse(403, ErrorCodes.INSUFFICIENT_PERMISSIONS, {
          requiredPermission: resolvedPermission,
          message: `You do not have permission to access this resource. Required permission: ${resolvedPermission}`,
        })
      );
    }
    return renderError(res, req, {
      code: 403,
      error: "Access Denied",
      message: `You do not have permission to access this resource. Required permission: ${resolvedPermission}`,
      pagename: "Home",
      page: homeRedirect,
    });
  } catch (err) {
    console.error(`[mbkauthe] Permission check error:`, err);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
};

/**
 * Pipeline: Authenticate Session -> Authorize Permission
 */
export const validateSessionAndPermission = (permission: any = DEFAULT_PERMISSION, strictTokenValidation: boolean = false) => async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  await validateSession(
    req,
    res,
    async () => {
      await checkPermission(permission)(req, res, next);
    },
    strictTokenValidation
  );
};

/**
 * Pipeline: Authenticate Session -> Authorize Role
 */
export const validateSessionAndRole = (requiredRole: string | string[], notAllowed?: string | null, strictTokenValidation: boolean = false) => async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  await validateSession(
    req,
    res,
    async () => {
      await checkRolePermission(requiredRole, notAllowed)(req, res, next);
    },
    strictTokenValidation
  );
};

export const authenticate = (authentication: string) => (req: Request, res: Response, next: NextFunction) => {
  const token = extractAuthorizationToken(req.headers?.authorization ?? (req.headers as any)?.["authorization"]);
  if (timingSafeTokenMatch(token, authentication)) {
    logAuth(`Authentication successful`);
    next();
  } else {
    logAuth(`Authentication failed`);
    res.status(401).send("Unauthorized");
  }
};

export const strictValidateSession = (req: Request, res: Response, next: NextFunction) => validateSession(req, res, next, true);
export const strictValidateSessionAndRole = (requiredRole: string | string[], notAllowed?: string | null) =>
  validateSessionAndRole(requiredRole, notAllowed, true);

export const sessVal = validateSession;
export const sessRole = validateSessionAndRole;
export const roleChk = checkRolePermission;
export const strictSessVal = strictValidateSession;
export const strictSessRole = strictValidateSessionAndRole;
export const permChk = checkPermission;
export const sessPerm = validateSessionAndPermission;
