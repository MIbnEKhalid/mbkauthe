import type { Request, Response } from "express";
import { mbkautheVar, packageJson } from "../../config/index.js";
import { getErrorByCode } from "../../core/errors/catalog.js";

export function getUserContext(req?: Request | null) {
  const user = (req as any)?.session?.user || (req as any)?.auth?.user;
  const cookieUsername = (req as any)?.cookies?.username;
  const cookieFullName = (req as any)?.cookies?.full_name;

  if (user?.username) {
    return {
      userLoggedIn: true,
      user_id: user.user_id || "mbk_notfound",
      username: user.username,
      full_name: user.full_name || user.username,
      role: user.role || "N/A",
      allowed_apps: Array.isArray(user.allowed_apps) ? user.allowed_apps : [],
    };
  }

  if (cookieUsername && typeof cookieUsername === "string" && cookieUsername.trim()) {
    const cleanUsername = cookieUsername.trim();
    return {
      userLoggedIn: true,
      user_id: "mbk_notfound",
      username: cleanUsername,
      full_name: (cookieFullName && typeof cookieFullName === "string") ? cookieFullName.trim() : cleanUsername,
      role: "N/A",
      allowed_apps: [],
    };
  }

  if (cookieFullName && typeof cookieFullName === "string" && cookieFullName.trim()) {
    const cleanFullName = cookieFullName.trim();
    return {
      userLoggedIn: true,
      user_id: "mbk_notfound",
      username: cleanFullName,
      full_name: cleanFullName,
      role: "N/A",
      allowed_apps: [],
    };
  }

  return {
    userLoggedIn: false,
    user_id: "mbk_notfound",
    username: "N/A",
    full_name: "N/A",
    role: "N/A",
    allowed_apps: [],
  };
}

export function sanitizeErrorDetails(details: unknown): string | null {
  if (!details) return null;
  let str = typeof details === "string" ? details : ((details as any).stack || (details as any).message || (typeof details === "object" ? JSON.stringify(details, null, 2) : String(details)));

  return str
    .replace(/(["']?(?:password|passwd|pwd|secret|token|apiKey|api_key|clientSecret|client_secret|authHeader|accessToken|access_token|refreshToken|refresh_token|privateKey|private_key|main_secret_token|db_password|session_secret)["']?\s*[:=]\s*["']?)([^"',\s\r\n}]+)(["']?)/gi, "$1[REDACTED]$3")
    .replace(/(Bearer\s+)[A-Za-z0-9_\-\.]+/gi, "$1[REDACTED]")
    .replace(/(Basic\s+)[A-Za-z0-9+/=]+/gi, "$1[REDACTED]")
    .replace(/([a-zA-Z0-9+.-]+:\/\/[^:]+:)([^@\s]+)(@)/g, "$1[REDACTED]$3")
    .replace(/(sessionId|connect\.sid|session_id|jwt)=([^;\s&]+)/gi, "$1=[REDACTED]")
    .replace(/-----BEGIN[ A-Z_-]+KEY-----[\s\S]+?-----END[ A-Z_-]+KEY-----/g, "[REDACTED_PRIVATE_KEY]");
}

export interface SendSuccessOptions {
  statusCode?: number;
  message?: string;
  req?: Request;
  res?: Response;
  requestId?: string;
  [key: string]: any;
}

function resolveRequestId(options: { req?: Request; requestId?: string }): string | undefined {
  if (options.requestId) return options.requestId;
  if (!options.req) return undefined;
  const headerId = options.req.headers?.["x-request-id"] || options.req.headers?.["x-correlation-id"];
  if (typeof headerId === "string") return headerId;
  return (options.req as any).id || (options.req as any).requestId;
}

function resolveDurationMs(req?: Request): number | undefined {
  if (!req) return undefined;
  const start = (req as any)._startTime || (req as any).startTime;
  if (typeof start === "number") return Date.now() - start;
  if (start instanceof Date) return Date.now() - start.getTime();
  return undefined;
}

export function sendSuccess(res: Response, data: any = null, options: SendSuccessOptions = {}): Response {
  const { statusCode = 200, message = undefined, req, res: _res, ...extra } = options;
  const requestId = resolveRequestId({ req, requestId: options.requestId });
  const durationMs = resolveDurationMs(req);

  const envelope: Record<string, any> = {
    success: true,
    ...(message && { message }),
    ...(data !== null && data !== undefined && { data }),
    ...(requestId && { requestId }),
    ...(durationMs !== undefined && { durationMs }),
    timestamp: new Date().toISOString(),
    ...extra,
  };
  if (data && typeof data === "object" && !Array.isArray(data)) {
    Object.assign(envelope, data);
  }
  return res.status(statusCode).json(envelope);
}

export interface SendErrorOptions {
  statusCode?: number;
  details?: unknown;
  errorCode?: number | string;
  code?: number | string;
  req?: Request;
  res?: Response;
  requestId?: string;
  [key: string]: any;
}

export function sendError(res: Response, errorInput: any, options: SendErrorOptions = {}): Response {
  const { statusCode = 500, details = undefined, errorCode = undefined, req, res: _res, ...extra } = options;
  let code = errorCode || options.code || (statusCode >= 500 ? "INTERNAL_SERVER_ERROR" : "BAD_REQUEST");
  let message = "An unexpected error occurred";
  let rawDetails = details;
  const requestId = resolveRequestId({ req, requestId: options.requestId });
  const durationMs = resolveDurationMs(req);

  if (typeof errorInput === "string") {
    message = errorInput;
  } else if (typeof errorInput === "number") {
    const errDef = getErrorByCode(errorInput);
    code = errDef.errorCode || errorInput;
    message = errDef.userMessage || errDef.message;
    rawDetails = errDef.hint || details;
  } else if (errorInput instanceof Error) {
    message = errorInput.message || message;
    if (!rawDetails && process.env.NODE_ENV !== "production") rawDetails = errorInput.stack;
  } else if (errorInput && typeof errorInput === "object") {
    message = errorInput.message || errorInput.error || message;
    code = errorInput.code || errorInput.errorCode || code;
    rawDetails = errorInput.details || errorInput.hint || details;
  }

  const sanitizedDetails = rawDetails ? sanitizeErrorDetails(rawDetails) : undefined;
  const envelope = {
    success: false,
    error: {
      code,
      message,
      ...(sanitizedDetails !== undefined && { details: sanitizedDetails }),
    },
    message,
    ...(typeof code === "number" || errorCode !== undefined ? { errorCode: typeof code === "number" ? code : errorCode } : {}),
    ...(requestId && { requestId }),
    ...(durationMs !== undefined && { durationMs }),
    timestamp: new Date().toISOString(),
    ...extra,
  };
  return res.status(statusCode).json(envelope);
}

export interface RenderErrorOptions {
  code: number | string;
  error?: string;
  message?: string;
  page?: string;
  pagename?: string;
  details?: unknown;
}

export const renderError = (res: Response, req: Request, { code, error, message, page, pagename, details }: RenderErrorOptions) => {
  res.status(parseInt(String(code), 10));
  const sanitizedDetails = details !== undefined && details !== null ? sanitizeErrorDetails(details) : undefined;
  return res.render("Error/dError.hbs", {
    layout: false,
    code,
    error,
    message,
    page,
    pagename,
    app: mbkautheVar.APP_NAME,
    version: packageJson.version,
    ...getUserContext(req),
    ...(sanitizedDetails !== undefined && { details: sanitizedDetails }),
  });
};

export async function renderPage(
  req: Request,
  res: Response,
  fileLocation: string,
  layout: boolean | string = true,
  data: Record<string, any> = {}
) {
  const userCtx = getUserContext(req);
  const userLoggedIn = userCtx.userLoggedIn || Boolean(data.userLoggedIn);
  const username = userCtx.userLoggedIn ? userCtx.username : (data.username || userCtx.username);

  const layoutOption = typeof layout === "string" ? { layout } : (layout === false ? { layout: false } : {});

  return res.render(fileLocation, {
    ...userCtx,
    ...data,
    userLoggedIn,
    username,
    ...layoutOption,
  });
}

