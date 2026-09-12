import { mbkautheVar, packageJson } from "#config.js";
import { getErrorByCode } from "./errors.js";

const NON_BROWSER_RE = /curl|wget|httpie|python-requests|python|go-http-client|java\/|php|node-fetch|axios|postman|insomnia|okhttp/;
const BROWSER_RE = /mozilla|applewebkit|chrome|safari|firefox|edg|msie|trident|opera/;

export function isJsonRequest(req) {
  if (!req) return false;
  const headers = req.headers || {};
  const accept = (headers.accept || "").toLowerCase();
  const contentType = (headers["content-type"] || "").toLowerCase();
  const userAgent = (headers["user-agent"] || "").toLowerCase();
  const url = (req.originalUrl || req.url || "").toLowerCase();
  const path = (req.path || "").toLowerCase();

  if (userAgent.trim() === "json" || url.startsWith("/mbkauthe/api/") || url.startsWith("/api/") || path.startsWith("/mbkauthe/api/") || path.startsWith("/api/")) return true;
  if (url.endsWith(".json") || path.endsWith(".json") || (headers["x-requested-with"] || "").toLowerCase() === "xmlhttprequest") return true;
  if (contentType.includes("application/json") || accept.includes("application/json") || (accept.includes("json") && !accept.includes("text/html"))) return true;

  return NON_BROWSER_RE.test(userAgent) && !BROWSER_RE.test(userAgent);
}

export function getUserContext(req) {
  const user = req?.session?.user || {};
  return {
    userLoggedIn: Boolean(user.username),
    user_id: user.user_id || "mbk_notfound",
    username: user.username || "N/A",
    full_name: user.full_name || "N/A",
    role: user.role || "N/A",
    allowed_apps: Array.isArray(user.allowed_apps) ? user.allowed_apps : [],
  };
}

export function sanitizeErrorDetails(details) {
  if (!details) return null;
  let str = typeof details === "string" ? details : (details.stack || details.message || (typeof details === "object" ? JSON.stringify(details, null, 2) : String(details)));

  return str
    .replace(/(["']?(?:password|passwd|pwd|secret|token|apiKey|api_key|clientSecret|client_secret|authHeader|accessToken|access_token|refreshToken|refresh_token|privateKey|private_key|main_secret_token|db_password|session_secret)["']?\s*[:=]\s*["']?)([^"',\s\r\n}]+)(["']?)/gi, "$1[REDACTED]$3")
    .replace(/(Bearer\s+)[A-Za-z0-9_\-\.]+/gi, "$1[REDACTED]")
    .replace(/(Basic\s+)[A-Za-z0-9+/=]+/gi, "$1[REDACTED]")
    .replace(/([a-zA-Z0-9+.-]+:\/\/[^:]+:)([^@\s]+)(@)/g, "$1[REDACTED]$3")
    .replace(/(sessionId|connect\.sid|session_id|jwt)=([^;\s&]+)/gi, "$1=[REDACTED]")
    .replace(/-----BEGIN[ A-Z_-]+KEY-----[\s\S]+?-----END[ A-Z_-]+KEY-----/g, "[REDACTED_PRIVATE_KEY]");
}

export function sendSuccess(res, data = null, options = {}) {
  const { statusCode = 200, message = undefined, ...extra } = options;
  const envelope = {
    success: true,
    ...(message && { message }),
    ...(data !== null && data !== undefined && { data }),
    timestamp: new Date().toISOString(),
    ...extra,
  };
  if (data && typeof data === "object" && !Array.isArray(data)) {
    Object.assign(envelope, data);
  }
  return res.status(statusCode).json(envelope);
}

export function sendError(res, errorInput, options = {}) {
  const { statusCode = 500, details = undefined, errorCode = undefined, ...extra } = options;
  let code = errorCode || options.code || (statusCode >= 500 ? "INTERNAL_SERVER_ERROR" : "BAD_REQUEST");
  let message = "An unexpected error occurred";
  let rawDetails = details;

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
    timestamp: new Date().toISOString(),
    ...extra,
  };
  return res.status(statusCode).json(envelope);
}

export const renderError = (res, req, { code, error, message, page, pagename, details }) => {
  res.status(parseInt(code, 10));
  const sanitizedDetails = details !== undefined && details !== null ? sanitizeErrorDetails(details) : undefined;
  return res.render("Error/dError.handlebars", {
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

export function createErrorHandler(options = {}) {
  const { appName = mbkautheVar?.APP_NAME || "mbktech", defaultPage = "/", defaultPageName = "Home" } = options;

  return (err, req, res, next) => {
    if (res.headersSent) return next(err);

    const statusCode = Number(err.status || err.statusCode || 500);
    const isClientError = statusCode >= 400 && statusCode < 500;
    if (!isClientError) console.error(`[${appName}] Unhandled error:`, err?.stack || err);

    if (isJsonRequest(req)) {
      return sendError(res, err, { statusCode, details: process.env.NODE_ENV !== "production" ? err.stack : undefined });
    }

    return renderError(res, req, {
      layout: false,
      code: statusCode,
      error: isClientError ? (err.name || "Client Error") : "Internal app Error",
      message: err.message || (isClientError ? "The request could not be processed." : "An unexpected error occurred on the app."),
      details: err.message,
      pagename: defaultPageName,
      page: defaultPage,
    });
  };
}

export function createNotFoundHandler(options = {}) {
  const { defaultPage = "/", defaultPageName = "Home" } = options;

  return (req, res) => {
    if (req.path?.startsWith("/Assets/") || req.path?.startsWith("/assets/")) return res.status(404).end();
    if (isJsonRequest(req)) {
      return sendError(res, "The requested API route was not found.", { statusCode: 404, code: "ROUTE_NOT_FOUND" });
    }
    return renderError(res, req, {
      layout: false,
      code: 404,
      error: "Not Found",
      message: "The requested page was not found.",
      pagename: defaultPageName,
      page: defaultPage,
    });
  };
}


export async function renderPage(req, res, fileLocation, layout = true, data = {}) {
  return res.render(fileLocation, {
    ...data,
    ...getUserContext(req),
    ...(!layout && { layout: false }),
  });
}

export async function proxycall(req, res, url, method = "GET", headerOption = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 30000);

  try {
    const sessionCookie = req.cookies?.session_id;
    const headers = { ...headerOption };
    if (sessionCookie && !headers.Cookie) headers.Cookie = `session_id=${sessionCookie}`;

    const isGetOrHead = ["GET", "HEAD"].includes(method);
    const body = isGetOrHead ? undefined : (typeof req.body === "string" || Buffer.isBuffer(req.body) ? req.body : JSON.stringify(req.body));
    if (body && !headers["Content-Type"]) headers["Content-Type"] = "application/json";

    const response = await fetch(url, { method, headers, body, signal: controller.signal });
    response.headers.forEach((value, key) => res.setHeader(key, value));

    const isJson = response.headers.get("content-type")?.includes("application/json");
    const data = isJson ? await response.json() : await response.text();
    return res.status(response.status).send(data);
  } catch (err) {
    console.error("Proxy error:", err);
    return res.status(err.name === "AbortError" ? 504 : 500).json({ error: "Proxy request failed" });
  } finally {
    clearTimeout(timeout);
  }
}