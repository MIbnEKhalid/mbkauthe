import type { Request, Response, NextFunction } from "express";
import { mbkautheVar } from "../../config/index.js";
import { isJsonRequest } from "./contentNegotiation.js";
import { sendError, renderError } from "./formatters.js";

export interface ErrorHandlerOptions {
  appName?: string;
  defaultPage?: string;
  defaultPageName?: string;
}

export function createErrorHandler(options: ErrorHandlerOptions = {}) {
  const { appName = mbkautheVar?.APP_NAME || "mbktech", defaultPage = "/", defaultPageName = "Home" } = options;

  return (err: any, req: Request, res: Response, next: NextFunction) => {
    if (res.headersSent) return next(err);

    const statusCode = Number(err.status || err.statusCode || 500);
    const isClientError = statusCode >= 400 && statusCode < 500;
    if (!isClientError) console.error(`[${appName}] Unhandled error:`, err?.stack || err);

    if (isJsonRequest(req)) {
      return sendError(res, err, { statusCode, details: process.env.NODE_ENV !== "production" ? err.stack : undefined });
    }

    return renderError(res, req, {
      code: statusCode,
      error: isClientError ? (err.name || "Client Error") : "Internal app Error",
      message: err.message || (isClientError ? "The request could not be processed." : "An unexpected error occurred on the app."),
      details: err.message,
      pagename: defaultPageName,
      page: defaultPage,
    });
  };
}

export interface NotFoundHandlerOptions {
  defaultPage?: string;
  defaultPageName?: string;
}

export function createNotFoundHandler(options: NotFoundHandlerOptions = {}) {
  const { defaultPage = "/", defaultPageName = "Home" } = options;

  return (req: Request, res: Response) => {
    if (req.path?.startsWith("/Assets/") || req.path?.startsWith("/assets/")) return res.status(404).end();
    if (isJsonRequest(req)) {
      return sendError(res, "The requested API route was not found.", { statusCode: 404, code: "ROUTE_NOT_FOUND" });
    }
    return renderError(res, req, {
      code: 404,
      error: "Not Found",
      message: "The requested page was not found.",
      pagename: defaultPageName,
      page: defaultPage,
    });
  };
}

export async function proxycall(req: Request, res: Response, url: string, method = "GET", headerOption: Record<string, string> = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 30000);

  try {
    const sessionCookie = (req as any).cookies?.session_id;
    const headers: Record<string, string> = { ...headerOption };
    if (sessionCookie && !headers.Cookie) headers.Cookie = `session_id=${sessionCookie}`;

    const isGetOrHead = ["GET", "HEAD"].includes(method);
    const body = isGetOrHead ? undefined : (typeof req.body === "string" || Buffer.isBuffer(req.body) ? req.body : JSON.stringify(req.body));
    if (body && !headers["Content-Type"]) headers["Content-Type"] = "application/json";

    const response = await fetch(url, { method, headers, body, signal: controller.signal });
    response.headers.forEach((value, key) => res.setHeader(key, value));

    const isJson = response.headers.get("content-type")?.includes("application/json");
    const data = isJson ? await response.json() : await response.text();
    return res.status(response.status).send(data);
  } catch (err: any) {
    console.error("Proxy error:", err);
    return res.status(err.name === "AbortError" ? 504 : 500).json({ error: "Proxy request failed" });
  } finally {
    clearTimeout(timeout);
  }
}
