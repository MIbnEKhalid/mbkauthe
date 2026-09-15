import type { Request } from "express";

const NON_BROWSER_RE = /curl|wget|httpie|python-requests|python|go-http-client|java\/|php|node-fetch|axios|postman|insomnia|okhttp/;
const BROWSER_RE = /mozilla|applewebkit|chrome|safari|firefox|edg|msie|trident|opera/;

export function isJsonRequest(req?: Request | null): boolean {
  if (!req) return false;
  const headers = req.headers || {};
  const accept = String(headers.accept || "").toLowerCase();
  const contentType = String(headers["content-type"] || "").toLowerCase();
  const userAgent = String(headers["user-agent"] || "").toLowerCase();
  const url = (req.originalUrl || req.url || "").toLowerCase();
  const path = (req.path || "").toLowerCase();
  const requestedWith = String(headers["x-requested-with"] || "").toLowerCase();

  if (userAgent.trim() === "json" || url.startsWith("/mbkauthe/api/") || url.startsWith("/api/") || path.startsWith("/mbkauthe/api/") || path.startsWith("/api/")) return true;
  if (url.endsWith(".json") || path.endsWith(".json") || requestedWith === "xmlhttprequest") return true;
  if (contentType.includes("application/json") || accept.includes("application/json") || (accept.includes("json") && !accept.includes("text/html"))) return true;

  return NON_BROWSER_RE.test(userAgent) && !BROWSER_RE.test(userAgent);
}
