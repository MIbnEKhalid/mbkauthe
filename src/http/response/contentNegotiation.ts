import type { Request } from "express";

export function isJsonRequest(req: Request | any): boolean {
  if (!req) return false;
  if (req.xhr) return true;

  const getHeader = (name: string): string => {
    if (typeof req.get === "function") return req.get(name) || "";
    if (req.headers && typeof req.headers === "object") {
      const lower = name.toLowerCase();
      return req.headers[lower] || req.headers[name] || "";
    }
    return "";
  };

  const accept = getHeader("accept");
  const contentType = getHeader("content-type");
  const xRequestedWith = getHeader("x-requested-with");
  const userAgent = getHeader("user-agent").toLowerCase();

  if (typeof accept === "string" && (accept.includes("application/json") || accept.includes("+json"))) {
    return true;
  }
  if (typeof contentType === "string" && contentType.includes("application/json")) {
    return true;
  }
  if (typeof xRequestedWith === "string" && xRequestedWith.toLowerCase() === "xmlhttprequest") {
    return true;
  }
  if (userAgent.startsWith("curl/") || userAgent.includes("curl/") || userAgent.includes("postmanruntime/")) {
    return true;
  }

  const path = req.path || req.originalUrl || req.url || "";
  if (path.startsWith("/api/") || path.includes("/api/") || path.endsWith(".json")) {
    return true;
  }

  return false;
}
