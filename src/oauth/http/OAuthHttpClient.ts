/**
 * Framework-Agnostic OAuth HTTP Client for MBKAuthe
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 */

export interface OAuthHttpRequestOptions {
  headers?: Record<string, string>;
  timeoutMs?: number;
  body?: any;
  form?: Record<string, string | number | boolean | undefined>;
}

export class OAuthHttpError extends Error {
  public status: number;
  public statusText: string;
  public data: any;

  constructor(message: string, status: number, statusText: string, data: any) {
    super(message);
    this.name = "OAuthHttpError";
    this.status = status;
    this.statusText = statusText;
    this.data = data;
  }
}

export class OAuthHttpClient {
  private defaultTimeoutMs: number;

  constructor(options: { defaultTimeoutMs?: number } = {}) {
    this.defaultTimeoutMs = options.defaultTimeoutMs || 10000;
  }

  /**
   * Performs an HTTP GET request and returns the parsed JSON response.
   */
  async get<T = any>(url: string, options: OAuthHttpRequestOptions = {}): Promise<T> {
    return this.request<T>(url, "GET", options);
  }

  /**
   * Performs an HTTP POST request and returns the parsed JSON response.
   */
  async post<T = any>(url: string, options: OAuthHttpRequestOptions = {}): Promise<T> {
    return this.request<T>(url, "POST", options);
  }

  /**
   * Core request executor using native fetch.
   */
  async request<T = any>(url: string, method: string, options: OAuthHttpRequestOptions = {}): Promise<T> {
    const timeoutMs = options.timeoutMs || this.defaultTimeoutMs;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    const headers: Record<string, string> = {
      Accept: "application/json",
      ...options.headers,
    };

    let body: string | undefined;

    if (options.form) {
      const params = new URLSearchParams();
      for (const [key, value] of Object.entries(options.form)) {
        if (value !== undefined) {
          params.append(key, String(value));
        }
      }
      body = params.toString();
      headers["Content-Type"] = "application/x-www-form-urlencoded";
    } else if (options.body !== undefined) {
      if (typeof options.body === "string") {
        body = options.body;
      } else {
        body = JSON.stringify(options.body);
        if (!headers["Content-Type"]) {
          headers["Content-Type"] = "application/json";
        }
      }
    }

    try {
      const response = await fetch(url, {
        method,
        headers,
        body,
        signal: controller.signal,
      });

      const contentType = response.headers.get("content-type") || "";
      let responseData: any;

      if (contentType.includes("application/json") || contentType.includes("+json")) {
        try {
          responseData = await response.json();
        } catch {
          responseData = null;
        }
      } else {
        const text = await response.text();
        try {
          // Attempt to parse text/plain or urlencoded as JSON or search params if feasible
          if (text.startsWith("{") || text.startsWith("[")) {
            responseData = JSON.parse(text);
          } else if (text.includes("=") && (contentType.includes("application/x-www-form-urlencoded") || text.includes("access_token="))) {
            const params = new URLSearchParams(text);
            const obj: Record<string, string> = {};
            params.forEach((v, k) => { obj[k] = v; });
            responseData = obj;
          } else {
            responseData = text;
          }
        } catch {
          responseData = text;
        }
      }

      if (!response.ok) {
        const errorMessage =
          (responseData && typeof responseData === "object" && (responseData.error_description || responseData.error || responseData.message)) ||
          `HTTP ${response.status}: ${response.statusText}`;
        throw new OAuthHttpError(errorMessage, response.status, response.statusText, responseData);
      }

      return responseData as T;
    } catch (err: any) {
      if (err.name === "AbortError") {
        throw new OAuthHttpError(`OAuth HTTP request timed out after ${timeoutMs}ms`, 408, "Request Timeout", null);
      }
      if (err instanceof OAuthHttpError) {
        throw err;
      }
      throw new OAuthHttpError(err.message || "OAuth HTTP Request Failed", 500, "Internal Error", null);
    } finally {
      clearTimeout(timeoutId);
    }
  }
}

export const defaultOAuthHttpClient = new OAuthHttpClient();
