import { describe, test, expect } from "vitest";
import { isJsonRequest, sendSuccess, sendError, sanitizeErrorDetails } from "../../lib/utils/response.js";
import { createErrorResponse, ErrorCodes } from "../../lib/utils/errors.js";

describe("Standardized Response & Error Envelope Unit Tests", () => {
  describe("isJsonRequest content negotiation", () => {
    test("detects /api/ path as JSON request", () => {
      expect(isJsonRequest({ originalUrl: "/api/chat" })).toBe(true);
      expect(isJsonRequest({ path: "/mbkauthe/api/verify" })).toBe(true);
      expect(isJsonRequest({ path: "/data.json" })).toBe(true);
    });

    test("detects Accept header with application/json", () => {
      expect(isJsonRequest({ headers: { accept: "application/json, text/plain, */*" } })).toBe(true);
      expect(isJsonRequest({ headers: { accept: "text/html,application/xhtml+xml" } })).toBe(false);
    });

    test("detects XMLHttpRequest", () => {
      expect(isJsonRequest({ headers: { "x-requested-with": "XMLHttpRequest" } })).toBe(true);
    });

    test("detects API CLI tools (curl, postman)", () => {
      expect(isJsonRequest({ headers: { "user-agent": "curl/7.68.0" } })).toBe(true);
      expect(isJsonRequest({ headers: { "user-agent": "PostmanRuntime/7.28.4" } })).toBe(true);
    });

    test("detects standard browser HTML requests as non-JSON", () => {
      const browserReq = {
        path: "/dashboard",
        headers: {
          accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
      };
      expect(isJsonRequest(browserReq)).toBe(false);
    });
  });

  describe("sendSuccess envelope structure", () => {
    const createMockRes = () => {
      const res = {
        statusCode: 200,
        body: null,
        status(code) {
          res.statusCode = code;
          return res;
        },
        json(data) {
          res.body = data;
          return res;
        }
      };
      return res;
    };

    test("formats standard success envelope with data and message", () => {
      const res = createMockRes();
      sendSuccess(res, { token: "abc-123", user: "maaz" }, { message: "Token generated", statusCode: 201 });

      expect(res.statusCode).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.message).toBe("Token generated");
      expect(res.body.data).toEqual({ token: "abc-123", user: "maaz" });
      expect(res.body.timestamp).toBeDefined();

      // Backward compatibility: object data is also flattened on root
      expect(res.body.token).toBe("abc-123");
      expect(res.body.user).toBe("maaz");
    });

    test("handles null or array data", () => {
      const res = createMockRes();
      sendSuccess(res, [1, 2, 3]);

      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toEqual([1, 2, 3]);
    });
  });

  describe("sendError envelope structure", () => {
    const createMockRes = () => {
      const res = {
        statusCode: 500,
        body: null,
        status(code) {
          res.statusCode = code;
          return res;
        },
        json(data) {
          res.body = data;
          return res;
        }
      };
      return res;
    };

    test("formats standard error envelope from string message", () => {
      const res = createMockRes();
      sendError(res, "Invalid authentication payload", { statusCode: 400, code: "INVALID_PAYLOAD" });

      expect(res.statusCode).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error).toBeDefined();
      expect(res.body.error.code).toBe("INVALID_PAYLOAD");
      expect(res.body.error.message).toBe("Invalid authentication payload");
      expect(res.body.message).toBe("Invalid authentication payload");
      expect(res.body.timestamp).toBeDefined();
    });

    test("formats standard error envelope from ErrorCodes integer", () => {
      const res = createMockRes();
      sendError(res, ErrorCodes.MISSING_REQUIRED_FIELD, { statusCode: 400 });

      expect(res.statusCode).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe(1001);
      expect(res.body.errorCode).toBe(1001);
      expect(res.body.message).toBeDefined();
    });

    test("formats standard error envelope from Error instance", () => {
      const res = createMockRes();
      const err = new Error("Database timeout");
      sendError(res, err, { statusCode: 500 });

      expect(res.statusCode).toBe(500);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe("INTERNAL_SERVER_ERROR");
      expect(res.body.error.message).toBe("Database timeout");
      expect(res.body.message).toBe("Database timeout");
    });
  });

  describe("createErrorResponse backward compatibility with standard error object", () => {
    test("produces both legacy errorCode/message and standard error object", () => {
      const resp = createErrorResponse(401, ErrorCodes.INVALID_CREDENTIALS);
      expect(resp.success).toBe(false);
      expect(resp.statusCode).toBe(401);
      expect(resp.errorCode).toBe(601);
      expect(resp.message).toBeDefined();
      expect(resp.error).toBeDefined();
      expect(resp.error.code).toBe(601);
      expect(resp.error.message).toBe(resp.message);
    });
  });

  describe("sanitizeErrorDetails redacts sensitive data", () => {
    test("redacts passwords, tokens, bearer headers and connection strings", () => {
      const raw = `Error: postgres://admin:secretPass123@localhost:5432/db
Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token123
password: "super_secret_password"
apiKey: 'secret-api-key'`;

      const sanitized = sanitizeErrorDetails(raw);
      expect(sanitized).not.toContain("secretPass123");
      expect(sanitized).not.toContain("token123");
      expect(sanitized).not.toContain("super_secret_password");
      expect(sanitized).not.toContain("secret-api-key");
      expect(sanitized).toContain("[REDACTED]");
    });
  });
});
