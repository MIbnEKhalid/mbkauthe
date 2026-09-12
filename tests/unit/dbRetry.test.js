import { describe, it, expect, vi } from "vitest";
import { isRetryableDbError, withQueryRetry, wrapPoolWithRetry, PostgresAdapter } from "../../index.js";

describe("Database Retry & Resilience", () => {
  describe("isRetryableDbError", () => {
    it("identifies connection timeouts and drops as retryable", () => {
      expect(isRetryableDbError(new Error("Connection terminated due to connection timeout"))).toBe(true);
      expect(isRetryableDbError(new Error("Connection terminated unexpectedly"))).toBe(true);
      expect(isRetryableDbError(new Error("timeout exceeded when trying to connect"))).toBe(true);
      expect(isRetryableDbError(new Error("Client has encountered a connection error and is not queryable"))).toBe(true);
      expect(isRetryableDbError(new Error("server closed the connection unexpectedly"))).toBe(true);
      expect(isRetryableDbError(new Error("socket hang up"))).toBe(true);
    });

    it("identifies network and Postgres connection error codes as retryable", () => {
      const errEconn = new Error("connection reset");
      errEconn.code = "ECONNRESET";
      expect(isRetryableDbError(errEconn)).toBe(true);

      const errTimeout = new Error("timeout");
      errTimeout.code = "ETIMEDOUT";
      expect(isRetryableDbError(errTimeout)).toBe(true);

      const errPgAdmin = new Error("admin shutdown");
      errPgAdmin.code = "57P01";
      expect(isRetryableDbError(errPgAdmin)).toBe(true);

      const errConnFail = new Error("connection failure");
      errConnFail.code = "08006";
      expect(isRetryableDbError(errConnFail)).toBe(true);
    });

    it("returns false for non-retryable errors", () => {
      expect(isRetryableDbError(null)).toBe(false);
      expect(isRetryableDbError(undefined)).toBe(false);

      const syntaxErr = new Error('syntax error at or near "SELCT"');
      syntaxErr.code = "42601";
      expect(isRetryableDbError(syntaxErr)).toBe(false);

      const uniqueViolation = new Error("duplicate key value violates unique constraint");
      uniqueViolation.code = "23505";
      expect(isRetryableDbError(uniqueViolation)).toBe(false);
    });
  });

  describe("withQueryRetry", () => {
    it("returns result on first try when query succeeds", async () => {
      const fn = vi.fn().mockResolvedValue({ rows: [{ id: 1 }], rowCount: 1 });
      const result = await withQueryRetry(fn);
      expect(result).toEqual({ rows: [{ id: 1 }], rowCount: 1 });
      expect(fn).toHaveBeenCalledTimes(1);
    });

    it("retries on transient connection error and succeeds", async () => {
      let attempts = 0;
      const fn = vi.fn().mockImplementation(async () => {
        attempts++;
        if (attempts === 1) {
          throw new Error("Connection terminated due to connection timeout");
        }
        return { rows: [{ id: 2 }], rowCount: 1 };
      });

      const result = await withQueryRetry(fn, { initialDelayMs: 10, maxRetries: 3 });
      expect(result).toEqual({ rows: [{ id: 2 }], rowCount: 1 });
      expect(fn).toHaveBeenCalledTimes(2);
    });

    it("immediately throws non-retryable errors without retrying", async () => {
      const syntaxErr = new Error('syntax error at or near "INVALID"');
      syntaxErr.code = "42601";
      const fn = vi.fn().mockRejectedValue(syntaxErr);

      await expect(withQueryRetry(fn, { maxRetries: 3, initialDelayMs: 10 })).rejects.toThrow(
        'syntax error at or near "INVALID"'
      );
      expect(fn).toHaveBeenCalledTimes(1);
    });

    it("throws last error if maxRetries is exceeded on persistent connection failure", async () => {
      const connErr = new Error("Connection terminated due to connection timeout");
      const fn = vi.fn().mockRejectedValue(connErr);

      await expect(withQueryRetry(fn, { maxRetries: 2, initialDelayMs: 10 })).rejects.toThrow(
        "Connection terminated due to connection timeout"
      );
      expect(fn).toHaveBeenCalledTimes(2);
    });
  });

  describe("wrapPoolWithRetry", () => {
    it("wraps pool.query and retries on connection drop", async () => {
      let callCount = 0;
      const mockPool = {
        options: { application_name: "test-pool" },
        on: vi.fn(),
        query: vi.fn().mockImplementation(async (sql) => {
          callCount++;
          if (callCount === 1) {
            throw new Error("Connection terminated unexpectedly");
          }
          return { rows: [{ val: "ok" }], rowCount: 1 };
        }),
      };

      const wrapped = wrapPoolWithRetry(mockPool, { maxRetries: 3 });
      expect(mockPool.on).toHaveBeenCalledWith("error", expect.any(Function));

      const res = await wrapped.query("SELECT 1");
      expect(res).toEqual({ rows: [{ val: "ok" }], rowCount: 1 });
      expect(callCount).toBe(2);
    });

    it("does not wrap twice", () => {
      const mockPool = { query: vi.fn(), on: vi.fn() };
      const wrapped1 = wrapPoolWithRetry(mockPool);
      const wrapped2 = wrapPoolWithRetry(wrapped1);
      expect(wrapped1).toBe(wrapped2);
    });
  });

  describe("PostgresAdapter with retry resilience", () => {
    it("retries queries on connection timeout transparently", async () => {
      let callCount = 0;
      const mockPool = {
        query: vi.fn().mockImplementation(async (config) => {
          callCount++;
          if (callCount === 1) {
            throw new Error("Connection terminated due to connection timeout");
          }
          return { rows: [{ user_id: "u1" }], rowCount: 1 };
        }),
        connect: vi.fn().mockResolvedValue({ release: vi.fn() }),
      };

      const adapter = new PostgresAdapter(mockPool);
      const res = await adapter.query("SELECT * FROM users WHERE user_id = $1", ["u1"]);
      expect(res).toEqual({ rows: [{ user_id: "u1" }], rowCount: 1 });
      expect(callCount).toBe(2);
    });
  });
});
