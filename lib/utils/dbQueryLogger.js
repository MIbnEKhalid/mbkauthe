import path from "path";
import { AsyncLocalStorage } from "async_hooks";

const isDev = process.env.env === "dev" && process.env.dbLogs === "true";
const requestContext = isDev ? new AsyncLocalStorage() : null;

export const runWithRequestContext = (req, fn) => {
  if (!isDev || !requestContext) return fn();
  return requestContext.run({ req }, fn);
};

export const getRequestContext = () => {
  if (!isDev || !requestContext) return undefined;
  return requestContext.getStore();
};

export const attachDevQueryLogger = (pool) => {
  if (!isDev || !pool || pool.__mbkQueryLoggerInstalled) {
    return;
  }

  pool.__mbkQueryLoggerInstalled = true;

  // Simple counter for all DB requests made via this pool. This is intentionally lightweight.
  let dbQueryCount = 0;
  const dbQueryLog = [];
  const MAX_QUERY_LOG_ENTRIES = 1000;

  const originalQuery = pool.query.bind(pool);

  const safeValue = (value, depth = 0, seen = new WeakSet()) => {
    if (value == null) return value;
    if (typeof value === "string") {
      return value.length > 300 ? `${value.slice(0, 300)}...` : value;
    }
    if (typeof value === "number" || typeof value === "boolean") return value;
    if (typeof value === "bigint") return value.toString();
    if (value instanceof Date) return value.toISOString();
    if (Buffer.isBuffer(value)) return `[buffer:${value.length}]`;

    if (Array.isArray(value)) {
      if (depth >= 4) return `[array:${value.length}]`;
      const sample = value.slice(0, 8).map((v) => safeValue(v, depth + 1, seen));
      if (value.length > 8) sample.push(`...(${value.length - 8} more)`);
      return sample;
    }

    if (typeof value === "object") {
      if (seen.has(value)) return "[circular]";
      seen.add(value);

      const keys = Object.keys(value);
      if (depth >= 4) {
        const head = keys.slice(0, 5).join(", ");
        return keys.length > 5 ? `[object:${head}, ...]` : `[object:${head}]`;
      }

      const out = {};
      const entries = Object.entries(value).slice(0, 20);
      for (const [k, v] of entries) {
        out[k] = safeValue(v, depth + 1, seen);
      }
      if (keys.length > 20) {
        out.__truncated = `${keys.length - 20} more keys`;
      }

      seen.delete(value);
      return out;
    }

    return String(value);
  };

  const buildReturnValue = (result) => {
    if (!result || typeof result !== "object") return undefined;

    const returnValue = {
      command: result.command || undefined,
      rowCount: typeof result.rowCount === "number" ? result.rowCount : undefined,
    };

    if (Array.isArray(result.rows)) {
      const previewSize = 3;
      returnValue.returnedRows = result.rows.length;
      returnValue.rowsPreview = result.rows.slice(0, previewSize).map((row) => safeValue(row));
      if (result.rows.length > previewSize) {
        returnValue.rowsTruncated = true;
      }
    }

    return returnValue;
  };

  pool.query = (...args) => {
    dbQueryCount++;

    // `pg` supports (text, values, callback) or (config, callback).
    let queryText = "";
    let queryName = "";
    let queryValues;
    try {
      if (typeof args[0] === "string") {
        queryText = args[0];
        queryValues = Array.isArray(args[1]) ? args[1] : undefined;
      } else if (args[0] && typeof args[0] === "object") {
        queryText = args[0].text || "";
        queryName = args[0].name || "";
        queryValues = Array.isArray(args[0].values) ? args[0].values : undefined;
      }
    } catch {
      queryText = "";
    }

    if (!queryText) {
      return originalQuery(...args);
    }

    const startTime = process.hrtime.bigint();
    const toWorkspacePath = (filePath) => {
      const rel = path.relative(process.cwd(), filePath) || filePath;
      return rel.replace(/\\/g, "/");
    };

    const buildCallsite = () => {
      try {
        const stack = new Error().stack || "";
        const lines = stack.split("\n").map((l) => l.trim());
        const frame = lines.find(
          (line) =>
            line.startsWith("at ") &&
            !line.includes("/lib/utils/dbQueryLogger.js") &&
            !line.includes("node:internal") &&
            !line.includes("internal/process")
        );

        if (!frame) return null;

        const withFunc = /^at\s+([^\s(]+)\s+\((.+):([0-9]+):([0-9]+)\)$/.exec(frame);
        const noFunc = /^at\s+(.+):([0-9]+):([0-9]+)$/.exec(frame);

        if (withFunc) {
          return {
            function: withFunc[1],
            file: toWorkspacePath(withFunc[2]),
            line: Number(withFunc[3]),
            column: Number(withFunc[4]),
          };
        }

        if (noFunc) {
          return {
            function: null,
            file: toWorkspacePath(noFunc[1]),
            line: Number(noFunc[2]),
            column: Number(noFunc[3]),
          };
        }
      } catch {
        return null;
      }
      return null;
    };

    const buildRequestContext = () => {
      const store = getRequestContext();
      const req = store?.req;
      if (!req) return null;

      const user = req.session?.user || null;
      return {
        method: req.method,
        url: req.originalUrl || req.url,
        ip: req.ip,
        userId: user?.id || null,
        username: user?.username || null,
      };
    };

    const callsiteSnapshot = buildCallsite();

    const recordLog = (success, error, result) => {
      const durationMs = Number(process.hrtime.bigint() - startTime) / 1_000_000;
      const request = buildRequestContext();
      const returnValue = buildReturnValue(result);

      dbQueryLog.push({
        time: new Date().toISOString(),
        query: queryText,
        name: queryName || undefined,
        values: queryValues,
        durationMs,
        success,
        error: error ? { message: error.message, code: error.code } : undefined,
        returnValue,
        request,
        pool: {
          total: pool.totalCount,
          idle: pool.idleCount,
          waiting: pool.waitingCount,
        },
        callsite: callsiteSnapshot,
      });

      if (dbQueryLog.length > MAX_QUERY_LOG_ENTRIES) {
        dbQueryLog.shift();
      }
    };

    try {
      const result = originalQuery(...args);
      if (result && typeof result.then === "function") {
        return result
          .then((res) => {
            recordLog(true, null, res);
            return res;
          })
          .catch((err) => {
            recordLog(false, err);
            throw err;
          });
      }

      recordLog(true, null, result);
      return result;
    } catch (err) {
      recordLog(false, err);
      throw err;
    }
  };

  pool.getQueryCount = () => dbQueryCount;
  pool.resetQueryCount = () => {
    dbQueryCount = 0;
  };

  pool.getQueryLog = (options = {}) => {
    const { limit } = options;
    if (typeof limit === "number") {
      return dbQueryLog.slice(-limit);
    }
    return [...dbQueryLog];
  };

  pool.resetQueryLog = () => {
    dbQueryLog.length = 0;
  };
};
