import path from "path";
import { AsyncLocalStorage } from "async_hooks";

const isDev = process.env.env === "dev" && process.env.dbLogs === "true";
const requestContext = isDev ? new AsyncLocalStorage() : null;

const GLOBAL_MAX_QUERY_LOG_ENTRIES = 1000;
const globalQueryState = {
  totalCount: 0,
  log: [],
};
let autoPoolId = 0;

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

const recordGlobalLog = (entry) => {
  globalQueryState.totalCount += 1;
  globalQueryState.log.push(entry);
  if (globalQueryState.log.length > GLOBAL_MAX_QUERY_LOG_ENTRIES) {
    globalQueryState.log.shift();
  }
};

export const getQueryCount = () => globalQueryState.totalCount;
export const getQueryLog = (options = {}) => {
  const { limit } = options;
  if (typeof limit === "number") {
    return globalQueryState.log.slice(-limit);
  }
  return [...globalQueryState.log];
};

export const resetQueryCount = () => {
  globalQueryState.totalCount = 0;
};

export const resetQueryLog = () => {
  globalQueryState.log.length = 0;
};

export const runWithRequestContext = (req, fn) => {
  if (!isDev || !requestContext) return fn();
  return requestContext.run({ req }, fn);
};

export const getRequestContext = () => {
  if (!isDev || !requestContext) return undefined;
  return requestContext.getStore();
};

const resolveLoggerPool = (item) => {
  if (item && typeof item === 'object') {
    if (item.pool && item.pool.query) {
      return { pool: item.pool, name: item.name || item.pool.__mbkQueryLoggerName || item.pool.name };
    }
    if (item.query) {
      // Don't force 'default' here; let getPoolName assign a non-default auto name.
      return { pool: item, name: item.__mbkQueryLoggerName || item.name || item.options?.application_name || null };
    }
  }
  return null;
};

const getPoolName = (pool, fallbackName) => {
  if (fallbackName) return fallbackName;
  if (pool.__mbkQueryLoggerName) return pool.__mbkQueryLoggerName;
  if (pool.name) return pool.name;
  if (pool.options && pool.options.application_name) return pool.options.application_name;
  // never return "default"; always provide an actual pool name
  autoPoolId += 1;
  return `pool-${autoPoolId}`;
};

const attachSinglePool = (pool, poolName = null) => {
  if (!pool) return;

  if (pool.__mbkQueryLoggerInstalled) {
    // Allow late explicit naming to override a previous auto name.
    if (poolName && pool.__mbkQueryLoggerName !== poolName) {
      pool.__mbkQueryLoggerName = poolName;
    }
    return;
  }

  pool.__mbkQueryLoggerInstalled = true;
  pool.__mbkQueryLoggerName = getPoolName(pool, poolName);

  let dbQueryCount = 0;
  const dbQueryLog = [];
  const originalQuery = pool.query.bind(pool);

  const recordPoolLog = (entry) => {
    dbQueryCount += 1;
    dbQueryLog.push(entry);
    if (dbQueryLog.length > GLOBAL_MAX_QUERY_LOG_ENTRIES) {
      dbQueryLog.shift();
    }
    recordGlobalLog(entry);
  };

  pool.query = (...args) => {
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
    const callsiteSnapshot = buildCallsite();

    const recordLog = (success, error, result) => {
      const durationMs = Number(process.hrtime.bigint() - startTime) / 1_000_000;
      const request = buildRequestContext();
      const returnValue = buildReturnValue(result);

      const entry = {
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
          name: pool.__mbkQueryLoggerName,
          total: pool.totalCount,
          idle: pool.idleCount,
          waiting: pool.waitingCount,
        },
        callsite: callsiteSnapshot,
      };

      recordPoolLog(entry);
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

export const attachDevQueryLogger = (poolOrPools) => {
  if (!isDev || !poolOrPools) return;

  const inputs = Array.isArray(poolOrPools) ? poolOrPools : [poolOrPools];
  for (const item of inputs) {
    const resolved = resolveLoggerPool(item);
    if (!resolved) continue;
    attachSinglePool(resolved.pool, resolved.name);
  }
};
