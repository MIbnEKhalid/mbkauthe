import path from "path";
import crypto from "crypto";
import { AsyncLocalStorage } from "async_hooks";

const isDev = process.env.env === "dev" && process.env.dbLogs === "true";
const requestContext = isDev ? new AsyncLocalStorage() : null;

const GLOBAL_MAX_QUERY_LOG_ENTRIES = 1000;
const globalQueryState = {
  totalCount: 0,
  log: [],
};
let autoPoolId = 0;

const callsiteCaptureSetting = (process.env.dbLogsCallsite || "true").toLowerCase();
const parsedCallsiteSampleRate = Number(process.env.dbLogsCallsiteSample || "1");
const callsiteSampleRate = Number.isFinite(parsedCallsiteSampleRate)
  ? Math.min(1, Math.max(0, parsedCallsiteSampleRate))
  : 1;

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

const isIgnorableStackFrame = (line) =>
  !line.startsWith("at ") ||
  line.includes("/lib/utils/dbQueryLogger.js") ||
  line.includes("\\lib\\utils\\dbQueryLogger.js") ||
  line.includes("node:internal") ||
  line.includes("internal/process");

const parseStackFrame = (frame) => {
  const withFunc = /^at\s+([^\s(]+)\s+\((.+):([0-9]+):([0-9]+)\)$/.exec(frame);
  const noFunc = /^at\s+(.+):([0-9]+):([0-9]+)$/.exec(frame);

  if (withFunc) {
    return {
      function: withFunc[1],
      file: withFunc[2],
      line: Number(withFunc[3]),
      column: Number(withFunc[4]),
    };
  }

  if (noFunc) {
    return {
      function: null,
      file: noFunc[1],
      line: Number(noFunc[2]),
      column: Number(noFunc[3]),
    };
  }

  return null;
};

const isNodeModulesFrame = (filePath) => /[\\/]node_modules[\\/]/i.test(filePath || "");

const shouldCaptureCallsite = () => {
  if (callsiteCaptureSetting === "false" || callsiteCaptureSetting === "0") {
    return false;
  }

  if (callsiteSampleRate <= 0) {
    return false;
  }

  if (callsiteSampleRate >= 1) {
    return true;
  }

  return Math.random() < callsiteSampleRate;
};

const buildCallsite = () => {
  if (!shouldCaptureCallsite()) {
    return null;
  }

  try {
    const stack = new Error().stack || "";
    const frames = stack
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => !isIgnorableStackFrame(line))
      .map(parseStackFrame)
      .filter(Boolean);

    if (!frames.length) return null;

    const preferredFrame = frames.find((frame) => !isNodeModulesFrame(frame.file));
    if (!preferredFrame) return null;

    return {
      function: preferredFrame.function,
      file: toWorkspacePath(preferredFrame.file),
      line: preferredFrame.line,
      column: preferredFrame.column,
    };
  } catch {
    return null;
  }

  return null;
};

const normalizeQueryText = (queryText) =>
  String(queryText || "")
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/--.*$/gm, " ")
    .replace(/\$[0-9]+\b/g, "?")
    .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/gi, "?")
    .replace(/'(?:''|[^'])*'/g, "?")
    .replace(/\b\d+(?:\.\d+)?\b/g, "?")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();

const buildQueryFingerprint = (queryText) => {
  const normalizedQuery = normalizeQueryText(queryText);
  if (!normalizedQuery) {
    return { fingerprint: null, normalizedQuery: "" };
  }

  return {
    normalizedQuery,
    fingerprint: crypto
      .createHash("sha1")
      .update(normalizedQuery)
      .digest("hex")
      .slice(0, 12),
  };
};

const isSessionStoreQuery = (normalizedQuery, queryName) => {
  const normalizedName = String(queryName || "").toLowerCase();
  if (normalizedName.includes("session")) {
    return true;
  }

  return /\b(?:from|update|into|delete from)\s+"session"\b/.test(normalizedQuery || "");
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
    userId: user?.userId || null,
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

const buildTriggerContext = ({ request, callsite, normalizedQuery, queryName }) => {
  const routeText = request ? `${request.method || ""} ${request.url || ""}`.trim() : "";
  const sessionStore = isSessionStoreQuery(normalizedQuery, queryName);

  if (request && sessionStore) {
    return {
      type: "request",
      source: "session-store",
      label: routeText ? `Session store during ${routeText}` : "Session store during request",
      route: routeText || null,
    };
  }

  if (request) {
    return {
      type: "request",
      source: "route",
      label: routeText || "Request route",
      route: routeText || null,
    };
  }

  if (callsite) {
    const functionName = callsite.function || "(anonymous)";
    const location = callsite.file
      ? `${callsite.file}:${callsite.line}:${callsite.column}`
      : "unknown location";

    return {
      type: "code",
      source: "callsite",
      label: `Code trigger: ${functionName} @ ${location}`,
      route: null,
    };
  }

  if (sessionStore) {
    return {
      type: "code",
      source: "session-store",
      label: "Session store outside request context",
      route: null,
    };
  }

  return {
    type: "code",
    source: "unknown",
    label: "Code trigger (unresolved)",
    route: null,
  };
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
  if (item && typeof item === "object") {
    if (item.pool && item.pool.query) {
      return { pool: item.pool, name: item.name || item.pool.__mbkQueryLoggerName || item.pool.name };
    }
    if (item.query) {
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
  autoPoolId += 1;
  return `pool-${autoPoolId}`;
};

const parseQueryArgs = (args) => {
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

  return { queryText, queryName, queryValues };
};

const attachSinglePool = (pool, poolName = null) => {
  if (!pool) return;

  if (pool.__mbkQueryLoggerInstalled) {
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
  const originalConnect = typeof pool.connect === "function" ? pool.connect.bind(pool) : null;

  const recordPoolLog = (entry) => {
    dbQueryCount += 1;
    dbQueryLog.push(entry);
    if (dbQueryLog.length > GLOBAL_MAX_QUERY_LOG_ENTRIES) {
      dbQueryLog.shift();
    }
    recordGlobalLog(entry);
  };

  const recordLogEntry = ({
    queryText,
    queryName,
    queryValues,
    callsiteSnapshot,
    success,
    error,
    result,
    durationMs,
    executionDurationMs,
    poolWait,
  }) => {
    const request = buildRequestContext();
    const returnValue = buildReturnValue(result);
    const { fingerprint, normalizedQuery } = buildQueryFingerprint(queryText);
    const trigger = buildTriggerContext({
      request,
      callsite: callsiteSnapshot,
      normalizedQuery,
      queryName,
    });

    recordPoolLog({
      time: new Date().toISOString(),
      query: queryText,
      normalizedQuery,
      fingerprint,
      name: queryName || undefined,
      values: queryValues,
      durationMs,
      executionDurationMs,
      success,
      error: error ? { message: error.message, code: error.code } : undefined,
      returnValue,
      request,
      trigger,
      pool: {
        name: pool.__mbkQueryLoggerName,
        total: pool.totalCount,
        idle: pool.idleCount,
        waiting: pool.waitingCount,
      },
      poolWait,
      callsite: callsiteSnapshot,
    });
  };

  const instrumentClient = (client, acquisition = null) => {
    if (!client || typeof client.query !== "function") {
      return client;
    }

    client.__mbkQueryLoggerAcquisition = acquisition
      ? { ...acquisition, attributedToQuery: false }
      : null;

    if (!client.__mbkQueryLoggerOriginalQuery) {
      client.__mbkQueryLoggerOriginalQuery = client.query.bind(client);
    }

    if (!client.__mbkQueryLoggerReleaseWrapped && typeof client.release === "function") {
      const originalRelease = client.release.bind(client);
      client.release = (...args) => {
        client.__mbkQueryLoggerAcquisition = null;
        return originalRelease(...args);
      };
      client.__mbkQueryLoggerReleaseWrapped = true;
    }

    if (client.__mbkQueryLoggerQueryWrapped) {
      return client;
    }

    client.query = (...args) => {
      const { queryText, queryName, queryValues } = parseQueryArgs(args);
      if (!queryText) {
        return client.__mbkQueryLoggerOriginalQuery(...args);
      }

      const callsiteSnapshot = buildCallsite();
      const executionStartTime = process.hrtime.bigint();
      const acquisitionMeta = client.__mbkQueryLoggerAcquisition;
      const waitMs = acquisitionMeta && acquisitionMeta.attributedToQuery
        ? 0
        : acquisitionMeta?.waitMs || 0;
      const waitingBefore = acquisitionMeta?.waitingBefore || 0;
      const waitSource = acquisitionMeta?.source || "pool.connect";

      if (acquisitionMeta && !acquisitionMeta.attributedToQuery) {
        acquisitionMeta.attributedToQuery = true;
      }

      const finalize = (success, error, result) => {
        const executionDurationMs = Number(process.hrtime.bigint() - executionStartTime) / 1_000_000;

        recordLogEntry({
          queryText,
          queryName,
          queryValues,
          callsiteSnapshot,
          success,
          error,
          result,
          durationMs: executionDurationMs + waitMs,
          executionDurationMs,
          poolWait: {
            source: waitSource,
            waitMs,
            waitingBefore,
            waitingAfter: pool.waitingCount,
            hadPoolPressure: waitingBefore > 0 || waitMs > 0,
            captured: true,
          },
        });
      };

      try {
        const result = client.__mbkQueryLoggerOriginalQuery(...args);
        if (result && typeof result.then === "function") {
          return result
            .then((res) => {
              finalize(true, null, res);
              return res;
            })
            .catch((err) => {
              finalize(false, err);
              throw err;
            });
        }

        finalize(true, null, result);
        return result;
      } catch (err) {
        finalize(false, err);
        throw err;
      }
    };

    client.__mbkQueryLoggerQueryWrapped = true;
    return client;
  };

  if (originalConnect) {
    pool.connect = (...args) => {
      const connectStartTime = process.hrtime.bigint();
      const waitingBefore = pool.waitingCount;

      if (typeof args[0] === "function") {
        const callback = args[0];
        return originalConnect((err, client, done) => {
          if (err || !client) {
            callback(err, client, done);
            return;
          }

          callback(
            null,
            instrumentClient(client, {
              source: "pool.connect",
              waitMs: Number(process.hrtime.bigint() - connectStartTime) / 1_000_000,
              waitingBefore,
            }),
            done
          );
        });
      }

      return originalConnect(...args).then((client) =>
        instrumentClient(client, {
          source: "pool.connect",
          waitMs: Number(process.hrtime.bigint() - connectStartTime) / 1_000_000,
          waitingBefore,
        })
      );
    };
  }

  const runDirectLoggedPoolQuery = (args, { queryText, queryName, queryValues }) => {
    const callsiteSnapshot = buildCallsite();
    const startTime = process.hrtime.bigint();
    const waitingBefore = pool.waitingCount;
    const finalize = (success, error, result) => {
      const durationMs = Number(process.hrtime.bigint() - startTime) / 1_000_000;

      recordLogEntry({
        queryText,
        queryName,
        queryValues,
        callsiteSnapshot,
        success,
        error,
        result,
        durationMs,
        executionDurationMs: durationMs,
        poolWait: {
          source: "pool.query",
          waitMs: 0,
          waitingBefore,
          waitingAfter: pool.waitingCount,
          hadPoolPressure: waitingBefore > 0,
          captured: false,
        },
      });
    };

    const callbackIndex = args.findIndex((arg) => typeof arg === "function");
    if (callbackIndex >= 0) {
      const wrappedArgs = [...args];
      const originalCallback = wrappedArgs[callbackIndex];
      wrappedArgs[callbackIndex] = (err, result) => {
        finalize(!err, err, result);
        return originalCallback(err, result);
      };

      try {
        return originalQuery(...wrappedArgs);
      } catch (err) {
        finalize(false, err, null);
        throw err;
      }
    }

    try {
      const result = originalQuery(...args);
      if (result && typeof result.then === "function") {
        return result
          .then((res) => {
            finalize(true, null, res);
            return res;
          })
          .catch((err) => {
            finalize(false, err, null);
            throw err;
          });
      }

      finalize(true, null, result);
      return result;
    } catch (err) {
      finalize(false, err, null);
      throw err;
    }
  };

  pool.query = (...args) => {
    const { queryText, queryName, queryValues } = parseQueryArgs(args);
    const usesCallback = args.some((arg) => typeof arg === "function");

    if (!queryText) {
      return originalQuery(...args);
    }

    if (usesCallback || !originalConnect) {
      return runDirectLoggedPoolQuery(args, { queryText, queryName, queryValues });
    }

    const callsiteSnapshot = buildCallsite();
    const connectStartTime = process.hrtime.bigint();
    const waitingBefore = pool.waitingCount;

    return originalConnect()
      .then(async (client) => {
        const waitMs = Number(process.hrtime.bigint() - connectStartTime) / 1_000_000;
        const rawQuery = client.query.bind(client);
        const release = typeof client.release === "function" ? client.release.bind(client) : null;
        const executionStartTime = process.hrtime.bigint();

        try {
          const result = await rawQuery(...args);
          const executionDurationMs = Number(process.hrtime.bigint() - executionStartTime) / 1_000_000;

          recordLogEntry({
            queryText,
            queryName,
            queryValues,
            callsiteSnapshot,
            success: true,
            error: null,
            result,
            durationMs: executionDurationMs + waitMs,
            executionDurationMs,
            poolWait: {
              source: "pool.query",
              waitMs,
              waitingBefore,
              waitingAfter: pool.waitingCount,
              hadPoolPressure: waitingBefore > 0 || waitMs > 0,
              captured: true,
            },
          });

          return result;
        } catch (err) {
          const executionDurationMs = Number(process.hrtime.bigint() - executionStartTime) / 1_000_000;

          recordLogEntry({
            queryText,
            queryName,
            queryValues,
            callsiteSnapshot,
            success: false,
            error: err,
            result: null,
            durationMs: executionDurationMs + waitMs,
            executionDurationMs,
            poolWait: {
              source: "pool.query",
              waitMs,
              waitingBefore,
              waitingAfter: pool.waitingCount,
              hadPoolPressure: waitingBefore > 0 || waitMs > 0,
              captured: true,
            },
          });

          throw err;
        } finally {
          release?.();
        }
      });
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
