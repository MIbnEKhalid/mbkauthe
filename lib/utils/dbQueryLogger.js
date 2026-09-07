import path from "path";
import crypto from "crypto";
import { AsyncLocalStorage } from "async_hooks";

const isDev = process.env.env === "dev" && process.env.dbLogs === "true";
const requestContext = isDev ? new AsyncLocalStorage() : null;

const GLOBAL_MAX_QUERY_LOG_ENTRIES = 1000;
const globalQueryState = { totalCount: 0, log: [] };
let autoPoolId = 0;

const callsiteCaptureSetting = (process.env.dbLogsCallsite || "true").toLowerCase();
const parsedSample = Number(process.env.dbLogsCallsiteSample || "1");
const callsiteSampleRate = Number.isFinite(parsedSample) ? Math.min(1, Math.max(0, parsedSample)) : 1;

const safeValue = (value, depth = 0, seen = new WeakSet()) => {
  if (value == null) return value;
  if (typeof value === "string") return value.length > 300 ? `${value.slice(0, 300)}...` : value;
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
    for (const [k, v] of Object.entries(value).slice(0, 20)) {
      out[k] = safeValue(v, depth + 1, seen);
    }
    if (keys.length > 20) out.__truncated = `${keys.length - 20} more keys`;
    seen.delete(value);
    return out;
  }

  return String(value);
};

const toWorkspacePath = (filePath) => (path.relative(process.cwd(), filePath) || filePath).replace(/\\/g, "/");

const isIgnorableStackFrame = (line) =>
  !line.startsWith("at ") ||
  line.includes("/lib/utils/dbQueryLogger.js") ||
  line.includes("\\lib\\utils\\dbQueryLogger.js") ||
  line.includes("node:internal") ||
  line.includes("internal/process");

const parseStackFrame = (frame) => {
  const withFunc = /^at\s+([^\s(]+)\s+\((.+):([0-9]+):([0-9]+)\)$/.exec(frame);
  if (withFunc) {
    return { function: withFunc[1], file: withFunc[2], line: Number(withFunc[3]), column: Number(withFunc[4]) };
  }
  const noFunc = /^at\s+(.+):([0-9]+):([0-9]+)$/.exec(frame);
  if (noFunc) {
    return { function: null, file: noFunc[1], line: Number(noFunc[2]), column: Number(noFunc[3]) };
  }
  return null;
};

const isNodeModulesFrame = (filePath) => /[\\/]node_modules[\\/]/i.test(filePath || "");

const shouldCaptureCallsite = () => {
  if (callsiteCaptureSetting === "false" || callsiteCaptureSetting === "0" || callsiteSampleRate <= 0) return false;
  return callsiteSampleRate >= 1 || Math.random() < callsiteSampleRate;
};

const buildCallsite = () => {
  if (!shouldCaptureCallsite()) return null;
  try {
    const frames = (new Error().stack || "")
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => !isIgnorableStackFrame(l))
      .map(parseStackFrame)
      .filter(Boolean);

    const preferred = frames.find((f) => !isNodeModulesFrame(f.file));
    if (!preferred) return null;
    return {
      function: preferred.function,
      file: toWorkspacePath(preferred.file),
      line: preferred.line,
      column: preferred.column,
    };
  } catch {
    return null;
  }
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
  if (!normalizedQuery) return { fingerprint: null, normalizedQuery: "" };
  return {
    normalizedQuery,
    fingerprint: crypto.createHash("sha1").update(normalizedQuery).digest("hex").slice(0, 12),
  };
};

const isSessionStoreQuery = (normalizedQuery, queryName) => {
  const name = String(queryName || "").toLowerCase();
  return name.includes("session") || /\b(?:from|update|into|delete from)\s+"?mbkcore_session"?\b/.test(normalizedQuery || "");
};

const buildRequestContext = () => {
  const req = getRequestContext()?.req;
  if (!req) return null;
  const user = req.session?.user || null;
  return {
    method: req.method,
    url: req.originalUrl || req.url,
    ip: req.ip,
    user_id: user?.user_id || null,
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
    returnValue.returnedRows = result.rows.length;
    returnValue.rowsPreview = result.rows.slice(0, 3).map((r) => safeValue(r));
    if (result.rows.length > 3) returnValue.rowsTruncated = true;
  }
  return returnValue;
};

const buildTriggerContext = ({ request, callsite, normalizedQuery, queryName }) => {
  const routeText = request ? `${request.method || ""} ${request.url || ""}`.trim() : "";
  const sessionStore = isSessionStoreQuery(normalizedQuery, queryName);

  if (request) {
    return {
      type: "request",
      source: sessionStore ? "session-store" : "route",
      label: sessionStore ? (routeText ? `Session store during ${routeText}` : "Session store during request") : (routeText || "Request route"),
      route: routeText || null,
    };
  }

  if (callsite) {
    const fn = callsite.function || "(anonymous)";
    const loc = callsite.file ? `${callsite.file}:${callsite.line}:${callsite.column}` : "unknown location";
    return { type: "code", source: "callsite", label: `Code trigger: ${fn} @ ${loc}`, route: null };
  }

  return {
    type: "code",
    source: sessionStore ? "session-store" : "unknown",
    label: sessionStore ? "Session store outside request context" : "Code trigger (unresolved)",
    route: null,
  };
};

const recordGlobalLog = (entry) => {
  globalQueryState.totalCount += 1;
  globalQueryState.log.push(entry);
  if (globalQueryState.log.length > GLOBAL_MAX_QUERY_LOG_ENTRIES) globalQueryState.log.shift();
};

export const getQueryCount = () => globalQueryState.totalCount;
export const getQueryLog = (options = {}) =>
  typeof options.limit === "number" ? globalQueryState.log.slice(-options.limit) : [...globalQueryState.log];
export const resetQueryCount = () => { globalQueryState.totalCount = 0; };
export const resetQueryLog = () => { globalQueryState.log.length = 0; };

export const runWithRequestContext = (req, fn) => (isDev && requestContext ? requestContext.run({ req }, fn) : fn());
export const getRequestContext = () => (isDev && requestContext ? requestContext.getStore() : undefined);

const resolveLoggerPool = (item) => {
  if (!item || typeof item !== "object") return null;
  if (item.pool?.query) return { pool: item.pool, name: item.name || item.pool.__mbkQueryLoggerName || item.pool.name };
  if (item.query) return { pool: item, name: item.__mbkQueryLoggerName || item.name || item.options?.application_name || null };
  return null;
};

const getPoolName = (pool, fallbackName) => {
  if (fallbackName || pool.__mbkQueryLoggerName || pool.name || pool.options?.application_name) {
    return fallbackName || pool.__mbkQueryLoggerName || pool.name || pool.options?.application_name;
  }
  return `pool-${++autoPoolId}`;
};

const parseQueryArgs = (args) => {
  try {
    if (typeof args[0] === "string") return { queryText: args[0], queryName: "", queryValues: Array.isArray(args[1]) ? args[1] : undefined };
    if (args[0] && typeof args[0] === "object") {
      return { queryText: args[0].text || "", queryName: args[0].name || "", queryValues: Array.isArray(args[0].values) ? args[0].values : undefined };
    }
  } catch {}
  return { queryText: "", queryName: "", queryValues: undefined };
};

const attachSinglePool = (pool, poolName = null) => {
  if (!pool) return;
  if (pool.__mbkQueryLoggerInstalled) {
    if (poolName && pool.__mbkQueryLoggerName !== poolName) pool.__mbkQueryLoggerName = poolName;
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
    if (dbQueryLog.length > GLOBAL_MAX_QUERY_LOG_ENTRIES) dbQueryLog.shift();
    recordGlobalLog(entry);
  };

  const recordLogEntry = ({ queryText, queryName, queryValues, callsiteSnapshot, success, error, result, durationMs, executionDurationMs, poolWait }) => {
    const request = buildRequestContext();
    const returnValue = buildReturnValue(result);
    const { fingerprint, normalizedQuery } = buildQueryFingerprint(queryText);
    const trigger = buildTriggerContext({ request, callsite: callsiteSnapshot, normalizedQuery, queryName });

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
    if (!client || typeof client.query !== "function") return client;

    client.__mbkQueryLoggerAcquisition = acquisition ? { ...acquisition, attributedToQuery: false } : null;
    if (!client.__mbkQueryLoggerOriginalQuery) client.__mbkQueryLoggerOriginalQuery = client.query.bind(client);

    if (!client.__mbkQueryLoggerReleaseWrapped && typeof client.release === "function") {
      const origRel = client.release.bind(client);
      client.release = (...args) => {
        client.__mbkQueryLoggerAcquisition = null;
        return origRel(...args);
      };
      client.__mbkQueryLoggerReleaseWrapped = true;
    }

    if (client.__mbkQueryLoggerQueryWrapped) return client;

    client.query = (...args) => {
      const { queryText, queryName, queryValues } = parseQueryArgs(args);
      if (!queryText) return client.__mbkQueryLoggerOriginalQuery(...args);

      const callsiteSnapshot = buildCallsite();
      const executionStartTime = process.hrtime.bigint();
      const acq = client.__mbkQueryLoggerAcquisition;
      const waitMs = acq && !acq.attributedToQuery ? acq.waitMs : 0;
      const waitingBefore = acq?.waitingBefore || 0;
      const waitSource = acq?.source || "pool.connect";
      if (acq && !acq.attributedToQuery) acq.attributedToQuery = true;

      const finalize = (success, error, result) => {
        const executionDurationMs = Number(process.hrtime.bigint() - executionStartTime) / 1_000_000;
        recordLogEntry({
          queryText, queryName, queryValues, callsiteSnapshot, success, error, result,
          durationMs: executionDurationMs + waitMs, executionDurationMs,
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
            .then((res) => { finalize(true, null, res); return res; })
            .catch((err) => { finalize(false, err); throw err; });
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
          if (err || !client) return callback(err, client, done);
          callback(null, instrumentClient(client, {
            source: "pool.connect",
            waitMs: Number(process.hrtime.bigint() - connectStartTime) / 1_000_000,
            waitingBefore,
          }), done);
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
        queryText, queryName, queryValues, callsiteSnapshot, success, error, result,
        durationMs, executionDurationMs: durationMs,
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

    const cbIdx = args.findIndex((arg) => typeof arg === "function");
    if (cbIdx >= 0) {
      const wrappedArgs = [...args];
      const origCb = wrappedArgs[cbIdx];
      wrappedArgs[cbIdx] = (err, res) => {
        finalize(!err, err, res);
        return origCb(err, res);
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
          .then((res) => { finalize(true, null, res); return res; })
          .catch((err) => { finalize(false, err, null); throw err; });
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

    if (!queryText) return originalQuery(...args);
    if (usesCallback || !originalConnect) return runDirectLoggedPoolQuery(args, { queryText, queryName, queryValues });

    const callsiteSnapshot = buildCallsite();
    const connectStartTime = process.hrtime.bigint();
    const waitingBefore = pool.waitingCount;

    return originalConnect().then(async (client) => {
      const waitMs = Number(process.hrtime.bigint() - connectStartTime) / 1_000_000;
      const rawQuery = client.query.bind(client);
      const release = typeof client.release === "function" ? client.release.bind(client) : null;
      const executionStartTime = process.hrtime.bigint();

      try {
        const result = await rawQuery(...args);
        const executionDurationMs = Number(process.hrtime.bigint() - executionStartTime) / 1_000_000;
        recordLogEntry({
          queryText, queryName, queryValues, callsiteSnapshot, success: true, error: null, result,
          durationMs: executionDurationMs + waitMs, executionDurationMs,
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
          queryText, queryName, queryValues, callsiteSnapshot, success: false, error: err, result: null,
          durationMs: executionDurationMs + waitMs, executionDurationMs,
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
  pool.resetQueryCount = () => { dbQueryCount = 0; };
  pool.getQueryLog = (options = {}) =>
    typeof options.limit === "number" ? dbQueryLog.slice(-options.limit) : [...dbQueryLog];
  pool.resetQueryLog = () => { dbQueryLog.length = 0; };
};

export const attachDevQueryLogger = (poolOrPools) => {
  if (!isDev || !poolOrPools) return;
  const inputs = Array.isArray(poolOrPools) ? poolOrPools : [poolOrPools];
  for (const item of inputs) {
    const resolved = resolveLoggerPool(item);
    if (resolved) attachSinglePool(resolved.pool, resolved.name);
  }
};
