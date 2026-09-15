import path from "node:path";
import crypto from "node:crypto";
import { AsyncLocalStorage } from "node:async_hooks";

const isDev = process.env.env === "dev" && process.env.dbLogs === "true";
const requestContext = isDev ? new AsyncLocalStorage<{ req: any }>() : null;

const GLOBAL_MAX_QUERY_LOG_ENTRIES = 1000;
const globalQueryState: { totalCount: number; log: any[] } = { totalCount: 0, log: [] };
let autoPoolId = 0;

const callsiteCaptureSetting = (process.env.dbLogsCallsite || "true").toLowerCase();
const parsedSample = Number(process.env.dbLogsCallsiteSample || "1");
const callsiteSampleRate = Number.isFinite(parsedSample) ? Math.min(1, Math.max(0, parsedSample)) : 1;

const safeValue = (value: any, depth = 0, seen = new WeakSet()): any => {
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
    const out: Record<string, any> = {};
    for (const [k, v] of Object.entries(value).slice(0, 20)) {
      out[k] = safeValue(v, depth + 1, seen);
    }
    if (keys.length > 20) out.__truncated = `${keys.length - 20} more keys`;
    seen.delete(value);
    return out;
  }

  return String(value);
};

const toWorkspacePath = (filePath: string) => (path.relative(process.cwd(), filePath) || filePath).replace(/\\/g, "/");

const isIgnorableStackFrame = (line: string) =>
  !line.startsWith("at ") ||
  line.includes("/dbQueryLogger.") ||
  line.includes("\\dbQueryLogger.") ||
  line.includes("node:internal") ||
  line.includes("internal/process");

const parseStackFrame = (frame: string) => {
  const withFunc = /^at\s+([^\s(]+)\s+\((.+):([0-9]+):([0-9]+)\)$/.exec(frame);
  if (withFunc) return { function: withFunc[1], file: withFunc[2], line: Number(withFunc[3]), column: Number(withFunc[4]) };
  const noFunc = /^at\s+(.+):([0-9]+):([0-9]+)$/.exec(frame);
  return noFunc ? { function: null, file: noFunc[1], line: Number(noFunc[2]), column: Number(noFunc[3]) } : null;
};

const isNodeModulesFrame = (filePath?: string | null) => /[\\/]node_modules[\\/]/i.test(filePath || "");

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

    const preferred = frames.find((f) => f && !isNodeModulesFrame(f.file));
    return preferred ? { function: preferred.function, file: toWorkspacePath(preferred.file), line: preferred.line, column: preferred.column } : null;
  } catch {
    return null;
  }
};

const normalizeQueryText = (queryText: string) =>
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

const buildQueryFingerprint = (queryText: string) => {
  const normalizedQuery = normalizeQueryText(queryText);
  return normalizedQuery ? { normalizedQuery, fingerprint: crypto.createHash("sha1").update(normalizedQuery).digest("hex").slice(0, 12) } : { fingerprint: null, normalizedQuery: "" };
};

const isSessionStoreQuery = (normalizedQuery: string, queryName: string) => {
  const name = String(queryName || "").toLowerCase();
  return name.includes("session") || /\b(?:from|update|into|delete from)\s+"?mbkcore_session"?\b/.test(normalizedQuery || "");
};

const buildRequestContext = () => {
  const req = getRequestContext()?.req;
  if (!req) return null;
  const user = req.session?.user || null;
  return { method: req.method, url: req.originalUrl || req.url, ip: req.ip, user_id: user?.user_id || null, username: user?.username || null };
};

const buildReturnValue = (result: any) => {
  if (!result || typeof result !== "object") return undefined;
  const returnValue: Record<string, any> = {
    command: result.command || undefined,
    rowCount: typeof result.rowCount === "number" ? result.rowCount : undefined,
  };
  if (Array.isArray(result.rows)) {
    returnValue.returnedRows = result.rows.length;
    returnValue.rowsPreview = result.rows.slice(0, 3).map((r: any) => safeValue(r));
    if (result.rows.length > 3) returnValue.rowsTruncated = true;
  }
  return returnValue;
};

const buildTriggerContext = ({ request, callsite, normalizedQuery, queryName }: any) => {
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

const recordGlobalLog = (entry: any) => {
  globalQueryState.totalCount += 1;
  globalQueryState.log.push(entry);
  if (globalQueryState.log.length > GLOBAL_MAX_QUERY_LOG_ENTRIES) globalQueryState.log.shift();
};

export const getQueryCount = (): number => globalQueryState.totalCount;
export const getQueryLog = (options: { limit?: number } = {}): any[] =>
  typeof options.limit === "number" ? globalQueryState.log.slice(-options.limit) : [...globalQueryState.log];
export const resetQueryCount = (): void => { globalQueryState.totalCount = 0; };
export const resetQueryLog = (): void => { globalQueryState.log.length = 0; };

export const runWithRequestContext = (req: any, fn: () => any) => (isDev && requestContext ? requestContext.run({ req }, fn) : fn());
export const getRequestContext = () => (isDev && requestContext ? requestContext.getStore() : undefined);

const resolveLoggerPool = (item: any) => {
  if (!item || typeof item !== "object") return null;
  if (item.pool?.query) return { pool: item.pool, name: item.name || item.pool.__mbkQueryLoggerName || item.pool.name };
  if (item.query) return { pool: item, name: item.__mbkQueryLoggerName || item.name || item.options?.application_name || null };
  return null;
};

const getPoolName = (pool: any, fallbackName?: string | null) =>
  fallbackName || pool.__mbkQueryLoggerName || pool.name || pool.options?.application_name || `pool-${++autoPoolId}`;

const parseQueryArgs = (args: any[]) => {
  try {
    if (typeof args[0] === "string") return { queryText: args[0], queryName: "", queryValues: Array.isArray(args[1]) ? args[1] : undefined };
    if (args[0] && typeof args[0] === "object") {
      return { queryText: args[0].text || "", queryName: args[0].name || "", queryValues: Array.isArray(args[0].values) ? args[0].values : undefined };
    }
  } catch {}
  return { queryText: "", queryName: "", queryValues: undefined };
};

const attachSinglePool = (pool: any, poolName: string | null = null) => {
  if (!pool) return;
  if (pool.__mbkQueryLoggerInstalled) {
    if (poolName && pool.__mbkQueryLoggerName !== poolName) pool.__mbkQueryLoggerName = poolName;
    return;
  }

  pool.__mbkQueryLoggerInstalled = true;
  pool.__mbkQueryLoggerName = getPoolName(pool, poolName);

  let dbQueryCount = 0;
  const dbQueryLog: any[] = [];
  const originalQuery = pool.query.bind(pool);
  const originalConnect = typeof pool.connect === "function" ? pool.connect.bind(pool) : null;

  const recordPoolLog = (entry: any) => {
    dbQueryCount += 1;
    dbQueryLog.push(entry);
    if (dbQueryLog.length > GLOBAL_MAX_QUERY_LOG_ENTRIES) dbQueryLog.shift();
    recordGlobalLog(entry);
  };

  const recordLogEntry = ({ queryText, queryName, queryValues, callsiteSnapshot, success, error, result, durationMs, executionDurationMs, poolWait }: any) => {
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

  pool.query = (...args: any[]) => {
    const { queryText, queryName, queryValues } = parseQueryArgs(args);
    if (!queryText) return originalQuery(...args);

    const callsiteSnapshot = buildCallsite();
    const startTime = process.hrtime.bigint();
    const waitingBefore = pool.waitingCount;

    const finalize = (success: boolean, error: any, result: any) => {
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
          captured: true,
        },
      });
    };

    try {
      const result = originalQuery(...args);
      if (result && typeof result.then === "function") {
        return result
          .then((res: any) => { finalize(true, null, res); return res; })
          .catch((err: any) => { finalize(false, err, null); throw err; });
      }
      finalize(true, null, result);
      return result;
    } catch (err) {
      finalize(false, err, null);
      throw err;
    }
  };

  pool.getQueryCount = () => dbQueryCount;
  pool.resetQueryCount = () => { dbQueryCount = 0; };
  pool.getQueryLog = (options: { limit?: number } = {}) =>
    typeof options.limit === "number" ? dbQueryLog.slice(-options.limit) : [...dbQueryLog];
  pool.resetQueryLog = () => { dbQueryLog.length = 0; };
};

export const attachDevQueryLogger = (poolOrPools: any) => {
  if (!isDev || !poolOrPools) return;
  const inputs = Array.isArray(poolOrPools) ? poolOrPools : [poolOrPools];
  for (const item of inputs) {
    const resolved = resolveLoggerPool(item);
    if (resolved) attachSinglePool(resolved.pool, resolved.name);
  }
};
