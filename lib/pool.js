import pkg from "pg";
const { Pool } = pkg;
import { mbkautheVar } from "#config.js";
import dotenv from "dotenv";
dotenv.config();

const poolConfig = {
  connectionString: mbkautheVar.LOGIN_DB,
  ssl: {
    rejectUnauthorized: true,
  },

  // Connection pool tuning for serverless/ephemeral environments (Vercel)
  // - keep max small to avoid exhausting DB connections
  // - reduce idle time so connections are returned sooner
  // - set a short connection timeout to fail fast
  max: 10,
  idleTimeoutMillis: 10000,
  connectionTimeoutMillis: 25000,
};

export const dblogin = new Pool(poolConfig);



// For logging and testing purposes, we can track query counts and logs in development mode.

import path from "path";
import { AsyncLocalStorage } from "async_hooks";

const isDev = process.env.env === 'dev';
const requestContext = isDev ? new AsyncLocalStorage() : null;

export const runWithRequestContext = (req, fn) => {
  if (!isDev || !requestContext) return fn();
  return requestContext.run({ req }, fn);
};

export const getRequestContext = () => {
  if (!isDev || !requestContext) return undefined;
  return requestContext.getStore();
};

if (isDev) {

  // Simple counter for all DB requests made via this pool. This is intentionally
  // lightweight.
  let _dbQueryCount = 0;
  const _dbQueryLog = [];
  const _MAX_QUERY_LOG_ENTRIES = 1000;

  const _origQuery = dblogin.query.bind(dblogin);

  dblogin.query = (...args) => {
    _dbQueryCount++;

    // Track query text for debugging/metrics.
    // `pg` supports (text, values, callback) or (config, callback).
    let queryText = '';
    let queryName = '';
    let queryValues;
    try {
      if (typeof args[0] === 'string') {
        queryText = args[0];
        queryValues = Array.isArray(args[1]) ? args[1] : undefined;
      } else if (args[0] && typeof args[0] === 'object') {
        queryText = args[0].text || '';
        queryName = args[0].name || '';
        queryValues = Array.isArray(args[0].values) ? args[0].values : undefined;
      }
    } catch {
      queryText = '';
    }

    if (!queryText) {
      return _origQuery(...args);
    }

    const startTime = process.hrtime.bigint();
    const toWorkspacePath = (filePath) => {
      const rel = path.relative(process.cwd(), filePath) || filePath;
      return rel.replace(/\\/g, '/');
    };

    const buildCallsite = () => {
      try {
        const stack = new Error().stack || '';
        const lines = stack.split('\n').map(l => l.trim());
        // Skip frames from this wrapper and node internals; pick first app frame.
        const frame = lines.find((line) =>
          line.startsWith('at ') &&
          !line.includes('/lib/pool.js') &&
          !line.includes('node:internal') &&
          !line.includes('internal/process')
        );

        if (!frame) return null;

        const withFunc = /^at\s+([^\s(]+)\s+\((.+):([0-9]+):([0-9]+)\)$/.exec(frame);
        const noFunc = /^at\s+(.+):([0-9]+):([0-9]+)$/.exec(frame);

        if (withFunc) {
          return {
            function: withFunc[1],
            file: toWorkspacePath(withFunc[2]),
            line: Number(withFunc[3]),
            column: Number(withFunc[4])
          };
        }
        if (noFunc) {
          return {
            function: null,
            file: toWorkspacePath(noFunc[1]),
            line: Number(noFunc[2]),
            column: Number(noFunc[3])
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
        username: user?.username || null
      };
    };

    const callsiteSnapshot = buildCallsite();

    const recordLog = (success, error) => {
      const durationMs = Number(process.hrtime.bigint() - startTime) / 1_000_000;
      const request = buildRequestContext();

      _dbQueryLog.push({
        time: new Date().toISOString(),
        query: queryText,
        name: queryName || undefined,
        values: queryValues,
        durationMs,
        success,
        error: error ? { message: error.message, code: error.code } : undefined,
        request,
        pool: {
          total: dblogin.totalCount,
          idle: dblogin.idleCount,
          waiting: dblogin.waitingCount
        },
        callsite: callsiteSnapshot
      });

      if (_dbQueryLog.length > _MAX_QUERY_LOG_ENTRIES) {
        _dbQueryLog.shift();
      }
    };

    try {
      const result = _origQuery(...args);
      if (result && typeof result.then === 'function') {
        return result
          .then((res) => {
            recordLog(true, null);
            return res;
          })
          .catch((err) => {
            recordLog(false, err);
            throw err;
          });
      }

      recordLog(true, null);
      return result;
    } catch (err) {
      recordLog(false, err);
      throw err;
    }
  };

  // Public helpers

  dblogin.getQueryCount = () => _dbQueryCount;
  dblogin.resetQueryCount = () => {
    _dbQueryCount = 0;
  };

  dblogin.getQueryLog = (options = {}) => {
    const { limit } = options;
    if (typeof limit === 'number') {
      return _dbQueryLog.slice(-limit);
    }
    return [..._dbQueryLog];
  };

  dblogin.resetQueryLog = () => {
    _dbQueryLog.length = 0;
  };
}

(async () => {
  try {
    const client = await dblogin.connect();
    client.release();
  } catch (err) {
    console.error("[mbkauthe] Database connection error (pool):", err);
  }
})();