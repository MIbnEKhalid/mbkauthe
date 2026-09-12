/**
 * MBKAuthe - Database Retry & Resilience Utilities
 * Handles connection drops, idle client terminations, serverless freeze/thaw, and query timeouts.
 */

const RETRYABLE_MESSAGES = [
  "connection terminated due to connection timeout",
  "connection terminated unexpectedly",
  "connection terminated",
  "timeout exceeded when trying to connect",
  "connection timeout",
  "client has encountered a connection error",
  "client has already been released to the pool",
  "terminating connection due to administrator command",
  "server closed the connection unexpectedly",
  "socket hang up",
  "econnreset",
  "econnrefused",
  "etimedout",
  "enotfound",
  "ehostunreach",
  "ssl syscall error",
  "connection closed",
  "the database system is shutting down",
  "the database system is starting up",
  "the database system is in recovery mode",
  "could not connect to server",
];

const RETRYABLE_CODES = new Set([
  "ECONNRESET",
  "ECONNREFUSED",
  "ETIMEDOUT",
  "EPIPE",
  "EHOSTUNREACH",
  "ENOTFOUND",
  "57P01", // admin_shutdown
  "57P02", // crash_shutdown
  "57P03", // cannot_connect_now
  "53300", // too_many_connections
  "08000", // connection_exception
  "08001", // sqlclient_unable_to_establish_sqlconnection
  "08003", // connection_does_not_exist
  "08004", // sqlserver_rejected_establishment_of_sqlconnection
  "08006", // connection_failure
  "08007", // transaction_resolution_unknown
  "08P01", // protocol_violation
]);

/**
 * Checks if an error is a transient connection error, timeout, or crash that should be retried.
 * @param {Error|any} err
 * @returns {boolean}
 */
export function isRetryableDbError(err) {
  if (!err) return false;

  const msg = String(err.message || "").toLowerCase();
  const code = String(err.code || "").toUpperCase();

  if (RETRYABLE_CODES.has(code)) return true;
  return RETRYABLE_MESSAGES.some((sub) => msg.includes(sub));
}

/**
 * Executes a database operation with exponential backoff and retry on transient connection failures.
 * @param {Function} queryFn
 * @param {Object} [options]
 * @returns {Promise<any>}
 */
export async function withQueryRetry(queryFn, options = {}) {
  const maxRetries = Number(options.maxRetries || process.env.DB_MAX_RETRIES || 3);
  const initialDelayMs = Number(options.initialDelayMs || process.env.DB_RETRY_DELAY_MS || 150);
  const maxDelayMs = Number(options.maxDelayMs || 2000);
  const factor = Number(options.factor || 2);
  const context = options.context || "database";

  let lastError;
  let delay = initialDelayMs;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await queryFn();
    } catch (err) {
      lastError = err;
      if (attempt < maxRetries && isRetryableDbError(err)) {
        const jitter = Math.floor(Math.random() * 50);
        const sleepMs = Math.min(delay + jitter, maxDelayMs);
        console.warn(
          `[${context}] Connection/timeout warning: "${err.message}". Retrying query (attempt ${attempt}/${maxRetries}) in ${sleepMs}ms...`
        );
        await new Promise((resolve) => setTimeout(resolve, sleepMs));
        delay *= factor;
        continue;
      }
      throw err;
    }
  }
  throw lastError;
}

/**
 * Wraps a pg.Pool instance with automatic error handling and query retries on transient connection dropouts.
 * @param {Object} pool - pg.Pool instance
 * @param {Object} [options]
 * @returns {Object} wrapped pool
 */
export function wrapPoolWithRetry(pool, options = {}) {
  if (!pool || pool.__mbkRetryWrapped) return pool;
  pool.__mbkRetryWrapped = true;

  const poolName = options.name || pool.options?.application_name || "pg-pool";
  const maxRetries = options.maxRetries || Number(process.env.DB_MAX_RETRIES) || 3;

  if (typeof pool.on === "function" && !pool.__mbkErrorHandlerAttached) {
    pool.on("error", (err) => {
      console.error(`[${poolName}] Pool idle client error (handled):`, err?.message || err);
    });
    pool.__mbkErrorHandlerAttached = true;
  }

  const originalQuery = pool.query.bind(pool);
  const originalConnect = typeof pool.connect === "function" ? pool.connect.bind(pool) : null;

  pool.query = function (...args) {
    const usesCallback = args.some((arg) => typeof arg === "function");
    if (usesCallback) {
      return originalQuery(...args);
    }

    return withQueryRetry(() => originalQuery(...args), {
      maxRetries,
      context: poolName,
    });
  };

  if (originalConnect) {
    pool.connect = function (...args) {
      const usesCallback = args.some((arg) => typeof arg === "function");
      if (usesCallback) {
        return originalConnect(...args);
      }
      return withQueryRetry(() => originalConnect(...args), {
        maxRetries,
        context: `${poolName}:connect`,
      });
    };
  }

  return pool;
}
