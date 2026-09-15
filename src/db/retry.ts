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

export function isRetryableDbError(err: any): boolean {
  if (!err) return false;
  const msg = String(err.message || "").toLowerCase();
  const code = String(err.code || "").toUpperCase();
  if (RETRYABLE_CODES.has(code)) return true;
  return RETRYABLE_MESSAGES.some((sub) => msg.includes(sub));
}

export async function withQueryRetry<T = any>(
  queryFn: () => Promise<T>,
  options: {
    maxRetries?: number;
    initialDelayMs?: number;
    maxDelayMs?: number;
    factor?: number;
    context?: string;
  } = {}
): Promise<T> {
  const maxRetries = Number(options.maxRetries || process.env.DB_MAX_RETRIES || 3);
  const initialDelayMs = Number(options.initialDelayMs || process.env.DB_RETRY_DELAY_MS || 150);
  const maxDelayMs = Number(options.maxDelayMs || 2000);
  const factor = Number(options.factor || 2);
  const context = options.context || "database";

  let lastError: any;
  let delay = initialDelayMs;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await queryFn();
    } catch (err: any) {
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

export function wrapPoolWithRetry<T extends object = any>(pool: T, options: { name?: string; maxRetries?: number } = {}): T {
  if (!pool || (pool as any).__mbkRetryWrapped) return pool;
  (pool as any).__mbkRetryWrapped = true;

  const poolName = options.name || (pool as any).options?.application_name || "pg-pool";
  const maxRetries = options.maxRetries || Number(process.env.DB_MAX_RETRIES) || 3;

  if (typeof (pool as any).on === "function" && !(pool as any).__mbkErrorHandlerAttached) {
    (pool as any).on("error", (err: any) => {
      console.error(`[${poolName}] Pool idle client error (handled):`, err?.message || err);
    });
    (pool as any).__mbkErrorHandlerAttached = true;
  }

  const originalQuery = (pool as any).query.bind(pool);
  const originalConnect = typeof (pool as any).connect === "function" ? (pool as any).connect.bind(pool) : null;

  (pool as any).query = function (...args: any[]) {
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
    (pool as any).connect = function (...args: any[]) {
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

export default wrapPoolWithRetry;
