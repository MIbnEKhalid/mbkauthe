import { dblogin, dialect } from "../db/pool.js";
import { appVersion, validateConfiguration } from "../config/index.js";
import { authEvents } from "../core/events/index.js";

export interface AuthHealthStatus {
  status: "healthy" | "degraded" | "unhealthy";
  version: string;
  dialect: string;
  database: {
    connected: boolean;
    latencyMs?: number;
    error?: string;
  };
  config: {
    valid: boolean;
    missingRequired: string[];
    warnings: string[];
  };
  timestamp: string;
}

/**
 * Performs a comprehensive health and diagnostics check for MBKAuthe
 */
export async function getAuthHealthReport(): Promise<AuthHealthStatus> {
  const startTime = Date.now();
  let dbConnected = false;
  let dbLatency: number | undefined;
  let dbError: string | undefined;

  try {
    const isSqlite = dialect.name === "sqlite";
    const text = isSqlite ? "SELECT 1 as ping" : "SELECT 1 as ping";
    await dblogin.query(text);
    dbLatency = Date.now() - startTime;
    dbConnected = true;
  } catch (err: any) {
    dbConnected = false;
    dbError = err?.message || String(err);
  }

  const configValidation = validateConfiguration();

  const isHealthy = dbConnected && configValidation.valid;
  const isDegraded = dbConnected && !configValidation.valid;

  return {
    status: isHealthy ? "healthy" : isDegraded ? "degraded" : "unhealthy",
    version: appVersion,
    dialect: dialect.name,
    database: {
      connected: dbConnected,
      latencyMs: dbLatency,
      error: dbError,
    },
    config: {
      valid: configValidation.valid,
      missingRequired: configValidation.missingRequired,
      warnings: configValidation.warnings,
    },
    timestamp: new Date().toISOString(),
  };
}
