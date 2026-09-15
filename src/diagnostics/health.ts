import { dblogin, dialect } from "../db/pool.js";
import { appVersion, checkConfigurationStatus } from "../config/index.js";
import { authEvents } from "../core/events/index.js";

export interface AuthHealthStatus {
  status: "healthy" | "degraded" | "unhealthy";
  version: string;
  dialect: string;
  uptimeSeconds: number;
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
    const text = "SELECT 1 as ping";
    await dblogin.query(text);
    dbLatency = Date.now() - startTime;
    dbConnected = true;
  } catch (err: any) {
    dbConnected = false;
    dbError = err?.message || String(err);
  }

  const configStatus = checkConfigurationStatus();

  const isHealthy = dbConnected && configStatus.valid;
  const isDegraded = dbConnected && !configStatus.valid;

  return {
    status: isHealthy ? "healthy" : isDegraded ? "degraded" : "unhealthy",
    version: appVersion,
    dialect: dialect.name,
    uptimeSeconds: Math.floor(process.uptime()),
    database: {
      connected: dbConnected,
      latencyMs: dbLatency,
      error: dbError,
    },
    config: {
      valid: configStatus.valid,
      missingRequired: configStatus.missingRequired,
      warnings: configStatus.warnings,
    },
    timestamp: new Date().toISOString(),
  };
}
