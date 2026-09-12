/**
 * MBKAuthe - Database Layer
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 * Source: https://github.com/MIbnEKhalid/mbkauthe
 */

export { BaseRepository } from "../repositories/BaseRepository.js";
export { SqliteAdapter, SqlitePool, Mutex, SqliteClient } from "./sqlitePool.js";
export { PostgresAdapter } from "./PostgresAdapter.js";
export { postgresDialect } from "./dialects/postgres.js";
export { sqliteDialect } from "./dialects/sqlite.js";
export { applySchema } from "./applySchema.js";
export { registerGracefulShutdown, closeAllConnections } from "./gracefulShutdown.js";
export { translatePgToSqlite } from "./sqlSqliteTranslate.js";
export { AuthRepository, normalizeUserRow } from "../repositories/AuthRepository.js";
export { ApiTokenRepository, apiTokenRepository } from "../repositories/ApiTokenRepository.js";
export { PermissionRepository, permissionRepository } from "../repositories/PermissionRepository.js";
export { CliAuthSessionRepository, cliAuthSessionRepository } from "../repositories/CliAuthSessionRepository.js";
