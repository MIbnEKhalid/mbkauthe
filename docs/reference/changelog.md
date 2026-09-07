# Changelog & Releases

[Back to docs index](../README.md) | [Back to project README](../../README.md)

All notable releases and architectural milestones for **MBKAuthe** are documented here.

---

## [5.6.0] - 2026-09-06

### Added
- **Dual-Database Architecture**: Unified `SqliteAdapter` and `PostgresAdapter` abstraction conforming to `BaseRepository`.
- **Automatic PostgreSQL to SQLite Query Translation**: `translatePgToSqlite` with parameter re-indexing, regex casts, `ILIKE`, boolean coercions, and UUID generators.
- **Graceful Shutdown Lifecycle**: `registerGracefulShutdown` and `closeAllConnections` for process signal hooks and clean pool draining.
- **RFC 8628 Device Authorization Flow**: Browser-based CLI authentication flow and token template provisioning.

### Enhanced
- Synchronized session cookies (`username`, `fullName`) for client UI consumption.
- Updated `better-sqlite3` and `pg` connection handlers.

---

## [5.0.0] - 2026-08-15

### Added
- Multi-session auto-eviction (`MAX_SESSIONS_PER_USER`) with FIFO stale session cleanup.
- Trusted device tokens with configurable expiration (`DEVICE_TRUST_DURATION_DAYS`).
- Strict session validation helpers (`strictSessVal`, `strictSessRole`).

### Security
- Timing-safe constant time comparisons for API token verification and secret validations.
- Subdomain cookie sharing in production (`IS_DEPLOYED=true`).

---

## [4.0.0] - 2026-06-20

### Added
- GitHub App and Google OAuth2 social login integrations.
- Two-Factor Authentication (TOTP / RFC 6238) via Speakeasy with QR codes.

---

## [1.0.0] - 2026-01-10

### Initial Release
- Core authentication engine for Express.
- Role-based access control (`superadmin`, `normaluser`, `member`, `guest`).
- PBKDF2 password hashing and encrypted session cookies.
