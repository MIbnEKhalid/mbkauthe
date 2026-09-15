# MBKAuthe Documentation & Coding Style Guide

Guidelines for contributing code, tests, and documentation to MBKAuthe.

---

## 1. Documentation Standards

- **TypeScript-First**: All code examples in documentation must use modern TypeScript / ES Module syntax (`import`/`export`).
- **Verifiable Code Snippets**: Every API, method, option, and endpoint documented must match real functions in `src/`.
- **Alert Syntax**: Use standard GitHub alerts for callouts:
  - `> [!NOTE]` for contextual background.
  - `> [!TIP]` for best practices.
  - `> [!IMPORTANT]` for mandatory steps.
  - `> [!WARNING]` for security warnings or breaking changes.
- **Heading IDs**: Use structured markdown headings without HTML formatting inside headings.

---

## 2. Code Architecture & Layer Rules

1. **`core/` Layer**:
   - Must remain pure business logic and in-memory operations.
   - Must never import Express `Request`/`Response` or direct database connections.
2. **`db/` Layer**:
   - All queries must be parameterized (`$1` for pg, `?` for sqlite).
   - Use `BaseRepository` for standard CRUD.
3. **`services/` Layer**:
   - Coordinates domain models, database operations, and emits `authEvents`.
4. **`http/` Layer**:
   - Validates DTOs, calls domain services, and handles HTTP response envelopes.
