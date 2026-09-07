# MBKAuthe Documentation

🌐 **Interactive Documentation Portal**: [https://mbkauthe.mbktech.org](https://mbkauthe.mbktech.org)

This directory is organized by how the documentation is used:

- **Guides** - setup, architecture, and operational walkthroughs.
- **Reference** - detailed API endpoints, middleware, types, and error-code documentation.
- **Schema** - database architecture, table definitions, and executable SQL.
- **Diagrams** - Mermaid source files and rendered visual flows.

## Start here

- [Interactive Documentation Portal](https://mbkauthe.mbktech.org/docs)
- [Project README](../README.md)
- [Configuration guide](guides/configuration.md)
- [Database guide](guides/database.md)
- [Dual-database & repository architecture guide](guides/dual-database-guide.md)
- [Role-Based Access Control (RBAC)](guides/rbac.md)
- [Social OAuth integration](guides/oauth.md)
- [Two-Factor Authentication (2FA)](guides/2fa.md)
- [API tokens & programmatic auth](guides/api-tokens.md)
- [CLI authentication (device flow)](guides/cli-auth.md)
- [Production deployment checklist](guides/deployment.md)
- [API reference](reference/api.md)
- [Endpoints catalog](reference/api/endpoints.md)
- [Middleware reference](reference/api/middleware.md)
- [Operations & rate limits](reference/api/operations.md)
- [Error codes directory](reference/error-codes.md)
- [Code examples & recipes](reference/api/examples.md)
- [Database schema specification](schema/database-schema.md)
- [Documentation style guide](STYLE.md)
- [Changelog & releases](reference/changelog.md)

## Source layout

- `guides/` - task-oriented setup and operations docs.
- `reference/` - detailed facts, route lists, middleware details, and error-code documentation.
- `reference/api/` - split API reference sections included from the API index.
- `schema/` - executable SQL and schema specification assets.
- `diagrams/` - Mermaid source files.
- `images/` - rendered diagram outputs and documentation images.

## Assets

- [Database schema SQL - PostgreSQL](schema/db.sql)
- [Database schema SQL - SQLite](schema/db.sqlite.sql)
- [Authentication flow Mermaid source](diagrams/auth-flows.mmd)
- [Authentication process Mermaid source](diagrams/auth-processes.mmd)
- [Rendered diagram images](images/)

<!--
 * MBKAuthe
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 * Source: https://github.com/MIbnEKhalid/mbkauthe
-->