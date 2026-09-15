# Database Schema & DDL Reference

MBKAuthe v6 maintains identical entity relational models across PostgreSQL and SQLite databases.

---

## Entity Relational Tables

### 1. `users`
Core user account credentials, roles, and provider identifiers.
- `id` (INTEGER / SERIAL PRIMARY KEY)
- `username` (VARCHAR(255) UNIQUE NOT NULL)
- `password_hash` (TEXT NOT NULL)
- `email` (VARCHAR(255) UNIQUE)
- `role` (VARCHAR(50) DEFAULT 'normaluser')
- `is_active` (BOOLEAN DEFAULT TRUE / INTEGER DEFAULT 1)
- `two_factor_enabled` (BOOLEAN DEFAULT FALSE / INTEGER DEFAULT 0)
- `two_factor_secret` (TEXT)
- `github_id` (VARCHAR(255))
- `google_id` (VARCHAR(255))
- `created_at` (TIMESTAMP DEFAULT NOW())
- `updated_at` (TIMESTAMP DEFAULT NOW())

### 2. `app_sessions` / `sessions`
Active session storage with device information and expiration.
- `sid` (VARCHAR(255) PRIMARY KEY)
- `user_id` (INTEGER REFERENCES users(id) ON DELETE CASCADE)
- `sess` (TEXT / JSONB NOT NULL)
- `device_id` (VARCHAR(255))
- `expire` (TIMESTAMP NOT NULL)

### 3. `api_tokens`
Hashed Personal Access Tokens with custom scopes.
- `id` (SERIAL PRIMARY KEY)
- `user_id` (INTEGER REFERENCES users(id) ON DELETE CASCADE)
- `name` (VARCHAR(255) NOT NULL)
- `token_hash` (VARCHAR(255) UNIQUE NOT NULL)
- `scopes` (TEXT NOT NULL)
- `expires_at` (TIMESTAMP)
- `last_used_at` (TIMESTAMP)
- `created_at` (TIMESTAMP DEFAULT NOW())

### 4. `cli_auth_sessions`
RFC 8628 device authorization requests and polling state.
- `id` (SERIAL PRIMARY KEY)
- `device_code` (VARCHAR(255) UNIQUE NOT NULL)
- `user_code` (VARCHAR(50) UNIQUE NOT NULL)
- `client_name` (VARCHAR(255) NOT NULL)
- `status` (VARCHAR(50) DEFAULT 'pending')
- `user_id` (INTEGER REFERENCES users(id))
- `token_hash` (VARCHAR(255))
- `expires_at` (TIMESTAMP NOT NULL)
- `created_at` (TIMESTAMP DEFAULT NOW())

### 5. `permissions_catalog` & `roles_catalog`
Dynamic permission manifests and role definitions.
- `id` (SERIAL PRIMARY KEY)
- `app_key` (VARCHAR(100) NOT NULL)
- `service_key` (VARCHAR(100) NOT NULL)
- `action_key` (VARCHAR(100) NOT NULL)
- `permission` (VARCHAR(255) UNIQUE NOT NULL)
- `label` (VARCHAR(255))
- `synced_at` (TIMESTAMP DEFAULT NOW())

### 6. `device_trust`
Trusted 2FA device tokens.
- `id` (SERIAL PRIMARY KEY)
- `user_id` (INTEGER REFERENCES users(id) ON DELETE CASCADE)
- `device_token_hash` (VARCHAR(255) UNIQUE NOT NULL)
- `device_info` (TEXT)
- `expires_at` (TIMESTAMP NOT NULL)
- `created_at` (TIMESTAMP DEFAULT NOW())
