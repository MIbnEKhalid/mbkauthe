# Code Examples & Recipes

Ready-to-use recipes and full integration patterns for MBKAuthe v6.

---

## 1. Complete Express TypeScript Server

```typescript
import express from "express";
import mbkauthe, { sessVal, roleChk, sessPerm } from "mbkauthe";
import { definePermissions } from "mbkauthe/core";
import { syncAppPermissions } from "mbkauthe/services";
import { authEvents } from "mbkauthe/core";

const app = express();

// 1. Define App Permissions
const AppPermissions = definePermissions({
  appKey: "analytics",
  permissions: {
    reports: {
      view: "View analytics reports",
      export: "Export CSV datasets",
    },
  },
  roles: {
    analyst: {
      label: "Data Analyst",
      permissions: ["analytics:reports:*"],
    },
  },
});

// 2. Register Audit Event Listeners
authEvents.on("auth:login:success", (evt) => {
  console.log(`[Audit] ${evt.username} logged in from ${evt.ip}`);
});

// 3. Mount MBKAuthe Router
app.use(mbkauthe);

// 4. Protect Routes
app.get("/api/reports", sessVal, permChk(AppPermissions.reports.view), (req, res) => {
  res.json({ reports: [{ id: 1, title: "Q3 Traffic" }] });
});

app.post("/api/reports/export", sessPerm(AppPermissions.reports.export), (req, res) => {
  res.json({ status: "exported", downloadUrl: "/downloads/q3.csv" });
});

// 5. Start Server & Sync Permissions
const PORT = process.env.PORT || 3000;
app.listen(PORT, async () => {
  await syncAppPermissions(AppPermissions);
  console.log(`Server running on http://localhost:${PORT}`);
});
```

---

## 2. Custom Database Repository Extension

Extend `BaseRepository` to create custom models with dual-database support:

```typescript
import { BaseRepository, dblogin, dialect } from "mbkauthe/db";

export interface Project {
  id: number;
  name: string;
  owner_id: number;
  created_at: Date;
}

export class ProjectRepository extends BaseRepository<Project> {
  constructor() {
    super("projects", dblogin, dialect);
  }

  async findByOwner(ownerId: number): Promise<Project[]> {
    return this.findMany({ owner_id: ownerId });
  }

  async createProject(name: string, ownerId: number): Promise<Project> {
    return this.insert({ name, owner_id: ownerId });
  }
}

export const projectRepository = new ProjectRepository();
```

---

## 3. Programmatic Login & Token Creation

```typescript
import { authService, apiTokenService } from "mbkauthe/services";

// Authenticate programmatically
const loginResult = await authService.authenticate({
  username: "developer",
  password: "securePassword123",
});

if (loginResult.success) {
  console.log("Logged in user:", loginResult.user.username);

  // Issue Personal Access Token
  const { token } = await apiTokenService.createToken({
    userId: loginResult.user.id,
    name: "CLI Token",
    scopes: ["analytics:reports:view"],
    expiresInDays: 30,
  });

  console.log("Generated PAT:", token);
}
```
