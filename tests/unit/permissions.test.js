import { describe, it, expect } from "vitest";
import {
  StandardActionBits,
  isValidActionMask,
  hasAction,
  combineActionMasks,
  combineResourceMasks,
  applyOverrides,
  defineResource,
  defineResources,
  definePermissions,
  evaluatePermission,
  evaluateRole,
  evaluateAppAccess,
  SUPERADMIN_ROLE,
  GlobalAccess,
  GlobalPermissions,
  authorizationService,
} from "../../dist/index.js";

describe("Bitmask Engine — Action Bits & Mask Operations", () => {
  it("defines standard action bits correctly", () => {
    expect(StandardActionBits.VIEW).toBe(1);
    expect(StandardActionBits.CREATE).toBe(2);
    expect(StandardActionBits.UPDATE).toBe(4);
    expect(StandardActionBits.DELETE).toBe(8);
    expect(StandardActionBits.MANAGE).toBe(16);
  });

  it("evaluates hasAction with single bitwise AND", () => {
    const mask = StandardActionBits.VIEW | StandardActionBits.UPDATE; // 1 | 4 = 5
    expect(hasAction(mask, StandardActionBits.VIEW)).toBe(true);
    expect(hasAction(mask, StandardActionBits.UPDATE)).toBe(true);
    expect(hasAction(mask, StandardActionBits.CREATE)).toBe(false);
    expect(hasAction(mask, StandardActionBits.DELETE)).toBe(false);
  });

  it("combines action masks using bitwise OR", () => {
    const combined = combineActionMasks(1, 2, 4, 8);
    expect(combined).toBe(15);
  });

  it("combines resource mask maps across multiple roles", () => {
    const role1 = { tasks: 1, projects: 2 };
    const role2 = { tasks: 4, documents: 1 };
    const combined = combineResourceMasks(role1, role2);

    expect(combined.tasks).toBe(5); // 1 | 4
    expect(combined.projects).toBe(2);
    expect(combined.documents).toBe(1);
  });

  it("handles explicit user allow and deny overrides deterministically", () => {
    const base = { tasks: 15, projects: 7 }; // tasks has view(1), create(2), update(4), delete(8)
    const overrides = {
      allows: { tasks: 16, documents: 1 }, // grant manage(16)
      denies: { tasks: 8 }, // strip delete(8)
    };

    const effective = applyOverrides(base, overrides);
    expect(effective.tasks).toBe(23); // (15 | 16) & ~8 = 31 & ~8 = 23 (1 | 2 | 4 | 16)
    expect(hasAction(effective.tasks, StandardActionBits.DELETE)).toBe(false);
    expect(hasAction(effective.tasks, StandardActionBits.VIEW)).toBe(true);
    expect(hasAction(effective.tasks, 16)).toBe(true);
    expect(effective.documents).toBe(1);
  });

  it("validates 31-bit non-negative integer limits", () => {
    expect(isValidActionMask(1)).toBe(true);
    expect(isValidActionMask(0x7fffffff)).toBe(true);
    expect(isValidActionMask(-1)).toBe(false);
    expect(isValidActionMask(1.5)).toBe(false);
  });
});

describe("Resource Declarations — defineResource & defineResources", () => {
  it("defines resource actions deterministically", () => {
    const Tasks = defineResource("tasks", {
      view: "View tasks",
      create: "Create tasks",
      update: "Edit tasks",
      delete: "Delete tasks",
      comment: "Comment on tasks",
    });

    expect(Tasks.name).toBe("tasks");
    expect(Tasks.actions.view.mask).toBe(1);
    expect(Tasks.actions.create.mask).toBe(2);
    expect(Tasks.actions.update.mask).toBe(4);
    expect(Tasks.actions.delete.mask).toBe(8);
    expect(Tasks.actions.comment.mask).toBe(32); // custom bit (1 << 5)
    expect(Tasks.allMask).toBe(47); // 1 + 2 + 4 + 8 + 32
    expect(Tasks.actions["*"].mask).toBe(47);
  });

  it("supports valueOf and toString for ActionDescriptor", () => {
    const Tasks = defineResource("tasks", { view: "View tasks" });
    expect(Number(Tasks.actions.view)).toBe(1);
    expect(String(Tasks.actions.view)).toBe("tasks:view");
  });

  it("defineResources parses manifest and resolves wildcard role permissions", () => {
    const Permissions = defineResources(
      {
        tasks: { view: "View", create: "Create" },
        projects: { view: "View", delete: "Delete" },
      },
      {
        roles: {
          admin: ["*"],
          member: ["tasks:view", "tasks:create", "projects:view"],
        },
      }
    );

    expect(Permissions.tasks.view.mask).toBe(1);
    expect(Permissions.tasks.create.mask).toBe(2);
    expect(Permissions.projects.view.mask).toBe(1);
    expect(Permissions.projects.delete.mask).toBe(8);

    const roles = Permissions.__roles;
    expect(roles.admin.permissions.tasks).toBe(Permissions.tasks["*"].mask);
    expect(roles.admin.permissions.projects).toBe(Permissions.projects["*"].mask);

    expect(roles.member.permissions.tasks).toBe(3); // 1 | 2
    expect(roles.member.permissions.projects).toBe(1);
  });
});

describe("Authorization Evaluation — evaluatePermission & AuthorizationService", () => {
  const Permissions = defineResources({
    tasks: { view: "View", create: "Create", delete: "Delete" },
    projects: { view: "View", edit: "Edit" },
  });

  it("grants access when user has the required action bit", () => {
    const user = {
      role: "normaluser",
      perms: {
        tasks: Permissions.tasks.view.mask | Permissions.tasks.create.mask, // 3
      },
    };

    expect(evaluatePermission({ masks: user.perms }, Permissions.tasks.view)).toBe(true);
    expect(evaluatePermission({ masks: user.perms }, Permissions.tasks.create)).toBe(true);
    expect(evaluatePermission({ masks: user.perms }, Permissions.tasks.delete)).toBe(false);
    expect(evaluatePermission({ masks: user.perms }, Permissions.projects.view)).toBe(false);
  });

  it("bypasses all checks instantly for SuperAdmin", () => {
    const superUser = { role: SUPERADMIN_ROLE, isSuperadmin: true };
    expect(evaluatePermission({ isSuperadmin: true }, Permissions.tasks.delete)).toBe(true);
    expect(evaluatePermission({ isSuperadmin: true }, "unknown:action")).toBe(true);
    expect(authorizationService.hasPermission(superUser, Permissions.tasks.delete)).toBe(true);
    expect(authorizationService.hasPermission(superUser, "anything")).toBe(true);
  });

  it("rejects unauthorized actions by default", () => {
    const guestUser = { role: "guest", perms: {} };
    expect(authorizationService.hasPermission(guestUser, Permissions.tasks.view)).toBe(false);
    expect(authorizationService.hasPermission(null, Permissions.tasks.view)).toBe(false);
  });

  it("isolates different resources and applications", () => {
    const user = {
      role: "normaluser",
      perms: {
        tasks: Permissions.tasks.view.mask, // 1
      },
    };
    // Projects.view has mask 1, but resource is different!
    expect(evaluatePermission({ masks: user.perms }, Permissions.projects.view)).toBe(false);
  });

  it("evaluates roles correctly", () => {
    const ctx = { role: "developer", roles: ["developer", "reviewer"] };
    expect(evaluateRole(ctx, "developer")).toBe(true);
    expect(evaluateRole(ctx, "reviewer")).toBe(true);
    expect(evaluateRole(ctx, "admin")).toBe(false);
    expect(evaluateRole(ctx, ["admin", "developer"])).toBe(true);
  });

  it("evaluates application access boundaries", () => {
    const ctx = { isSuperadmin: false, allowedApps: ["portal", "mbkauthe"] };
    expect(evaluateAppAccess(ctx, "portal")).toBe(true);
    expect(evaluateAppAccess(ctx, "mbkauthe")).toBe(true);
    expect(evaluateAppAccess(ctx, "secret_app")).toBe(false);
  });
});

describe("Global Permissions", () => {
  it("provides GlobalAccess and GlobalPermissions descriptor", () => {
    expect(GlobalAccess.resource).toBe("global");
    expect(GlobalAccess.action).toBe("access");
    expect(GlobalAccess.mask).toBe(1);
    expect(GlobalPermissions.basic.access.mask).toBe(1);
  });
});
