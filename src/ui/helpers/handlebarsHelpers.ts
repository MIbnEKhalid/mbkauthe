/**
 * MBKAuthe — Authentication & Authorization Handlebars Helpers
 * Pure auth & bitmask permission helpers.
 */

import { evaluatePermission } from "../../core/permissions/evaluator.js";
import { appVersion } from "../../config/env.js";

const isSuperAdminUser = (user: any, root: any): boolean => {
  const role = user?.role || root?.role;
  return typeof role === "string" && role.trim().toLowerCase() === "superadmin";
};

const resolveUserContext = (context: any, options: any): any => {
  const root = options?.data?.root || context;
  if (root?.sessionUser) return root.sessionUser;
  if (root?.user && typeof root.user === "object") return root.user;
  if (root?.role) return { role: root.role, roles: root.roles || [root.role], perms: root.perms || root.permissions || {} };
  return null;
};

const extractUserMasks = (user: any): Record<string, number> => {
  const masks: Record<string, number> = {};
  if (user?.perms && typeof user.perms === "object") {
    Object.assign(masks, user.perms);
  } else if (user?.permissions && typeof user.permissions === "object" && !Array.isArray(user.permissions)) {
    Object.assign(masks, user.permissions);
  }

  // Handle overrides or string permissions
  const rawList = Array.isArray(user?.permissions)
    ? user.permissions
    : (Array.isArray(user?.overrides?.allows) ? user.overrides.allows : []);

  for (const item of rawList) {
    if (typeof item === "string") {
      const raw = item.trim().toLowerCase();
      masks[raw] = 1;
      if (raw.includes(":")) {
        const parts = raw.split(":");
        const res = parts.length === 3 ? parts[1] : parts[0];
        masks[res] = (masks[res] || 0) | 1;
      }
    }
  }

  return masks;
};

const checkPermHelper = (self: any, requiredPermission: any, options: any): boolean => {
  const user = resolveUserContext(self, options);
  if (!user) return false;
  const isSuper = isSuperAdminUser(user, options?.data?.root || self);
  if (isSuper) return true;
  const masks = extractUserMasks(user);
  return evaluatePermission({ isSuperadmin: isSuper, role: user.role, roles: user.roles, masks }, requiredPermission);
};

export const authHandlebarsHelpers: Record<string, any> = {
  // Permissions & Auth
  hasPerm: function (this: any, requiredPermission: any, options: any) { return checkPermHelper(this, requiredPermission, options); },
  hasPermission: function (this: any, requiredPermission: any, options: any) { return checkPermHelper(this, requiredPermission, options); },

  hasAnyPerm: function (this: any, ...args: any[]) {
    const options = args.pop();
    const user = resolveUserContext(this, options);
    if (!user) return false;
    if (isSuperAdminUser(user, options?.data?.root || this)) return true;
    const masks = extractUserMasks(user);
    return args.some((perm) => perm && evaluatePermission({ isSuperadmin: false, role: user.role, roles: user.roles, masks }, perm));
  },

  isSuperAdmin: function (this: any, options: any) {
    return isSuperAdminUser(resolveUserContext(this, options), options?.data?.root || this);
  },

  can: function (this: any, requiredPermission: any, options: any) {
    const allowed = checkPermHelper(this, requiredPermission, options);
    return options && typeof options.fn === "function" ? (allowed ? options.fn(this) : options.inverse(this)) : allowed;
  },

  getRoleColor: (role: string) => ({ superadmin: "danger", admin: "warning", normaluser: "success", guest: "secondary" })[role?.toLowerCase()] || "secondary",
  cachebust: (target?: any) => {
    const v = typeof target === "string" && /^\d+\./.test(target) ? target : (appVersion || "1.0.0");
    return `?v=${v}`;
  },
  acachebust: (version?: any) => {
    const v = typeof version === "string" ? version : (appVersion || "1.0.0");
    return `?v=${v}`;
  },
};