/**
 * MBKAuthe — Authentication & Authorization Handlebars Helpers
 * Pure auth & permission helpers. General helpers are imported directly from mbkutils.
 */

import { hasPermission as mbkHasPermission } from "../../core/permissions/roleRegistry.js";

const isSuperAdminUser = (user: any, root: any): boolean => {
  const role = user?.role || root?.role;
  return typeof role === "string" && role.trim().toLowerCase() === "superadmin";
};

const resolveUserContext = (context: any, options: any): any => {
  const root = options?.data?.root || context;
  if (root?.sessionUser) return root.sessionUser;
  if (root?.user && typeof root.user === "object") return root.user;
  if (root?.role) return { role: root.role, roles: root.roles || [root.role], overrides: root.overrides || null };
  return null;
};

const checkPermHelper = (self: any, requiredPermission: string, options: any): boolean => {
  const user = resolveUserContext(self, options);
  return isSuperAdminUser(user, options?.data?.root || self) || (Boolean(requiredPermission && user) && mbkHasPermission(user, requiredPermission));
};

export const authHandlebarsHelpers: Record<string, any> = {
  // Permissions & Auth
  hasPerm: function (this: any, requiredPermission: string, options: any) { return checkPermHelper(this, requiredPermission, options); },
  hasPermission: function (this: any, requiredPermission: string, options: any) { return checkPermHelper(this, requiredPermission, options); },

  hasAnyPerm: function (this: any, ...args: any[]) {
    const options = args.pop();
    const user = resolveUserContext(this, options);
    if (isSuperAdminUser(user, options?.data?.root || this)) return true;
    return Boolean(user) && args.some((perm) => typeof perm === "string" && mbkHasPermission(user, perm));
  },

  isSuperAdmin: function (this: any, options: any) {
    return isSuperAdminUser(resolveUserContext(this, options), options?.data?.root || this);
  },

  can: function (this: any, requiredPermission: string, options: any) {
    const allowed = checkPermHelper(this, requiredPermission, options);
    return options && typeof options.fn === "function" ? (allowed ? options.fn(this) : options.inverse(this)) : allowed;
  },

  getRoleColor: (role: string) => ({ superadmin: "danger", admin: "warning", normaluser: "success", guest: "secondary" })[role?.toLowerCase()] || "secondary",
};

export default authHandlebarsHelpers;