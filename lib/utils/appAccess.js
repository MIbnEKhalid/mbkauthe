import { mbkautheVar } from "#config.js";

export function isUserAuthorizedForApp(role, allowed_apps) {
  if (role === "superadmin") return true;
  return Array.isArray(allowed_apps)
    && allowed_apps.length > 0
    && allowed_apps.some((app) => app && app.toLowerCase() === mbkautheVar.APP_NAME);
}
