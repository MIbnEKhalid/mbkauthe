import { mbkautheVar } from "#config.js";

export function isUserAuthorizedForApp(role, allowedApps) {
  if (role === "SuperAdmin") return true;
  return Array.isArray(allowedApps)
    && allowedApps.length > 0
    && allowedApps.some((app) => app && app.toLowerCase() === mbkautheVar.APP_NAME);
}
