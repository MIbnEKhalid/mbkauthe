import { mbkautheVar } from "#config.js";

export function isUserAuthorizedForApp(role, allowed_apps) {
  return role === "superadmin" || (
    Array.isArray(allowed_apps) &&
    allowed_apps.some((app) => typeof app === "string" && app.toLowerCase() === mbkautheVar.APP_NAME)
  );
}
