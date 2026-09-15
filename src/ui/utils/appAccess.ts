import { mbkautheVar } from "../../config/index.js";

export function isUserAuthorizedForApp(role?: string | null, allowed_apps?: string[] | null): boolean {
  return role === "superadmin" || (
    Array.isArray(allowed_apps) &&
    allowed_apps.some((app) => typeof app === "string" && app.toLowerCase() === mbkautheVar.APP_NAME)
  );
}
