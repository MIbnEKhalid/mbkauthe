import { mbkautheVar } from "../../config/index.js";

export function isUserAuthorizedForApp(
  userOrRole: any,
  allowedAppsOrTargetApp?: any,
  targetApp: string = mbkautheVar.APP_NAME
): boolean {
  if (!userOrRole) return false;

  // Handle (role, allowed_apps, targetApp)
  if (typeof userOrRole === "string" && (Array.isArray(allowedAppsOrTargetApp) || allowedAppsOrTargetApp === undefined)) {
    const role = userOrRole.toLowerCase();
    if (role === "superadmin") return true;
    const allowed = allowedAppsOrTargetApp || [];
    const app = (targetApp || mbkautheVar.APP_NAME || "").toLowerCase();
    return Array.isArray(allowed) && allowed.some((a: any) => String(a).toLowerCase() === app);
  }

  // Handle (userObject, targetApp)
  const user = userOrRole;
  if (user.role === "superadmin") return true;
  const allowed = user.allowed_apps || user.user_allowed_apps || [];
  const app = (typeof allowedAppsOrTargetApp === "string" ? allowedAppsOrTargetApp : targetApp || mbkautheVar.APP_NAME || "").toLowerCase();
  return Array.isArray(allowed) && allowed.some((a: any) => String(a).toLowerCase() === app);
}

