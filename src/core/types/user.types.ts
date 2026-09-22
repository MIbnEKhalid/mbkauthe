export interface AuthUser {
  user_id: string | number;
  username: string;
  role: 'superadmin' | 'normaluser' | 'guest' | string;
  full_name?: string;
  image?: string;
  is_active?: boolean | number;
  is_local_only?: boolean | number;
  is_enabled?: boolean | null;
  origin?: string;
  domain?: string;
  allowed_apps?: string[];
  user_allowed_apps?: string[];
  permissions?: string[] | Record<string, boolean>;
  [key: string]: any;
}

export interface UserContext {
  userLoggedIn: boolean;
  user_id: string | number;
  username: string;
  full_name: string;
  role: string;
  allowed_apps: string[];
  is_local_only?: boolean;
  origin?: string;
  domain?: string;
}

export function isLocalOnlyUser(val: unknown): boolean {
  if (val === true || val === 1 || val === "1" || val === "true") return true;
  return false;
}

