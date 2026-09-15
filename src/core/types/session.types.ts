import { AuthUser } from "./user.types.js";

export interface SessionUser {
  session_id?: string;
  user_id?: string | number;
  username: string;
  full_name?: string;
  role?: string;
  allowed_apps?: string[];
  roles?: string[];
  overrides?: {
    allows?: string[];
    denies?: string[];
  };
  permissions?: {
    allows?: string[];
    denies?: string[];
  };
  [key: string]: any;
}

export interface PreAuthUser {
  user_id?: string | number;
  username: string;
  role: string;
  login_method?: "password" | "github" | "google" | string;
  redirect_url?: string | null;
  allowed_apps?: string[];
  full_name?: string;
  image?: string | null;
  [key: string]: any;
}

export interface SessionData {
  user?: SessionUser | AuthUser;
  pre_auth_user?: PreAuthUser;
  oauth_redirect?: string;
  oauth_csrf_token?: string;
  [key: string]: any;
}
