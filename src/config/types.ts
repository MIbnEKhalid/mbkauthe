export interface MBKAuthConfig {
  // Lowercase normalized
  app_name?: string;
  session_secret_key?: string;
  main_secret_token?: string;
  is_deployed?: 'true' | 'false' | 'f' | boolean;
  domain?: string;
  db_type?: 'postgres' | 'sqlite' | string;
  login_db?: string;
  sqlite_path?: string;
  mbkauth_two_fa_enable?: 'true' | 'false' | 'f' | boolean;
  cookie_expire_time?: number;
  device_trust_duration_days?: number;
  github_login_enabled?: 'true' | 'false' | 'f' | boolean;
  github_app_client_id?: string;
  github_app_client_secret?: string;
  github_client_id?: string;
  github_client_secret?: string;
  google_login_enabled?: 'true' | 'false' | 'f' | boolean;
  google_client_id?: string;
  google_client_secret?: string;
  login_redirect_url?: string;
  max_sessions_per_user?: number;
  cli_auth_base_url?: string;
  cli_auth_enabled?: 'true' | 'false' | 'f' | boolean;

  // Uppercase canonical
  APP_NAME: string;
  SESSION_SECRET_KEY: string;
  MAIN_SECRET_TOKEN: string;
  IS_DEPLOYED: 'true' | 'false' | 'f' | boolean;
  DOMAIN: string;
  DB_TYPE?: 'postgres' | 'sqlite' | string;
  LOGIN_DB?: string;
  SQLITE_PATH?: string;
  MBKAUTH_TWO_FA_ENABLE: 'true' | 'false' | 'f' | boolean;
  COOKIE_EXPIRE_TIME?: number;
  DEVICE_TRUST_DURATION_DAYS?: number;
  GITHUB_LOGIN_ENABLED?: 'true' | 'false' | 'f' | boolean;
  GITHUB_APP_CLIENT_ID?: string;
  GITHUB_APP_CLIENT_SECRET?: string;
  GITHUB_CLIENT_ID?: string;
  GITHUB_CLIENT_SECRET?: string;
  GOOGLE_LOGIN_ENABLED?: 'true' | 'false' | 'f' | boolean;
  GOOGLE_CLIENT_ID?: string;
  GOOGLE_CLIENT_SECRET?: string;
  LOGIN_REDIRECT_URL?: string;
  MAX_SESSIONS_PER_USER?: number;
  CLI_AUTH_BASE_URL?: string;
  CLI_AUTH_ENABLED?: 'true' | 'false' | 'f' | boolean;

  [key: string]: any;
}
