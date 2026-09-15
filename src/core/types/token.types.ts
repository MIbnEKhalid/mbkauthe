export interface ApiTokenRecord {
  id: number | string;
  username: string;
  name?: string;
  token_hash?: string;
  prefix?: string;
  permissions?: any;
  token_permissions?: string[];
  last_used?: Date | string | null;
  created_at?: Date | string;
  expires_at?: Date | string | null;
  email?: string;
  role?: string;
  full_name?: string;
  formatted_created?: string;
  formatted_expires?: string;
  is_active?: boolean;
  [key: string]: any;
}

export interface ApiTokenStats {
  total_tokens: number;
  users_with_tokens: number;
  never_expire: number;
  expired: number;
  active_with_expiry: number;
  used_tokens: number;
  never_used: number;
  [key: string]: any;
}

export interface ApiTokenProfile {
  id: number | string;
  profile_key?: string;
  name: string;
  description?: string;
  permissions: string[];
  expires_in_days: number;
  is_active?: boolean;
  created_at?: string | Date;
  updated_at?: string | Date;
  [key: string]: any;
}

export interface CliAuthSession {
  id: number | string;
  device_code_hash: string;
  user_code_hash: string;
  client_name: string;
  profile_id?: number | null;
  username?: string | null;
  token_id?: number | string | null;
  pending_token?: string | null;
  status: "pending" | "approved" | "denied" | "expired" | "completed" | string;
  expires_at: Date | string;
  created_at?: Date | string;
  approved_at?: Date | string | null;
  [key: string]: any;
}
