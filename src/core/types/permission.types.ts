export type PermissionString = string;

export interface PermissionManifest {
  [domain: string]: {
    [action: string]: string;
  };
}

export interface DeclaredPermission {
  serviceKey: string;
  actionKey: string;
  label?: string | null;
}

export interface CatalogPermission {
  id?: number | string;
  app_key: string;
  service_key: string;
  action_key: string;
  label?: string | null;
  is_active: boolean;
  updated_at?: Date | string;
  permission: string;
}

export interface RoleDefinition {
  id?: number | string;
  name?: string;
  label: string;
  description?: string;
  is_system?: boolean;
  permissions: string[];
  created_at?: Date | string;
  updated_at?: Date | string;
}

export interface RoleRegistryMap {
  [roleName: string]: RoleDefinition | string[];
}

export interface UserPermissionOverride {
  permission: string;
  effect: "allow" | "deny";
  granted_by?: string | null;
  created_at?: Date | string;
}

export interface UserRoleAssignment {
  role: string;
  roles: string[];
  perm_version: number;
}

export interface EffectivePermissionsResult {
  roles?: string[];
  overrides?: {
    allows: string[];
    denies: string[];
  };
  effective?: {
    allows: string[];
    denies: string[];
  };
  perm_version?: number;
}

export interface DefinePermissionsOptions {
  appKey?: string | null;
  fallbackAppKey?: string | null;
  roles?: RoleRegistryMap;
}

export interface SyncPermissionsResult {
  synced: number;
  deactivated: number;
  rolesSynced: number;
  appKey: string;
  skipped?: boolean;
}
