export type PermissionId = number;

export interface PermissionDescriptor {
  id: number;
  appKey: string;
  serviceKey: string;
  actionKey: string;
  label?: string;
  key: string;
  valueOf(): number;
  toString(): string;
}

export type PermissionTarget = number | PermissionDescriptor | { id?: number; key?: string; [key: string]: any };

export interface PermissionManifest {
  [domain: string]: {
    [action: string]: string | { id?: number; label: string };
  };
}

export interface DeclaredPermission {
  id?: number;
  serviceKey: string;
  actionKey: string;
  label?: string | null;
}

export interface CatalogPermission {
  id: number;
  app_key: string;
  service_key: string;
  action_key: string;
  label?: string | null;
  is_active: boolean;
  updated_at?: Date | string;
  permission?: string;
}

export interface RoleDefinition {
  id?: number | string;
  name?: string;
  label: string;
  description?: string;
  is_system?: boolean;
  permissions: number[];
  created_at?: Date | string;
  updated_at?: Date | string;
}

export interface RoleRegistryMap {
  [roleName: string]: RoleDefinition | number[] | any;
}

export interface UserPermissionOverride {
  permission_id: number;
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
    allows: number[];
    denies: number[];
  };
  effective?: {
    allows: number[];
    denies: number[];
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
