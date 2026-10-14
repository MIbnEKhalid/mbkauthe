/**
 * MBKAuthe — Bitmask Authorization Types
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 */

export type ResourceMasks = Record<string, number>;

export interface ActionDescriptor {
  readonly resource: string;
  readonly action: string;
  readonly mask: number;
  readonly id?: number;
  readonly key?: string;
  readonly label?: string;
  valueOf(): number;
  toString(): string;
}

export type PermissionTarget = ActionDescriptor | { resource: string; mask: number } | string | number;

export interface ResourceDefinition {
  readonly name: string;
  readonly label?: string;
  readonly app?: string;
  readonly actions: Record<string, ActionDescriptor>;
  readonly allMask: number;
}

export interface RoleDefinition {
  id?: number | string;
  name: string;
  label?: string;
  description?: string;
  is_system?: boolean;
  permissions: ResourceMasks;
  created_at?: Date | string;
  updated_at?: Date | string;
}

export interface UserPermissionOverrides {
  allows?: ResourceMasks;
  denies?: ResourceMasks;
}

export interface UserAuthorizationSnapshot {
  role: string;
  roles: string[];
  masks: ResourceMasks;
  overrides?: UserPermissionOverrides;
  isSuperadmin: boolean;
  perm_version: number;
}

export interface DefineResourcesOptions {
  app?: string;
  fallbackAppKey?: string;
  roles?: Record<string, { label?: string; description?: string; permissions?: Record<string, number> | string[] }>;
}
