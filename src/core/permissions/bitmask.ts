/**
 * MBKAuthe — Numeric Permission Bitmask Engine
 * Fast, pure bitwise operations for resource-scoped access control.
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 */

import type { ResourceMasks, UserPermissionOverrides } from "../types/permission.types.js";

/**
 * Standard CRUD action bits (deterministic, zero collision).
 * Each bit position represents a unique action on a resource.
 */
export const StandardActionBits = {
  VIEW: 1 << 0,   // 1
  CREATE: 1 << 1, // 2
  UPDATE: 1 << 2, // 4
  DELETE: 1 << 3, // 8
  MANAGE: 1 << 4, // 16
} as const;

/**
 * Validates that an action mask is a non-negative 31-bit integer.
 */
export function isValidActionMask(mask: number): boolean {
  return typeof mask === "number" && Number.isInteger(mask) && mask >= 0 && mask <= 0x7fffffff;
}

/**
 * Tests whether `userMask` contains all required bits of `requiredMask`.
 * Evaluation takes a single CPU bitwise AND cycle (< 1ns).
 */
export function hasAction(userMask: number, requiredMask: number): boolean {
  if (!userMask || !requiredMask) return false;
  return (userMask & requiredMask) === requiredMask;
}

/**
 * Combines multiple action masks using bitwise OR.
 */
export function combineActionMasks(...masks: number[]): number {
  let combined = 0;
  for (const m of masks) {
    if (typeof m === "number" && m > 0) {
      combined |= m;
    }
  }
  return combined;
}

/**
 * Combines multiple role resource mask maps using bitwise OR.
 * e.g. { tasks: 1 } | { tasks: 4, projects: 1 } => { tasks: 5, projects: 1 }
 */
export function combineResourceMasks(...maps: (ResourceMasks | undefined | null)[]): ResourceMasks {
  const result: ResourceMasks = {};
  for (const map of maps) {
    if (!map) continue;
    for (const [resource, mask] of Object.entries(map)) {
      if (typeof mask === "number" && mask > 0) {
        result[resource] = (result[resource] || 0) | mask;
      }
    }
  }
  return result;
}

/**
 * Computes effective permissions with explicit user overrides.
 * Formula: (roleMask | userAllows) & ~userDenies
 * Explicit denials deterministically strip granted bits.
 */
export function applyOverrides(baseMasks: ResourceMasks, overrides?: UserPermissionOverrides | null): ResourceMasks {
  if (!overrides) return { ...baseMasks };

  const result: ResourceMasks = { ...baseMasks };

  if (overrides.allows) {
    for (const [res, allowMask] of Object.entries(overrides.allows)) {
      if (typeof allowMask === "number" && allowMask > 0) {
        result[res] = (result[res] || 0) | allowMask;
      }
    }
  }

  if (overrides.denies) {
    for (const [res, denyMask] of Object.entries(overrides.denies)) {
      if (typeof denyMask === "number" && denyMask > 0 && result[res]) {
        result[res] = result[res] & ~denyMask;
        if (result[res] <= 0) {
          delete result[res];
        }
      }
    }
  }

  return result;
}
