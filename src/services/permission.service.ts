/**
 * Permission Service - Check and manage user permissions
 * Validates: Requirements 4.5, 4.6
 */

import { getMembership, getUserMemberships } from '../repositories/membership.repository';
import { getPermissionsForRoles } from '../repositories/role.repository';
import { hasPermission, hasAllPermissions, hasAnyPermission, normalizePermissions, getEffectiveScope, PermissionScope } from '../utils/permissions';

/**
 * Simple in-memory cache for permissions
 * TTL: 5 minutes
 */
interface CacheEntry {
  permissions: string[];
  timestamp: number;
}

const permissionCache = new Map<string, CacheEntry>();
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

function getCacheKey(userId: string, orgId?: string): string {
  return orgId ? `${userId}:${orgId}` : userId;
}

function getFromCache(key: string): string[] | null {
  const entry = permissionCache.get(key);
  if (!entry) return null;
  
  if (Date.now() - entry.timestamp > CACHE_TTL_MS) {
    permissionCache.delete(key);
    return null;
  }
  
  return entry.permissions;
}

function setCache(key: string, permissions: string[]): void {
  permissionCache.set(key, {
    permissions,
    timestamp: Date.now(),
  });
}

/**
 * Clear permission cache for a user
 */
export function clearPermissionCache(userId: string, orgId?: string): void {
  if (orgId) {
    permissionCache.delete(getCacheKey(userId, orgId));
  } else {
    // Clear all entries for this user
    for (const key of permissionCache.keys()) {
      if (key.startsWith(userId)) {
        permissionCache.delete(key);
      }
    }
  }
}

/**
 * Get all permissions for a user in an organization
 */
export async function getUserPermissions(
  userId: string,
  orgId: string
): Promise<string[]> {
  const cacheKey = getCacheKey(userId, orgId);
  const cached = getFromCache(cacheKey);
  if (cached) {
    return cached;
  }

  const membership = await getMembership(userId, orgId);
  if (!membership || membership.status !== 'active') {
    return [];
  }

  // Get permissions from roles
  const rolePermissions = await getPermissionsForRoles(membership.role_ids);

  // Combine with direct permissions
  const allPermissions = [...rolePermissions, ...membership.direct_permissions];

  // Normalize and deduplicate
  const normalized = normalizePermissions(allPermissions);

  setCache(cacheKey, normalized);
  return normalized;
}

/**
 * Get all permissions for a user across all organizations
 */
export async function getUserAllPermissions(
  userId: string,
  realmId?: string
): Promise<Map<string, string[]>> {
  const memberships = await getUserMemberships({
    user_id: userId,
    realm_id: realmId,
    status: 'active',
  });

  const result = new Map<string, string[]>();

  for (const membership of memberships) {
    const permissions = await getUserPermissions(userId, membership.org_id);
    result.set(membership.org_id, permissions);
  }

  return result;
}

/**
 * Check if user has a specific permission in an organization
 */
export async function checkPermission(
  userId: string,
  orgId: string,
  requiredPermission: string
): Promise<boolean> {
  const permissions = await getUserPermissions(userId, orgId);
  return hasPermission(permissions, requiredPermission);
}

/**
 * Check if user has all required permissions
 */
export async function checkAllPermissions(
  userId: string,
  orgId: string,
  requiredPermissions: string[]
): Promise<boolean> {
  const permissions = await getUserPermissions(userId, orgId);
  return hasAllPermissions(permissions, requiredPermissions);
}

/**
 * Check if user has any of the required permissions
 */
export async function checkAnyPermission(
  userId: string,
  orgId: string,
  requiredPermissions: string[]
): Promise<boolean> {
  const permissions = await getUserPermissions(userId, orgId);
  return hasAnyPermission(permissions, requiredPermissions);
}

/**
 * Get effective scope for a user's permission
 */
export async function getUserEffectiveScope(
  userId: string,
  orgId: string,
  resource: string,
  action: string
): Promise<PermissionScope | null> {
  const permissions = await getUserPermissions(userId, orgId);
  return getEffectiveScope(permissions, resource, action);
}

/**
 * Permission check result with details
 */
export interface PermissionCheckResult {
  allowed: boolean;
  reason?: string;
  effectiveScope?: PermissionScope | null;
}

/**
 * Detailed permission check with scope information
 */
export async function checkPermissionDetailed(
  userId: string,
  orgId: string,
  resource: string,
  action: string,
  requiredScope: PermissionScope = 'own'
): Promise<PermissionCheckResult> {
  const permissions = await getUserPermissions(userId, orgId);
  
  if (permissions.length === 0) {
    return {
      allowed: false,
      reason: 'No permissions found for user in organization',
    };
  }

  const effectiveScope = getEffectiveScope(permissions, resource, action);
  
  if (!effectiveScope) {
    return {
      allowed: false,
      reason: `No ${resource}:${action} permission found`,
      effectiveScope: null,
    };
  }

  const scopeHierarchy: Record<PermissionScope, number> = {
    'own': 1,
    'org': 2,
    'realm': 3,
    '*': 4,
  };

  if (scopeHierarchy[effectiveScope] >= scopeHierarchy[requiredScope]) {
    return {
      allowed: true,
      effectiveScope,
    };
  }

  return {
    allowed: false,
    reason: `Insufficient scope: has ${effectiveScope}, needs ${requiredScope}`,
    effectiveScope,
  };
}

/**
 * Middleware helper - throws if permission check fails
 */
export async function requirePermission(
  userId: string,
  orgId: string,
  requiredPermission: string
): Promise<void> {
  const allowed = await checkPermission(userId, orgId, requiredPermission);
  if (!allowed) {
    const error = new Error('Permission denied');
    (error as Error & { statusCode: number }).statusCode = 403;
    throw error;
  }
}

/**
 * Middleware helper - throws if any permission check fails
 */
export async function requireAllPermissions(
  userId: string,
  orgId: string,
  requiredPermissions: string[]
): Promise<void> {
  const allowed = await checkAllPermissions(userId, orgId, requiredPermissions);
  if (!allowed) {
    const error = new Error('Permission denied');
    (error as Error & { statusCode: number }).statusCode = 403;
    throw error;
  }
}
