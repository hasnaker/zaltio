/**
 * Tediyat Permission Service
 * Permission validation and checking utilities
 * 
 * Validates: Requirements 18.1-18.3, 19.1-19.4
 */

import {
  TEDIYAT_PERMISSION_CATEGORIES,
  isValidPermission,
  expandWildcardPermission,
} from '../../models/tediyat/role.model';
import {
  hasPermission as checkMembershipPermission,
} from '../../models/tediyat/membership.model';
import * as membershipRepo from '../../repositories/tediyat/membership.repository';
import * as roleService from './role.service';

export interface PermissionCheckResult {
  allowed: boolean;
  reason?: string;
}

/**
 * Get all available permission categories
 */
export function getPermissionCategories(): typeof TEDIYAT_PERMISSION_CATEGORIES {
  return TEDIYAT_PERMISSION_CATEGORIES;
}

/**
 * Get all available permissions as flat list
 */
export function getAllPermissions(): string[] {
  const permissions: string[] = [];
  
  for (const [resource, category] of Object.entries(TEDIYAT_PERMISSION_CATEGORIES)) {
    for (const action of category.actions) {
      if (action !== '*') {
        permissions.push(`${resource}:${action}`);
      }
    }
  }
  
  return permissions;
}

/**
 * Validate permission format
 */
export function validatePermission(permission: string): boolean {
  return isValidPermission(permission);
}

/**
 * Validate multiple permissions
 */
export function validatePermissions(permissions: string[]): { 
  valid: boolean; 
  invalidPermissions: string[] 
} {
  const invalidPermissions: string[] = [];
  
  for (const perm of permissions) {
    if (!isValidPermission(perm)) {
      invalidPermissions.push(perm);
    }
  }
  
  return {
    valid: invalidPermissions.length === 0,
    invalidPermissions,
  };
}

/**
 * Expand wildcard permission to individual permissions
 */
export function expandWildcard(permission: string): string[] {
  return expandWildcardPermission(permission);
}

/**
 * Check if user has permission in tenant
 */
export async function checkUserPermission(
  userId: string,
  tenantId: string,
  requiredPermission: string
): Promise<PermissionCheckResult> {
  // Get membership
  const membership = await membershipRepo.getMembership(userId, tenantId);
  
  if (!membership) {
    return {
      allowed: false,
      reason: 'User is not a member of this tenant',
    };
  }
  
  if (membership.status !== 'active') {
    return {
      allowed: false,
      reason: 'Membership is not active',
    };
  }
  
  // Get role permissions
  const rolePermissions = await roleService.getEffectivePermissions(
    membership.role_id,
    membership.direct_permissions
  );
  
  // Check permission
  const allowed = checkMembershipPermission(membership, rolePermissions, requiredPermission);
  
  return {
    allowed,
    reason: allowed ? undefined : 'Permission denied',
  };
}

/**
 * Check multiple permissions at once
 */
export async function checkUserPermissions(
  userId: string,
  tenantId: string,
  requiredPermissions: string[]
): Promise<{ 
  allAllowed: boolean; 
  results: Record<string, boolean> 
}> {
  const results: Record<string, boolean> = {};
  
  // Get membership once
  const membership = await membershipRepo.getMembership(userId, tenantId);
  
  if (!membership || membership.status !== 'active') {
    for (const perm of requiredPermissions) {
      results[perm] = false;
    }
    return { allAllowed: false, results };
  }
  
  // Get role permissions once
  const rolePermissions = await roleService.getEffectivePermissions(
    membership.role_id,
    membership.direct_permissions
  );
  
  // Check each permission
  let allAllowed = true;
  for (const perm of requiredPermissions) {
    const allowed = checkMembershipPermission(membership, rolePermissions, perm);
    results[perm] = allowed;
    if (!allowed) {
      allAllowed = false;
    }
  }
  
  return { allAllowed, results };
}

/**
 * Get user's effective permissions in a tenant
 */
export async function getUserPermissions(
  userId: string,
  tenantId: string
): Promise<string[]> {
  // Get membership
  const membership = await membershipRepo.getMembership(userId, tenantId);
  
  if (!membership || membership.status !== 'active') {
    return [];
  }
  
  // Get effective permissions
  return roleService.getEffectivePermissions(
    membership.role_id,
    membership.direct_permissions
  );
}

/**
 * Check if permission grants access to resource
 */
export function permissionGrantsAccess(
  userPermissions: string[],
  requiredPermission: string
): boolean {
  // Check for global wildcard
  if (userPermissions.includes('*')) {
    return true;
  }
  
  // Check for exact match
  if (userPermissions.includes(requiredPermission)) {
    return true;
  }
  
  // Check for resource wildcard
  const [resource] = requiredPermission.split(':');
  if (userPermissions.includes(`${resource}:*`)) {
    return true;
  }
  
  return false;
}

/**
 * Filter permissions by resource
 */
export function filterPermissionsByResource(
  permissions: string[],
  resource: string
): string[] {
  return permissions.filter(p => p.startsWith(`${resource}:`));
}

/**
 * Get permission description
 */
export function getPermissionDescription(permission: string): string {
  const [resource, action] = permission.split(':');
  
  const category = TEDIYAT_PERMISSION_CATEGORIES[resource as keyof typeof TEDIYAT_PERMISSION_CATEGORIES];
  if (!category) {
    return permission;
  }
  
  const actionDescriptions: Record<string, string> = {
    read: 'görüntüleme',
    create: 'oluşturma',
    update: 'güncelleme',
    delete: 'silme',
    write: 'yazma',
    export: 'dışa aktarma',
    send: 'gönderme',
    invite: 'davet etme',
    manage: 'yönetme',
    refund: 'iade',
    '*': 'tüm işlemler',
  };
  
  const actionDesc = actionDescriptions[action] || action;
  return `${category.name} ${actionDesc}`;
}
