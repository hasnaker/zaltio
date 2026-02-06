/**
 * Tediyat Role Service
 * Business logic for role and permission management
 * 
 * Validates: Requirements 16.1-16.6, 17.1-17.4, 18.1-18.3
 */

import {
  Role,
  CreateRoleInput,
  UpdateRoleInput,
  TEDIYAT_SYSTEM_ROLES,
  getAllSystemRoles,
  getSystemRole,
  isSystemRole,
  isValidPermission,
  expandWildcardPermission,
  getEffectiveRolePermissions,
} from '../../models/tediyat/role.model';
import * as roleRepo from '../../repositories/tediyat/role.repository';

export interface RoleServiceResult<T> {
  success: boolean;
  data?: T;
  error?: string;
  code?: string;
}

/**
 * Get all system roles
 */
export function getSystemRoles(): Role[] {
  return getAllSystemRoles();
}

/**
 * Get role by ID (system or custom)
 */
export async function getRole(roleId: string): Promise<RoleServiceResult<Role>> {
  try {
    // Check system roles first
    const systemRole = getSystemRole(roleId);
    if (systemRole) {
      return {
        success: true,
        data: systemRole,
      };
    }

    // Check custom roles
    const customRole = await roleRepo.getRole(roleId);
    if (!customRole) {
      return {
        success: false,
        error: 'Role not found',
        code: 'ROLE_NOT_FOUND',
      };
    }

    return {
      success: true,
      data: customRole,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    return {
      success: false,
      error: message,
      code: 'GET_FAILED',
    };
  }
}

/**
 * List all roles for a tenant (system + custom)
 */
export async function listTenantRoles(
  tenantId: string
): Promise<RoleServiceResult<Role[]>> {
  try {
    // Get system roles
    const systemRoles = getAllSystemRoles();

    // Get custom roles for tenant
    const { roles: customRoles } = await roleRepo.listTenantRoles(tenantId, 100);

    // Combine and return
    const allRoles = [...systemRoles, ...customRoles];

    return {
      success: true,
      data: allRoles,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    return {
      success: false,
      error: message,
      code: 'LIST_FAILED',
    };
  }
}

/**
 * Create a custom role for a tenant
 */
export async function createCustomRole(
  input: CreateRoleInput,
  requestingUserRole: string
): Promise<RoleServiceResult<Role>> {
  try {
    // Only owner/admin can create roles
    if (requestingUserRole !== 'role_owner' && requestingUserRole !== 'role_admin') {
      return {
        success: false,
        error: 'Only owners and admins can create custom roles',
        code: 'FORBIDDEN',
      };
    }

    // Validate role name uniqueness within tenant
    const existingByName = await roleRepo.findRoleByName(input.tenant_id, input.name);
    if (existingByName) {
      return {
        success: false,
        error: `Role with name "${input.name}" already exists in this tenant`,
        code: 'ROLE_EXISTS',
      };
    }

    // Check if name conflicts with system role names
    const systemRoleNames = getAllSystemRoles().map(r => r.name.toLowerCase());
    if (systemRoleNames.includes(input.name.toLowerCase())) {
      return {
        success: false,
        error: 'Cannot use system role names for custom roles',
        code: 'INVALID_ROLE_NAME',
      };
    }

    // Validate permissions
    for (const perm of input.permissions) {
      if (!isValidPermission(perm)) {
        return {
          success: false,
          error: `Invalid permission format: ${perm}`,
          code: 'INVALID_PERMISSION',
        };
      }
    }

    // Validate inherits_from if provided
    if (input.inherits_from) {
      const parentRole = await getRole(input.inherits_from);
      if (!parentRole.success) {
        return {
          success: false,
          error: 'Parent role not found',
          code: 'PARENT_ROLE_NOT_FOUND',
        };
      }
    }

    // Create role
    const role = await roleRepo.createRole(input);

    return {
      success: true,
      data: role,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    return {
      success: false,
      error: message,
      code: 'CREATE_FAILED',
    };
  }
}

/**
 * Update a custom role
 */
export async function updateRole(
  roleId: string,
  input: UpdateRoleInput,
  requestingUserRole: string
): Promise<RoleServiceResult<Role>> {
  try {
    // Only owner/admin can update roles
    if (requestingUserRole !== 'role_owner' && requestingUserRole !== 'role_admin') {
      return {
        success: false,
        error: 'Only owners and admins can update roles',
        code: 'FORBIDDEN',
      };
    }

    // Cannot update system roles
    if (isSystemRole(roleId)) {
      return {
        success: false,
        error: 'Cannot modify system roles',
        code: 'CANNOT_MODIFY_SYSTEM_ROLE',
      };
    }

    // Validate permissions if provided
    if (input.permissions) {
      for (const perm of input.permissions) {
        if (!isValidPermission(perm)) {
          return {
            success: false,
            error: `Invalid permission format: ${perm}`,
            code: 'INVALID_PERMISSION',
          };
        }
      }
    }

    const role = await roleRepo.updateRole(roleId, input);
    
    if (!role) {
      return {
        success: false,
        error: 'Role not found',
        code: 'ROLE_NOT_FOUND',
      };
    }

    return {
      success: true,
      data: role,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    return {
      success: false,
      error: message,
      code: 'UPDATE_FAILED',
    };
  }
}

/**
 * Delete a custom role
 */
export async function deleteRole(
  roleId: string,
  requestingUserRole: string
): Promise<RoleServiceResult<void>> {
  try {
    // Only owner can delete roles
    if (requestingUserRole !== 'role_owner') {
      return {
        success: false,
        error: 'Only owners can delete roles',
        code: 'FORBIDDEN',
      };
    }

    // Cannot delete system roles
    if (isSystemRole(roleId)) {
      return {
        success: false,
        error: 'Cannot delete system roles',
        code: 'CANNOT_DELETE_SYSTEM_ROLE',
      };
    }

    const deleted = await roleRepo.deleteRole(roleId);
    
    if (!deleted) {
      return {
        success: false,
        error: 'Role not found',
        code: 'ROLE_NOT_FOUND',
      };
    }

    return {
      success: true,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    return {
      success: false,
      error: message,
      code: 'DELETE_FAILED',
    };
  }
}

/**
 * Get effective permissions for a role (including inherited)
 */
export async function getEffectivePermissions(
  roleId: string,
  additionalPermissions?: string[]
): Promise<string[]> {
  // Get role
  const roleResult = await getRole(roleId);
  if (!roleResult.success || !roleResult.data) {
    return additionalPermissions || [];
  }

  const role = roleResult.data;

  // Build role map for inheritance resolution
  const roleMap: Record<string, Role> = { ...TEDIYAT_SYSTEM_ROLES };
  
  // If custom role, add to map
  if (!role.is_system) {
    roleMap[role.id] = role;
  }

  // Get effective permissions from role
  const rolePermissions = getEffectiveRolePermissions(role, roleMap);

  // Add additional permissions
  const allPermissions = new Set(rolePermissions);
  if (additionalPermissions) {
    for (const perm of additionalPermissions) {
      const expanded = expandWildcardPermission(perm);
      for (const p of expanded) {
        allPermissions.add(p);
      }
    }
  }

  return Array.from(allPermissions);
}

/**
 * Validate permission format
 */
export function validatePermission(permission: string): boolean {
  return isValidPermission(permission);
}

/**
 * Expand wildcard permission
 */
export function expandPermission(permission: string): string[] {
  return expandWildcardPermission(permission);
}
