/**
 * Tediyat Membership Service
 * Business logic for membership management
 * 
 * Validates: Requirements 14.1-14.4, 15.1-15.4, 19.1-19.4
 */

import {
  Membership,
  MemberWithUser,
  PaginatedMembers,
  CreateMembershipInput,
  UpdateMembershipInput,
  hasPermission,
  getEffectivePermissions,
} from '../../models/tediyat/membership.model';
import {
  TEDIYAT_SYSTEM_ROLES,
  getSystemRole,
  getEffectiveRolePermissions,
} from '../../models/tediyat/role.model';
import * as membershipRepo from '../../repositories/tediyat/membership.repository';
import * as tenantRepo from '../../repositories/tediyat/tenant.repository';

export interface MembershipServiceResult<T> {
  success: boolean;
  data?: T;
  error?: string;
  code?: string;
}

/**
 * Create a new membership (used when owner creates tenant or invitation is accepted)
 */
export async function createMembership(
  input: CreateMembershipInput
): Promise<MembershipServiceResult<Membership>> {
  try {
    // Check if tenant exists and is active
    const tenantActive = await tenantRepo.isTenantActive(input.tenant_id);
    if (!tenantActive) {
      return {
        success: false,
        error: 'Tenant not found or inactive',
        code: 'TENANT_NOT_FOUND',
      };
    }

    // Check if membership already exists
    const existing = await membershipRepo.getMembership(input.user_id, input.tenant_id);
    if (existing) {
      return {
        success: false,
        error: 'User is already a member of this tenant',
        code: 'MEMBERSHIP_EXISTS',
      };
    }

    // Create membership
    const membership = await membershipRepo.createMembership(input);

    // Increment tenant member count
    await tenantRepo.incrementMemberCount(input.tenant_id, 1);

    return {
      success: true,
      data: membership,
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
 * Get membership by user and tenant
 */
export async function getMembership(
  userId: string,
  tenantId: string
): Promise<MembershipServiceResult<Membership>> {
  try {
    const membership = await membershipRepo.getMembership(userId, tenantId);
    
    if (!membership) {
      return {
        success: false,
        error: 'Membership not found',
        code: 'MEMBERSHIP_NOT_FOUND',
      };
    }

    if (membership.status !== 'active') {
      return {
        success: false,
        error: 'Membership is not active',
        code: 'MEMBERSHIP_INACTIVE',
      };
    }

    return {
      success: true,
      data: membership,
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
 * List all members of a tenant
 * Only owner/admin can view member list
 */
export async function listTenantMembers(
  tenantId: string,
  requestingUserId: string,
  requestingUserRole: string,
  page: number = 1,
  pageSize: number = 50
): Promise<MembershipServiceResult<PaginatedMembers>> {
  try {
    // Check authorization - only owner/admin can view members
    if (requestingUserRole !== 'role_owner' && requestingUserRole !== 'role_admin') {
      return {
        success: false,
        error: 'Only owners and admins can view member list',
        code: 'FORBIDDEN',
      };
    }

    const { memberships, nextCursor } = await membershipRepo.listTenantMembers(
      tenantId,
      pageSize
    );

    // TODO: Join with user data to get MemberWithUser
    // For now, return memberships without user details
    const membersWithUser: MemberWithUser[] = memberships.map(m => ({
      ...m,
      user: {
        id: m.user_id,
        email: '', // Would be fetched from user repository
        first_name: '',
        last_name: '',
      },
    }));

    return {
      success: true,
      data: {
        members: membersWithUser,
        total: memberships.length,
        page,
        page_size: pageSize,
        has_more: !!nextCursor,
        next_cursor: nextCursor,
      },
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
 * List all memberships for a user
 */
export async function listUserMemberships(
  userId: string
): Promise<MembershipServiceResult<Membership[]>> {
  try {
    const { memberships } = await membershipRepo.listUserMemberships(userId, 100);

    return {
      success: true,
      data: memberships,
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
 * Update membership (role, permissions)
 * Only owner/admin can update memberships
 */
export async function updateMembership(
  userId: string,
  tenantId: string,
  input: UpdateMembershipInput,
  requestingUserId: string,
  requestingUserRole: string
): Promise<MembershipServiceResult<Membership>> {
  try {
    // Check authorization
    if (requestingUserRole !== 'role_owner' && requestingUserRole !== 'role_admin') {
      return {
        success: false,
        error: 'Only owners and admins can update memberships',
        code: 'FORBIDDEN',
      };
    }

    // Cannot change owner's role (must transfer ownership first)
    const targetMembership = await membershipRepo.getMembership(userId, tenantId);
    if (!targetMembership) {
      return {
        success: false,
        error: 'Membership not found',
        code: 'MEMBERSHIP_NOT_FOUND',
      };
    }

    if (targetMembership.role_id === 'role_owner' && input.role_id && input.role_id !== 'role_owner') {
      return {
        success: false,
        error: 'Cannot change owner role. Use transfer ownership instead.',
        code: 'CANNOT_CHANGE_OWNER',
      };
    }

    // Admin cannot promote to owner
    if (requestingUserRole === 'role_admin' && input.role_id === 'role_owner') {
      return {
        success: false,
        error: 'Admins cannot promote members to owner',
        code: 'FORBIDDEN',
      };
    }

    const membership = await membershipRepo.updateMembership(userId, tenantId, input);
    
    if (!membership) {
      return {
        success: false,
        error: 'Membership not found',
        code: 'MEMBERSHIP_NOT_FOUND',
      };
    }

    return {
      success: true,
      data: membership,
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
 * Remove member from tenant
 * Cannot remove the only owner
 */
export async function deleteMembership(
  userId: string,
  tenantId: string,
  requestingUserId: string,
  requestingUserRole: string
): Promise<MembershipServiceResult<void>> {
  try {
    // Check authorization
    if (requestingUserRole !== 'role_owner' && requestingUserRole !== 'role_admin') {
      return {
        success: false,
        error: 'Only owners and admins can remove members',
        code: 'FORBIDDEN',
      };
    }

    // Get target membership
    const targetMembership = await membershipRepo.getMembership(userId, tenantId);
    if (!targetMembership) {
      return {
        success: false,
        error: 'Membership not found',
        code: 'MEMBERSHIP_NOT_FOUND',
      };
    }

    // Cannot remove owner if they are the only owner
    if (targetMembership.role_id === 'role_owner') {
      const ownerCount = await membershipRepo.countMembersByRole(tenantId, 'role_owner');
      if (ownerCount <= 1) {
        return {
          success: false,
          error: 'Cannot remove the only owner. Transfer ownership first.',
          code: 'CANNOT_REMOVE_OWNER',
        };
      }
    }

    // Admin cannot remove owner
    if (requestingUserRole === 'role_admin' && targetMembership.role_id === 'role_owner') {
      return {
        success: false,
        error: 'Admins cannot remove owners',
        code: 'FORBIDDEN',
      };
    }

    // Delete membership
    const deleted = await membershipRepo.deleteMembership(userId, tenantId);
    if (!deleted) {
      return {
        success: false,
        error: 'Failed to remove member',
        code: 'DELETE_FAILED',
      };
    }

    // Decrement tenant member count
    await tenantRepo.incrementMemberCount(tenantId, -1);

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
 * Transfer ownership to another member
 */
export async function transferOwnership(
  tenantId: string,
  fromUserId: string,
  toUserId: string,
  requestingUserId: string,
  requestingUserRole: string
): Promise<MembershipServiceResult<void>> {
  try {
    // Only current owner can transfer ownership
    if (requestingUserRole !== 'role_owner' || requestingUserId !== fromUserId) {
      return {
        success: false,
        error: 'Only the current owner can transfer ownership',
        code: 'FORBIDDEN',
      };
    }

    // Check target user is a member
    const targetMembership = await membershipRepo.getMembership(toUserId, tenantId);
    if (!targetMembership || targetMembership.status !== 'active') {
      return {
        success: false,
        error: 'Target user is not an active member of this tenant',
        code: 'MEMBERSHIP_NOT_FOUND',
      };
    }

    // Update target to owner
    await membershipRepo.updateMembership(toUserId, tenantId, {
      role_id: 'role_owner',
      role_name: TEDIYAT_SYSTEM_ROLES.owner.name,
    });

    // Demote current owner to admin
    await membershipRepo.updateMembership(fromUserId, tenantId, {
      role_id: 'role_admin',
      role_name: TEDIYAT_SYSTEM_ROLES.admin.name,
    });

    return {
      success: true,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    return {
      success: false,
      error: message,
      code: 'TRANSFER_FAILED',
    };
  }
}

/**
 * Check if user has specific permission in tenant
 */
export async function checkUserPermission(
  userId: string,
  tenantId: string,
  requiredPermission: string
): Promise<boolean> {
  const membership = await membershipRepo.getMembership(userId, tenantId);
  if (!membership || membership.status !== 'active') {
    return false;
  }

  // Get role permissions
  const role = getSystemRole(membership.role_id);
  const rolePermissions = role?.permissions || [];

  return hasPermission(membership, rolePermissions, requiredPermission);
}

/**
 * Get effective permissions for a user in a tenant
 */
export async function getUserPermissions(
  userId: string,
  tenantId: string
): Promise<string[]> {
  const membership = await membershipRepo.getMembership(userId, tenantId);
  if (!membership || membership.status !== 'active') {
    return [];
  }

  // Get role permissions
  const role = getSystemRole(membership.role_id);
  const rolePermissions = role ? getEffectiveRolePermissions(role, TEDIYAT_SYSTEM_ROLES) : [];

  return getEffectivePermissions(rolePermissions, membership.direct_permissions);
}

/**
 * Check if user has membership in tenant
 */
export async function hasMembership(
  userId: string,
  tenantId: string
): Promise<boolean> {
  return membershipRepo.hasMembership(userId, tenantId);
}

/**
 * Set default tenant for user
 */
export async function setDefaultTenant(
  userId: string,
  tenantId: string
): Promise<MembershipServiceResult<void>> {
  try {
    // Check membership exists
    const membership = await membershipRepo.getMembership(userId, tenantId);
    if (!membership || membership.status !== 'active') {
      return {
        success: false,
        error: 'Membership not found',
        code: 'MEMBERSHIP_NOT_FOUND',
      };
    }

    await membershipRepo.setDefaultTenant(userId, tenantId);

    return {
      success: true,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    return {
      success: false,
      error: message,
      code: 'SET_DEFAULT_FAILED',
    };
  }
}
