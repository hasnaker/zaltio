/**
 * Tediyat Tenant Service
 * Business logic for tenant management
 * 
 * Validates: Requirements 9.1-9.5, 10.1-10.3
 */

import {
  Tenant,
  TenantWithRole,
  CreateTenantInput,
  UpdateTenantInput,
  generateSlug,
  isValidSlug,
} from '../../models/tediyat/tenant.model';
import {
  Membership,
} from '../../models/tediyat/membership.model';
import {
  TEDIYAT_SYSTEM_ROLES,
} from '../../models/tediyat/role.model';
import * as tenantRepo from '../../repositories/tediyat/tenant.repository';

export interface CreateTenantWithOwnerInput {
  name: string;
  slug?: string;
  logo_url?: string;
  metadata?: {
    taxNumber?: string;
    address?: string;
    phone?: string;
    email?: string;
    city?: string;
    country?: string;
  };
  settings?: {
    mfa_required?: boolean;
    session_timeout?: number;
    allowed_domains?: string[];
    max_members?: number;
  };
  owner_user_id: string;
}

export interface TenantServiceResult<T> {
  success: boolean;
  data?: T;
  error?: string;
  code?: string;
}

/**
 * Create a new tenant with owner
 * The creating user automatically becomes the owner
 */
export async function createTenant(
  input: CreateTenantWithOwnerInput
): Promise<TenantServiceResult<Tenant>> {
  try {
    // Generate or validate slug
    const slug = input.slug || generateSlug(input.name);
    
    if (!isValidSlug(slug)) {
      return {
        success: false,
        error: 'Invalid slug format. Use lowercase letters, numbers, and hyphens only.',
        code: 'INVALID_SLUG',
      };
    }

    // Check slug availability
    const isAvailable = await tenantRepo.isSlugAvailable(slug);
    if (!isAvailable) {
      return {
        success: false,
        error: `Slug "${slug}" is already in use. Please choose a different name.`,
        code: 'SLUG_EXISTS',
      };
    }

    // Create tenant
    const tenant = await tenantRepo.createTenant({
      name: input.name,
      slug,
      logo_url: input.logo_url,
      metadata: input.metadata,
      settings: input.settings,
      created_by: input.owner_user_id,
    });

    return {
      success: true,
      data: tenant,
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
 * Get tenant by ID
 */
export async function getTenant(tenantId: string): Promise<TenantServiceResult<Tenant>> {
  try {
    const tenant = await tenantRepo.getTenant(tenantId);
    
    if (!tenant) {
      return {
        success: false,
        error: 'Tenant not found',
        code: 'TENANT_NOT_FOUND',
      };
    }

    if (tenant.status === 'deleted') {
      return {
        success: false,
        error: 'Tenant has been deleted',
        code: 'TENANT_DELETED',
      };
    }

    return {
      success: true,
      data: tenant,
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
 * Get tenant by slug
 */
export async function getTenantBySlug(slug: string): Promise<TenantServiceResult<Tenant>> {
  try {
    const tenant = await tenantRepo.findTenantBySlug(slug);
    
    if (!tenant) {
      return {
        success: false,
        error: 'Tenant not found',
        code: 'TENANT_NOT_FOUND',
      };
    }

    if (tenant.status === 'deleted') {
      return {
        success: false,
        error: 'Tenant has been deleted',
        code: 'TENANT_DELETED',
      };
    }

    return {
      success: true,
      data: tenant,
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
 * List tenants for a user (with their roles)
 * This requires membership data to be joined
 */
export async function listUserTenants(
  userId: string,
  memberships: Membership[]
): Promise<TenantServiceResult<TenantWithRole[]>> {
  try {
    const tenantsWithRoles: TenantWithRole[] = [];

    for (const membership of memberships) {
      if (membership.status !== 'active') continue;

      const tenant = await tenantRepo.getTenant(membership.tenant_id);
      if (!tenant || tenant.status !== 'active') continue;

      // Get role name from system roles or use the stored role_name
      const systemRole = Object.values(TEDIYAT_SYSTEM_ROLES).find(
        r => r.id === membership.role_id
      );

      tenantsWithRoles.push({
        ...tenant,
        role: membership.role_id,
        role_name: systemRole?.name || membership.role_name,
        is_default: membership.is_default,
      });
    }

    return {
      success: true,
      data: tenantsWithRoles,
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
 * Update tenant
 */
export async function updateTenant(
  tenantId: string,
  input: UpdateTenantInput,
  requestingUserId: string,
  requestingUserRole: string
): Promise<TenantServiceResult<Tenant>> {
  try {
    // Check if user has permission to update
    if (requestingUserRole !== 'role_owner' && requestingUserRole !== 'role_admin') {
      return {
        success: false,
        error: 'Only owners and admins can update tenant settings',
        code: 'FORBIDDEN',
      };
    }

    const tenant = await tenantRepo.updateTenant(tenantId, input);
    
    if (!tenant) {
      return {
        success: false,
        error: 'Tenant not found',
        code: 'TENANT_NOT_FOUND',
      };
    }

    return {
      success: true,
      data: tenant,
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
 * Delete tenant (soft delete)
 */
export async function deleteTenant(
  tenantId: string,
  requestingUserId: string,
  requestingUserRole: string
): Promise<TenantServiceResult<void>> {
  try {
    // Only owner can delete tenant
    if (requestingUserRole !== 'role_owner') {
      return {
        success: false,
        error: 'Only the owner can delete a tenant',
        code: 'FORBIDDEN',
      };
    }

    const deleted = await tenantRepo.deleteTenant(tenantId);
    
    if (!deleted) {
      return {
        success: false,
        error: 'Tenant not found',
        code: 'TENANT_NOT_FOUND',
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
 * Validate slug uniqueness
 */
export async function validateSlugUniqueness(slug: string): Promise<boolean> {
  return tenantRepo.isSlugAvailable(slug);
}

/**
 * Generate slug from name (exposed for handlers)
 */
export function generateTenantSlug(name: string): string {
  return generateSlug(name);
}

/**
 * Validate slug format (exposed for handlers)
 */
export function validateSlugFormat(slug: string): boolean {
  return isValidSlug(slug);
}

/**
 * Increment member count
 */
export async function incrementMemberCount(tenantId: string, delta: number = 1): Promise<void> {
  await tenantRepo.incrementMemberCount(tenantId, delta);
}

/**
 * Check if tenant is active
 */
export async function isTenantActive(tenantId: string): Promise<boolean> {
  return tenantRepo.isTenantActive(tenantId);
}
