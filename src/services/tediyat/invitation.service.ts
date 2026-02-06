/**
 * Tediyat Invitation Service
 * Business logic for invitation management
 * 
 * Validates: Requirements 12.1-12.7, 13.1-13.4
 */

import {
  Invitation,
  CreateInvitationInput,
  AcceptInvitationInput,
  canAcceptInvitation as checkCanAcceptInvitation,
  isInvitationExpired,
} from '../../models/tediyat/invitation.model';

// Re-export for handler use
export { isInvitationExpired };
export function canAcceptInvitation(invitation: Invitation): boolean {
  const result = checkCanAcceptInvitation(invitation);
  return result.canAccept;
}
import {
  TEDIYAT_SYSTEM_ROLES,
  getSystemRole,
} from '../../models/tediyat/role.model';
import * as invitationRepo from '../../repositories/tediyat/invitation.repository';
import * as membershipRepo from '../../repositories/tediyat/membership.repository';
import * as tenantRepo from '../../repositories/tediyat/tenant.repository';

export interface InvitationServiceResult<T> {
  success: boolean;
  data?: T;
  error?: string;
  code?: string;
}

export interface CreateInvitationResult {
  invitation: Invitation;
  inviteUrl: string;
}

/**
 * Create a new invitation
 */
export async function createInvitation(
  input: CreateInvitationInput,
  requestingUserRole: string,
  baseUrl: string = 'https://app.tediyat.com'
): Promise<InvitationServiceResult<CreateInvitationResult>> {
  try {
    // Only owner/admin can invite
    if (requestingUserRole !== 'role_owner' && requestingUserRole !== 'role_admin') {
      return {
        success: false,
        error: 'Only owners and admins can invite users',
        code: 'FORBIDDEN',
      };
    }

    // Check if tenant exists
    const tenantActive = await tenantRepo.isTenantActive(input.tenant_id);
    if (!tenantActive) {
      return {
        success: false,
        error: 'Tenant not found or inactive',
        code: 'TENANT_NOT_FOUND',
      };
    }

    // Check if user already has pending invitation
    const hasPending = await invitationRepo.hasPendingInvitation(
      input.email,
      input.tenant_id
    );
    if (hasPending) {
      return {
        success: false,
        error: 'User already has a pending invitation to this tenant',
        code: 'INVITATION_EXISTS',
      };
    }

    // Check if user is already a member
    // Note: This would require user lookup by email, simplified here
    
    // Validate role
    const role = getSystemRole(input.role_id);
    if (!role && !input.role_id.startsWith('role_')) {
      return {
        success: false,
        error: 'Invalid role',
        code: 'INVALID_ROLE',
      };
    }

    // Admin cannot invite as owner
    if (requestingUserRole === 'role_admin' && input.role_id === 'role_owner') {
      return {
        success: false,
        error: 'Admins cannot invite users as owners',
        code: 'FORBIDDEN',
      };
    }

    // Create invitation
    const { invitation, rawToken } = await invitationRepo.createInvitation(input);

    // Generate invite URL
    const inviteUrl = `${baseUrl}/invite/${rawToken}`;

    return {
      success: true,
      data: {
        invitation,
        inviteUrl,
      },
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
 * Get invitation by token
 */
export async function getInvitationByToken(
  token: string
): Promise<InvitationServiceResult<Invitation>> {
  try {
    const invitation = await invitationRepo.getInvitationByToken(token);
    
    if (!invitation) {
      return {
        success: false,
        error: 'Invitation not found',
        code: 'INVITATION_NOT_FOUND',
      };
    }

    // Check if expired
    if (isInvitationExpired(invitation)) {
      // Update status to expired
      await invitationRepo.updateInvitationStatus(invitation.id, 'expired');
      return {
        success: false,
        error: 'Invitation has expired',
        code: 'INVITATION_EXPIRED',
      };
    }

    const { canAccept, reason } = checkCanAcceptInvitation(invitation);
    if (!canAccept) {
      return {
        success: false,
        error: reason || 'Cannot accept invitation',
        code: 'CANNOT_ACCEPT',
      };
    }

    return {
      success: true,
      data: invitation,
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
 * Accept invitation (for existing user)
 */
export async function acceptInvitation(
  token: string,
  userId: string
): Promise<InvitationServiceResult<void>> {
  try {
    // Get and validate invitation
    const invitationResult = await getInvitationByToken(token);
    if (!invitationResult.success || !invitationResult.data) {
      return invitationResult as InvitationServiceResult<void>;
    }

    const invitation = invitationResult.data;

    // Check if user already has membership
    const existingMembership = await membershipRepo.getMembership(
      userId,
      invitation.tenant_id
    );
    if (existingMembership) {
      return {
        success: false,
        error: 'User is already a member of this tenant',
        code: 'ALREADY_MEMBER',
      };
    }

    // Create membership
    await membershipRepo.createMembership({
      user_id: userId,
      tenant_id: invitation.tenant_id,
      realm_id: 'tediyat',
      role_id: invitation.role_id,
      role_name: invitation.role_name,
      direct_permissions: invitation.direct_permissions,
      invited_by: invitation.invited_by,
    });

    // Update invitation status
    await invitationRepo.updateInvitationStatus(invitation.id, 'accepted', userId);

    // Increment tenant member count
    await tenantRepo.incrementMemberCount(invitation.tenant_id, 1);

    return { success: true };
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    return {
      success: false,
      error: message,
      code: 'ACCEPT_FAILED',
    };
  }
}

/**
 * Cancel invitation
 */
export async function cancelInvitation(
  invitationId: string,
  requestingUserRole: string
): Promise<InvitationServiceResult<void>> {
  try {
    if (requestingUserRole !== 'role_owner' && requestingUserRole !== 'role_admin') {
      return {
        success: false,
        error: 'Only owners and admins can cancel invitations',
        code: 'FORBIDDEN',
      };
    }

    const invitation = await invitationRepo.getInvitation(invitationId);
    if (!invitation) {
      return {
        success: false,
        error: 'Invitation not found',
        code: 'INVITATION_NOT_FOUND',
      };
    }

    if (invitation.status !== 'pending') {
      return {
        success: false,
        error: 'Can only cancel pending invitations',
        code: 'INVALID_STATUS',
      };
    }

    await invitationRepo.updateInvitationStatus(invitationId, 'cancelled');

    return { success: true };
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    return {
      success: false,
      error: message,
      code: 'CANCEL_FAILED',
    };
  }
}

/**
 * List pending invitations for a tenant
 */
export async function listPendingInvitations(
  tenantId: string,
  requestingUserRole: string
): Promise<InvitationServiceResult<Invitation[]>> {
  try {
    if (requestingUserRole !== 'role_owner' && requestingUserRole !== 'role_admin') {
      return {
        success: false,
        error: 'Only owners and admins can view invitations',
        code: 'FORBIDDEN',
      };
    }

    const { invitations } = await invitationRepo.listTenantInvitations(
      tenantId,
      'pending',
      100
    );

    return {
      success: true,
      data: invitations,
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
