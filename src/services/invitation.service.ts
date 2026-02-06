/**
 * Invitation Service - Team Member Invitation System for Zalt.io
 * 
 * Handles the complete invitation lifecycle:
 * - Creating invitations with 7-day expiry
 * - Accepting invitations (existing users or new registration)
 * - Revoking invitations
 * - Listing invitations
 * - Resending invitation emails
 * 
 * Security Requirements:
 * - Validate email format
 * - Check for duplicate pending invitations
 * - Rate limit invitation creation
 * - Audit logging for all operations
 * - No email enumeration
 * 
 * Validates: Requirements 11.1, 11.2, 11.3, 11.4, 11.5, 11.6
 */

import {
  Invitation,
  InvitationResponse,
  InvitationWithToken,
  CreateInvitationInput,
  AcceptInvitationInput,
  InvitationValidationResult,
  isValidEmail,
  normalizeEmail,
  hashInvitationToken,
  toInvitationResponse,
  DEFAULT_INVITATION_EXPIRY_DAYS
} from '../models/invitation.model';
import * as invitationRepository from '../repositories/invitation.repository';
import { createMembership, getMembership } from '../repositories/membership.repository';
import { createUser, findUserByEmail, findUserById } from '../repositories/user.repository';
import { getOrganization } from '../repositories/organization.repository';
import { sendEmail, sendInvitationEmail, RealmBranding, InvitationEmailInput } from './email.service';
import { logAuditEvent, AuditEventType, AuditResult, AuditSeverity } from './audit.service';

// ============================================================================
// Types
// ============================================================================

/**
 * Input for creating an invitation via the service
 */
export interface CreateInvitationServiceInput {
  tenant_id: string;
  email: string;
  role: string;
  permissions?: string[];
  invited_by: string;
  inviter_name?: string;
  inviter_email?: string;
  custom_message?: string;
  expires_in_days?: number;
  realm_id: string;
  branding?: RealmBranding;
}

/**
 * Input for accepting an invitation via the service
 */
export interface AcceptInvitationServiceInput {
  token: string;
  user_id?: string;
  new_user_data?: {
    first_name: string;
    last_name: string;
    password: string;
  };
  ip_address: string;
  user_agent?: string;
}

/**
 * Input for revoking an invitation
 */
export interface RevokeInvitationInput {
  invitation_id: string;
  tenant_id: string;
  revoked_by: string;
  ip_address: string;
}

/**
 * Input for resending an invitation
 */
export interface ResendInvitationInput {
  invitation_id: string;
  tenant_id: string;
  resent_by: string;
  ip_address: string;
  branding?: RealmBranding;
}

/**
 * Input for listing invitations
 */
export interface ListInvitationsInput {
  tenant_id: string;
  status?: 'pending' | 'accepted' | 'expired' | 'revoked';
  limit?: number;
  cursor?: string;
}

/**
 * Result of listing invitations
 */
export interface ListInvitationsResult {
  invitations: InvitationResponse[];
  next_cursor?: string;
}

/**
 * Service error codes
 */
export enum InvitationErrorCode {
  INVALID_EMAIL = 'INVALID_EMAIL',
  DUPLICATE_INVITATION = 'DUPLICATE_INVITATION',
  INVITATION_NOT_FOUND = 'INVITATION_NOT_FOUND',
  INVITATION_EXPIRED = 'INVITATION_EXPIRED',
  INVITATION_ALREADY_USED = 'INVITATION_ALREADY_USED',
  INVITATION_REVOKED = 'INVITATION_REVOKED',
  TENANT_NOT_FOUND = 'TENANT_NOT_FOUND',
  USER_ALREADY_MEMBER = 'USER_ALREADY_MEMBER',
  USER_NOT_FOUND = 'USER_NOT_FOUND',
  INVALID_TOKEN = 'INVALID_TOKEN',
  CANNOT_REVOKE = 'CANNOT_REVOKE',
  CANNOT_RESEND = 'CANNOT_RESEND',
  RATE_LIMIT_EXCEEDED = 'RATE_LIMIT_EXCEEDED'
}

/**
 * Service error class
 */
export class InvitationServiceError extends Error {
  constructor(
    public code: InvitationErrorCode,
    message: string,
    public details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'InvitationServiceError';
  }
}

// ============================================================================
// Webhook Types (for integration)
// ============================================================================

export interface WebhookPayload {
  event: string;
  data: Record<string, unknown>;
  timestamp: string;
}

// Webhook dispatcher function type (to be injected)
export type WebhookDispatcher = (
  realmId: string,
  event: string,
  data: Record<string, unknown>
) => Promise<void>;

// ============================================================================
// Invitation Service Class
// ============================================================================

/**
 * Invitation Service
 * Handles all invitation-related business logic
 */
export class InvitationService {
  private webhookDispatcher?: WebhookDispatcher;

  constructor(webhookDispatcher?: WebhookDispatcher) {
    this.webhookDispatcher = webhookDispatcher;
  }

  /**
   * Set webhook dispatcher for triggering webhooks
   */
  setWebhookDispatcher(dispatcher: WebhookDispatcher): void {
    this.webhookDispatcher = dispatcher;
  }

  /**
   * Create a new invitation
   * 
   * Security:
   * - Validates email format
   * - Checks for duplicate pending invitations
   * - Sends invitation email
   * - Triggers member.invited webhook
   * - Audit logs the operation
   * 
   * Validates: Requirements 11.1, 11.2
   */
  async create(input: CreateInvitationServiceInput): Promise<InvitationWithToken> {
    const normalizedEmail = normalizeEmail(input.email);

    // Validate email format
    if (!isValidEmail(normalizedEmail)) {
      throw new InvitationServiceError(
        InvitationErrorCode.INVALID_EMAIL,
        'Invalid email format'
      );
    }

    // Check for duplicate pending invitation
    const hasPending = await invitationRepository.hasPendingInvitation(
      input.tenant_id,
      normalizedEmail
    );
    if (hasPending) {
      throw new InvitationServiceError(
        InvitationErrorCode.DUPLICATE_INVITATION,
        'An invitation is already pending for this email'
      );
    }

    // Get tenant/organization info for email
    const tenant = await getOrganization(input.tenant_id);
    const tenantName = tenant?.name || 'Organization';

    // Create invitation in repository
    const createInput: CreateInvitationInput = {
      tenant_id: input.tenant_id,
      email: normalizedEmail,
      role: input.role,
      permissions: input.permissions,
      invited_by: input.invited_by,
      expires_in_days: input.expires_in_days || DEFAULT_INVITATION_EXPIRY_DAYS,
      metadata: {
        tenant_name: tenantName,
        inviter_name: input.inviter_name,
        inviter_email: input.inviter_email,
        custom_message: input.custom_message
      }
    };

    const result = await invitationRepository.createInvitation(createInput);

    // Send invitation email
    await this.sendInvitationEmailInternal(
      normalizedEmail,
      result.token,
      tenantName,
      input.inviter_name || 'A team member',
      input.role,
      input.custom_message,
      input.branding
    );

    // Trigger webhook: member.invited
    await this.dispatchWebhook(input.realm_id, 'member.invited', {
      invitation_id: result.invitation.id,
      tenant_id: input.tenant_id,
      email: normalizedEmail,
      role: input.role,
      invited_by: input.invited_by,
      expires_at: result.invitation.expires_at
    });

    // Audit log
    await logAuditEvent({
      eventType: AuditEventType.ADMIN_ACTION,
      result: AuditResult.SUCCESS,
      realmId: input.realm_id,
      userId: input.invited_by,
      ipAddress: '0.0.0.0', // Will be set by handler
      action: 'invitation_created',
      resource: `invitation:${result.invitation.id}`,
      details: {
        tenant_id: input.tenant_id,
        email: normalizedEmail,
        role: input.role
      }
    });

    return result;
  }

  /**
   * Accept an invitation
   * 
   * Handles both:
   * - Existing users: Adds them to the tenant
   * - New users: Creates account and adds to tenant
   * 
   * Security:
   * - Validates invitation token
   * - Checks invitation status and expiry
   * - Prevents double acceptance
   * - Triggers member.joined webhook
   * - Audit logs the operation
   * 
   * Validates: Requirements 11.3, 11.4, 11.5
   */
  async accept(input: AcceptInvitationServiceInput): Promise<{
    user_id: string;
    tenant_id: string;
    role: string;
    is_new_user: boolean;
  }> {
    // Validate token and get invitation
    const validation = await invitationRepository.validateInvitationToken(input.token);
    
    if (!validation.valid || !validation.invitation) {
      const errorCode = this.mapValidationErrorCode(validation.error_code);
      throw new InvitationServiceError(
        errorCode,
        validation.error || 'Invalid invitation'
      );
    }

    const invitation = validation.invitation;
    let userId: string;
    let isNewUser = false;
    let realmId: string;

    // Get tenant to find realm_id
    const tenant = await getOrganization(invitation.tenant_id);
    if (!tenant) {
      throw new InvitationServiceError(
        InvitationErrorCode.TENANT_NOT_FOUND,
        'Tenant not found'
      );
    }
    realmId = tenant.realm_id;

    // Determine if existing user or new user
    if (input.user_id) {
      // Existing user accepting invitation
      userId = input.user_id;

      // Verify user exists
      const user = await findUserById(realmId, userId);
      if (!user) {
        throw new InvitationServiceError(
          InvitationErrorCode.USER_NOT_FOUND,
          'User not found'
        );
      }

      // Check if user is already a member
      const existingMembership = await getMembership(userId, invitation.tenant_id);
      if (existingMembership) {
        throw new InvitationServiceError(
          InvitationErrorCode.USER_ALREADY_MEMBER,
          'User is already a member of this organization'
        );
      }
    } else if (input.new_user_data) {
      // New user registration during acceptance
      isNewUser = true;

      // Check if user with this email already exists
      const existingUser = await findUserByEmail(realmId, invitation.email);
      if (existingUser) {
        throw new InvitationServiceError(
          InvitationErrorCode.USER_ALREADY_MEMBER,
          'A user with this email already exists. Please sign in to accept the invitation.'
        );
      }

      // Create new user
      const newUser = await createUser({
        realm_id: realmId,
        email: invitation.email,
        password: input.new_user_data.password,
        profile: {
          first_name: input.new_user_data.first_name,
          last_name: input.new_user_data.last_name,
          metadata: {}
        }
      });

      userId = newUser.id;
    } else {
      throw new InvitationServiceError(
        InvitationErrorCode.INVALID_TOKEN,
        'Either user_id or new_user_data must be provided'
      );
    }

    // Accept invitation in repository (marks as accepted)
    const acceptedInvitation = await invitationRepository.acceptInvitation(
      invitation.tenant_id,
      invitation.id,
      userId
    );

    if (!acceptedInvitation) {
      throw new InvitationServiceError(
        InvitationErrorCode.INVITATION_ALREADY_USED,
        'Invitation has already been accepted or is no longer valid'
      );
    }

    // Create membership
    await createMembership({
      user_id: userId,
      org_id: invitation.tenant_id,
      realm_id: realmId,
      role_ids: [invitation.role],
      direct_permissions: invitation.permissions || [],
      is_default: false
    });

    // Trigger webhook: member.joined
    await this.dispatchWebhook(realmId, 'member.joined', {
      invitation_id: invitation.id,
      tenant_id: invitation.tenant_id,
      user_id: userId,
      email: invitation.email,
      role: invitation.role,
      is_new_user: isNewUser,
      joined_at: new Date().toISOString()
    });

    // Audit log
    await logAuditEvent({
      eventType: AuditEventType.ADMIN_ACTION,
      result: AuditResult.SUCCESS,
      realmId: realmId,
      userId: userId,
      ipAddress: input.ip_address,
      userAgent: input.user_agent,
      action: 'invitation_accepted',
      resource: `invitation:${invitation.id}`,
      details: {
        tenant_id: invitation.tenant_id,
        role: invitation.role,
        is_new_user: isNewUser
      }
    });

    return {
      user_id: userId,
      tenant_id: invitation.tenant_id,
      role: invitation.role,
      is_new_user: isNewUser
    };
  }

  /**
   * Revoke an invitation
   * 
   * Invalidates the invitation so it can no longer be accepted.
   * 
   * Validates: Requirement 11.6
   */
  async revoke(input: RevokeInvitationInput): Promise<InvitationResponse> {
    // Get invitation first to verify it exists and get realm_id
    const invitation = await invitationRepository.getInvitationById(
      input.tenant_id,
      input.invitation_id
    );

    if (!invitation) {
      throw new InvitationServiceError(
        InvitationErrorCode.INVITATION_NOT_FOUND,
        'Invitation not found'
      );
    }

    if (invitation.status !== 'pending') {
      throw new InvitationServiceError(
        InvitationErrorCode.CANNOT_REVOKE,
        `Cannot revoke invitation with status: ${invitation.status}`
      );
    }

    // Get tenant for realm_id
    const tenant = await getOrganization(input.tenant_id);
    const realmId = tenant?.realm_id || 'unknown';

    // Revoke in repository
    const revokedInvitation = await invitationRepository.revokeInvitation(
      input.tenant_id,
      input.invitation_id,
      input.revoked_by
    );

    if (!revokedInvitation) {
      throw new InvitationServiceError(
        InvitationErrorCode.CANNOT_REVOKE,
        'Failed to revoke invitation'
      );
    }

    // Audit log
    await logAuditEvent({
      eventType: AuditEventType.ADMIN_ACTION,
      result: AuditResult.SUCCESS,
      realmId: realmId,
      userId: input.revoked_by,
      ipAddress: input.ip_address,
      action: 'invitation_revoked',
      resource: `invitation:${input.invitation_id}`,
      details: {
        tenant_id: input.tenant_id,
        email: invitation.email
      }
    });

    return toInvitationResponse(revokedInvitation);
  }

  /**
   * List invitations for a tenant
   * 
   * Returns pending and expired invitations.
   * 
   * Validates: Requirement 11.7
   */
  async list(input: ListInvitationsInput): Promise<ListInvitationsResult> {
    const result = await invitationRepository.listInvitationsByTenant(
      input.tenant_id,
      {
        status: input.status,
        limit: input.limit,
        cursor: input.cursor
      }
    );

    return {
      invitations: result.invitations,
      next_cursor: result.nextCursor
    };
  }

  /**
   * Resend an invitation email
   * 
   * Generates a new token and extends expiry.
   * 
   * Validates: Requirement 11.2 (resend capability)
   */
  async resend(input: ResendInvitationInput): Promise<InvitationWithToken> {
    // Get invitation first to verify it exists
    const invitation = await invitationRepository.getInvitationById(
      input.tenant_id,
      input.invitation_id
    );

    if (!invitation) {
      throw new InvitationServiceError(
        InvitationErrorCode.INVITATION_NOT_FOUND,
        'Invitation not found'
      );
    }

    if (invitation.status !== 'pending') {
      throw new InvitationServiceError(
        InvitationErrorCode.CANNOT_RESEND,
        `Cannot resend invitation with status: ${invitation.status}`
      );
    }

    // Get tenant for realm_id and name
    const tenant = await getOrganization(input.tenant_id);
    const realmId = tenant?.realm_id || 'unknown';
    const tenantName = tenant?.name || 'Organization';

    // Resend in repository (generates new token)
    const result = await invitationRepository.resendInvitation(
      input.tenant_id,
      input.invitation_id
    );

    if (!result) {
      throw new InvitationServiceError(
        InvitationErrorCode.CANNOT_RESEND,
        'Failed to resend invitation'
      );
    }

    // Send invitation email with new token
    await this.sendInvitationEmailInternal(
      invitation.email,
      result.token,
      tenantName,
      invitation.metadata?.inviter_name || 'A team member',
      invitation.role,
      invitation.metadata?.custom_message,
      input.branding
    );

    // Audit log
    await logAuditEvent({
      eventType: AuditEventType.ADMIN_ACTION,
      result: AuditResult.SUCCESS,
      realmId: realmId,
      userId: input.resent_by,
      ipAddress: input.ip_address,
      action: 'invitation_resent',
      resource: `invitation:${input.invitation_id}`,
      details: {
        tenant_id: input.tenant_id,
        email: invitation.email,
        resend_count: invitation.metadata?.resend_count || 0
      }
    });

    return result;
  }

  /**
   * Get invitation by ID
   */
  async getById(tenantId: string, invitationId: string): Promise<InvitationResponse | null> {
    const invitation = await invitationRepository.getInvitationById(tenantId, invitationId);
    if (!invitation) {
      return null;
    }
    return toInvitationResponse(invitation);
  }

  /**
   * Validate invitation token without accepting
   * Useful for showing invitation details before acceptance
   */
  async validateToken(token: string): Promise<InvitationValidationResult & { invitation_details?: InvitationResponse }> {
    const validation = await invitationRepository.validateInvitationToken(token);
    
    if (validation.valid && validation.invitation) {
      return {
        ...validation,
        invitation_details: toInvitationResponse(validation.invitation)
      };
    }
    
    return validation;
  }

  /**
   * Get invitation statistics for a tenant
   */
  async getStatistics(tenantId: string): Promise<{
    pending: number;
    accepted: number;
    expired: number;
    revoked: number;
  }> {
    return invitationRepository.countInvitationsByStatus(tenantId);
  }

  // ============================================================================
  // Private Helper Methods
  // ============================================================================

  /**
   * Send invitation email using the email service
   * 
   * Delegates to the centralized email service which provides:
   * - Professional HTML and plain text templates
   * - AWS SES integration
   * - Realm branding support
   * - XSS protection
   * 
   * Validates: Requirement 11.2
   */
  private async sendInvitationEmailInternal(
    email: string,
    token: string,
    tenantName: string,
    inviterName: string,
    role: string,
    customMessage?: string,
    branding?: RealmBranding
  ): Promise<void> {
    await sendInvitationEmail({
      email,
      token,
      tenantName,
      inviterName,
      role,
      customMessage,
      expiresInDays: 7,
      branding
    });
  }

  /**
   * Dispatch webhook event
   */
  private async dispatchWebhook(
    realmId: string,
    event: string,
    data: Record<string, unknown>
  ): Promise<void> {
    if (this.webhookDispatcher) {
      try {
        await this.webhookDispatcher(realmId, event, data);
      } catch (error) {
        // Log but don't fail the operation
        console.error(`Failed to dispatch webhook ${event}:`, error);
      }
    }
  }

  /**
   * Map validation error code to service error code
   */
  private mapValidationErrorCode(
    code?: 'INVITATION_NOT_FOUND' | 'INVITATION_EXPIRED' | 'INVITATION_ALREADY_USED' | 'INVITATION_REVOKED'
  ): InvitationErrorCode {
    switch (code) {
      case 'INVITATION_NOT_FOUND':
        return InvitationErrorCode.INVALID_TOKEN;
      case 'INVITATION_EXPIRED':
        return InvitationErrorCode.INVITATION_EXPIRED;
      case 'INVITATION_ALREADY_USED':
        return InvitationErrorCode.INVITATION_ALREADY_USED;
      case 'INVITATION_REVOKED':
        return InvitationErrorCode.INVITATION_REVOKED;
      default:
        return InvitationErrorCode.INVALID_TOKEN;
    }
  }
}

// ============================================================================
// Singleton Instance
// ============================================================================

/**
 * Default invitation service instance
 */
export const invitationService = new InvitationService();

// ============================================================================
// Convenience Functions (for backward compatibility)
// ============================================================================

/**
 * Create a new invitation
 */
export async function createInvitation(
  input: CreateInvitationServiceInput
): Promise<InvitationWithToken> {
  return invitationService.create(input);
}

/**
 * Accept an invitation
 */
export async function acceptInvitation(
  input: AcceptInvitationServiceInput
): Promise<{
  user_id: string;
  tenant_id: string;
  role: string;
  is_new_user: boolean;
}> {
  return invitationService.accept(input);
}

/**
 * Revoke an invitation
 */
export async function revokeInvitation(
  input: RevokeInvitationInput
): Promise<InvitationResponse> {
  return invitationService.revoke(input);
}

/**
 * List invitations for a tenant
 */
export async function listInvitations(
  input: ListInvitationsInput
): Promise<ListInvitationsResult> {
  return invitationService.list(input);
}

/**
 * Resend an invitation
 */
export async function resendInvitation(
  input: ResendInvitationInput
): Promise<InvitationWithToken> {
  return invitationService.resend(input);
}
