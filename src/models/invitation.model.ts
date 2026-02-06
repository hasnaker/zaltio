/**
 * Invitation Model - Team Member Invitation System for Zalt.io
 * 
 * Invitations allow tenant owners/admins to invite team members by email.
 * The invitation includes role assignment and optional permissions.
 * 
 * DynamoDB Schema:
 * - Table: zalt-invitations
 * - pk: TENANT#{tenantId}#INVITATION#{invitationId}
 * - sk: INVITATION
 * - GSI: token-index (tokenHash -> invitationId)
 * - GSI: email-index (email -> invitations)
 * 
 * Security Requirements:
 * - Token must be cryptographically secure (32 bytes, hex encoded)
 * - Token must be hashed before storage (SHA-256)
 * - Audit logging for all operations
 * - No email enumeration
 * 
 * Validates: Requirements 11.1 (Invitation System)
 */

import { createHash, randomBytes } from 'crypto';

/**
 * Invitation status types
 */
export type InvitationStatus = 'pending' | 'accepted' | 'expired' | 'revoked';

/**
 * Invitation entity
 */
export interface Invitation {
  id: string;                    // inv_xxx format
  tenant_id: string;             // Target tenant
  email: string;                 // Invited email (lowercase)
  role: string;                  // Assigned role
  permissions?: string[];        // Additional direct permissions
  invited_by: string;            // Inviter user_id
  token_hash: string;            // SHA-256 hash of token (never store raw token)
  status: InvitationStatus;      // Current status
  expires_at: string;            // Expiry timestamp (7 days default)
  created_at: string;            // Creation timestamp
  accepted_at?: string;          // When accepted
  accepted_by_user_id?: string;  // User ID who accepted (existing or new)
  revoked_at?: string;           // When revoked
  revoked_by?: string;           // Who revoked
  metadata?: InvitationMetadata; // Additional metadata
}

/**
 * Invitation metadata for additional context
 */
export interface InvitationMetadata {
  tenant_name?: string;          // Tenant name for email
  inviter_name?: string;         // Inviter name for email
  inviter_email?: string;        // Inviter email for email
  custom_message?: string;       // Custom message in invitation email
  resend_count?: number;         // Number of times resent
  last_resent_at?: string;       // Last resend timestamp
}

/**
 * Input for creating an invitation
 */
export interface CreateInvitationInput {
  tenant_id: string;
  email: string;
  role: string;
  permissions?: string[];
  invited_by: string;
  metadata?: InvitationMetadata;
  expires_in_days?: number;      // Default: 7 days
}

/**
 * Input for accepting an invitation
 */
export interface AcceptInvitationInput {
  // For existing users
  user_id?: string;
  
  // For new users (registration during acceptance)
  new_user?: {
    first_name: string;
    last_name: string;
    password: string;
  };
}

/**
 * Invitation response (API response format - excludes sensitive data)
 */
export interface InvitationResponse {
  id: string;
  tenant_id: string;
  email: string;
  role: string;
  permissions?: string[];
  invited_by: string;
  status: InvitationStatus;
  expires_at: string;
  created_at: string;
  accepted_at?: string;
  metadata?: Omit<InvitationMetadata, 'custom_message'>;
}

/**
 * Invitation with raw token (returned only on creation)
 */
export interface InvitationWithToken {
  invitation: InvitationResponse;
  token: string;                 // Raw token - only returned once on creation
}

/**
 * Invitation validation result
 */
export interface InvitationValidationResult {
  valid: boolean;
  invitation?: Invitation;
  error?: string;
  error_code?: 'INVITATION_NOT_FOUND' | 'INVITATION_EXPIRED' | 'INVITATION_ALREADY_USED' | 'INVITATION_REVOKED';
}

// ============================================================================
// Constants
// ============================================================================

/**
 * Default invitation expiry in days
 */
export const DEFAULT_INVITATION_EXPIRY_DAYS = 7;

/**
 * Maximum invitation expiry in days
 */
export const MAX_INVITATION_EXPIRY_DAYS = 30;

/**
 * Token length in bytes (32 bytes = 64 hex chars)
 */
export const INVITATION_TOKEN_BYTES = 32;

/**
 * Invitation ID prefix
 */
export const INVITATION_ID_PREFIX = 'inv_';

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Generate unique invitation ID
 */
export function generateInvitationId(): string {
  return `${INVITATION_ID_PREFIX}${randomBytes(12).toString('hex')}`;
}

/**
 * Generate cryptographically secure invitation token
 * Returns 64 character hex string (32 bytes)
 */
export function generateInvitationToken(): string {
  return randomBytes(INVITATION_TOKEN_BYTES).toString('hex');
}

/**
 * Hash invitation token using SHA-256
 * Token is hashed before storage for security
 */
export function hashInvitationToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

/**
 * Calculate expiry date from now
 */
export function calculateExpiryDate(days: number = DEFAULT_INVITATION_EXPIRY_DAYS): string {
  const expiryDate = new Date();
  expiryDate.setDate(expiryDate.getDate() + Math.min(days, MAX_INVITATION_EXPIRY_DAYS));
  return expiryDate.toISOString();
}

/**
 * Calculate TTL for DynamoDB (Unix timestamp in seconds)
 * Used for automatic cleanup of expired invitations
 */
export function calculateTTL(expiresAt: string): number {
  return Math.floor(new Date(expiresAt).getTime() / 1000);
}

/**
 * Check if invitation is expired
 */
export function isInvitationExpired(invitation: Invitation): boolean {
  return new Date(invitation.expires_at) < new Date();
}

/**
 * Validate invitation status
 */
export function isValidInvitationStatus(status: string): status is InvitationStatus {
  return ['pending', 'accepted', 'expired', 'revoked'].includes(status);
}

/**
 * Check if invitation can be accepted
 */
export function canAcceptInvitation(invitation: Invitation): InvitationValidationResult {
  if (invitation.status === 'accepted') {
    return {
      valid: false,
      error: 'Invitation has already been accepted',
      error_code: 'INVITATION_ALREADY_USED'
    };
  }
  
  if (invitation.status === 'revoked') {
    return {
      valid: false,
      error: 'Invitation has been revoked',
      error_code: 'INVITATION_REVOKED'
    };
  }
  
  if (invitation.status === 'expired' || isInvitationExpired(invitation)) {
    return {
      valid: false,
      error: 'Invitation has expired',
      error_code: 'INVITATION_EXPIRED'
    };
  }
  
  return {
    valid: true,
    invitation
  };
}

/**
 * Normalize email for consistent storage and lookup
 */
export function normalizeEmail(email: string): string {
  return email.toLowerCase().trim();
}

/**
 * Convert Invitation to API response format (excludes sensitive data)
 */
export function toInvitationResponse(invitation: Invitation): InvitationResponse {
  const { custom_message, ...safeMetadata } = invitation.metadata || {};
  
  return {
    id: invitation.id,
    tenant_id: invitation.tenant_id,
    email: invitation.email,
    role: invitation.role,
    permissions: invitation.permissions,
    invited_by: invitation.invited_by,
    status: invitation.status,
    expires_at: invitation.expires_at,
    created_at: invitation.created_at,
    accepted_at: invitation.accepted_at,
    metadata: Object.keys(safeMetadata).length > 0 ? safeMetadata : undefined
  };
}

/**
 * Validate email format
 */
export function isValidEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

/**
 * Mask email for display (e.g., j***@example.com)
 */
export function maskEmail(email: string): string {
  const [local, domain] = email.split('@');
  if (!local || !domain) return '***@***';
  
  const maskedLocal = local.length > 2 
    ? `${local[0]}${'*'.repeat(Math.min(local.length - 1, 3))}` 
    : local[0] + '*';
  
  return `${maskedLocal}@${domain}`;
}
