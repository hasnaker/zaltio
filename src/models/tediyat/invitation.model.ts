/**
 * Tediyat Invitation Model
 * Tenant'a kullanıcı davet etme modeli
 * 
 * Validates: Requirements 12.1-12.7, 13.1-13.4
 */

import { randomBytes } from 'crypto';

export type InvitationStatus = 'pending' | 'accepted' | 'expired' | 'cancelled';

export interface Invitation {
  id: string;                       // inv_xxx format
  tenant_id: string;                // Target tenant
  tenant_name: string;              // Tenant name (denormalized for email)
  email: string;                    // Invited email
  role_id: string;                  // Assigned role
  role_name: string;                // Role name (denormalized)
  direct_permissions?: string[];    // Additional permissions
  token: string;                    // Hashed invitation token
  status: InvitationStatus;         // Invitation status
  invited_by: string;               // Inviter user_id
  invited_by_name: string;          // Inviter name (denormalized for email)
  expires_at: string;               // Expiry timestamp (7 days)
  created_at: string;               // Creation timestamp
  accepted_at?: string;             // When accepted
  accepted_by?: string;             // User ID who accepted
}

export interface CreateInvitationInput {
  tenant_id: string;
  tenant_name: string;
  email: string;
  role_id: string;
  role_name: string;
  direct_permissions?: string[];
  invited_by: string;
  invited_by_name: string;
}

export interface AcceptInvitationInput {
  // For existing users
  user_id?: string;
  
  // For new users (registration)
  first_name?: string;
  last_name?: string;
  password?: string;
}

/**
 * DynamoDB Schema:
 * 
 * Primary Key:
 *   PK: INVITATION#{invitation_id}
 *   SK: METADATA
 * 
 * GSI1 (TenantInvitations):
 *   GSI1PK: TENANT#{tenant_id}#INVITATIONS
 *   GSI1SK: STATUS#{status}#CREATED#{created_at}
 * 
 * GSI2 (TokenLookup):
 *   GSI2PK: TOKEN#{token_hash}
 *   GSI2SK: INVITATION
 * 
 * GSI3 (EmailInvitations):
 *   GSI3PK: EMAIL#{email}#INVITATIONS
 *   GSI3SK: TENANT#{tenant_id}
 * 
 * TTL: expires_at (auto-delete expired invitations)
 */

export interface InvitationDynamoDBItem {
  PK: string;                       // INVITATION#{invitation_id}
  SK: string;                       // METADATA
  GSI1PK: string;                   // TENANT#{tenant_id}#INVITATIONS
  GSI1SK: string;                   // STATUS#{status}#CREATED#{created_at}
  GSI2PK: string;                   // TOKEN#{token_hash}
  GSI2SK: string;                   // INVITATION
  GSI3PK: string;                   // EMAIL#{email}#INVITATIONS
  GSI3SK: string;                   // TENANT#{tenant_id}
  
  // Entity data
  id: string;
  tenant_id: string;
  tenant_name: string;
  email: string;
  role_id: string;
  role_name: string;
  direct_permissions?: string[];
  token: string;
  status: InvitationStatus;
  invited_by: string;
  invited_by_name: string;
  expires_at: string;
  created_at: string;
  accepted_at?: string;
  accepted_by?: string;
  
  // TTL for auto-expiry (Unix timestamp)
  ttl: number;
  
  // Entity type for filtering
  entity_type: 'INVITATION';
}

/**
 * Generate invitation ID
 */
export function generateInvitationId(): string {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 8);
  return `inv_${timestamp}${random}`;
}

/**
 * Generate secure invitation token
 * Returns both raw token (for email) and hashed token (for storage)
 */
export function generateInvitationToken(): { rawToken: string; hashedToken: string } {
  const rawToken = randomBytes(32).toString('hex');
  // Simple hash for lookup - in production use proper hashing
  const hashedToken = Buffer.from(rawToken).toString('base64');
  return { rawToken, hashedToken };
}

/**
 * Hash token for lookup
 */
export function hashInvitationToken(rawToken: string): string {
  return Buffer.from(rawToken).toString('base64');
}

/**
 * Calculate expiry date (7 days from now)
 */
export function calculateExpiryDate(): string {
  const expiryDate = new Date();
  expiryDate.setDate(expiryDate.getDate() + 7);
  return expiryDate.toISOString();
}

/**
 * Calculate TTL for DynamoDB (Unix timestamp)
 */
export function calculateTTL(): number {
  const expiryDate = new Date();
  expiryDate.setDate(expiryDate.getDate() + 7);
  return Math.floor(expiryDate.getTime() / 1000);
}

/**
 * Check if invitation is expired
 */
export function isInvitationExpired(invitation: Invitation): boolean {
  return new Date(invitation.expires_at) < new Date();
}

/**
 * Check if invitation can be accepted
 */
export function canAcceptInvitation(invitation: Invitation): { 
  canAccept: boolean; 
  reason?: string 
} {
  if (invitation.status === 'accepted') {
    return { canAccept: false, reason: 'Invitation already accepted' };
  }
  
  if (invitation.status === 'cancelled') {
    return { canAccept: false, reason: 'Invitation was cancelled' };
  }
  
  if (invitation.status === 'expired' || isInvitationExpired(invitation)) {
    return { canAccept: false, reason: 'Invitation has expired' };
  }
  
  return { canAccept: true };
}
