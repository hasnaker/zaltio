/**
 * Impersonation Model - Admin User Impersonation for Zalt.io
 * 
 * Allows admins to impersonate users for debugging and support purposes.
 * All impersonation sessions are logged for audit compliance.
 * 
 * DynamoDB Schema:
 * - Table: zalt-sessions (shared with regular sessions)
 * - pk: REALM#{realmId}#IMPERSONATION#{sessionId}
 * - sk: IMPERSONATION
 * - GSI: admin-index (adminId -> impersonation sessions)
 * - GSI: target-index (targetUserId -> impersonation sessions)
 * 
 * Security Requirements:
 * - Only admins with impersonation permission can impersonate
 * - Reason is required for audit trail
 * - Certain actions are restricted during impersonation
 * - Session expires after configurable duration (default: 1 hour)
 * - All actions during impersonation are logged with admin context
 * 
 * Validates: Requirements 6.1, 6.2, 6.3 (User Impersonation)
 */

import { randomBytes } from 'crypto';

/**
 * Impersonation session status
 */
export type ImpersonationStatus = 'active' | 'ended' | 'expired';

/**
 * All valid impersonation statuses
 */
export const IMPERSONATION_STATUSES: ImpersonationStatus[] = ['active', 'ended', 'expired'];

/**
 * Actions restricted during impersonation
 */
export type RestrictedAction = 
  | 'change_password'
  | 'delete_account'
  | 'change_email'
  | 'disable_mfa'
  | 'revoke_sessions'
  | 'manage_api_keys'
  | 'billing_changes';

/**
 * All possible restricted actions
 */
export const ALL_RESTRICTED_ACTIONS: RestrictedAction[] = [
  'change_password',
  'delete_account',
  'change_email',
  'disable_mfa',
  'revoke_sessions',
  'manage_api_keys',
  'billing_changes'
];

/**
 * Default restricted actions during impersonation
 */
export const DEFAULT_RESTRICTED_ACTIONS: RestrictedAction[] = [
  'change_password',
  'delete_account',
  'change_email',
  'disable_mfa',
  'revoke_sessions',
  'manage_api_keys',
  'billing_changes'
];

/**
 * Impersonation session entity
 */
export interface ImpersonationSession {
  id: string;                      // imp_xxx format
  realm_id: string;                // Realm where impersonation occurs
  admin_id: string;                // Admin user performing impersonation
  admin_email: string;             // Admin email for audit
  target_user_id: string;          // User being impersonated
  target_user_email: string;       // Target user email for audit
  reason: string;                  // Required reason for impersonation
  status: ImpersonationStatus;     // Current status
  restricted_actions: RestrictedAction[]; // Actions blocked during impersonation
  access_token: string;            // Impersonation access token
  refresh_token_hash: string;      // Hashed refresh token
  started_at: string;              // When impersonation started
  expires_at: string;              // When impersonation expires
  ended_at?: string;               // When impersonation was ended (if manually ended)
  ended_by?: string;               // Who ended the impersonation
  end_reason?: string;             // Reason for ending
  ip_address: string;              // Admin's IP address
  user_agent: string;              // Admin's user agent
  metadata?: ImpersonationMetadata; // Additional metadata
  created_at: string;              // Record creation timestamp
  updated_at: string;              // Last update timestamp
}

/**
 * Impersonation metadata for additional context
 */
export interface ImpersonationMetadata {
  ticket_id?: string;              // Support ticket reference
  case_id?: string;                // Case ID for tracking
  notes?: string;                  // Additional notes
  actions_performed?: string[];    // Log of actions during impersonation
}

/**
 * Input for starting impersonation
 */
export interface StartImpersonationInput {
  realm_id: string;
  admin_id: string;
  admin_email: string;
  target_user_id: string;
  target_user_email: string;
  reason: string;
  ip_address: string;
  user_agent: string;
  duration_minutes?: number;       // Custom duration (default: 60)
  restricted_actions?: RestrictedAction[]; // Custom restrictions
  metadata?: ImpersonationMetadata;
}

/**
 * Input for ending impersonation
 */
export interface EndImpersonationInput {
  session_id: string;
  ended_by: string;
  end_reason?: string;
}

/**
 * Impersonation session response (API response format)
 */
export interface ImpersonationResponse {
  id: string;
  realm_id: string;
  admin_id: string;
  target_user_id: string;
  status: ImpersonationStatus;
  restricted_actions: RestrictedAction[];
  started_at: string;
  expires_at: string;
  ended_at?: string;
  reason: string;
}

/**
 * Impersonation token claims (added to JWT)
 */
export interface ImpersonationClaims {
  is_impersonation: true;
  impersonation_session_id: string;
  admin_id: string;
  admin_email: string;
  original_user_id: string;        // The admin's actual user ID
  restricted_actions: RestrictedAction[];
}

/**
 * Audit log entry for impersonation
 */
export interface ImpersonationAuditLog {
  id: string;
  impersonation_session_id: string;
  realm_id: string;
  admin_id: string;
  admin_email: string;
  target_user_id: string;
  target_user_email: string;
  event: ImpersonationAuditEvent;
  action?: string;                 // Action performed during impersonation
  details?: Record<string, unknown>;
  ip_address: string;
  user_agent: string;
  timestamp: string;
}

/**
 * Impersonation audit events
 */
export type ImpersonationAuditEvent = 
  | 'impersonation_started'
  | 'impersonation_ended'
  | 'impersonation_expired'
  | 'action_performed'
  | 'action_blocked';

// ============================================================================
// Constants
// ============================================================================

/**
 * Impersonation session ID prefix
 */
export const IMPERSONATION_ID_PREFIX = 'imp_';

/**
 * Default impersonation duration in minutes
 */
export const DEFAULT_IMPERSONATION_DURATION_MINUTES = 60;

/**
 * Maximum impersonation duration in minutes (4 hours)
 */
export const MAX_IMPERSONATION_DURATION_MINUTES = 240;

/**
 * Minimum reason length
 */
export const MIN_REASON_LENGTH = 10;

/**
 * Maximum reason length
 */
export const MAX_REASON_LENGTH = 500;

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Generate unique impersonation session ID
 */
export function generateImpersonationId(): string {
  return `${IMPERSONATION_ID_PREFIX}${randomBytes(12).toString('hex')}`;
}

/**
 * Calculate impersonation expiry time
 */
export function calculateImpersonationExpiry(durationMinutes: number = DEFAULT_IMPERSONATION_DURATION_MINUTES): string {
  const duration = Math.min(durationMinutes, MAX_IMPERSONATION_DURATION_MINUTES);
  const expiryDate = new Date(Date.now() + duration * 60 * 1000);
  return expiryDate.toISOString();
}

/**
 * Check if impersonation session is expired
 */
export function isImpersonationExpired(session: ImpersonationSession): boolean {
  return new Date() > new Date(session.expires_at);
}

/**
 * Check if impersonation session is active
 */
export function isImpersonationActive(session: ImpersonationSession): boolean {
  if (session.status !== 'active') return false;
  return !isImpersonationExpired(session);
}

/**
 * Check if action is restricted during impersonation
 */
export function isActionRestricted(
  session: ImpersonationSession,
  action: RestrictedAction
): boolean {
  // Only active sessions have restrictions
  if (session.status !== 'active') return false;
  return session.restricted_actions.includes(action);
}

/**
 * Validate impersonation reason
 */
export function isValidReason(reason: string): { valid: boolean; error?: string } {
  if (!reason || typeof reason !== 'string') {
    return { valid: false, error: 'Reason is required' };
  }
  
  const trimmedReason = reason.trim();
  
  if (trimmedReason.length < MIN_REASON_LENGTH) {
    return { valid: false, error: `Reason must be at least ${MIN_REASON_LENGTH} characters` };
  }
  
  if (trimmedReason.length > MAX_REASON_LENGTH) {
    return { valid: false, error: `Reason must be at most ${MAX_REASON_LENGTH} characters` };
  }
  
  return { valid: true };
}

/**
 * Check if user can be impersonated
 * Admins cannot impersonate other admins or themselves
 */
export function canImpersonateUser(
  adminId: string,
  targetUserId: string,
  targetIsAdmin: boolean
): { valid: boolean; error?: string } {
  if (adminId === targetUserId) {
    return { valid: false, error: 'Cannot impersonate yourself' };
  }
  
  if (targetIsAdmin) {
    return { valid: false, error: 'Cannot impersonate admin users' };
  }
  
  return { valid: true };
}

/**
 * Convert ImpersonationSession to API response format
 */
export function toImpersonationResponse(session: ImpersonationSession): ImpersonationResponse {
  return {
    id: session.id,
    realm_id: session.realm_id,
    admin_id: session.admin_id,
    target_user_id: session.target_user_id,
    status: session.status,
    restricted_actions: session.restricted_actions,
    started_at: session.started_at,
    expires_at: session.expires_at,
    ended_at: session.ended_at,
    reason: session.reason
  };
}

/**
 * Get remaining time for impersonation session in seconds
 */
export function getRemainingTime(session: ImpersonationSession): number {
  // Ended or expired sessions have no remaining time
  if (session.status === 'ended' || session.status === 'expired') {
    return 0;
  }
  
  const expiresAt = new Date(session.expires_at).getTime();
  const now = Date.now();
  const remaining = Math.max(0, Math.floor((expiresAt - now) / 1000));
  return remaining;
}

/**
 * Map action name to RestrictedAction type
 */
export function mapToRestrictedAction(action: string): RestrictedAction | null {
  const actionMap: Record<string, RestrictedAction> = {
    'change_password': 'change_password',
    'delete_account': 'delete_account',
    'change_email': 'change_email',
    'disable_mfa': 'disable_mfa',
    'revoke_sessions': 'revoke_sessions',
    'manage_api_keys': 'manage_api_keys',
    'billing_changes': 'billing_changes'
  };
  
  return actionMap[action] || null;
}

/**
 * Check if a string is a valid RestrictedAction
 */
export function isValidRestrictedAction(action: string): action is RestrictedAction {
  return DEFAULT_RESTRICTED_ACTIONS.includes(action as RestrictedAction);
}
