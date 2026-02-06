/**
 * Webhook Events Service - Auth Event Integration for Zalt.io
 * 
 * Provides a centralized way to dispatch webhook events from auth handlers.
 * This service wraps the WebhookService.dispatch() method with type-safe
 * event payloads for all supported auth events.
 * 
 * Supported Events:
 * - user.created, user.updated, user.deleted
 * - session.created, session.revoked
 * - tenant.created, tenant.updated
 * - member.invited, member.joined, member.removed
 * - mfa.enabled, mfa.disabled
 * 
 * Validates: Requirements 12.2, 11.8, 11.9
 */

import { dispatchWebhook, DispatchResult } from './webhook.service';
import { WebhookEventType } from '../models/webhook.model';

// ============================================================================
// Event Payload Types
// ============================================================================

/**
 * User event payload
 */
export interface UserEventPayload {
  user_id: string;
  realm_id: string;
  email?: string;
  first_name?: string;
  last_name?: string;
  metadata?: Record<string, unknown>;
}

/**
 * Session event payload
 */
export interface SessionEventPayload {
  session_id: string;
  user_id: string;
  realm_id: string;
  device_id?: string;
  ip_address?: string;
  user_agent?: string;
  created_at?: string;
  expires_at?: string;
}

/**
 * Tenant event payload
 */
export interface TenantEventPayload {
  tenant_id: string;
  realm_id: string;
  name: string;
  slug?: string;
  metadata?: Record<string, unknown>;
}

/**
 * Member event payload
 */
export interface MemberEventPayload {
  membership_id: string;
  user_id: string;
  tenant_id: string;
  realm_id: string;
  role: string;
  permissions?: string[];
  invited_by?: string;
  invitation_id?: string;
}

/**
 * MFA event payload
 */
export interface MfaEventPayload {
  user_id: string;
  realm_id: string;
  mfa_type: 'totp' | 'webauthn' | 'sms' | 'email';
  device_id?: string;
}

/**
 * Invitation event payload
 */
export interface InvitationEventPayload {
  invitation_id: string;
  tenant_id: string;
  realm_id: string;
  email: string;
  role: string;
  invited_by: string;
  status: 'pending' | 'accepted' | 'revoked' | 'expired';
}

// ============================================================================
// User Events
// ============================================================================

/**
 * Dispatch user.created event
 * Called when a new user registers
 */
export async function dispatchUserCreated(
  realmId: string,
  payload: UserEventPayload
): Promise<DispatchResult> {
  return dispatchWebhook(realmId, 'user.created' as WebhookEventType, {
    type: 'user.created',
    ...sanitizePayload(payload)
  });
}

/**
 * Dispatch user.updated event
 * Called when user profile is updated
 */
export async function dispatchUserUpdated(
  realmId: string,
  payload: UserEventPayload & { changes?: Record<string, unknown> }
): Promise<DispatchResult> {
  return dispatchWebhook(realmId, 'user.updated' as WebhookEventType, {
    type: 'user.updated',
    ...sanitizePayload(payload)
  });
}

/**
 * Dispatch user.deleted event
 * Called when user account is deleted
 */
export async function dispatchUserDeleted(
  realmId: string,
  payload: Pick<UserEventPayload, 'user_id' | 'realm_id'>
): Promise<DispatchResult> {
  return dispatchWebhook(realmId, 'user.deleted' as WebhookEventType, {
    type: 'user.deleted',
    ...sanitizePayload(payload)
  });
}

// ============================================================================
// Session Events
// ============================================================================

/**
 * Dispatch session.created event
 * Called when a new session is created (login)
 */
export async function dispatchSessionCreated(
  realmId: string,
  payload: SessionEventPayload
): Promise<DispatchResult> {
  return dispatchWebhook(realmId, 'session.created' as WebhookEventType, {
    type: 'session.created',
    ...sanitizePayload(payload)
  });
}

/**
 * Dispatch session.revoked event
 * Called when a session is revoked (logout, force logout)
 */
export async function dispatchSessionRevoked(
  realmId: string,
  payload: Pick<SessionEventPayload, 'session_id' | 'user_id' | 'realm_id'> & {
    reason?: 'logout' | 'force_logout' | 'password_change' | 'security' | 'expired' | 'impossible_travel' | 'session_limit_exceeded';
  }
): Promise<DispatchResult> {
  return dispatchWebhook(realmId, 'session.revoked' as WebhookEventType, {
    type: 'session.revoked',
    ...sanitizePayload(payload)
  });
}

// ============================================================================
// Tenant Events
// ============================================================================

/**
 * Dispatch tenant.created event
 * Called when a new tenant/organization is created
 */
export async function dispatchTenantCreated(
  realmId: string,
  payload: TenantEventPayload
): Promise<DispatchResult> {
  return dispatchWebhook(realmId, 'tenant.created' as WebhookEventType, {
    type: 'tenant.created',
    ...sanitizePayload(payload)
  });
}

/**
 * Dispatch tenant.updated event
 * Called when tenant settings are updated
 */
export async function dispatchTenantUpdated(
  realmId: string,
  payload: TenantEventPayload & { changes?: Record<string, unknown> }
): Promise<DispatchResult> {
  return dispatchWebhook(realmId, 'tenant.updated' as WebhookEventType, {
    type: 'tenant.updated',
    ...sanitizePayload(payload)
  });
}

// ============================================================================
// Member Events
// ============================================================================

/**
 * Dispatch member.invited event
 * Called when a user is invited to a tenant
 * Validates: Requirement 11.8
 */
export async function dispatchMemberInvited(
  realmId: string,
  payload: InvitationEventPayload
): Promise<DispatchResult> {
  return dispatchWebhook(realmId, 'member.invited' as WebhookEventType, {
    type: 'member.invited',
    ...sanitizePayload(payload)
  });
}

/**
 * Dispatch member.joined event
 * Called when a user accepts an invitation and joins a tenant
 * Validates: Requirement 11.9
 */
export async function dispatchMemberJoined(
  realmId: string,
  payload: MemberEventPayload
): Promise<DispatchResult> {
  return dispatchWebhook(realmId, 'member.joined' as WebhookEventType, {
    type: 'member.joined',
    ...sanitizePayload(payload)
  });
}

/**
 * Dispatch member.removed event
 * Called when a member is removed from a tenant
 */
export async function dispatchMemberRemoved(
  realmId: string,
  payload: Pick<MemberEventPayload, 'membership_id' | 'user_id' | 'tenant_id' | 'realm_id'> & {
    removed_by?: string;
    reason?: string;
  }
): Promise<DispatchResult> {
  return dispatchWebhook(realmId, 'member.removed' as WebhookEventType, {
    type: 'member.removed',
    ...sanitizePayload(payload)
  });
}

// ============================================================================
// MFA Events
// ============================================================================

/**
 * Dispatch mfa.enabled event
 * Called when MFA is enabled for a user
 */
export async function dispatchMfaEnabled(
  realmId: string,
  payload: MfaEventPayload
): Promise<DispatchResult> {
  return dispatchWebhook(realmId, 'mfa.enabled' as WebhookEventType, {
    type: 'mfa.enabled',
    ...sanitizePayload(payload)
  });
}

/**
 * Dispatch mfa.disabled event
 * Called when MFA is disabled for a user
 */
export async function dispatchMfaDisabled(
  realmId: string,
  payload: MfaEventPayload & { disabled_by?: string }
): Promise<DispatchResult> {
  return dispatchWebhook(realmId, 'mfa.disabled' as WebhookEventType, {
    type: 'mfa.disabled',
    ...sanitizePayload(payload)
  });
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Sanitize payload to remove sensitive data
 * Never include passwords, tokens, or secrets in webhook payloads
 */
function sanitizePayload(payload: object): Record<string, unknown> {
  const sensitiveKeys = [
    'password',
    'password_hash',
    'secret',
    'token',
    'access_token',
    'refresh_token',
    'api_key',
    'private_key',
    'client_secret'
  ];

  const sanitized: Record<string, unknown> = {};
  
  for (const [key, value] of Object.entries(payload)) {
    if (!sensitiveKeys.includes(key)) {
      sanitized[key] = value;
    }
  }

  return sanitized;
}

/**
 * Batch dispatch multiple events
 * Useful for bulk operations
 */
export async function dispatchBatch(
  events: Array<{
    realmId: string;
    eventType: WebhookEventType;
    data: Record<string, unknown>;
  }>
): Promise<DispatchResult[]> {
  const results = await Promise.allSettled(
    events.map(event => dispatchWebhook(event.realmId, event.eventType, event.data))
  );

  return results.map(result => {
    if (result.status === 'fulfilled') {
      return result.value;
    }
    return { webhooks_triggered: 0, delivery_ids: [] };
  });
}

// ============================================================================
// Event Type Guards
// ============================================================================

/**
 * Check if an event type is a user event
 */
export function isUserEvent(eventType: string): boolean {
  return eventType.startsWith('user.');
}

/**
 * Check if an event type is a session event
 */
export function isSessionEvent(eventType: string): boolean {
  return eventType.startsWith('session.');
}

/**
 * Check if an event type is a tenant event
 */
export function isTenantEvent(eventType: string): boolean {
  return eventType.startsWith('tenant.');
}

/**
 * Check if an event type is a member event
 */
export function isMemberEvent(eventType: string): boolean {
  return eventType.startsWith('member.');
}

/**
 * Check if an event type is an MFA event
 */
export function isMfaEvent(eventType: string): boolean {
  return eventType.startsWith('mfa.');
}

/**
 * Check if an event type is a security event
 */
export function isSecurityEvent(eventType: string): boolean {
  return eventType.startsWith('security.');
}

// ============================================================================
// Security Events (Task 15.6 - Requirement 10.9)
// ============================================================================

/**
 * High-risk login event payload
 * Triggered when AI risk assessment detects a high-risk login attempt
 */
export interface HighRiskLoginEventPayload {
  user_id: string;
  realm_id: string;
  email: string;
  risk_score: number;
  risk_level: 'low' | 'medium' | 'high' | 'critical';
  risk_factors: Array<{
    type: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    score: number;
    description: string;
  }>;
  recommendation: 'allow' | 'mfa_required' | 'block';
  ip_address: string;
  location?: {
    city?: string;
    country?: string;
    country_code?: string;
  };
  device?: {
    user_agent?: string;
    is_new_device?: boolean;
  };
  action_taken: 'allowed' | 'mfa_required' | 'blocked';
  assessment_id: string;
  timestamp: string;
}

/**
 * Dispatch security.high_risk_login event
 * Called when AI risk assessment detects a high-risk login attempt
 * 
 * Validates: Requirement 10.9 - WHEN high-risk login detected THEN trigger webhook
 * 
 * @param realmId - The realm where the login attempt occurred
 * @param payload - High-risk login event details including risk factors
 * @returns Dispatch result with triggered webhook count
 */
export async function dispatchHighRiskLogin(
  realmId: string,
  payload: HighRiskLoginEventPayload
): Promise<DispatchResult> {
  return dispatchWebhook(realmId, 'security.high_risk_login' as WebhookEventType, {
    type: 'security.high_risk_login',
    ...sanitizePayload(payload)
  });
}
