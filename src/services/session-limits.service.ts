/**
 * Session Limits Service
 * Validates: Requirement 13.6 - Configure maximum concurrent sessions per realm
 * 
 * Features:
 * - Per-realm session limits enforcement
 * - Revoke oldest session when limit exceeded
 * - Notify user when session is revoked due to limit
 * 
 * SECURITY: Concurrent session limits per realm policy (Zalt Security Best Practices)
 */

import { getRealmSettings } from '../repositories/realm.repository';
import { 
  getUserSessions, 
  deleteSession,
  countUserSessions 
} from '../repositories/session.repository';
import { Session } from '../models/session.model';
import { 
  SessionLimitsConfig, 
  DEFAULT_SESSION_LIMITS,
  HEALTHCARE_SESSION_LIMITS 
} from '../models/realm.model';
import { isHealthcareRealm } from './realm.service';
import { logSecurityEvent } from './security-logger.service';
import { dispatchSessionRevoked } from './webhook-events.service';

/**
 * Session limit check result
 */
export interface SessionLimitCheckResult {
  /** Whether a new session can be created */
  allowed: boolean;
  /** Current session count for the user */
  currentCount: number;
  /** Maximum allowed sessions */
  maxSessions: number;
  /** Sessions that were revoked to make room (if any) */
  revokedSessions: RevokedSessionInfo[];
  /** Reason if not allowed */
  reason?: string;
  /** Whether user was notified of revocation */
  notificationSent: boolean;
}

/**
 * Information about a revoked session
 */
export interface RevokedSessionInfo {
  sessionId: string;
  createdAt: string;
  ipAddress?: string;
  userAgent?: string;
  reason: 'session_limit_exceeded';
}

/**
 * Session limit enforcement options
 */
export interface EnforceSessionLimitOptions {
  /** User ID */
  userId: string;
  /** Realm ID */
  realmId: string;
  /** Client IP address for audit logging */
  clientIp?: string;
  /** User agent for audit logging */
  userAgent?: string;
  /** User email for notifications */
  userEmail?: string;
}

/**
 * Get session limits configuration for a realm
 * Falls back to defaults if not configured
 * Healthcare realms get stricter limits
 */
export async function getRealmSessionLimits(realmId: string): Promise<SessionLimitsConfig> {
  try {
    const settings = await getRealmSettings(realmId);
    
    // Check if session_limits is configured
    if (settings.session_limits) {
      return settings.session_limits;
    }
    
    // Healthcare realms get stricter defaults
    if (isHealthcareRealm(realmId)) {
      return HEALTHCARE_SESSION_LIMITS;
    }
    
    return DEFAULT_SESSION_LIMITS;
  } catch (error) {
    console.warn(`Failed to get session limits for realm ${realmId}, using defaults:`, error);
    return DEFAULT_SESSION_LIMITS;
  }
}

/**
 * Check if session limits are enabled for a realm
 */
export async function isSessionLimitsEnabled(realmId: string): Promise<boolean> {
  const config = await getRealmSessionLimits(realmId);
  return config.enabled && config.max_concurrent_sessions > 0;
}

/**
 * Get the oldest session for a user (to be revoked when limit exceeded)
 * Sorts by created_at ascending and returns the oldest
 */
function getOldestSession(sessions: Session[]): Session | null {
  if (sessions.length === 0) return null;
  
  // Filter out revoked sessions
  const activeSessions = sessions.filter(s => !s.revoked);
  if (activeSessions.length === 0) return null;
  
  // Sort by created_at ascending (oldest first)
  const sorted = [...activeSessions].sort((a, b) => {
    const dateA = new Date(a.created_at).getTime();
    const dateB = new Date(b.created_at).getTime();
    return dateA - dateB;
  });
  
  return sorted[0];
}

/**
 * Notify user that their session was revoked due to limit
 * Validates: Requirement 13.6 - Notify user when session is revoked due to limit
 */
async function notifyUserSessionRevoked(
  realmId: string,
  userId: string,
  userEmail: string | undefined,
  revokedSession: RevokedSessionInfo
): Promise<boolean> {
  try {
    // Log the notification attempt
    await logSecurityEvent({
      event_type: 'session_limit_notification_sent',
      ip_address: 'system',
      realm_id: realmId,
      user_id: userId,
      details: {
        revoked_session_id: revokedSession.sessionId,
        reason: revokedSession.reason,
        email: userEmail ? '***' : 'not_provided'
      }
    });

    // TODO: In production, send email notification via SES
    // For now, we just log the event
    // await sendEmail({
    //   to: userEmail,
    //   template: 'session_revoked_limit',
    //   data: {
    //     session_ip: revokedSession.ipAddress,
    //     session_created: revokedSession.createdAt
    //   }
    // });

    console.log(`[SESSION_LIMIT] Notification sent to user ${userId} about revoked session ${revokedSession.sessionId}`);
    return true;
  } catch (error) {
    console.error('Failed to notify user about session revocation:', error);
    return false;
  }
}

/**
 * Enforce session limits for a user before creating a new session
 * Validates: Requirement 13.6
 * - Configure maximum concurrent sessions per realm
 * - When limit is exceeded, revoke the oldest session
 * - Notify user when session is revoked due to limit
 * 
 * @param options - Enforcement options
 * @returns Result indicating if new session is allowed and any revoked sessions
 */
export async function enforceSessionLimits(
  options: EnforceSessionLimitOptions
): Promise<SessionLimitCheckResult> {
  const { userId, realmId, clientIp, userAgent, userEmail } = options;
  
  const result: SessionLimitCheckResult = {
    allowed: true,
    currentCount: 0,
    maxSessions: 0,
    revokedSessions: [],
    notificationSent: false
  };

  try {
    // Get session limits configuration
    const limitsConfig = await getRealmSessionLimits(realmId);
    result.maxSessions = limitsConfig.max_concurrent_sessions;

    // Check if limits are enabled
    if (!limitsConfig.enabled || limitsConfig.max_concurrent_sessions <= 0) {
      // Unlimited sessions allowed
      result.maxSessions = 0; // 0 means unlimited
      return result;
    }

    // Count current sessions
    const currentCount = await countUserSessions(realmId, userId);
    result.currentCount = currentCount;

    // Check if under limit
    if (currentCount < limitsConfig.max_concurrent_sessions) {
      // Under limit, new session allowed
      return result;
    }

    // Limit reached or exceeded
    if (limitsConfig.limit_exceeded_action === 'block_new') {
      // Block new session creation
      result.allowed = false;
      result.reason = `Maximum concurrent sessions (${limitsConfig.max_concurrent_sessions}) reached. Please log out from another device.`;
      
      // Log the blocked attempt
      await logSecurityEvent({
        event_type: 'session_limit_blocked',
        ip_address: clientIp || 'unknown',
        realm_id: realmId,
        user_id: userId,
        details: {
          current_count: currentCount,
          max_sessions: limitsConfig.max_concurrent_sessions,
          action: 'block_new'
        }
      });

      return result;
    }

    // Action is 'revoke_oldest' - revoke oldest sessions until under limit
    const sessions = await getUserSessions(realmId, userId);
    const sessionsToRevoke = currentCount - limitsConfig.max_concurrent_sessions + 1;

    for (let i = 0; i < sessionsToRevoke; i++) {
      const oldestSession = getOldestSession(
        sessions.filter(s => !result.revokedSessions.some(r => r.sessionId === s.id))
      );

      if (!oldestSession) break;

      // Revoke the oldest session
      const deleted = await deleteSession(oldestSession.id, realmId, userId);
      
      if (deleted) {
        const revokedInfo: RevokedSessionInfo = {
          sessionId: oldestSession.id,
          createdAt: oldestSession.created_at,
          ipAddress: oldestSession.ip_address,
          userAgent: oldestSession.user_agent,
          reason: 'session_limit_exceeded'
        };
        
        result.revokedSessions.push(revokedInfo);

        // Log the revocation
        await logSecurityEvent({
          event_type: 'session_revoked_limit_exceeded',
          ip_address: clientIp || 'system',
          realm_id: realmId,
          user_id: userId,
          details: {
            revoked_session_id: oldestSession.id,
            revoked_session_created: oldestSession.created_at,
            revoked_session_ip: oldestSession.ip_address,
            current_count: currentCount,
            max_sessions: limitsConfig.max_concurrent_sessions,
            new_session_ip: clientIp,
            new_session_user_agent: userAgent
          }
        });

        // Trigger session.revoked webhook
        try {
          await dispatchSessionRevoked(realmId, {
            session_id: oldestSession.id,
            user_id: userId,
            realm_id: realmId,
            reason: 'session_limit_exceeded'
          });
        } catch (webhookError) {
          console.error('Failed to dispatch session.revoked webhook:', webhookError);
        }

        // Notify user if configured
        if (limitsConfig.notify_on_revoke) {
          const notified = await notifyUserSessionRevoked(
            realmId,
            userId,
            userEmail,
            revokedInfo
          );
          result.notificationSent = result.notificationSent || notified;
        }
      }
    }

    // Update current count after revocations
    result.currentCount = currentCount - result.revokedSessions.length;

    return result;
  } catch (error) {
    console.error('Error enforcing session limits:', error);
    // On error, allow the session but log the issue
    await logSecurityEvent({
      event_type: 'session_limit_enforcement_error',
      ip_address: clientIp || 'unknown',
      realm_id: realmId,
      user_id: userId,
      details: {
        error: (error as Error).message
      }
    });
    return result;
  }
}

/**
 * Check session limits without enforcing (for UI display)
 */
export async function checkSessionLimits(
  realmId: string,
  userId: string
): Promise<{
  currentCount: number;
  maxSessions: number;
  limitReached: boolean;
  enabled: boolean;
}> {
  const limitsConfig = await getRealmSessionLimits(realmId);
  const currentCount = await countUserSessions(realmId, userId);
  
  return {
    currentCount,
    maxSessions: limitsConfig.max_concurrent_sessions,
    limitReached: limitsConfig.enabled && 
      limitsConfig.max_concurrent_sessions > 0 && 
      currentCount >= limitsConfig.max_concurrent_sessions,
    enabled: limitsConfig.enabled && limitsConfig.max_concurrent_sessions > 0
  };
}
