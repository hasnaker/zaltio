/**
 * Impersonation Service - Admin User Impersonation for Zalt.io
 * 
 * Allows admins to impersonate users for debugging and support purposes.
 * All impersonation sessions are logged for audit compliance.
 * 
 * Validates: Requirements 6.1, 6.5, 6.6 (User Impersonation)
 * 
 * Security:
 * - Only admins with impersonation permission can impersonate
 * - Reason is required for audit trail
 * - Certain actions are restricted during impersonation
 * - Session expires after configurable duration (default: 1 hour)
 * - All actions during impersonation are logged with admin context
 */

import { createHash, randomBytes } from 'crypto';
import {
  ImpersonationSession,
  ImpersonationStatus,
  RestrictedAction,
  StartImpersonationInput,
  EndImpersonationInput,
  ImpersonationResponse,
  ImpersonationClaims,
  ImpersonationAuditLog,
  ImpersonationAuditEvent,
  DEFAULT_RESTRICTED_ACTIONS,
  DEFAULT_IMPERSONATION_DURATION_MINUTES,
  generateImpersonationId,
  calculateImpersonationExpiry,
  isImpersonationExpired,
  isImpersonationActive,
  isActionRestricted,
  isValidReason,
  canImpersonateUser,
  toImpersonationResponse,
  getRemainingTime
} from '../models/impersonation.model';

// Re-export types for convenience
export {
  ImpersonationSession,
  ImpersonationStatus,
  RestrictedAction,
  ImpersonationResponse,
  ImpersonationClaims,
  DEFAULT_RESTRICTED_ACTIONS
};

/**
 * In-memory store for impersonation sessions (use DynamoDB in production)
 */
const impersonationStore = new Map<string, ImpersonationSession>();

/**
 * Index by admin ID for quick lookup
 */
const adminSessionIndex = new Map<string, Set<string>>();

/**
 * Index by target user ID for quick lookup
 */
const targetSessionIndex = new Map<string, Set<string>>();

/**
 * Impersonation Service Error
 */
export class ImpersonationError extends Error {
  code: string;
  statusCode: number;
  
  constructor(code: string, message: string, statusCode: number = 403) {
    super(message);
    this.name = 'ImpersonationError';
    this.code = code;
    this.statusCode = statusCode;
  }
}

/**
 * Impersonation Service
 */
export class ImpersonationService {
  
  /**
   * Start impersonation session
   * Creates a new impersonation session for an admin to act as a target user
   */
  async startImpersonation(input: StartImpersonationInput): Promise<{
    session: ImpersonationResponse;
    access_token: string;
    refresh_token: string;
    expires_in: number;
  }> {
    // Validate reason
    const reasonValidation = isValidReason(input.reason);
    if (!reasonValidation.valid) {
      throw new ImpersonationError('INVALID_REASON', reasonValidation.error!, 400);
    }
    
    // Check if admin can impersonate target
    // Note: In production, we'd fetch target user to check if they're admin
    const canImpersonate = canImpersonateUser(
      input.admin_id,
      input.target_user_id,
      false // Assume target is not admin for now
    );
    
    if (!canImpersonate.valid) {
      throw new ImpersonationError('CANNOT_IMPERSONATE', canImpersonate.error!, 403);
    }
    
    // Check if admin already has an active impersonation session
    const existingSession = await this.getActiveSessionByAdmin(input.admin_id);
    if (existingSession) {
      throw new ImpersonationError(
        'ACTIVE_SESSION_EXISTS',
        'You already have an active impersonation session. End it before starting a new one.',
        409
      );
    }
    
    // Generate tokens
    const accessToken = this.generateToken();
    const refreshToken = this.generateToken();
    const refreshTokenHash = this.hashToken(refreshToken);
    
    // Calculate expiry
    const durationMinutes = input.duration_minutes || DEFAULT_IMPERSONATION_DURATION_MINUTES;
    const expiresAt = calculateImpersonationExpiry(durationMinutes);
    
    // Create session
    const now = new Date().toISOString();
    const session: ImpersonationSession = {
      id: generateImpersonationId(),
      realm_id: input.realm_id,
      admin_id: input.admin_id,
      admin_email: input.admin_email,
      target_user_id: input.target_user_id,
      target_user_email: input.target_user_email,
      reason: input.reason.trim(),
      status: 'active',
      restricted_actions: input.restricted_actions || DEFAULT_RESTRICTED_ACTIONS,
      access_token: accessToken,
      refresh_token_hash: refreshTokenHash,
      started_at: now,
      expires_at: expiresAt,
      ip_address: input.ip_address,
      user_agent: input.user_agent,
      metadata: input.metadata,
      created_at: now,
      updated_at: now
    };
    
    // Store session
    impersonationStore.set(session.id, session);
    
    // Update indexes
    this.addToIndex(adminSessionIndex, input.admin_id, session.id);
    this.addToIndex(targetSessionIndex, input.target_user_id, session.id);
    
    // Log audit event
    await this.logAuditEvent('impersonation_started', session);
    
    // Calculate expires_in in seconds
    const expiresIn = Math.floor((new Date(expiresAt).getTime() - Date.now()) / 1000);
    
    return {
      session: toImpersonationResponse(session),
      access_token: accessToken,
      refresh_token: refreshToken,
      expires_in: expiresIn
    };
  }
  
  /**
   * End impersonation session
   */
  async endImpersonation(input: EndImpersonationInput): Promise<ImpersonationResponse> {
    const session = impersonationStore.get(input.session_id);
    
    if (!session) {
      throw new ImpersonationError('SESSION_NOT_FOUND', 'Impersonation session not found', 404);
    }
    
    if (session.status !== 'active') {
      throw new ImpersonationError(
        'SESSION_NOT_ACTIVE',
        `Session is already ${session.status}`,
        400
      );
    }
    
    // Update session
    const now = new Date().toISOString();
    session.status = 'ended';
    session.ended_at = now;
    session.ended_by = input.ended_by;
    session.end_reason = input.end_reason;
    session.updated_at = now;
    
    // Update store
    impersonationStore.set(session.id, session);
    
    // Log audit event
    await this.logAuditEvent('impersonation_ended', session);
    
    return toImpersonationResponse(session);
  }
  
  /**
   * Check if a session is an impersonation session
   */
  async isImpersonating(sessionId: string): Promise<boolean> {
    const session = impersonationStore.get(sessionId);
    if (!session) return false;
    return isImpersonationActive(session);
  }
  
  /**
   * Get impersonation session by ID
   */
  async getSession(sessionId: string): Promise<ImpersonationSession | null> {
    const session = impersonationStore.get(sessionId);
    if (!session) return null;
    
    // Check if expired and update status
    if (session.status === 'active' && isImpersonationExpired(session)) {
      session.status = 'expired';
      session.updated_at = new Date().toISOString();
      impersonationStore.set(session.id, session);
      
      // Log expiry
      await this.logAuditEvent('impersonation_expired', session);
    }
    
    return session;
  }
  
  /**
   * Get impersonation session response by ID
   */
  async getSessionResponse(sessionId: string): Promise<ImpersonationResponse | null> {
    const session = await this.getSession(sessionId);
    if (!session) return null;
    return toImpersonationResponse(session);
  }
  
  /**
   * Get restrictions for an impersonation session
   */
  async getRestrictions(sessionId: string): Promise<RestrictedAction[]> {
    const session = impersonationStore.get(sessionId);
    if (!session) return [];
    return session.restricted_actions;
  }
  
  /**
   * Check if an action is restricted for a session
   */
  async isRestricted(sessionId: string, action: RestrictedAction): Promise<boolean> {
    const session = impersonationStore.get(sessionId);
    if (!session) return false;
    if (!isImpersonationActive(session)) return false;
    return isActionRestricted(session, action);
  }
  
  /**
   * Get active impersonation session by admin ID
   */
  async getActiveSessionByAdmin(adminId: string): Promise<ImpersonationSession | null> {
    const sessionIds = adminSessionIndex.get(adminId);
    if (!sessionIds) return null;
    
    for (const sessionId of sessionIds) {
      const session = await this.getSession(sessionId);
      if (session && isImpersonationActive(session)) {
        return session;
      }
    }
    
    return null;
  }
  
  /**
   * Get all impersonation sessions for a target user
   */
  async getSessionsByTargetUser(targetUserId: string): Promise<ImpersonationSession[]> {
    const sessionIds = targetSessionIndex.get(targetUserId);
    if (!sessionIds) return [];
    
    const sessions: ImpersonationSession[] = [];
    for (const sessionId of sessionIds) {
      const session = await this.getSession(sessionId);
      if (session) {
        sessions.push(session);
      }
    }
    
    return sessions;
  }
  
  /**
   * Get impersonation status for a session
   */
  async getStatus(sessionId: string): Promise<{
    is_impersonating: boolean;
    session?: ImpersonationResponse;
    remaining_seconds?: number;
  }> {
    const session = await this.getSession(sessionId);
    
    if (!session || !isImpersonationActive(session)) {
      return { is_impersonating: false };
    }
    
    return {
      is_impersonating: true,
      session: toImpersonationResponse(session),
      remaining_seconds: getRemainingTime(session)
    };
  }
  
  /**
   * Validate impersonation token
   */
  async validateToken(token: string): Promise<ImpersonationSession | null> {
    // Find session by access token
    for (const session of impersonationStore.values()) {
      if (session.access_token === token && isImpersonationActive(session)) {
        return session;
      }
    }
    return null;
  }
  
  /**
   * Get impersonation claims for JWT
   */
  getImpersonationClaims(session: ImpersonationSession): ImpersonationClaims {
    return {
      is_impersonation: true,
      impersonation_session_id: session.id,
      admin_id: session.admin_id,
      admin_email: session.admin_email,
      original_user_id: session.admin_id,
      restricted_actions: session.restricted_actions
    };
  }
  
  /**
   * Log action performed during impersonation
   */
  async logAction(sessionId: string, action: string, details?: Record<string, unknown>): Promise<void> {
    const session = impersonationStore.get(sessionId);
    if (!session) return;
    
    // Add to session metadata
    if (!session.metadata) {
      session.metadata = {};
    }
    if (!session.metadata.actions_performed) {
      session.metadata.actions_performed = [];
    }
    session.metadata.actions_performed.push(`${new Date().toISOString()}: ${action}`);
    session.updated_at = new Date().toISOString();
    
    impersonationStore.set(session.id, session);
    
    // Log audit event
    await this.logAuditEvent('action_performed', session, action, details);
  }
  
  /**
   * Log blocked action during impersonation
   */
  async logBlockedAction(sessionId: string, action: RestrictedAction): Promise<void> {
    const session = impersonationStore.get(sessionId);
    if (!session) return;
    
    await this.logAuditEvent('action_blocked', session, action);
  }
  
  // ============================================================================
  // Private Helper Methods
  // ============================================================================
  
  /**
   * Generate a secure random token
   */
  private generateToken(): string {
    return randomBytes(32).toString('hex');
  }
  
  /**
   * Hash a token for storage
   */
  private hashToken(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }
  
  /**
   * Add session ID to an index
   */
  private addToIndex(index: Map<string, Set<string>>, key: string, sessionId: string): void {
    let sessionIds = index.get(key);
    if (!sessionIds) {
      sessionIds = new Set();
      index.set(key, sessionIds);
    }
    sessionIds.add(sessionId);
  }
  
  /**
   * Log audit event for impersonation
   */
  private async logAuditEvent(
    event: ImpersonationAuditEvent,
    session: ImpersonationSession,
    action?: string,
    details?: Record<string, unknown>
  ): Promise<void> {
    const auditLog: ImpersonationAuditLog = {
      id: `audit_${randomBytes(12).toString('hex')}`,
      impersonation_session_id: session.id,
      realm_id: session.realm_id,
      admin_id: session.admin_id,
      admin_email: session.admin_email,
      target_user_id: session.target_user_id,
      target_user_email: session.target_user_email,
      event,
      action,
      details,
      ip_address: session.ip_address,
      user_agent: session.user_agent,
      timestamp: new Date().toISOString()
    };
    
    // In production, this would write to DynamoDB or CloudWatch
    console.log('[IMPERSONATION_AUDIT]', JSON.stringify(auditLog));
  }
  
  /**
   * Clear all sessions (for testing)
   */
  clearAllSessions(): void {
    impersonationStore.clear();
    adminSessionIndex.clear();
    targetSessionIndex.clear();
  }
}

// Export singleton instance
export const impersonationService = new ImpersonationService();
