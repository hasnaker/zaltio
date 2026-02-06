/**
 * Reverification Service (Step-Up Authentication)
 * Requires users to re-authenticate for sensitive operations
 * 
 * Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5 (Reverification)
 * 
 * Levels:
 * - password: Re-enter password (lowest)
 * - mfa: Verify with MFA code (medium)
 * - webauthn: Verify with WebAuthn (highest, phishing-proof)
 * 
 * Security:
 * - Reverification expires after configured time
 * - Higher levels satisfy lower level requirements
 * - Audit logging for all reverification events
 */

import { randomBytes } from 'crypto';
import {
  ReverificationLevel,
  SessionReverification,
  ReverificationConfig,
  ReverificationProof,
  ReverificationProofType,
  REVERIFICATION_LEVEL_HIERARCHY,
  DEFAULT_REVERIFICATION_VALIDITY,
  DEFAULT_REVERIFICATION_REQUIREMENTS,
  levelSatisfiesRequirement,
  getValidityMinutes,
  isReverificationValid,
  reverificationSatisfiesRequirement,
  proofTypeToLevel,
  findReverificationRequirement
} from '../models/reverification.model';

// Re-export types for convenience
export {
  ReverificationLevel,
  SessionReverification,
  ReverificationConfig,
  ReverificationProof,
  ReverificationProofType,
  REVERIFICATION_LEVEL_HIERARCHY,
  DEFAULT_REVERIFICATION_VALIDITY
};

/**
 * In-memory store for reverification status (use DynamoDB in production)
 */
const reverificationStore = new Map<string, SessionReverification>();

/**
 * Reverification Service Error
 */
export class ReverificationError extends Error {
  code: string;
  statusCode: number;
  requiredLevel?: ReverificationLevel;
  
  constructor(code: string, message: string, statusCode: number = 403, requiredLevel?: ReverificationLevel) {
    super(message);
    this.name = 'ReverificationError';
    this.code = code;
    this.statusCode = statusCode;
    this.requiredLevel = requiredLevel;
  }
}

/**
 * Reverification Service
 */
export class ReverificationService {
  
  /**
   * Mark session as requiring reverification
   */
  async requireReverification(
    sessionId: string,
    level: ReverificationLevel
  ): Promise<void> {
    // Clear any existing reverification for this session
    reverificationStore.delete(sessionId);
    
    // Log the requirement
    this.logAuditEvent('reverification.required', {
      sessionId,
      level
    }).catch(() => {});
  }
  
  /**
   * Check if session has valid reverification for required level
   */
  async checkReverification(
    sessionId: string,
    requiredLevel: ReverificationLevel
  ): Promise<boolean> {
    const reverification = reverificationStore.get(sessionId);
    return reverificationSatisfiesRequirement(reverification, requiredLevel);
  }
  
  /**
   * Complete reverification for a session
   */
  async completeReverification(
    sessionId: string,
    userId: string,
    proof: ReverificationProof,
    options: {
      validityMinutes?: number;
      ipAddress?: string;
      userAgent?: string;
    } = {}
  ): Promise<SessionReverification> {
    // Validate the proof (in production, this would verify password/MFA/WebAuthn)
    await this.validateProof(userId, proof);
    
    // Determine level from proof type
    const level = proofTypeToLevel(proof.type);
    
    const now = new Date();
    const validityMinutes = getValidityMinutes(level, options.validityMinutes);
    const expiresAt = new Date(now.getTime() + validityMinutes * 60 * 1000);
    
    const reverification: SessionReverification = {
      sessionId,
      level,
      verifiedAt: now.toISOString(),
      expiresAt: expiresAt.toISOString(),
      method: proof.type
    };
    
    // Store reverification
    reverificationStore.set(sessionId, reverification);
    
    // Log completion
    this.logAuditEvent('reverification.completed', {
      sessionId,
      userId,
      level,
      method: proof.type,
      expiresAt: expiresAt.toISOString()
    }).catch(() => {});
    
    return reverification;
  }
  
  /**
   * Get reverification requirement for an endpoint
   */
  getRequiredLevel(endpoint: string, method: string): ReverificationConfig | null {
    const requirement = findReverificationRequirement(endpoint, method);
    
    if (!requirement) {
      return null;
    }
    
    return {
      level: requirement.level,
      validityMinutes: requirement.validityMinutes || DEFAULT_REVERIFICATION_VALIDITY[requirement.level]
    };
  }
  
  /**
   * Get current reverification status for a session
   */
  async getReverificationStatus(
    sessionId: string,
    requiredLevel?: ReverificationLevel
  ): Promise<{
    hasReverification: boolean;
    reverification: SessionReverification | null;
    isValid: boolean;
    requiredLevel: ReverificationLevel | null;
  }> {
    const reverification = reverificationStore.get(sessionId) || null;
    const hasReverification = reverification !== null;
    const isValid = reverification ? isReverificationValid(reverification) : false;
    
    // Clean up expired reverification
    if (reverification && !isValid) {
      reverificationStore.delete(sessionId);
    }
    
    return {
      hasReverification,
      reverification: isValid ? reverification : null,
      isValid,
      requiredLevel: requiredLevel || null
    };
  }
  
  /**
   * Clear reverification for a session
   */
  async clearReverification(sessionId: string): Promise<void> {
    reverificationStore.delete(sessionId);
    
    this.logAuditEvent('reverification.cleared', {
      sessionId
    }).catch(() => {});
  }
  
  /**
   * Check if one level satisfies another
   * Higher levels satisfy lower level requirements
   */
  levelSatisfies(actualLevel: ReverificationLevel, requiredLevel: ReverificationLevel): boolean {
    return levelSatisfiesRequirement(actualLevel, requiredLevel);
  }
  
  /**
   * Get the level index (for comparison)
   */
  getLevelIndex(level: ReverificationLevel): number {
    return REVERIFICATION_LEVEL_HIERARCHY.indexOf(level);
  }
  
  /**
   * Validate reverification proof
   * In production, this would verify password/MFA/WebAuthn
   */
  private async validateProof(userId: string, proof: ReverificationProof): Promise<void> {
    if (!proof.value) {
      throw new ReverificationError('MISSING_PROOF_VALUE', 'Proof value is required', 400);
    }
    
    switch (proof.type) {
      case 'password':
        // In production: verify password against stored hash
        if (proof.value.length < 1) {
          throw new ReverificationError('INVALID_PASSWORD', 'Invalid password', 401);
        }
        break;
        
      case 'totp':
        // In production: verify TOTP code
        if (!/^\d{6}$/.test(proof.value)) {
          throw new ReverificationError('INVALID_TOTP', 'Invalid TOTP code format', 401);
        }
        break;
        
      case 'backup_code':
        // In production: verify backup code
        if (proof.value.length < 8) {
          throw new ReverificationError('INVALID_BACKUP_CODE', 'Invalid backup code', 401);
        }
        break;
        
      case 'webauthn':
        // In production: verify WebAuthn assertion
        if (!proof.challenge) {
          throw new ReverificationError('MISSING_CHALLENGE', 'WebAuthn challenge is required', 400);
        }
        break;
        
      default:
        throw new ReverificationError('INVALID_PROOF_TYPE', 'Invalid proof type', 400);
    }
  }
  
  /**
   * Log audit event
   */
  private async logAuditEvent(
    event: string,
    data: Record<string, unknown>
  ): Promise<void> {
    if (process.env.NODE_ENV !== 'test') {
      console.log(`[AUDIT] ${event}`, JSON.stringify(data));
    }
  }
}

// Export singleton instance
export const reverificationService = new ReverificationService();
