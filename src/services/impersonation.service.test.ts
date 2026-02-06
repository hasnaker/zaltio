/**
 * Impersonation Service Tests
 * Validates: Requirements 6.1, 6.5, 6.6 (User Impersonation)
 * 
 * Tests cover:
 * - Starting impersonation sessions
 * - Ending impersonation sessions
 * - Checking impersonation status
 * - Restriction enforcement
 * - Session expiry
 * - Audit logging
 */

import {
  ImpersonationService,
  ImpersonationError,
  ImpersonationSession,
  ImpersonationResponse,
  DEFAULT_RESTRICTED_ACTIONS
} from './impersonation.service';
import {
  DEFAULT_IMPERSONATION_DURATION_MINUTES,
  MAX_IMPERSONATION_DURATION_MINUTES,
  MIN_REASON_LENGTH,
  MAX_REASON_LENGTH,
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

describe('ImpersonationService', () => {
  let service: ImpersonationService;
  
  // Test data
  const validInput = {
    realm_id: 'test-realm-123',
    admin_id: 'admin-user-001',
    admin_email: 'admin@example.com',
    target_user_id: 'target-user-002',
    target_user_email: 'user@example.com',
    reason: 'Debugging user issue with login flow - ticket #12345',
    ip_address: '192.168.1.100',
    user_agent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)'
  };
  
  beforeEach(() => {
    service = new ImpersonationService();
    service.clearAllSessions();
  });
  
  describe('startImpersonation', () => {
    it('should create impersonation session with valid input', async () => {
      const result = await service.startImpersonation(validInput);
      
      expect(result.session).toBeDefined();
      expect(result.session.id).toMatch(/^imp_/);
      expect(result.session.realm_id).toBe(validInput.realm_id);
      expect(result.session.admin_id).toBe(validInput.admin_id);
      expect(result.session.target_user_id).toBe(validInput.target_user_id);
      expect(result.session.status).toBe('active');
      expect(result.session.reason).toBe(validInput.reason);
      expect(result.access_token).toBeDefined();
      expect(result.refresh_token).toBeDefined();
      expect(result.expires_in).toBeGreaterThan(0);
    });
    
    it('should set default restricted actions', async () => {
      const result = await service.startImpersonation(validInput);
      
      expect(result.session.restricted_actions).toEqual(DEFAULT_RESTRICTED_ACTIONS);
    });
    
    it('should allow custom restricted actions', async () => {
      const customRestrictions = ['change_password', 'delete_account'] as const;
      const result = await service.startImpersonation({
        ...validInput,
        restricted_actions: [...customRestrictions]
      });
      
      expect(result.session.restricted_actions).toEqual(customRestrictions);
    });
    
    it('should use default duration when not specified', async () => {
      const result = await service.startImpersonation(validInput);
      
      const expectedExpiry = Date.now() + DEFAULT_IMPERSONATION_DURATION_MINUTES * 60 * 1000;
      const actualExpiry = new Date(result.session.expires_at).getTime();
      
      // Allow 5 second tolerance
      expect(Math.abs(actualExpiry - expectedExpiry)).toBeLessThan(5000);
    });
    
    it('should use custom duration when specified', async () => {
      const customDuration = 30;
      const result = await service.startImpersonation({
        ...validInput,
        duration_minutes: customDuration
      });
      
      const expectedExpiry = Date.now() + customDuration * 60 * 1000;
      const actualExpiry = new Date(result.session.expires_at).getTime();
      
      // Allow 5 second tolerance
      expect(Math.abs(actualExpiry - expectedExpiry)).toBeLessThan(5000);
    });
    
    it('should cap duration at maximum', async () => {
      const result = await service.startImpersonation({
        ...validInput,
        duration_minutes: 1000 // Way over max
      });
      
      const expectedExpiry = Date.now() + MAX_IMPERSONATION_DURATION_MINUTES * 60 * 1000;
      const actualExpiry = new Date(result.session.expires_at).getTime();
      
      // Allow 5 second tolerance
      expect(Math.abs(actualExpiry - expectedExpiry)).toBeLessThan(5000);
    });
    
    it('should include metadata when provided', async () => {
      const metadata = {
        ticket_id: 'TICKET-12345',
        case_id: 'CASE-67890',
        notes: 'User reported login issues'
      };
      
      const result = await service.startImpersonation({
        ...validInput,
        metadata
      });
      
      // Session should be created successfully
      expect(result.session.id).toBeDefined();
    });
    
    it('should reject reason that is too short', async () => {
      await expect(
        service.startImpersonation({
          ...validInput,
          reason: 'Short'
        })
      ).rejects.toThrow(ImpersonationError);
      
      try {
        await service.startImpersonation({
          ...validInput,
          reason: 'Short'
        });
      } catch (error) {
        expect((error as ImpersonationError).code).toBe('INVALID_REASON');
        expect((error as ImpersonationError).statusCode).toBe(400);
      }
    });
    
    it('should reject reason that is too long', async () => {
      const longReason = 'A'.repeat(MAX_REASON_LENGTH + 1);
      
      await expect(
        service.startImpersonation({
          ...validInput,
          reason: longReason
        })
      ).rejects.toThrow(ImpersonationError);
    });
    
    it('should reject empty reason', async () => {
      await expect(
        service.startImpersonation({
          ...validInput,
          reason: ''
        })
      ).rejects.toThrow(ImpersonationError);
    });
    
    it('should reject self-impersonation', async () => {
      await expect(
        service.startImpersonation({
          ...validInput,
          target_user_id: validInput.admin_id
        })
      ).rejects.toThrow(ImpersonationError);
      
      try {
        await service.startImpersonation({
          ...validInput,
          target_user_id: validInput.admin_id
        });
      } catch (error) {
        expect((error as ImpersonationError).code).toBe('CANNOT_IMPERSONATE');
      }
    });
    
    it('should reject if admin already has active session', async () => {
      // Start first session
      await service.startImpersonation(validInput);
      
      // Try to start another
      await expect(
        service.startImpersonation({
          ...validInput,
          target_user_id: 'another-user-003'
        })
      ).rejects.toThrow(ImpersonationError);
      
      try {
        await service.startImpersonation({
          ...validInput,
          target_user_id: 'another-user-003'
        });
      } catch (error) {
        expect((error as ImpersonationError).code).toBe('ACTIVE_SESSION_EXISTS');
        expect((error as ImpersonationError).statusCode).toBe(409);
      }
    });
    
    it('should trim reason whitespace', async () => {
      const result = await service.startImpersonation({
        ...validInput,
        reason: '   Debugging user issue with login flow   '
      });
      
      expect(result.session.reason).toBe('Debugging user issue with login flow');
    });
  });
  
  describe('endImpersonation', () => {
    it('should end active impersonation session', async () => {
      const { session } = await service.startImpersonation(validInput);
      
      const result = await service.endImpersonation({
        session_id: session.id,
        ended_by: validInput.admin_id,
        end_reason: 'Issue resolved'
      });
      
      expect(result.status).toBe('ended');
      expect(result.ended_at).toBeDefined();
    });
    
    it('should reject ending non-existent session', async () => {
      await expect(
        service.endImpersonation({
          session_id: 'imp_nonexistent',
          ended_by: validInput.admin_id
        })
      ).rejects.toThrow(ImpersonationError);
      
      try {
        await service.endImpersonation({
          session_id: 'imp_nonexistent',
          ended_by: validInput.admin_id
        });
      } catch (error) {
        expect((error as ImpersonationError).code).toBe('SESSION_NOT_FOUND');
        expect((error as ImpersonationError).statusCode).toBe(404);
      }
    });
    
    it('should reject ending already ended session', async () => {
      const { session } = await service.startImpersonation(validInput);
      
      // End it once
      await service.endImpersonation({
        session_id: session.id,
        ended_by: validInput.admin_id
      });
      
      // Try to end again
      await expect(
        service.endImpersonation({
          session_id: session.id,
          ended_by: validInput.admin_id
        })
      ).rejects.toThrow(ImpersonationError);
      
      try {
        await service.endImpersonation({
          session_id: session.id,
          ended_by: validInput.admin_id
        });
      } catch (error) {
        expect((error as ImpersonationError).code).toBe('SESSION_NOT_ACTIVE');
      }
    });
  });
  
  describe('isImpersonating', () => {
    it('should return true for active session', async () => {
      const { session } = await service.startImpersonation(validInput);
      
      const result = await service.isImpersonating(session.id);
      
      expect(result).toBe(true);
    });
    
    it('should return false for ended session', async () => {
      const { session } = await service.startImpersonation(validInput);
      
      await service.endImpersonation({
        session_id: session.id,
        ended_by: validInput.admin_id
      });
      
      const result = await service.isImpersonating(session.id);
      
      expect(result).toBe(false);
    });
    
    it('should return false for non-existent session', async () => {
      const result = await service.isImpersonating('imp_nonexistent');
      
      expect(result).toBe(false);
    });
  });
  
  describe('getSession', () => {
    it('should return session by ID', async () => {
      const { session: created } = await service.startImpersonation(validInput);
      
      const session = await service.getSession(created.id);
      
      expect(session).not.toBeNull();
      expect(session?.id).toBe(created.id);
      expect(session?.admin_id).toBe(validInput.admin_id);
      expect(session?.target_user_id).toBe(validInput.target_user_id);
    });
    
    it('should return null for non-existent session', async () => {
      const session = await service.getSession('imp_nonexistent');
      
      expect(session).toBeNull();
    });
  });
  
  describe('getRestrictions', () => {
    it('should return restrictions for session', async () => {
      const { session } = await service.startImpersonation(validInput);
      
      const restrictions = await service.getRestrictions(session.id);
      
      expect(restrictions).toEqual(DEFAULT_RESTRICTED_ACTIONS);
    });
    
    it('should return empty array for non-existent session', async () => {
      const restrictions = await service.getRestrictions('imp_nonexistent');
      
      expect(restrictions).toEqual([]);
    });
  });
  
  describe('isRestricted', () => {
    it('should return true for restricted action', async () => {
      const { session } = await service.startImpersonation(validInput);
      
      const result = await service.isRestricted(session.id, 'change_password');
      
      expect(result).toBe(true);
    });
    
    it('should return false for non-existent session', async () => {
      const result = await service.isRestricted('imp_nonexistent', 'change_password');
      
      expect(result).toBe(false);
    });
    
    it('should return false for ended session', async () => {
      const { session } = await service.startImpersonation(validInput);
      
      await service.endImpersonation({
        session_id: session.id,
        ended_by: validInput.admin_id
      });
      
      const result = await service.isRestricted(session.id, 'change_password');
      
      expect(result).toBe(false);
    });
  });
  
  describe('getActiveSessionByAdmin', () => {
    it('should return active session for admin', async () => {
      const { session: created } = await service.startImpersonation(validInput);
      
      const session = await service.getActiveSessionByAdmin(validInput.admin_id);
      
      expect(session).not.toBeNull();
      expect(session?.id).toBe(created.id);
    });
    
    it('should return null when admin has no active session', async () => {
      const session = await service.getActiveSessionByAdmin('admin-no-session');
      
      expect(session).toBeNull();
    });
    
    it('should return null when admin session is ended', async () => {
      const { session } = await service.startImpersonation(validInput);
      
      await service.endImpersonation({
        session_id: session.id,
        ended_by: validInput.admin_id
      });
      
      const result = await service.getActiveSessionByAdmin(validInput.admin_id);
      
      expect(result).toBeNull();
    });
  });
  
  describe('getStatus', () => {
    it('should return impersonating status for active session', async () => {
      const { session } = await service.startImpersonation(validInput);
      
      const status = await service.getStatus(session.id);
      
      expect(status.is_impersonating).toBe(true);
      expect(status.session).toBeDefined();
      expect(status.remaining_seconds).toBeGreaterThan(0);
    });
    
    it('should return not impersonating for ended session', async () => {
      const { session } = await service.startImpersonation(validInput);
      
      await service.endImpersonation({
        session_id: session.id,
        ended_by: validInput.admin_id
      });
      
      const status = await service.getStatus(session.id);
      
      expect(status.is_impersonating).toBe(false);
      expect(status.session).toBeUndefined();
    });
    
    it('should return not impersonating for non-existent session', async () => {
      const status = await service.getStatus('imp_nonexistent');
      
      expect(status.is_impersonating).toBe(false);
    });
  });
  
  describe('validateToken', () => {
    it('should return session for valid token', async () => {
      const { session, access_token } = await service.startImpersonation(validInput);
      
      const result = await service.validateToken(access_token);
      
      expect(result).not.toBeNull();
      expect(result?.id).toBe(session.id);
    });
    
    it('should return null for invalid token', async () => {
      const result = await service.validateToken('invalid-token');
      
      expect(result).toBeNull();
    });
    
    it('should return null for ended session token', async () => {
      const { session, access_token } = await service.startImpersonation(validInput);
      
      await service.endImpersonation({
        session_id: session.id,
        ended_by: validInput.admin_id
      });
      
      const result = await service.validateToken(access_token);
      
      expect(result).toBeNull();
    });
  });
  
  describe('getImpersonationClaims', () => {
    it('should return correct JWT claims', async () => {
      const { session } = await service.startImpersonation(validInput);
      const fullSession = await service.getSession(session.id);
      
      const claims = service.getImpersonationClaims(fullSession!);
      
      expect(claims.is_impersonation).toBe(true);
      expect(claims.impersonation_session_id).toBe(session.id);
      expect(claims.admin_id).toBe(validInput.admin_id);
      expect(claims.admin_email).toBe(validInput.admin_email);
      expect(claims.original_user_id).toBe(validInput.admin_id);
      expect(claims.restricted_actions).toEqual(DEFAULT_RESTRICTED_ACTIONS);
    });
  });
  
  describe('logAction', () => {
    it('should log action without error', async () => {
      const { session } = await service.startImpersonation(validInput);
      
      // Should not throw
      await expect(
        service.logAction(session.id, 'viewed_profile', { page: '/profile' })
      ).resolves.not.toThrow();
    });
    
    it('should handle non-existent session gracefully', async () => {
      // Should not throw
      await expect(
        service.logAction('imp_nonexistent', 'some_action')
      ).resolves.not.toThrow();
    });
  });
  
  describe('logBlockedAction', () => {
    it('should log blocked action without error', async () => {
      const { session } = await service.startImpersonation(validInput);
      
      // Should not throw
      await expect(
        service.logBlockedAction(session.id, 'change_password')
      ).resolves.not.toThrow();
    });
  });
  
  describe('getSessionsByTargetUser', () => {
    it('should return sessions for target user', async () => {
      await service.startImpersonation(validInput);
      
      const sessions = await service.getSessionsByTargetUser(validInput.target_user_id);
      
      expect(sessions.length).toBe(1);
      expect(sessions[0].target_user_id).toBe(validInput.target_user_id);
    });
    
    it('should return empty array for user with no sessions', async () => {
      const sessions = await service.getSessionsByTargetUser('user-no-sessions');
      
      expect(sessions).toEqual([]);
    });
  });
});

describe('Model Helper Functions', () => {
  describe('generateImpersonationId', () => {
    it('should generate ID with correct prefix', () => {
      const id = generateImpersonationId();
      
      expect(id).toMatch(/^imp_[a-f0-9]{24}$/);
    });
    
    it('should generate unique IDs', () => {
      const ids = new Set<string>();
      for (let i = 0; i < 100; i++) {
        ids.add(generateImpersonationId());
      }
      
      expect(ids.size).toBe(100);
    });
  });
  
  describe('calculateImpersonationExpiry', () => {
    it('should calculate expiry with default duration', () => {
      const expiry = calculateImpersonationExpiry();
      const expectedExpiry = Date.now() + DEFAULT_IMPERSONATION_DURATION_MINUTES * 60 * 1000;
      const actualExpiry = new Date(expiry).getTime();
      
      // Allow 1 second tolerance
      expect(Math.abs(actualExpiry - expectedExpiry)).toBeLessThan(1000);
    });
    
    it('should calculate expiry with custom duration', () => {
      const duration = 30;
      const expiry = calculateImpersonationExpiry(duration);
      const expectedExpiry = Date.now() + duration * 60 * 1000;
      const actualExpiry = new Date(expiry).getTime();
      
      // Allow 1 second tolerance
      expect(Math.abs(actualExpiry - expectedExpiry)).toBeLessThan(1000);
    });
    
    it('should cap at maximum duration', () => {
      const expiry = calculateImpersonationExpiry(1000);
      const expectedExpiry = Date.now() + MAX_IMPERSONATION_DURATION_MINUTES * 60 * 1000;
      const actualExpiry = new Date(expiry).getTime();
      
      // Allow 1 second tolerance
      expect(Math.abs(actualExpiry - expectedExpiry)).toBeLessThan(1000);
    });
  });
  
  describe('isImpersonationExpired', () => {
    it('should return false for non-expired session', () => {
      const session = {
        expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString()
      } as ImpersonationSession;
      
      expect(isImpersonationExpired(session)).toBe(false);
    });
    
    it('should return true for expired session', () => {
      const session = {
        expires_at: new Date(Date.now() - 60 * 1000).toISOString()
      } as ImpersonationSession;
      
      expect(isImpersonationExpired(session)).toBe(true);
    });
  });
  
  describe('isImpersonationActive', () => {
    it('should return true for active non-expired session', () => {
      const session = {
        status: 'active',
        expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString()
      } as ImpersonationSession;
      
      expect(isImpersonationActive(session)).toBe(true);
    });
    
    it('should return false for ended session', () => {
      const session = {
        status: 'ended',
        expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString()
      } as ImpersonationSession;
      
      expect(isImpersonationActive(session)).toBe(false);
    });
    
    it('should return false for expired session', () => {
      const session = {
        status: 'active',
        expires_at: new Date(Date.now() - 60 * 1000).toISOString()
      } as ImpersonationSession;
      
      expect(isImpersonationActive(session)).toBe(false);
    });
  });
  
  describe('isActionRestricted', () => {
    it('should return true for restricted action', () => {
      const session = {
        status: 'active',
        restricted_actions: ['change_password', 'delete_account']
      } as ImpersonationSession;
      
      expect(isActionRestricted(session, 'change_password')).toBe(true);
    });
    
    it('should return false for non-restricted action', () => {
      const session = {
        status: 'active',
        restricted_actions: ['change_password']
      } as ImpersonationSession;
      
      expect(isActionRestricted(session, 'delete_account')).toBe(false);
    });

    it('should return false for ended session', () => {
      const session = {
        status: 'ended',
        restricted_actions: ['change_password', 'delete_account']
      } as ImpersonationSession;
      
      expect(isActionRestricted(session, 'change_password')).toBe(false);
    });

    it('should return false for expired session', () => {
      const session = {
        status: 'expired',
        restricted_actions: ['change_password', 'delete_account']
      } as ImpersonationSession;
      
      expect(isActionRestricted(session, 'change_password')).toBe(false);
    });
  });
  
  describe('isValidReason', () => {
    it('should accept valid reason', () => {
      const result = isValidReason('Debugging user login issue - ticket #12345');
      
      expect(result.valid).toBe(true);
      expect(result.error).toBeUndefined();
    });
    
    it('should reject empty reason', () => {
      const result = isValidReason('');
      
      expect(result.valid).toBe(false);
      expect(result.error).toBe('Reason is required');
    });
    
    it('should reject short reason', () => {
      const result = isValidReason('Short');
      
      expect(result.valid).toBe(false);
      expect(result.error).toContain(`at least ${MIN_REASON_LENGTH}`);
    });
    
    it('should reject long reason', () => {
      const result = isValidReason('A'.repeat(MAX_REASON_LENGTH + 1));
      
      expect(result.valid).toBe(false);
      expect(result.error).toContain(`at most ${MAX_REASON_LENGTH}`);
    });
  });
  
  describe('canImpersonateUser', () => {
    it('should allow impersonating regular user', () => {
      const result = canImpersonateUser('admin-001', 'user-002', false);
      
      expect(result.valid).toBe(true);
    });
    
    it('should reject self-impersonation', () => {
      const result = canImpersonateUser('admin-001', 'admin-001', false);
      
      expect(result.valid).toBe(false);
      expect(result.error).toBe('Cannot impersonate yourself');
    });
    
    it('should reject impersonating admin', () => {
      const result = canImpersonateUser('admin-001', 'admin-002', true);
      
      expect(result.valid).toBe(false);
      expect(result.error).toBe('Cannot impersonate admin users');
    });
  });
  
  describe('toImpersonationResponse', () => {
    it('should convert session to response format', () => {
      const session: ImpersonationSession = {
        id: 'imp_test123',
        realm_id: 'test-realm',
        admin_id: 'admin-001',
        admin_email: 'admin@example.com',
        target_user_id: 'user-002',
        target_user_email: 'user@example.com',
        reason: 'Testing',
        status: 'active',
        restricted_actions: ['change_password'],
        access_token: 'token',
        refresh_token_hash: 'hash',
        started_at: '2026-01-01T00:00:00Z',
        expires_at: '2026-01-01T01:00:00Z',
        ip_address: '127.0.0.1',
        user_agent: 'Test',
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z'
      };
      
      const response = toImpersonationResponse(session);
      
      expect(response.id).toBe(session.id);
      expect(response.realm_id).toBe(session.realm_id);
      expect(response.admin_id).toBe(session.admin_id);
      expect(response.target_user_id).toBe(session.target_user_id);
      expect(response.status).toBe(session.status);
      expect(response.restricted_actions).toEqual(session.restricted_actions);
      expect(response.started_at).toBe(session.started_at);
      expect(response.expires_at).toBe(session.expires_at);
      expect(response.reason).toBe(session.reason);
      
      // Should not include sensitive fields
      expect((response as unknown as Record<string, unknown>).access_token).toBeUndefined();
      expect((response as unknown as Record<string, unknown>).refresh_token_hash).toBeUndefined();
    });
  });
  
  describe('getRemainingTime', () => {
    it('should return positive seconds for non-expired session', () => {
      const session = {
        expires_at: new Date(Date.now() + 30 * 60 * 1000).toISOString()
      } as ImpersonationSession;
      
      const remaining = getRemainingTime(session);
      
      expect(remaining).toBeGreaterThan(0);
      expect(remaining).toBeLessThanOrEqual(30 * 60);
    });
    
    it('should return 0 for expired session', () => {
      const session = {
        expires_at: new Date(Date.now() - 60 * 1000).toISOString()
      } as ImpersonationSession;
      
      const remaining = getRemainingTime(session);
      
      expect(remaining).toBe(0);
    });
  });
});
