/**
 * Session Limits Service Tests
 * Validates: Requirement 13.6 - Configure maximum concurrent sessions per realm
 * 
 * Tests for:
 * - Per-realm session limits configuration
 * - Revoke oldest session when limit exceeded
 * - Notify user when session is revoked due to limit
 * - Block new session when configured
 * 
 * ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK (using mocks for external dependencies only)
 */

// Mock dependencies before importing
jest.mock('../repositories/realm.repository', () => ({
  getRealmSettings: jest.fn()
}));

jest.mock('../repositories/session.repository', () => ({
  getUserSessions: jest.fn(),
  deleteSession: jest.fn(),
  countUserSessions: jest.fn()
}));

jest.mock('./security-logger.service', () => ({
  logSecurityEvent: jest.fn()
}));

jest.mock('./webhook-events.service', () => ({
  dispatchSessionRevoked: jest.fn()
}));

import {
  getRealmSessionLimits,
  isSessionLimitsEnabled,
  enforceSessionLimits,
  checkSessionLimits,
  SessionLimitCheckResult,
  EnforceSessionLimitOptions
} from './session-limits.service';
import { getRealmSettings } from '../repositories/realm.repository';
import { 
  getUserSessions, 
  deleteSession, 
  countUserSessions 
} from '../repositories/session.repository';
import { logSecurityEvent } from './security-logger.service';
import { dispatchSessionRevoked } from './webhook-events.service';
import { 
  DEFAULT_SESSION_LIMITS, 
  HEALTHCARE_SESSION_LIMITS,
  SessionLimitsConfig 
} from '../models/realm.model';
import { Session } from '../models/session.model';

// Test data
const TEST_USER_ID = 'user_test123';
const TEST_REALM_ID = 'realm_test123';
const TEST_HEALTHCARE_REALM_ID = 'clinisyn_healthcare';

const createMockSession = (id: string, createdAt: string, overrides: Partial<Session> = {}): Session => ({
  id,
  user_id: TEST_USER_ID,
  realm_id: TEST_REALM_ID,
  access_token: 'mock_access_token',
  refresh_token: 'mock_refresh_token',
  refresh_token_hash: 'mock_hash',
  expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
  created_at: createdAt,
  last_used_at: new Date().toISOString(),
  ip_address: '192.168.1.100',
  user_agent: 'Mozilla/5.0 Chrome/120.0.0.0',
  revoked: false,
  ...overrides
});

describe('Session Limits Service', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    
    // Default mock implementations
    (logSecurityEvent as jest.Mock).mockResolvedValue(undefined);
    (dispatchSessionRevoked as jest.Mock).mockResolvedValue({ webhooks_triggered: 1 });
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  describe('getRealmSessionLimits', () => {
    /**
     * Validates: Requirement 13.6 - Configure maximum concurrent sessions per realm
     */
    it('should return configured session limits for realm', async () => {
      const customLimits: SessionLimitsConfig = {
        max_concurrent_sessions: 10,
        limit_exceeded_action: 'block_new',
        notify_on_revoke: false,
        enabled: true
      };
      
      (getRealmSettings as jest.Mock).mockResolvedValue({
        session_limits: customLimits
      });

      const result = await getRealmSessionLimits(TEST_REALM_ID);

      expect(result).toEqual(customLimits);
      expect(getRealmSettings).toHaveBeenCalledWith(TEST_REALM_ID);
    });

    it('should return default limits when not configured', async () => {
      (getRealmSettings as jest.Mock).mockResolvedValue({});

      const result = await getRealmSessionLimits(TEST_REALM_ID);

      expect(result).toEqual(DEFAULT_SESSION_LIMITS);
    });

    it('should return healthcare limits for healthcare realms', async () => {
      (getRealmSettings as jest.Mock).mockResolvedValue({});

      const result = await getRealmSessionLimits(TEST_HEALTHCARE_REALM_ID);

      expect(result).toEqual(HEALTHCARE_SESSION_LIMITS);
      expect(result.max_concurrent_sessions).toBe(3); // Stricter for healthcare
    });

    it('should return defaults on error', async () => {
      (getRealmSettings as jest.Mock).mockRejectedValue(new Error('Database error'));

      const result = await getRealmSessionLimits(TEST_REALM_ID);

      expect(result).toEqual(DEFAULT_SESSION_LIMITS);
    });
  });

  describe('isSessionLimitsEnabled', () => {
    it('should return true when limits are enabled', async () => {
      (getRealmSettings as jest.Mock).mockResolvedValue({
        session_limits: {
          ...DEFAULT_SESSION_LIMITS,
          enabled: true,
          max_concurrent_sessions: 5
        }
      });

      const result = await isSessionLimitsEnabled(TEST_REALM_ID);

      expect(result).toBe(true);
    });

    it('should return false when limits are disabled', async () => {
      (getRealmSettings as jest.Mock).mockResolvedValue({
        session_limits: {
          ...DEFAULT_SESSION_LIMITS,
          enabled: false
        }
      });

      const result = await isSessionLimitsEnabled(TEST_REALM_ID);

      expect(result).toBe(false);
    });

    it('should return false when max_concurrent_sessions is 0', async () => {
      (getRealmSettings as jest.Mock).mockResolvedValue({
        session_limits: {
          ...DEFAULT_SESSION_LIMITS,
          enabled: true,
          max_concurrent_sessions: 0
        }
      });

      const result = await isSessionLimitsEnabled(TEST_REALM_ID);

      expect(result).toBe(false);
    });
  });

  describe('enforceSessionLimits', () => {
    const defaultOptions: EnforceSessionLimitOptions = {
      userId: TEST_USER_ID,
      realmId: TEST_REALM_ID,
      clientIp: '192.168.1.1',
      userAgent: 'Mozilla/5.0',
      userEmail: 'test@example.com'
    };

    /**
     * Validates: Requirement 13.6 - Allow session when under limit
     */
    it('should allow session when under limit', async () => {
      (getRealmSettings as jest.Mock).mockResolvedValue({
        session_limits: {
          max_concurrent_sessions: 5,
          limit_exceeded_action: 'revoke_oldest',
          notify_on_revoke: true,
          enabled: true
        }
      });
      (countUserSessions as jest.Mock).mockResolvedValue(3);

      const result = await enforceSessionLimits(defaultOptions);

      expect(result.allowed).toBe(true);
      expect(result.currentCount).toBe(3);
      expect(result.maxSessions).toBe(5);
      expect(result.revokedSessions).toHaveLength(0);
    });

    it('should allow session when limits are disabled', async () => {
      (getRealmSettings as jest.Mock).mockResolvedValue({
        session_limits: {
          ...DEFAULT_SESSION_LIMITS,
          enabled: false
        }
      });

      const result = await enforceSessionLimits(defaultOptions);

      expect(result.allowed).toBe(true);
      expect(result.maxSessions).toBe(0); // 0 means unlimited
    });

    /**
     * Validates: Requirement 13.6 - Revoke oldest session when limit exceeded
     */
    it('should revoke oldest session when limit reached and action is revoke_oldest', async () => {
      const sessions = [
        createMockSession('session_1', '2026-01-20T10:00:00Z'),
        createMockSession('session_2', '2026-01-21T10:00:00Z'),
        createMockSession('session_3', '2026-01-22T10:00:00Z'),
        createMockSession('session_4', '2026-01-23T10:00:00Z'),
        createMockSession('session_5', '2026-01-24T10:00:00Z')
      ];

      (getRealmSettings as jest.Mock).mockResolvedValue({
        session_limits: {
          max_concurrent_sessions: 5,
          limit_exceeded_action: 'revoke_oldest',
          notify_on_revoke: true,
          enabled: true
        }
      });
      (countUserSessions as jest.Mock).mockResolvedValue(5);
      (getUserSessions as jest.Mock).mockResolvedValue(sessions);
      (deleteSession as jest.Mock).mockResolvedValue(true);

      const result = await enforceSessionLimits(defaultOptions);

      expect(result.allowed).toBe(true);
      expect(result.revokedSessions).toHaveLength(1);
      expect(result.revokedSessions[0].sessionId).toBe('session_1'); // Oldest
      expect(result.revokedSessions[0].reason).toBe('session_limit_exceeded');
      expect(deleteSession).toHaveBeenCalledWith('session_1', TEST_REALM_ID, TEST_USER_ID);
    });

    it('should revoke multiple sessions when significantly over limit', async () => {
      const sessions = [
        createMockSession('session_1', '2026-01-20T10:00:00Z'),
        createMockSession('session_2', '2026-01-21T10:00:00Z'),
        createMockSession('session_3', '2026-01-22T10:00:00Z'),
        createMockSession('session_4', '2026-01-23T10:00:00Z'),
        createMockSession('session_5', '2026-01-24T10:00:00Z'),
        createMockSession('session_6', '2026-01-25T10:00:00Z'),
        createMockSession('session_7', '2026-01-26T10:00:00Z')
      ];

      (getRealmSettings as jest.Mock).mockResolvedValue({
        session_limits: {
          max_concurrent_sessions: 5,
          limit_exceeded_action: 'revoke_oldest',
          notify_on_revoke: true,
          enabled: true
        }
      });
      (countUserSessions as jest.Mock).mockResolvedValue(7);
      (getUserSessions as jest.Mock).mockResolvedValue(sessions);
      (deleteSession as jest.Mock).mockResolvedValue(true);

      const result = await enforceSessionLimits(defaultOptions);

      expect(result.allowed).toBe(true);
      // Need to revoke 3 sessions (7 - 5 + 1 = 3) to make room for new one
      expect(result.revokedSessions).toHaveLength(3);
      expect(result.revokedSessions[0].sessionId).toBe('session_1');
      expect(result.revokedSessions[1].sessionId).toBe('session_2');
      expect(result.revokedSessions[2].sessionId).toBe('session_3');
    });

    /**
     * Validates: Requirement 13.6 - Block new session when configured
     */
    it('should block new session when action is block_new', async () => {
      (getRealmSettings as jest.Mock).mockResolvedValue({
        session_limits: {
          max_concurrent_sessions: 5,
          limit_exceeded_action: 'block_new',
          notify_on_revoke: true,
          enabled: true
        }
      });
      (countUserSessions as jest.Mock).mockResolvedValue(5);

      const result = await enforceSessionLimits(defaultOptions);

      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('Maximum concurrent sessions');
      expect(result.revokedSessions).toHaveLength(0);
      expect(deleteSession).not.toHaveBeenCalled();
    });

    /**
     * Validates: Requirement 13.6 - Notify user when session is revoked due to limit
     */
    it('should notify user when session is revoked and notify_on_revoke is true', async () => {
      const sessions = [
        createMockSession('session_1', '2026-01-20T10:00:00Z'),
        createMockSession('session_2', '2026-01-21T10:00:00Z')
      ];

      (getRealmSettings as jest.Mock).mockResolvedValue({
        session_limits: {
          max_concurrent_sessions: 2,
          limit_exceeded_action: 'revoke_oldest',
          notify_on_revoke: true,
          enabled: true
        }
      });
      (countUserSessions as jest.Mock).mockResolvedValue(2);
      (getUserSessions as jest.Mock).mockResolvedValue(sessions);
      (deleteSession as jest.Mock).mockResolvedValue(true);

      const result = await enforceSessionLimits(defaultOptions);

      expect(result.notificationSent).toBe(true);
      expect(logSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'session_limit_notification_sent'
        })
      );
    });

    it('should not notify user when notify_on_revoke is false', async () => {
      const sessions = [
        createMockSession('session_1', '2026-01-20T10:00:00Z'),
        createMockSession('session_2', '2026-01-21T10:00:00Z')
      ];

      (getRealmSettings as jest.Mock).mockResolvedValue({
        session_limits: {
          max_concurrent_sessions: 2,
          limit_exceeded_action: 'revoke_oldest',
          notify_on_revoke: false,
          enabled: true
        }
      });
      (countUserSessions as jest.Mock).mockResolvedValue(2);
      (getUserSessions as jest.Mock).mockResolvedValue(sessions);
      (deleteSession as jest.Mock).mockResolvedValue(true);

      const result = await enforceSessionLimits(defaultOptions);

      expect(result.notificationSent).toBe(false);
      expect(logSecurityEvent).not.toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'session_limit_notification_sent'
        })
      );
    });

    it('should trigger session.revoked webhook when session is revoked', async () => {
      const sessions = [
        createMockSession('session_1', '2026-01-20T10:00:00Z'),
        createMockSession('session_2', '2026-01-21T10:00:00Z')
      ];

      (getRealmSettings as jest.Mock).mockResolvedValue({
        session_limits: {
          max_concurrent_sessions: 2,
          limit_exceeded_action: 'revoke_oldest',
          notify_on_revoke: true,
          enabled: true
        }
      });
      (countUserSessions as jest.Mock).mockResolvedValue(2);
      (getUserSessions as jest.Mock).mockResolvedValue(sessions);
      (deleteSession as jest.Mock).mockResolvedValue(true);

      await enforceSessionLimits(defaultOptions);

      expect(dispatchSessionRevoked).toHaveBeenCalledWith(
        TEST_REALM_ID,
        expect.objectContaining({
          session_id: 'session_1',
          user_id: TEST_USER_ID,
          reason: 'session_limit_exceeded'
        })
      );
    });

    it('should log security event when session is revoked', async () => {
      const sessions = [
        createMockSession('session_1', '2026-01-20T10:00:00Z'),
        createMockSession('session_2', '2026-01-21T10:00:00Z')
      ];

      (getRealmSettings as jest.Mock).mockResolvedValue({
        session_limits: {
          max_concurrent_sessions: 2,
          limit_exceeded_action: 'revoke_oldest',
          notify_on_revoke: true,
          enabled: true
        }
      });
      (countUserSessions as jest.Mock).mockResolvedValue(2);
      (getUserSessions as jest.Mock).mockResolvedValue(sessions);
      (deleteSession as jest.Mock).mockResolvedValue(true);

      await enforceSessionLimits(defaultOptions);

      expect(logSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'session_revoked_limit_exceeded',
          realm_id: TEST_REALM_ID,
          user_id: TEST_USER_ID,
          details: expect.objectContaining({
            revoked_session_id: 'session_1',
            max_sessions: 2
          })
        })
      );
    });

    it('should log security event when session is blocked', async () => {
      (getRealmSettings as jest.Mock).mockResolvedValue({
        session_limits: {
          max_concurrent_sessions: 5,
          limit_exceeded_action: 'block_new',
          notify_on_revoke: true,
          enabled: true
        }
      });
      (countUserSessions as jest.Mock).mockResolvedValue(5);

      await enforceSessionLimits(defaultOptions);

      expect(logSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'session_limit_blocked',
          details: expect.objectContaining({
            action: 'block_new'
          })
        })
      );
    });

    it('should skip revoked sessions when finding oldest', async () => {
      const sessions = [
        createMockSession('session_1', '2026-01-20T10:00:00Z', { revoked: true }),
        createMockSession('session_2', '2026-01-21T10:00:00Z'),
        createMockSession('session_3', '2026-01-22T10:00:00Z')
      ];

      (getRealmSettings as jest.Mock).mockResolvedValue({
        session_limits: {
          max_concurrent_sessions: 2,
          limit_exceeded_action: 'revoke_oldest',
          notify_on_revoke: true,
          enabled: true
        }
      });
      (countUserSessions as jest.Mock).mockResolvedValue(2);
      (getUserSessions as jest.Mock).mockResolvedValue(sessions);
      (deleteSession as jest.Mock).mockResolvedValue(true);

      const result = await enforceSessionLimits(defaultOptions);

      // Should revoke session_2 (oldest non-revoked), not session_1 (revoked)
      expect(result.revokedSessions[0].sessionId).toBe('session_2');
    });

    it('should handle delete failure gracefully', async () => {
      const sessions = [
        createMockSession('session_1', '2026-01-20T10:00:00Z'),
        createMockSession('session_2', '2026-01-21T10:00:00Z')
      ];

      (getRealmSettings as jest.Mock).mockResolvedValue({
        session_limits: {
          max_concurrent_sessions: 2,
          limit_exceeded_action: 'revoke_oldest',
          notify_on_revoke: true,
          enabled: true
        }
      });
      (countUserSessions as jest.Mock).mockResolvedValue(2);
      (getUserSessions as jest.Mock).mockResolvedValue(sessions);
      (deleteSession as jest.Mock).mockResolvedValue(false); // Delete fails

      const result = await enforceSessionLimits(defaultOptions);

      // Should still allow but no sessions revoked
      expect(result.allowed).toBe(true);
      expect(result.revokedSessions).toHaveLength(0);
    });

    it('should handle errors gracefully and allow session', async () => {
      // When getRealmSettings throws, getRealmSessionLimits catches it and returns defaults
      // So we need to make countUserSessions throw to test the error handling in enforceSessionLimits
      (getRealmSettings as jest.Mock).mockResolvedValue({
        session_limits: DEFAULT_SESSION_LIMITS
      });
      (countUserSessions as jest.Mock).mockRejectedValue(new Error('Database error'));

      const result = await enforceSessionLimits(defaultOptions);

      // On error, allow the session
      expect(result.allowed).toBe(true);
      expect(logSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'session_limit_enforcement_error'
        })
      );
    });
  });

  describe('checkSessionLimits', () => {
    it('should return current session count and limit info', async () => {
      (getRealmSettings as jest.Mock).mockResolvedValue({
        session_limits: {
          max_concurrent_sessions: 5,
          limit_exceeded_action: 'revoke_oldest',
          notify_on_revoke: true,
          enabled: true
        }
      });
      (countUserSessions as jest.Mock).mockResolvedValue(3);

      const result = await checkSessionLimits(TEST_REALM_ID, TEST_USER_ID);

      expect(result.currentCount).toBe(3);
      expect(result.maxSessions).toBe(5);
      expect(result.limitReached).toBe(false);
      expect(result.enabled).toBe(true);
    });

    it('should indicate when limit is reached', async () => {
      (getRealmSettings as jest.Mock).mockResolvedValue({
        session_limits: {
          max_concurrent_sessions: 5,
          limit_exceeded_action: 'revoke_oldest',
          notify_on_revoke: true,
          enabled: true
        }
      });
      (countUserSessions as jest.Mock).mockResolvedValue(5);

      const result = await checkSessionLimits(TEST_REALM_ID, TEST_USER_ID);

      expect(result.limitReached).toBe(true);
    });

    it('should indicate when limits are disabled', async () => {
      (getRealmSettings as jest.Mock).mockResolvedValue({
        session_limits: {
          ...DEFAULT_SESSION_LIMITS,
          enabled: false
        }
      });
      (countUserSessions as jest.Mock).mockResolvedValue(10);

      const result = await checkSessionLimits(TEST_REALM_ID, TEST_USER_ID);

      expect(result.enabled).toBe(false);
      expect(result.limitReached).toBe(false);
    });
  });

  describe('Healthcare Realm Session Limits', () => {
    /**
     * Healthcare realms should have stricter session limits (HIPAA compliance)
     */
    it('should use stricter limits for healthcare realms', async () => {
      (getRealmSettings as jest.Mock).mockResolvedValue({});

      const result = await getRealmSessionLimits(TEST_HEALTHCARE_REALM_ID);

      expect(result.max_concurrent_sessions).toBe(3); // Stricter than default 5
    });

    it('should enforce healthcare limits correctly', async () => {
      const sessions = [
        createMockSession('session_1', '2026-01-20T10:00:00Z'),
        createMockSession('session_2', '2026-01-21T10:00:00Z'),
        createMockSession('session_3', '2026-01-22T10:00:00Z')
      ];

      (getRealmSettings as jest.Mock).mockResolvedValue({});
      (countUserSessions as jest.Mock).mockResolvedValue(3);
      (getUserSessions as jest.Mock).mockResolvedValue(sessions);
      (deleteSession as jest.Mock).mockResolvedValue(true);

      const result = await enforceSessionLimits({
        userId: TEST_USER_ID,
        realmId: TEST_HEALTHCARE_REALM_ID,
        clientIp: '192.168.1.1'
      });

      // Healthcare realm has max 3 sessions, so oldest should be revoked
      expect(result.revokedSessions).toHaveLength(1);
      expect(result.revokedSessions[0].sessionId).toBe('session_1');
    });
  });
});
