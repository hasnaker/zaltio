/**
 * Session Timeout E2E Tests
 * Task 6.6: Session Timeout Policies
 * 
 * HEALTHCARE CRITICAL:
 * - Idle timeout: 30 minutes inactivity → logout
 * - Absolute timeout: 8-12 hours → forced logout
 * - Activity tracking: Every API call updates last_activity
 * - Realm-based configuration
 */

import {
  SessionTimeoutConfig,
  SessionStatus,
  TIMEOUT_CONFIGS,
  DEFAULT_HEALTHCARE_TIMEOUT,
  checkSessionTimeout,
  updateSessionActivity,
  createSessionWithTimeout,
  expireSession,
  getRealmTimeoutConfig,
  getUserActiveSessions,
  terminateAllUserSessions,
  extendSession,
  needsTimeoutWarning,
  getTimeoutInfo
} from '../../services/session-timeout.service';
import * as crypto from 'crypto';

// Generate UUID v4 without external dependency
function uuidv4(): string {
  return crypto.randomUUID();
}

// Mock DynamoDB
jest.mock('../../services/dynamodb.service', () => {
  const sessions = new Map<string, any>();
  
  return {
    dynamoDb: {
      send: jest.fn().mockImplementation((command: any) => {
        const commandName = command.constructor.name;
        
        if (commandName === 'GetCommand') {
          const key = `${command.input.Key.pk}#${command.input.Key.sk}`;
          const item = sessions.get(key);
          return Promise.resolve({ Item: item });
        }
        
        if (commandName === 'PutCommand') {
          const key = `${command.input.Item.pk}#${command.input.Item.sk}`;
          sessions.set(key, command.input.Item);
          return Promise.resolve({});
        }
        
        if (commandName === 'UpdateCommand') {
          const key = `${command.input.Key.pk}#${command.input.Key.sk}`;
          const item = sessions.get(key);
          if (item) {
            // Parse update expression and apply
            const updates = command.input.ExpressionAttributeValues;
            if (updates[':now']) item.last_activity = updates[':now'];
            if (updates[':true'] !== undefined && updates[':reason']) {
              item.revoked = true;
              item.revoked_reason = updates[':reason'];
              item.is_active = false;
            }
            if (updates[':expiry']) item.absolute_expiry = updates[':expiry'];
            sessions.set(key, item);
          }
          return Promise.resolve({});
        }
        
        if (commandName === 'QueryCommand') {
          const pk = command.input.ExpressionAttributeValues[':pk'];
          const userId = command.input.ExpressionAttributeValues[':userId'];
          const now = command.input.ExpressionAttributeValues[':now'];
          
          const items: any[] = [];
          sessions.forEach((item, key) => {
            if (key.startsWith(pk) && 
                item.user_id === userId && 
                !item.revoked && 
                item.absolute_expiry > now) {
              items.push(item);
            }
          });
          return Promise.resolve({ Items: items });
        }
        
        return Promise.resolve({});
      })
    },
    TableNames: {
      SESSIONS: 'zalt-sessions'
    },
    // Expose for test cleanup
    __sessions: sessions
  };
});

// Mock security logger
jest.mock('../../services/security-logger.service', () => ({
  logSimpleSecurityEvent: jest.fn().mockResolvedValue(undefined)
}));

describe('Session Timeout E2E Tests', () => {
  const testRealmId = 'clinisyn-psychologists';
  const testUserId = uuidv4();
  
  beforeEach(() => {
    jest.clearAllMocks();
    // Clear sessions
    const { __sessions } = require('../../services/dynamodb.service');
    __sessions.clear();
  });

  describe('Healthcare Realm Timeout Configuration', () => {
    it('should use 30 minute idle timeout for clinisyn realms', () => {
      const config = getRealmTimeoutConfig('clinisyn-psychologists');
      expect(config.idleTimeoutSeconds).toBe(1800); // 30 minutes
    });

    it('should use 8 hour absolute timeout for clinisyn realms', () => {
      const config = getRealmTimeoutConfig('clinisyn-psychologists');
      expect(config.absoluteTimeoutSeconds).toBe(28800); // 8 hours
    });

    it('should enable activity tracking for healthcare', () => {
      const config = getRealmTimeoutConfig('clinisyn-students');
      expect(config.activityTrackingEnabled).toBe(true);
    });

    it('should use standard config for non-healthcare realms', () => {
      const config = getRealmTimeoutConfig('other-company');
      expect(config.idleTimeoutSeconds).toBe(3600); // 1 hour
      expect(config.absoluteTimeoutSeconds).toBe(43200); // 12 hours
    });
  });

  describe('Session Creation with Timeout', () => {
    it('should create session with correct timeout values', async () => {
      const sessionId = uuidv4();
      
      await createSessionWithTimeout(
        sessionId,
        testUserId,
        testRealmId,
        DEFAULT_HEALTHCARE_TIMEOUT,
        { deviceInfo: 'Chrome/Windows', ipAddress: '192.168.1.1' }
      );

      const status = await checkSessionTimeout(sessionId, testRealmId);
      expect(status.isValid).toBe(true);
      expect(status.isExpired).toBe(false);
    });

    it('should set absolute expiry based on config', async () => {
      const sessionId = uuidv4();
      const config = TIMEOUT_CONFIGS.healthcare;
      
      await createSessionWithTimeout(sessionId, testUserId, testRealmId, config);

      const status = await checkSessionTimeout(sessionId, testRealmId, config);
      expect(status.absoluteTimeRemaining).toBeLessThanOrEqual(config.absoluteTimeoutSeconds);
      expect(status.absoluteTimeRemaining).toBeGreaterThan(config.absoluteTimeoutSeconds - 5);
    });

    it('should log session creation event', async () => {
      const { logSimpleSecurityEvent } = require('../../services/security-logger.service');
      const sessionId = uuidv4();
      
      await createSessionWithTimeout(sessionId, testUserId, testRealmId);

      expect(logSimpleSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'session_created',
          realm_id: testRealmId,
          user_id: testUserId
        })
      );
    });
  });

  describe('Session Timeout Checking', () => {
    it('should return valid for active session', async () => {
      const sessionId = uuidv4();
      await createSessionWithTimeout(sessionId, testUserId, testRealmId);

      const status = await checkSessionTimeout(sessionId, testRealmId);
      
      expect(status.isValid).toBe(true);
      expect(status.isExpired).toBe(false);
      expect(status.idleTimeRemaining).toBeGreaterThan(0);
      expect(status.absoluteTimeRemaining).toBeGreaterThan(0);
    });

    it('should return invalid for non-existent session', async () => {
      const status = await checkSessionTimeout('non-existent', testRealmId);
      
      expect(status.isValid).toBe(false);
      expect(status.isExpired).toBe(true);
      expect(status.expiredReason).toBe('revoked');
    });

    it('should return invalid for revoked session', async () => {
      const sessionId = uuidv4();
      await createSessionWithTimeout(sessionId, testUserId, testRealmId);
      await expireSession(sessionId, testRealmId, 'manual');

      const status = await checkSessionTimeout(sessionId, testRealmId);
      
      expect(status.isValid).toBe(false);
      expect(status.isExpired).toBe(true);
      expect(status.expiredReason).toBe('revoked');
    });

    it('should include last activity timestamp', async () => {
      const sessionId = uuidv4();
      await createSessionWithTimeout(sessionId, testUserId, testRealmId);

      const status = await checkSessionTimeout(sessionId, testRealmId);
      
      expect(status.lastActivity).toBeDefined();
      expect(new Date(status.lastActivity!).getTime()).toBeLessThanOrEqual(Date.now());
    });

    it('should include session start timestamp', async () => {
      const sessionId = uuidv4();
      await createSessionWithTimeout(sessionId, testUserId, testRealmId);

      const status = await checkSessionTimeout(sessionId, testRealmId);
      
      expect(status.sessionStart).toBeDefined();
      expect(new Date(status.sessionStart!).getTime()).toBeLessThanOrEqual(Date.now());
    });
  });

  describe('Activity Tracking', () => {
    it('should update last activity on API call', async () => {
      const sessionId = uuidv4();
      await createSessionWithTimeout(sessionId, testUserId, testRealmId);

      // Wait a bit
      await new Promise(resolve => setTimeout(resolve, 100));

      const result = await updateSessionActivity(sessionId, testRealmId);
      expect(result).toBe(true);
    });

    it('should return false for invalid session', async () => {
      const result = await updateSessionActivity('non-existent', testRealmId);
      expect(result).toBe(false);
    });

    it('should not update if activity tracking disabled', async () => {
      const sessionId = uuidv4();
      const config: SessionTimeoutConfig = {
        ...DEFAULT_HEALTHCARE_TIMEOUT,
        activityTrackingEnabled: false
      };
      
      await createSessionWithTimeout(sessionId, testUserId, testRealmId, config);
      const result = await updateSessionActivity(sessionId, testRealmId, config);
      
      expect(result).toBe(true); // Returns true but doesn't update
    });
  });

  describe('Session Expiration', () => {
    it('should expire session with idle reason', async () => {
      const sessionId = uuidv4();
      await createSessionWithTimeout(sessionId, testUserId, testRealmId);
      
      await expireSession(sessionId, testRealmId, 'idle');

      const status = await checkSessionTimeout(sessionId, testRealmId);
      expect(status.isValid).toBe(false);
      expect(status.expiredReason).toBe('revoked');
    });

    it('should expire session with absolute reason', async () => {
      const sessionId = uuidv4();
      await createSessionWithTimeout(sessionId, testUserId, testRealmId);
      
      await expireSession(sessionId, testRealmId, 'absolute');

      const status = await checkSessionTimeout(sessionId, testRealmId);
      expect(status.isValid).toBe(false);
    });

    it('should expire session with manual reason', async () => {
      const sessionId = uuidv4();
      await createSessionWithTimeout(sessionId, testUserId, testRealmId);
      
      await expireSession(sessionId, testRealmId, 'manual');

      const status = await checkSessionTimeout(sessionId, testRealmId);
      expect(status.isValid).toBe(false);
    });

    it('should log session expiration event', async () => {
      const { logSimpleSecurityEvent } = require('../../services/security-logger.service');
      const sessionId = uuidv4();
      await createSessionWithTimeout(sessionId, testUserId, testRealmId);
      
      await expireSession(sessionId, testRealmId, 'idle');

      expect(logSimpleSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'session_expired',
          realm_id: testRealmId,
          details: expect.objectContaining({
            reason: 'idle'
          })
        })
      );
    });
  });

  describe('User Session Management', () => {
    it('should get all active sessions for user', async () => {
      const session1 = uuidv4();
      const session2 = uuidv4();
      
      await createSessionWithTimeout(session1, testUserId, testRealmId);
      await createSessionWithTimeout(session2, testUserId, testRealmId);

      const sessions = await getUserActiveSessions(testUserId, testRealmId);
      expect(sessions.length).toBe(2);
    });

    it('should not include expired sessions', async () => {
      const session1 = uuidv4();
      const session2 = uuidv4();
      
      await createSessionWithTimeout(session1, testUserId, testRealmId);
      await createSessionWithTimeout(session2, testUserId, testRealmId);
      await expireSession(session1, testRealmId, 'manual');

      const sessions = await getUserActiveSessions(testUserId, testRealmId);
      expect(sessions.length).toBe(1);
    });

    it('should terminate all user sessions', async () => {
      const session1 = uuidv4();
      const session2 = uuidv4();
      
      await createSessionWithTimeout(session1, testUserId, testRealmId);
      await createSessionWithTimeout(session2, testUserId, testRealmId);

      const count = await terminateAllUserSessions(testUserId, testRealmId, 'password_change');
      expect(count).toBe(2);

      const sessions = await getUserActiveSessions(testUserId, testRealmId);
      expect(sessions.length).toBe(0);
    });

    it('should log all sessions terminated event', async () => {
      const { logSimpleSecurityEvent } = require('../../services/security-logger.service');
      const session1 = uuidv4();
      
      await createSessionWithTimeout(session1, testUserId, testRealmId);
      await terminateAllUserSessions(testUserId, testRealmId, 'security_concern');

      expect(logSimpleSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'all_sessions_terminated',
          user_id: testUserId,
          details: expect.objectContaining({
            reason: 'security_concern'
          })
        })
      );
    });
  });

  describe('Session Extension', () => {
    it('should not allow extension for clinisyn realms', async () => {
      const sessionId = uuidv4();
      await createSessionWithTimeout(sessionId, testUserId, 'clinisyn-psychologists');

      const result = await extendSession(sessionId, 'clinisyn-psychologists', 3600);
      expect(result).toBe(false);
    });

    it('should allow extension for non-healthcare realms', async () => {
      const sessionId = uuidv4();
      const realmId = 'other-company';
      await createSessionWithTimeout(sessionId, testUserId, realmId);

      const result = await extendSession(sessionId, realmId, 3600);
      expect(result).toBe(true);
    });

    it('should not extend invalid session', async () => {
      const result = await extendSession('non-existent', 'other-company', 3600);
      expect(result).toBe(false);
    });
  });

  describe('Timeout Warning', () => {
    it('should indicate warning when idle time is low', () => {
      const config = TIMEOUT_CONFIGS.healthcare;
      const status: SessionStatus = {
        isValid: true,
        isExpired: false,
        idleTimeRemaining: 200, // Less than 300 warning threshold
        absoluteTimeRemaining: 10000,
        warningActive: true
      };

      expect(needsTimeoutWarning(status, config)).toBe(true);
    });

    it('should indicate warning when absolute time is low', () => {
      const config = TIMEOUT_CONFIGS.healthcare;
      const status: SessionStatus = {
        isValid: true,
        isExpired: false,
        idleTimeRemaining: 1000,
        absoluteTimeRemaining: 200, // Less than 300 warning threshold
        warningActive: true
      };

      expect(needsTimeoutWarning(status, config)).toBe(true);
    });

    it('should not indicate warning when times are sufficient', () => {
      const config = TIMEOUT_CONFIGS.healthcare;
      const status: SessionStatus = {
        isValid: true,
        isExpired: false,
        idleTimeRemaining: 1000,
        absoluteTimeRemaining: 10000,
        warningActive: false
      };

      expect(needsTimeoutWarning(status, config)).toBe(false);
    });
  });

  describe('Timeout Info for Client', () => {
    it('should return idle timeout info when idle is sooner', () => {
      const config = TIMEOUT_CONFIGS.healthcare;
      const status: SessionStatus = {
        isValid: true,
        isExpired: false,
        idleTimeRemaining: 500,
        absoluteTimeRemaining: 10000,
        warningActive: false
      };

      const info = getTimeoutInfo(status, config);
      expect(info.timeoutType).toBe('idle');
      expect(info.secondsRemaining).toBe(500);
    });

    it('should return absolute timeout info when absolute is sooner', () => {
      const config = TIMEOUT_CONFIGS.healthcare;
      const status: SessionStatus = {
        isValid: true,
        isExpired: false,
        idleTimeRemaining: 10000,
        absoluteTimeRemaining: 500,
        warningActive: false
      };

      const info = getTimeoutInfo(status, config);
      expect(info.timeoutType).toBe('absolute');
      expect(info.secondsRemaining).toBe(500);
    });

    it('should return null for invalid session', () => {
      const config = TIMEOUT_CONFIGS.healthcare;
      const status: SessionStatus = {
        isValid: false,
        isExpired: true,
        warningActive: false
      };

      const info = getTimeoutInfo(status, config);
      expect(info.timeoutType).toBeNull();
      expect(info.secondsRemaining).toBeNull();
    });
  });

  describe('Realm-based Configuration', () => {
    it('should use healthcare config for clinisyn-psychologists', () => {
      const config = getRealmTimeoutConfig('clinisyn-psychologists');
      expect(config).toEqual(TIMEOUT_CONFIGS.healthcare);
    });

    it('should use healthcare config for clinisyn-students', () => {
      const config = getRealmTimeoutConfig('clinisyn-students');
      expect(config).toEqual(TIMEOUT_CONFIGS.healthcare);
    });

    it('should use standard config for generic realms', () => {
      const config = getRealmTimeoutConfig('generic-company');
      expect(config).toEqual(TIMEOUT_CONFIGS.standard);
    });

    it('should allow custom timeout type', () => {
      const config = getRealmTimeoutConfig('custom-realm', {
        session_timeout_type: 'extended'
      });
      expect(config.idleTimeoutSeconds).toBe(TIMEOUT_CONFIGS.extended.idleTimeoutSeconds);
    });

    it('should allow custom idle timeout override', () => {
      const config = getRealmTimeoutConfig('custom-realm', {
        session_timeout_type: 'standard',
        custom_idle_timeout: 900
      });
      expect(config.idleTimeoutSeconds).toBe(900);
    });

    it('should allow custom absolute timeout override', () => {
      const config = getRealmTimeoutConfig('custom-realm', {
        session_timeout_type: 'standard',
        custom_absolute_timeout: 14400
      });
      expect(config.absoluteTimeoutSeconds).toBe(14400);
    });
  });

  describe('HIPAA Compliance Scenarios', () => {
    it('should enforce strict timeout for patient data access', async () => {
      const sessionId = uuidv4();
      const config = getRealmTimeoutConfig('clinisyn-psychologists');
      
      await createSessionWithTimeout(sessionId, testUserId, 'clinisyn-psychologists', config);

      const status = await checkSessionTimeout(sessionId, 'clinisyn-psychologists', config);
      
      // Healthcare must have 30 min idle timeout
      expect(config.idleTimeoutSeconds).toBe(1800);
      // Healthcare must have 8 hour absolute timeout
      expect(config.absoluteTimeoutSeconds).toBe(28800);
      // Session should be valid initially
      expect(status.isValid).toBe(true);
    });

    it('should not allow session extension for healthcare realms', async () => {
      const sessionId = uuidv4();
      await createSessionWithTimeout(sessionId, testUserId, 'clinisyn-psychologists');

      // Attempt to extend session
      const extended = await extendSession(sessionId, 'clinisyn-psychologists', 7200);
      
      // Should be rejected for healthcare
      expect(extended).toBe(false);
    });

    it('should track all activity for audit purposes', async () => {
      const { logSimpleSecurityEvent } = require('../../services/security-logger.service');
      const sessionId = uuidv4();
      
      await createSessionWithTimeout(sessionId, testUserId, 'clinisyn-psychologists');
      
      // Verify audit logging
      expect(logSimpleSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'session_created'
        })
      );
    });
  });

  describe('Edge Cases', () => {
    it('should handle concurrent session updates', async () => {
      const sessionId = uuidv4();
      await createSessionWithTimeout(sessionId, testUserId, testRealmId);

      // Concurrent updates
      const results = await Promise.all([
        updateSessionActivity(sessionId, testRealmId),
        updateSessionActivity(sessionId, testRealmId),
        updateSessionActivity(sessionId, testRealmId)
      ]);

      expect(results.every(r => r === true)).toBe(true);
    });

    it('should handle empty user sessions', async () => {
      const sessions = await getUserActiveSessions('non-existent-user', testRealmId);
      expect(sessions).toEqual([]);
    });

    it('should handle terminate with no sessions', async () => {
      const count = await terminateAllUserSessions('non-existent-user', testRealmId);
      expect(count).toBe(0);
    });
  });
});
