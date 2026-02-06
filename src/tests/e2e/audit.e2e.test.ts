/**
 * Audit Logging Service E2E Tests
 * Task 7.1: Audit Logging Service
 * 
 * Tests:
 * - Event logging to DynamoDB
 * - Query operations
 * - HIPAA compliance (6 year retention)
 * - Data sanitization
 */

import {
  AuditEventType,
  AuditResult,
  AuditSeverity,
  AuditLogInput,
  AuditLogEntry,
  DEFAULT_AUDIT_CONFIG,
  hashSensitiveData,
  maskEmail,
  maskIP,
  determineSeverity,
  calculateTTL,
  createAuditLogEntry,
  sanitizeDetails,
  logAuditEvent,
  logAuditEventSync,
  batchLogAuditEvents,
  queryAuditLogsByRealm,
  queryAuditLogsByUser,
  queryAuditLogsByEventType,
  getAuditStatistics,
  AuditHelpers
} from '../../services/audit.service';

// Mock DynamoDB for E2E tests
const mockSend = jest.fn();
jest.mock('../../services/dynamodb.service', () => ({
  dynamoDb: {
    send: (...args: unknown[]) => mockSend(...args)
  },
  TableNames: {
    AUDIT: 'zalt-audit'
  }
}));

describe('Audit Logging Service - E2E Tests', () => {
  beforeEach(() => {
    mockSend.mockReset();
    mockSend.mockResolvedValue({});
  });

  describe('Event Logging', () => {
    describe('logAuditEvent', () => {
      it('should log login success event', async () => {
        const input: AuditLogInput = {
          eventType: AuditEventType.LOGIN_SUCCESS,
          result: AuditResult.SUCCESS,
          realmId: 'clinisyn-psychologists',
          userId: 'user-123',
          userEmail: 'dr.ayse@example.com',
          ipAddress: '85.100.50.25',
          userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
          action: 'User logged in successfully'
        };

        const entry = await logAuditEvent(input);

        expect(entry.eventType).toBe(AuditEventType.LOGIN_SUCCESS);
        expect(entry.result).toBe(AuditResult.SUCCESS);
        expect(entry.realmId).toBe('clinisyn-psychologists');
        expect(entry.userId).toBe('user-123');
        expect(entry.severity).toBe(AuditSeverity.INFO);
      });

      it('should log login failure event', async () => {
        const input: AuditLogInput = {
          eventType: AuditEventType.LOGIN_FAILURE,
          result: AuditResult.FAILURE,
          realmId: 'clinisyn-psychologists',
          userEmail: 'unknown@example.com',
          ipAddress: '192.168.1.100',
          action: 'Login attempt failed',
          errorCode: 'INVALID_CREDENTIALS',
          errorMessage: 'Invalid email or password'
        };

        const entry = await logAuditEvent(input);

        expect(entry.eventType).toBe(AuditEventType.LOGIN_FAILURE);
        expect(entry.result).toBe(AuditResult.FAILURE);
        expect(entry.severity).toBe(AuditSeverity.WARNING);
        expect(entry.errorCode).toBe('INVALID_CREDENTIALS');
      });

      it('should log MFA enable event', async () => {
        const input: AuditLogInput = {
          eventType: AuditEventType.MFA_ENABLE,
          result: AuditResult.SUCCESS,
          realmId: 'clinisyn-psychologists',
          userId: 'user-456',
          ipAddress: '10.0.0.1',
          action: 'User enabled TOTP MFA',
          details: { mfaType: 'totp' }
        };

        const entry = await logAuditEvent(input);

        expect(entry.eventType).toBe(AuditEventType.MFA_ENABLE);
        expect(entry.details?.mfaType).toBe('totp');
      });

      it('should log account lock event with ERROR severity', async () => {
        const input: AuditLogInput = {
          eventType: AuditEventType.ACCOUNT_LOCK,
          result: AuditResult.BLOCKED,
          realmId: 'clinisyn-psychologists',
          userId: 'user-789',
          ipAddress: '172.16.0.1',
          action: 'Account locked due to failed attempts',
          details: { reason: 'Too many failed login attempts', lockDuration: 900 }
        };

        const entry = await logAuditEvent(input);

        expect(entry.eventType).toBe(AuditEventType.ACCOUNT_LOCK);
        expect(entry.severity).toBe(AuditSeverity.ERROR);
      });

      it('should log credential stuffing with CRITICAL severity', async () => {
        const input: AuditLogInput = {
          eventType: AuditEventType.CREDENTIAL_STUFFING,
          result: AuditResult.BLOCKED,
          realmId: 'clinisyn-psychologists',
          ipAddress: '203.0.113.50',
          action: 'Credential stuffing attack detected',
          details: { attackPattern: 'same_password_multiple_emails', count: 150 }
        };

        const entry = await logAuditEvent(input);

        expect(entry.eventType).toBe(AuditEventType.CREDENTIAL_STUFFING);
        expect(entry.severity).toBe(AuditSeverity.CRITICAL);
      });

      it('should log impossible travel with CRITICAL severity', async () => {
        const input: AuditLogInput = {
          eventType: AuditEventType.IMPOSSIBLE_TRAVEL,
          result: AuditResult.BLOCKED,
          realmId: 'clinisyn-psychologists',
          userId: 'user-travel',
          ipAddress: '198.51.100.1',
          action: 'Impossible travel detected',
          details: {
            fromLocation: 'Istanbul, Turkey',
            toLocation: 'New York, USA',
            distanceKm: 8000,
            timeHours: 1
          }
        };

        const entry = await logAuditEvent(input);

        expect(entry.eventType).toBe(AuditEventType.IMPOSSIBLE_TRAVEL);
        expect(entry.severity).toBe(AuditSeverity.CRITICAL);
      });
    });

    describe('logAuditEventSync', () => {
      it('should log event synchronously', async () => {
        mockSend.mockResolvedValueOnce({});

        const input: AuditLogInput = {
          eventType: AuditEventType.PASSWORD_CHANGE,
          result: AuditResult.SUCCESS,
          realmId: 'test-realm',
          userId: 'user-sync',
          ipAddress: '1.2.3.4',
          action: 'Password changed'
        };

        const entry = await logAuditEventSync(input);

        expect(entry.eventType).toBe(AuditEventType.PASSWORD_CHANGE);
        expect(mockSend).toHaveBeenCalled();
      });
    });

    describe('batchLogAuditEvents', () => {
      it('should batch log multiple events', async () => {
        mockSend.mockResolvedValue({});

        const inputs: AuditLogInput[] = [
          {
            eventType: AuditEventType.LOGIN_SUCCESS,
            result: AuditResult.SUCCESS,
            realmId: 'test-realm',
            userId: 'user-1',
            ipAddress: '1.1.1.1',
            action: 'Login 1'
          },
          {
            eventType: AuditEventType.LOGIN_SUCCESS,
            result: AuditResult.SUCCESS,
            realmId: 'test-realm',
            userId: 'user-2',
            ipAddress: '2.2.2.2',
            action: 'Login 2'
          }
        ];

        const entries = await batchLogAuditEvents(inputs);

        expect(entries.length).toBe(2);
        expect(mockSend).toHaveBeenCalled();
      });

      it('should handle large batches (>25 items)', async () => {
        mockSend.mockResolvedValue({});

        const inputs: AuditLogInput[] = Array.from({ length: 30 }, (_, i) => ({
          eventType: AuditEventType.LOGIN_SUCCESS,
          result: AuditResult.SUCCESS,
          realmId: 'test-realm',
          userId: `user-${i}`,
          ipAddress: `1.1.1.${i % 256}`,
          action: `Login ${i}`
        }));

        const entries = await batchLogAuditEvents(inputs);

        expect(entries.length).toBe(30);
        // Should be called twice (25 + 5)
        expect(mockSend).toHaveBeenCalledTimes(2);
      });
    });
  });

  describe('Data Privacy', () => {
    it('should hash user email', async () => {
      const input: AuditLogInput = {
        eventType: AuditEventType.REGISTER,
        result: AuditResult.SUCCESS,
        realmId: 'test-realm',
        userId: 'user-new',
        userEmail: 'sensitive@example.com',
        ipAddress: '1.2.3.4',
        action: 'User registered'
      };

      const entry = await logAuditEvent(input);

      expect(entry.userEmail).not.toBe('sensitive@example.com');
      expect(entry.userEmail?.length).toBe(16);
    });

    it('should mask IP address', async () => {
      const input: AuditLogInput = {
        eventType: AuditEventType.LOGIN_SUCCESS,
        result: AuditResult.SUCCESS,
        realmId: 'test-realm',
        userId: 'user-ip',
        ipAddress: '192.168.100.50',
        action: 'Login'
      };

      const entry = await logAuditEvent(input);

      expect(entry.ipAddress).toBe('192.168.*.*');
      expect(entry.ipAddressHash).toBeDefined();
      expect(entry.ipAddressHash.length).toBe(16);
    });

    it('should sanitize sensitive details', async () => {
      const input: AuditLogInput = {
        eventType: AuditEventType.LOGIN_FAILURE,
        result: AuditResult.FAILURE,
        realmId: 'test-realm',
        ipAddress: '1.2.3.4',
        action: 'Login failed',
        details: {
          attemptedPassword: 'secret123',
          username: 'john',
          apiKey: 'key-12345'
        }
      };

      const entry = await logAuditEvent(input);

      expect(entry.details?.attemptedPassword).toBe('[REDACTED]');
      expect(entry.details?.username).toBe('john');
      expect(entry.details?.apiKey).toBe('[REDACTED]');
    });
  });

  describe('HIPAA Compliance', () => {
    it('should set 6 year TTL for healthcare realms', async () => {
      const input: AuditLogInput = {
        eventType: AuditEventType.LOGIN_SUCCESS,
        result: AuditResult.SUCCESS,
        realmId: 'clinisyn-psychologists',
        userId: 'dr-123',
        ipAddress: '1.2.3.4',
        action: 'Healthcare login'
      };

      const entry = await logAuditEvent(input);

      const now = Math.floor(Date.now() / 1000);
      const sixYears = 6 * 365 * 24 * 60 * 60;
      expect(entry.ttl).toBeGreaterThan(now + sixYears - 100);
    });

    it('should set 90 day TTL for standard realms', async () => {
      const input: AuditLogInput = {
        eventType: AuditEventType.LOGIN_SUCCESS,
        result: AuditResult.SUCCESS,
        realmId: 'standard-app',
        userId: 'user-std',
        ipAddress: '1.2.3.4',
        action: 'Standard login'
      };

      const entry = await logAuditEvent(input);

      const now = Math.floor(Date.now() / 1000);
      const ninetyDays = 90 * 24 * 60 * 60;
      expect(entry.ttl).toBeGreaterThan(now + ninetyDays - 100);
      expect(entry.ttl).toBeLessThan(now + ninetyDays + 100);
    });

    it('should include all required audit fields', async () => {
      const input: AuditLogInput = {
        eventType: AuditEventType.LOGIN_SUCCESS,
        result: AuditResult.SUCCESS,
        realmId: 'clinisyn-psychologists',
        userId: 'user-audit',
        userEmail: 'audit@example.com',
        sessionId: 'session-123',
        ipAddress: '85.100.50.25',
        userAgent: 'Mozilla/5.0',
        requestId: 'req-456',
        geoCountry: 'TR',
        geoCity: 'Istanbul',
        action: 'User logged in'
      };

      const entry = await logAuditEvent(input);

      // Required HIPAA audit fields
      expect(entry.id).toBeDefined();
      expect(entry.timestamp).toBeDefined();
      expect(entry.eventType).toBeDefined();
      expect(entry.result).toBeDefined();
      expect(entry.userId).toBeDefined();
      expect(entry.realmId).toBeDefined();
      expect(entry.ipAddress).toBeDefined();
      expect(entry.action).toBeDefined();
      expect(entry.ttl).toBeDefined();
    });
  });

  describe('Query Operations', () => {
    describe('queryAuditLogsByRealm', () => {
      it('should query logs by realm', async () => {
        const mockLogs: Partial<AuditLogEntry>[] = [
          { id: '1', eventType: AuditEventType.LOGIN_SUCCESS, realmId: 'test-realm' },
          { id: '2', eventType: AuditEventType.LOGOUT, realmId: 'test-realm' }
        ];

        mockSend.mockResolvedValueOnce({
          Items: mockLogs,
          Count: 2
        });

        const result = await queryAuditLogsByRealm('test-realm');

        expect(result.logs.length).toBe(2);
        expect(result.count).toBe(2);
        expect(mockSend).toHaveBeenCalled();
      });

      it('should support time range filtering', async () => {
        mockSend.mockResolvedValueOnce({
          Items: [],
          Count: 0
        });

        const startTime = new Date('2026-01-01');
        const endTime = new Date('2026-01-15');

        await queryAuditLogsByRealm('test-realm', { startTime, endTime });

        expect(mockSend).toHaveBeenCalled();
      });

      it('should support pagination', async () => {
        mockSend.mockResolvedValueOnce({
          Items: [{ id: '1' }],
          Count: 1,
          LastEvaluatedKey: { pk: 'REALM#test', sk: 'TIMESTAMP#2026-01-15' }
        });

        const result = await queryAuditLogsByRealm('test-realm', { limit: 1 });

        expect(result.lastEvaluatedKey).toBeDefined();
      });
    });

    describe('queryAuditLogsByUser', () => {
      it('should query logs by user', async () => {
        const mockLogs: Partial<AuditLogEntry>[] = [
          { id: '1', userId: 'user-123', eventType: AuditEventType.LOGIN_SUCCESS }
        ];

        mockSend.mockResolvedValueOnce({
          Items: mockLogs,
          Count: 1
        });

        const result = await queryAuditLogsByUser('user-123');

        expect(result.logs.length).toBe(1);
        expect(mockSend).toHaveBeenCalled();
      });
    });

    describe('queryAuditLogsByEventType', () => {
      it('should query logs by event type', async () => {
        const mockLogs: Partial<AuditLogEntry>[] = [
          { id: '1', eventType: AuditEventType.LOGIN_FAILURE },
          { id: '2', eventType: AuditEventType.LOGIN_FAILURE }
        ];

        mockSend.mockResolvedValueOnce({
          Items: mockLogs,
          Count: 2
        });

        const result = await queryAuditLogsByEventType(AuditEventType.LOGIN_FAILURE);

        expect(result.logs.length).toBe(2);
      });
    });

    describe('getAuditStatistics', () => {
      it('should calculate audit statistics', async () => {
        const mockLogs: Partial<AuditLogEntry>[] = [
          { eventType: AuditEventType.LOGIN_SUCCESS, result: AuditResult.SUCCESS, severity: AuditSeverity.INFO },
          { eventType: AuditEventType.LOGIN_SUCCESS, result: AuditResult.SUCCESS, severity: AuditSeverity.INFO },
          { eventType: AuditEventType.LOGIN_FAILURE, result: AuditResult.FAILURE, severity: AuditSeverity.WARNING },
          { eventType: AuditEventType.ACCOUNT_LOCK, result: AuditResult.BLOCKED, severity: AuditSeverity.ERROR }
        ];

        mockSend.mockResolvedValueOnce({
          Items: mockLogs,
          Count: 4
        });

        const stats = await getAuditStatistics(
          'test-realm',
          new Date('2026-01-01'),
          new Date('2026-01-15')
        );

        expect(stats.totalEvents).toBe(4);
        expect(stats.eventsByType[AuditEventType.LOGIN_SUCCESS]).toBe(2);
        expect(stats.eventsByType[AuditEventType.LOGIN_FAILURE]).toBe(1);
        expect(stats.eventsByResult[AuditResult.SUCCESS]).toBe(2);
        expect(stats.eventsBySeverity[AuditSeverity.INFO]).toBe(2);
      });
    });
  });

  describe('DynamoDB Keys', () => {
    it('should set correct partition key for realm queries', async () => {
      const input: AuditLogInput = {
        eventType: AuditEventType.LOGIN_SUCCESS,
        result: AuditResult.SUCCESS,
        realmId: 'clinisyn-psychologists',
        userId: 'user-pk',
        ipAddress: '1.2.3.4',
        action: 'Test'
      };

      const entry = await logAuditEvent(input);

      expect(entry.pk).toBe('REALM#clinisyn-psychologists');
    });

    it('should set correct sort key with timestamp', async () => {
      const input: AuditLogInput = {
        eventType: AuditEventType.LOGIN_SUCCESS,
        result: AuditResult.SUCCESS,
        realmId: 'test-realm',
        userId: 'user-sk',
        ipAddress: '1.2.3.4',
        action: 'Test'
      };

      const entry = await logAuditEvent(input);

      expect(entry.sk).toMatch(/^TIMESTAMP#\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
      expect(entry.sk).toContain(entry.id);
    });

    it('should set GSI1 keys for user queries', async () => {
      const input: AuditLogInput = {
        eventType: AuditEventType.LOGIN_SUCCESS,
        result: AuditResult.SUCCESS,
        realmId: 'test-realm',
        userId: 'user-gsi1',
        ipAddress: '1.2.3.4',
        action: 'Test'
      };

      const entry = await logAuditEvent(input);

      expect(entry.gsi1pk).toBe('USER#user-gsi1');
      expect(entry.gsi1sk).toMatch(/^TIMESTAMP#/);
    });

    it('should set GSI2 keys for event type queries', async () => {
      const input: AuditLogInput = {
        eventType: AuditEventType.MFA_ENABLE,
        result: AuditResult.SUCCESS,
        realmId: 'test-realm',
        userId: 'user-gsi2',
        ipAddress: '1.2.3.4',
        action: 'Test'
      };

      const entry = await logAuditEvent(input);

      expect(entry.gsi2pk).toBe('EVENT#mfa_enable');
      expect(entry.gsi2sk).toMatch(/^TIMESTAMP#/);
    });
  });

  describe('AuditHelpers', () => {
    it('should log login success via helper', async () => {
      const entry = await AuditHelpers.logLoginSuccess({
        realmId: 'test-realm',
        userId: 'user-helper',
        userEmail: 'helper@example.com',
        ipAddress: '1.2.3.4',
        sessionId: 'session-helper'
      });

      expect(entry.eventType).toBe(AuditEventType.LOGIN_SUCCESS);
      expect(entry.result).toBe(AuditResult.SUCCESS);
    });

    it('should log login failure via helper', async () => {
      const entry = await AuditHelpers.logLoginFailure({
        realmId: 'test-realm',
        userEmail: 'failed@example.com',
        ipAddress: '1.2.3.4',
        errorCode: 'INVALID_PASSWORD'
      });

      expect(entry.eventType).toBe(AuditEventType.LOGIN_FAILURE);
      expect(entry.result).toBe(AuditResult.FAILURE);
    });

    it('should log logout via helper', async () => {
      const entry = await AuditHelpers.logLogout({
        realmId: 'test-realm',
        userId: 'user-logout',
        ipAddress: '1.2.3.4',
        allDevices: true
      });

      expect(entry.eventType).toBe(AuditEventType.LOGOUT);
      expect(entry.details?.allDevices).toBe(true);
    });

    it('should log register via helper', async () => {
      const entry = await AuditHelpers.logRegister({
        realmId: 'test-realm',
        userId: 'user-new',
        userEmail: 'new@example.com',
        ipAddress: '1.2.3.4'
      });

      expect(entry.eventType).toBe(AuditEventType.REGISTER);
    });

    it('should log password change via helper', async () => {
      const entry = await AuditHelpers.logPasswordChange({
        realmId: 'test-realm',
        userId: 'user-pwd',
        ipAddress: '1.2.3.4'
      });

      expect(entry.eventType).toBe(AuditEventType.PASSWORD_CHANGE);
    });

    it('should log MFA enable via helper', async () => {
      const entry = await AuditHelpers.logMFAEnable({
        realmId: 'test-realm',
        userId: 'user-mfa',
        ipAddress: '1.2.3.4',
        mfaType: 'webauthn'
      });

      expect(entry.eventType).toBe(AuditEventType.MFA_ENABLE);
      expect(entry.details?.mfaType).toBe('webauthn');
    });

    it('should log account lock via helper (sync)', async () => {
      mockSend.mockResolvedValueOnce({});

      const entry = await AuditHelpers.logAccountLock({
        realmId: 'test-realm',
        userId: 'user-lock',
        ipAddress: '1.2.3.4',
        reason: 'Too many failed attempts',
        lockDuration: 900
      });

      expect(entry.eventType).toBe(AuditEventType.ACCOUNT_LOCK);
      expect(entry.severity).toBe(AuditSeverity.ERROR);
    });

    it('should log suspicious activity via helper (sync)', async () => {
      mockSend.mockResolvedValueOnce({});

      const entry = await AuditHelpers.logSuspiciousActivity({
        realmId: 'test-realm',
        userId: 'user-sus',
        ipAddress: '1.2.3.4',
        activityType: 'unusual_login_pattern'
      });

      expect(entry.eventType).toBe(AuditEventType.SUSPICIOUS_ACTIVITY);
      expect(entry.severity).toBe(AuditSeverity.CRITICAL);
    });

    it('should log impossible travel via helper (sync)', async () => {
      mockSend.mockResolvedValueOnce({});

      const entry = await AuditHelpers.logImpossibleTravel({
        realmId: 'test-realm',
        userId: 'user-travel',
        ipAddress: '1.2.3.4',
        fromLocation: 'Istanbul',
        toLocation: 'New York',
        distanceKm: 8000,
        timeHours: 1
      });

      expect(entry.eventType).toBe(AuditEventType.IMPOSSIBLE_TRAVEL);
      expect(entry.severity).toBe(AuditSeverity.CRITICAL);
      expect(entry.details?.distanceKm).toBe(8000);
    });
  });

  describe('All Event Types Coverage', () => {
    const testEventType = async (eventType: AuditEventType) => {
      const input: AuditLogInput = {
        eventType,
        result: AuditResult.SUCCESS,
        realmId: 'test-realm',
        userId: 'user-coverage',
        ipAddress: '1.2.3.4',
        action: `Test ${eventType}`
      };

      const entry = await logAuditEvent(input);
      expect(entry.eventType).toBe(eventType);
    };

    it('should log LOGIN_SUCCESS', () => testEventType(AuditEventType.LOGIN_SUCCESS));
    it('should log LOGIN_FAILURE', () => testEventType(AuditEventType.LOGIN_FAILURE));
    it('should log LOGOUT', () => testEventType(AuditEventType.LOGOUT));
    it('should log REGISTER', () => testEventType(AuditEventType.REGISTER));
    it('should log PASSWORD_CHANGE', () => testEventType(AuditEventType.PASSWORD_CHANGE));
    it('should log PASSWORD_RESET_REQUEST', () => testEventType(AuditEventType.PASSWORD_RESET_REQUEST));
    it('should log PASSWORD_RESET_COMPLETE', () => testEventType(AuditEventType.PASSWORD_RESET_COMPLETE));
    it('should log MFA_ENABLE', () => testEventType(AuditEventType.MFA_ENABLE));
    it('should log MFA_DISABLE', () => testEventType(AuditEventType.MFA_DISABLE));
    it('should log MFA_VERIFY_SUCCESS', () => testEventType(AuditEventType.MFA_VERIFY_SUCCESS));
    it('should log MFA_VERIFY_FAILURE', () => testEventType(AuditEventType.MFA_VERIFY_FAILURE));
    it('should log BACKUP_CODE_USED', () => testEventType(AuditEventType.BACKUP_CODE_USED));
    it('should log WEBAUTHN_REGISTER', () => testEventType(AuditEventType.WEBAUTHN_REGISTER));
    it('should log WEBAUTHN_REMOVE', () => testEventType(AuditEventType.WEBAUTHN_REMOVE));
    it('should log WEBAUTHN_AUTH_SUCCESS', () => testEventType(AuditEventType.WEBAUTHN_AUTH_SUCCESS));
    it('should log WEBAUTHN_AUTH_FAILURE', () => testEventType(AuditEventType.WEBAUTHN_AUTH_FAILURE));
    it('should log DEVICE_TRUST', () => testEventType(AuditEventType.DEVICE_TRUST));
    it('should log DEVICE_REVOKE', () => testEventType(AuditEventType.DEVICE_REVOKE));
    it('should log NEW_DEVICE_LOGIN', () => testEventType(AuditEventType.NEW_DEVICE_LOGIN));
    it('should log ACCOUNT_LOCK', () => testEventType(AuditEventType.ACCOUNT_LOCK));
    it('should log ACCOUNT_UNLOCK', () => testEventType(AuditEventType.ACCOUNT_UNLOCK));
    it('should log EMAIL_VERIFY', () => testEventType(AuditEventType.EMAIL_VERIFY));
    it('should log SUSPICIOUS_ACTIVITY', () => testEventType(AuditEventType.SUSPICIOUS_ACTIVITY));
    it('should log IMPOSSIBLE_TRAVEL', () => testEventType(AuditEventType.IMPOSSIBLE_TRAVEL));
    it('should log CREDENTIAL_STUFFING', () => testEventType(AuditEventType.CREDENTIAL_STUFFING));
    it('should log RATE_LIMIT_EXCEEDED', () => testEventType(AuditEventType.RATE_LIMIT_EXCEEDED));
    it('should log SESSION_TIMEOUT', () => testEventType(AuditEventType.SESSION_TIMEOUT));
    it('should log TOKEN_REFRESH', () => testEventType(AuditEventType.TOKEN_REFRESH));
    it('should log TOKEN_REVOKE', () => testEventType(AuditEventType.TOKEN_REVOKE));
    it('should log ADMIN_ACTION', () => testEventType(AuditEventType.ADMIN_ACTION));
    it('should log CONFIG_CHANGE', () => testEventType(AuditEventType.CONFIG_CHANGE));
    it('should log OAUTH_LINK', () => testEventType(AuditEventType.OAUTH_LINK));
    it('should log OAUTH_UNLINK', () => testEventType(AuditEventType.OAUTH_UNLINK));
    it('should log OAUTH_LOGIN', () => testEventType(AuditEventType.OAUTH_LOGIN));
  });
});
