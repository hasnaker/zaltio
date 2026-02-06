/**
 * Audit Logging Service Tests
 * Task 7.1: Audit Logging Service
 * 
 * Tests:
 * - Event logging
 * - Data sanitization
 * - Query operations
 * - TTL calculation
 * - Helper functions
 */

import * as fc from 'fast-check';
import {
  AuditEventType,
  AuditResult,
  AuditSeverity,
  AuditLogInput,
  AuditConfig,
  DEFAULT_AUDIT_CONFIG,
  hashSensitiveData,
  maskEmail,
  maskIP,
  determineSeverity,
  calculateTTL,
  createAuditLogEntry,
  sanitizeDetails,
  AuditHelpers
} from './audit.service';

// Mock DynamoDB
jest.mock('./dynamodb.service', () => ({
  dynamoDb: {
    send: jest.fn().mockResolvedValue({})
  },
  TableNames: {
    AUDIT: 'test-audit-table'
  }
}));

describe('Audit Logging Service - Unit Tests', () => {
  describe('hashSensitiveData', () => {
    it('should hash data consistently', () => {
      const data = 'test@example.com';
      const hash1 = hashSensitiveData(data);
      const hash2 = hashSensitiveData(data);
      expect(hash1).toBe(hash2);
    });

    it('should produce different hashes for different data', () => {
      const hash1 = hashSensitiveData('user1@example.com');
      const hash2 = hashSensitiveData('user2@example.com');
      expect(hash1).not.toBe(hash2);
    });

    it('should return 16 character hash', () => {
      const hash = hashSensitiveData('test@example.com');
      expect(hash.length).toBe(16);
    });

    it('should handle empty string', () => {
      const hash = hashSensitiveData('');
      expect(hash.length).toBe(16);
    });

    it('should handle unicode characters', () => {
      const hash = hashSensitiveData('test@örnek.com');
      expect(hash.length).toBe(16);
    });
  });

  describe('maskEmail', () => {
    it('should mask email local part', () => {
      const masked = maskEmail('john.doe@example.com');
      expect(masked).toMatch(/^j\*+e@example\.com$/);
    });

    it('should handle short local parts', () => {
      const masked = maskEmail('ab@example.com');
      expect(masked).toBe('**@example.com');
    });

    it('should handle single character local part', () => {
      const masked = maskEmail('a@example.com');
      expect(masked).toBe('*@example.com');
    });

    it('should preserve domain', () => {
      const masked = maskEmail('test@subdomain.example.com');
      expect(masked).toContain('@subdomain.example.com');
    });

    it('should handle invalid email format', () => {
      const masked = maskEmail('invalid-email');
      expect(masked).toBe('***@***');
    });
  });

  describe('maskIP', () => {
    it('should mask IPv4 last two octets', () => {
      const masked = maskIP('192.168.1.100');
      expect(masked).toBe('192.168.*.*');
    });

    it('should handle different IPv4 addresses', () => {
      expect(maskIP('10.0.0.1')).toBe('10.0.*.*');
      expect(maskIP('172.16.50.25')).toBe('172.16.*.*');
    });

    it('should handle non-IPv4 format', () => {
      const masked = maskIP('2001:0db8:85a3:0000:0000:8a2e:0370:7334');
      expect(masked).toContain('***');
    });
  });

  describe('determineSeverity', () => {
    it('should return CRITICAL for credential stuffing', () => {
      const severity = determineSeverity(AuditEventType.CREDENTIAL_STUFFING, AuditResult.BLOCKED);
      expect(severity).toBe(AuditSeverity.CRITICAL);
    });

    it('should return CRITICAL for impossible travel', () => {
      const severity = determineSeverity(AuditEventType.IMPOSSIBLE_TRAVEL, AuditResult.BLOCKED);
      expect(severity).toBe(AuditSeverity.CRITICAL);
    });

    it('should return CRITICAL for user impersonation', () => {
      const severity = determineSeverity(AuditEventType.USER_IMPERSONATE, AuditResult.SUCCESS);
      expect(severity).toBe(AuditSeverity.CRITICAL);
    });

    it('should return ERROR for account lock', () => {
      const severity = determineSeverity(AuditEventType.ACCOUNT_LOCK, AuditResult.SUCCESS);
      expect(severity).toBe(AuditSeverity.ERROR);
    });

    it('should return ERROR for blocked results', () => {
      const severity = determineSeverity(AuditEventType.LOGIN_SUCCESS, AuditResult.BLOCKED);
      expect(severity).toBe(AuditSeverity.ERROR);
    });

    it('should return WARNING for login failure', () => {
      const severity = determineSeverity(AuditEventType.LOGIN_FAILURE, AuditResult.FAILURE);
      expect(severity).toBe(AuditSeverity.WARNING);
    });

    it('should return WARNING for MFA verify failure', () => {
      const severity = determineSeverity(AuditEventType.MFA_VERIFY_FAILURE, AuditResult.FAILURE);
      expect(severity).toBe(AuditSeverity.WARNING);
    });

    it('should return WARNING for new device login', () => {
      const severity = determineSeverity(AuditEventType.NEW_DEVICE_LOGIN, AuditResult.SUCCESS);
      expect(severity).toBe(AuditSeverity.WARNING);
    });

    it('should return INFO for login success', () => {
      const severity = determineSeverity(AuditEventType.LOGIN_SUCCESS, AuditResult.SUCCESS);
      expect(severity).toBe(AuditSeverity.INFO);
    });

    it('should return INFO for register', () => {
      const severity = determineSeverity(AuditEventType.REGISTER, AuditResult.SUCCESS);
      expect(severity).toBe(AuditSeverity.INFO);
    });
  });

  describe('calculateTTL', () => {
    it('should return healthcare TTL for clinisyn realm', () => {
      const ttl = calculateTTL('clinisyn-psychologists');
      const now = Math.floor(Date.now() / 1000);
      const sixYears = 6 * 365 * 24 * 60 * 60;
      expect(ttl).toBeGreaterThan(now + sixYears - 100);
      expect(ttl).toBeLessThan(now + sixYears + 100);
    });

    it('should return healthcare TTL for healthcare realm', () => {
      const ttl = calculateTTL('healthcare-provider');
      const now = Math.floor(Date.now() / 1000);
      const sixYears = 6 * 365 * 24 * 60 * 60;
      expect(ttl).toBeGreaterThan(now + sixYears - 100);
    });

    it('should return healthcare TTL for medical realm', () => {
      const ttl = calculateTTL('medical-clinic');
      const now = Math.floor(Date.now() / 1000);
      const sixYears = 6 * 365 * 24 * 60 * 60;
      expect(ttl).toBeGreaterThan(now + sixYears - 100);
    });

    it('should return standard TTL for non-healthcare realm', () => {
      const ttl = calculateTTL('standard-app');
      const now = Math.floor(Date.now() / 1000);
      const ninetyDays = 90 * 24 * 60 * 60;
      expect(ttl).toBeGreaterThan(now + ninetyDays - 100);
      expect(ttl).toBeLessThan(now + ninetyDays + 100);
    });

    it('should use custom config', () => {
      const config: AuditConfig = {
        ...DEFAULT_AUDIT_CONFIG,
        standardTTL: 30 * 24 * 60 * 60  // 30 days
      };
      const ttl = calculateTTL('standard-app', config);
      const now = Math.floor(Date.now() / 1000);
      const thirtyDays = 30 * 24 * 60 * 60;
      expect(ttl).toBeGreaterThan(now + thirtyDays - 100);
      expect(ttl).toBeLessThan(now + thirtyDays + 100);
    });
  });

  describe('sanitizeDetails', () => {
    it('should redact password fields', () => {
      const details = { username: 'john', password: 'secret123' };
      const sanitized = sanitizeDetails(details);
      expect(sanitized?.username).toBe('john');
      expect(sanitized?.password).toBe('[REDACTED]');
    });

    it('should redact token fields', () => {
      const details = { accessToken: 'abc123', refreshToken: 'xyz789' };
      const sanitized = sanitizeDetails(details);
      expect(sanitized?.accessToken).toBe('[REDACTED]');
      expect(sanitized?.refreshToken).toBe('[REDACTED]');
    });

    it('should redact secret fields', () => {
      const details = { apiSecret: 'secret', clientSecret: 'secret2' };
      const sanitized = sanitizeDetails(details);
      expect(sanitized?.apiSecret).toBe('[REDACTED]');
      expect(sanitized?.clientSecret).toBe('[REDACTED]');
    });

    it('should redact key fields', () => {
      const details = { apiKey: 'key123', privateKey: 'private' };
      const sanitized = sanitizeDetails(details);
      expect(sanitized?.apiKey).toBe('[REDACTED]');
      expect(sanitized?.privateKey).toBe('[REDACTED]');
    });

    it('should redact credential fields', () => {
      const details = { userCredential: 'cred123' };
      const sanitized = sanitizeDetails(details);
      expect(sanitized?.userCredential).toBe('[REDACTED]');
    });

    it('should redact authorization fields', () => {
      const details = { authorizationHeader: 'Bearer xxx' };
      const sanitized = sanitizeDetails(details);
      expect(sanitized?.authorizationHeader).toBe('[REDACTED]');
    });

    it('should preserve non-sensitive fields', () => {
      const details = { userId: '123', action: 'login', timestamp: '2026-01-15' };
      const sanitized = sanitizeDetails(details);
      expect(sanitized).toEqual(details);
    });

    it('should handle nested objects', () => {
      const details = {
        user: { id: '123', password: 'secret' },
        metadata: { ip: '1.2.3.4' }
      };
      const sanitized = sanitizeDetails(details);
      expect((sanitized?.user as Record<string, unknown>)?.id).toBe('123');
      expect((sanitized?.user as Record<string, unknown>)?.password).toBe('[REDACTED]');
      expect((sanitized?.metadata as Record<string, unknown>)?.ip).toBe('1.2.3.4');
    });

    it('should handle undefined', () => {
      const sanitized = sanitizeDetails(undefined);
      expect(sanitized).toBeUndefined();
    });

    it('should handle empty object', () => {
      const sanitized = sanitizeDetails({});
      expect(sanitized).toEqual({});
    });
  });

  describe('createAuditLogEntry', () => {
    const baseInput: AuditLogInput = {
      eventType: AuditEventType.LOGIN_SUCCESS,
      result: AuditResult.SUCCESS,
      realmId: 'test-realm',
      userId: 'user-123',
      userEmail: 'test@example.com',
      ipAddress: '192.168.1.100',
      action: 'User logged in'
    };

    it('should create entry with all required fields', () => {
      const entry = createAuditLogEntry(baseInput);
      
      expect(entry.id).toBeDefined();
      expect(entry.timestamp).toBeDefined();
      expect(entry.eventType).toBe(AuditEventType.LOGIN_SUCCESS);
      expect(entry.result).toBe(AuditResult.SUCCESS);
      expect(entry.realmId).toBe('test-realm');
      expect(entry.userId).toBe('user-123');
      expect(entry.action).toBe('User logged in');
    });

    it('should hash user email', () => {
      const entry = createAuditLogEntry(baseInput);
      expect(entry.userEmail).not.toBe('test@example.com');
      expect(entry.userEmail?.length).toBe(16);
    });

    it('should mask IP address', () => {
      const entry = createAuditLogEntry(baseInput);
      expect(entry.ipAddress).toBe('192.168.*.*');
    });

    it('should hash IP address for querying', () => {
      const entry = createAuditLogEntry(baseInput);
      expect(entry.ipAddressHash).toBeDefined();
      expect(entry.ipAddressHash.length).toBe(16);
    });

    it('should set correct partition key', () => {
      const entry = createAuditLogEntry(baseInput);
      expect(entry.pk).toBe('REALM#test-realm');
    });

    it('should set correct sort key', () => {
      const entry = createAuditLogEntry(baseInput);
      expect(entry.sk).toMatch(/^TIMESTAMP#\d{4}-\d{2}-\d{2}T/);
      expect(entry.sk).toContain(entry.id);
    });

    it('should set GSI1 keys for user queries', () => {
      const entry = createAuditLogEntry(baseInput);
      expect(entry.gsi1pk).toBe('USER#user-123');
      expect(entry.gsi1sk).toMatch(/^TIMESTAMP#/);
    });

    it('should set GSI2 keys for event type queries', () => {
      const entry = createAuditLogEntry(baseInput);
      expect(entry.gsi2pk).toBe('EVENT#login_success');
      expect(entry.gsi2sk).toMatch(/^TIMESTAMP#/);
    });

    it('should not set GSI1 keys when no userId', () => {
      const input = { ...baseInput, userId: undefined };
      const entry = createAuditLogEntry(input);
      expect(entry.gsi1pk).toBeUndefined();
      expect(entry.gsi1sk).toBeUndefined();
    });

    it('should calculate TTL', () => {
      const entry = createAuditLogEntry(baseInput);
      expect(entry.ttl).toBeDefined();
      expect(entry.ttl).toBeGreaterThan(Math.floor(Date.now() / 1000));
    });

    it('should determine severity automatically', () => {
      const entry = createAuditLogEntry(baseInput);
      expect(entry.severity).toBe(AuditSeverity.INFO);
    });

    it('should use provided severity', () => {
      const input = { ...baseInput, severity: AuditSeverity.WARNING };
      const entry = createAuditLogEntry(input);
      expect(entry.severity).toBe(AuditSeverity.WARNING);
    });

    it('should include optional fields', () => {
      const input: AuditLogInput = {
        ...baseInput,
        sessionId: 'session-123',
        userAgent: 'Mozilla/5.0',
        requestId: 'req-456',
        geoCountry: 'TR',
        geoCity: 'Istanbul',
        resource: '/api/login',
        details: { browser: 'Chrome' },
        errorCode: 'AUTH_001',
        errorMessage: 'Invalid credentials'
      };
      const entry = createAuditLogEntry(input);
      
      expect(entry.sessionId).toBe('session-123');
      expect(entry.userAgent).toBe('Mozilla/5.0');
      expect(entry.requestId).toBe('req-456');
      expect(entry.geoCountry).toBe('TR');
      expect(entry.geoCity).toBe('Istanbul');
      expect(entry.resource).toBe('/api/login');
      expect(entry.details).toEqual({ browser: 'Chrome' });
      expect(entry.errorCode).toBe('AUTH_001');
      expect(entry.errorMessage).toBe('Invalid credentials');
    });

    it('should sanitize details', () => {
      const input = {
        ...baseInput,
        details: { password: 'secret', action: 'test' }
      };
      const entry = createAuditLogEntry(input);
      expect(entry.details?.password).toBe('[REDACTED]');
      expect(entry.details?.action).toBe('test');
    });
  });

  describe('DEFAULT_AUDIT_CONFIG', () => {
    it('should have 6 year default TTL', () => {
      const sixYears = 6 * 365 * 24 * 60 * 60;
      expect(DEFAULT_AUDIT_CONFIG.defaultTTL).toBe(sixYears);
    });

    it('should have 6 year healthcare TTL', () => {
      const sixYears = 6 * 365 * 24 * 60 * 60;
      expect(DEFAULT_AUDIT_CONFIG.healthcareTTL).toBe(sixYears);
    });

    it('should have 90 day standard TTL', () => {
      const ninetyDays = 90 * 24 * 60 * 60;
      expect(DEFAULT_AUDIT_CONFIG.standardTTL).toBe(ninetyDays);
    });

    it('should enable async logging by default', () => {
      expect(DEFAULT_AUDIT_CONFIG.asyncLogging).toBe(true);
    });

    it('should have batch size of 25', () => {
      expect(DEFAULT_AUDIT_CONFIG.batchSize).toBe(25);
    });
  });

  describe('AuditEventType enum', () => {
    it('should have all authentication events', () => {
      expect(AuditEventType.LOGIN_SUCCESS).toBe('login_success');
      expect(AuditEventType.LOGIN_FAILURE).toBe('login_failure');
      expect(AuditEventType.LOGOUT).toBe('logout');
      expect(AuditEventType.REGISTER).toBe('register');
    });

    it('should have all password events', () => {
      expect(AuditEventType.PASSWORD_CHANGE).toBe('password_change');
      expect(AuditEventType.PASSWORD_RESET_REQUEST).toBe('password_reset_request');
      expect(AuditEventType.PASSWORD_RESET_COMPLETE).toBe('password_reset_complete');
    });

    it('should have all MFA events', () => {
      expect(AuditEventType.MFA_ENABLE).toBe('mfa_enable');
      expect(AuditEventType.MFA_DISABLE).toBe('mfa_disable');
      expect(AuditEventType.MFA_VERIFY_SUCCESS).toBe('mfa_verify_success');
      expect(AuditEventType.MFA_VERIFY_FAILURE).toBe('mfa_verify_failure');
      expect(AuditEventType.BACKUP_CODE_USED).toBe('backup_code_used');
    });

    it('should have all WebAuthn events', () => {
      expect(AuditEventType.WEBAUTHN_REGISTER).toBe('webauthn_register');
      expect(AuditEventType.WEBAUTHN_REMOVE).toBe('webauthn_remove');
      expect(AuditEventType.WEBAUTHN_AUTH_SUCCESS).toBe('webauthn_auth_success');
      expect(AuditEventType.WEBAUTHN_AUTH_FAILURE).toBe('webauthn_auth_failure');
    });

    it('should have all device events', () => {
      expect(AuditEventType.DEVICE_TRUST).toBe('device_trust');
      expect(AuditEventType.DEVICE_REVOKE).toBe('device_revoke');
      expect(AuditEventType.NEW_DEVICE_LOGIN).toBe('new_device_login');
    });

    it('should have all security events', () => {
      expect(AuditEventType.SUSPICIOUS_ACTIVITY).toBe('suspicious_activity');
      expect(AuditEventType.IMPOSSIBLE_TRAVEL).toBe('impossible_travel');
      expect(AuditEventType.CREDENTIAL_STUFFING).toBe('credential_stuffing');
      expect(AuditEventType.RATE_LIMIT_EXCEEDED).toBe('rate_limit_exceeded');
    });

    it('should have all admin events', () => {
      expect(AuditEventType.ADMIN_ACTION).toBe('admin_action');
      expect(AuditEventType.CONFIG_CHANGE).toBe('config_change');
      expect(AuditEventType.USER_IMPERSONATE).toBe('user_impersonate');
    });
  });

  describe('AuditResult enum', () => {
    it('should have all result types', () => {
      expect(AuditResult.SUCCESS).toBe('success');
      expect(AuditResult.FAILURE).toBe('failure');
      expect(AuditResult.BLOCKED).toBe('blocked');
      expect(AuditResult.PENDING).toBe('pending');
    });
  });

  describe('AuditSeverity enum', () => {
    it('should have all severity levels', () => {
      expect(AuditSeverity.INFO).toBe('info');
      expect(AuditSeverity.WARNING).toBe('warning');
      expect(AuditSeverity.ERROR).toBe('error');
      expect(AuditSeverity.CRITICAL).toBe('critical');
    });
  });

  describe('Property-based tests', () => {
    describe('hashSensitiveData', () => {
      it('should always return 16 character string', () => {
        fc.assert(
          fc.property(fc.string(), (data) => {
            const hash = hashSensitiveData(data);
            return hash.length === 16;
          }),
          { numRuns: 100 }
        );
      });

      it('should be deterministic', () => {
        fc.assert(
          fc.property(fc.string(), (data) => {
            const hash1 = hashSensitiveData(data);
            const hash2 = hashSensitiveData(data);
            return hash1 === hash2;
          }),
          { numRuns: 100 }
        );
      });
    });

    describe('maskEmail', () => {
      it('should always contain @', () => {
        fc.assert(
          fc.property(
            fc.emailAddress(),
            (email) => {
              const masked = maskEmail(email);
              return masked.includes('@');
            }
          ),
          { numRuns: 100 }
        );
      });
    });

    describe('maskIP', () => {
      it('should always mask IPv4 addresses', () => {
        fc.assert(
          fc.property(
            fc.integer({ min: 0, max: 255 }),
            fc.integer({ min: 0, max: 255 }),
            fc.integer({ min: 0, max: 255 }),
            fc.integer({ min: 0, max: 255 }),
            (a, b, c, d) => {
              const ip = `${a}.${b}.${c}.${d}`;
              const masked = maskIP(ip);
              return masked.includes('*');
            }
          ),
          { numRuns: 100 }
        );
      });
    });

    describe('createAuditLogEntry', () => {
      it('should always create valid entry', () => {
        fc.assert(
          fc.property(
            fc.record({
              eventType: fc.constantFrom(...Object.values(AuditEventType)),
              result: fc.constantFrom(...Object.values(AuditResult)),
              realmId: fc.string({ minLength: 1 }),
              ipAddress: fc.ipV4(),
              action: fc.string({ minLength: 1 })
            }),
            (input) => {
              const entry = createAuditLogEntry(input as AuditLogInput);
              return (
                entry.id !== undefined &&
                entry.timestamp !== undefined &&
                entry.pk.startsWith('REALM#') &&
                entry.sk.startsWith('TIMESTAMP#')
              );
            }
          ),
          { numRuns: 50 }
        );
      });
    });
  });

  describe('AuditHelpers', () => {
    beforeEach(() => {
      jest.clearAllMocks();
    });

    it('should have logLoginSuccess helper', () => {
      expect(typeof AuditHelpers.logLoginSuccess).toBe('function');
    });

    it('should have logLoginFailure helper', () => {
      expect(typeof AuditHelpers.logLoginFailure).toBe('function');
    });

    it('should have logLogout helper', () => {
      expect(typeof AuditHelpers.logLogout).toBe('function');
    });

    it('should have logRegister helper', () => {
      expect(typeof AuditHelpers.logRegister).toBe('function');
    });

    it('should have logPasswordChange helper', () => {
      expect(typeof AuditHelpers.logPasswordChange).toBe('function');
    });

    it('should have logMFAEnable helper', () => {
      expect(typeof AuditHelpers.logMFAEnable).toBe('function');
    });

    it('should have logAccountLock helper', () => {
      expect(typeof AuditHelpers.logAccountLock).toBe('function');
    });

    it('should have logSuspiciousActivity helper', () => {
      expect(typeof AuditHelpers.logSuspiciousActivity).toBe('function');
    });

    it('should have logImpossibleTravel helper', () => {
      expect(typeof AuditHelpers.logImpossibleTravel).toBe('function');
    });
  });
});
