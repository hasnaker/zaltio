/**
 * Security Alerting Service Tests
 * Task 7.2: Security Alerting
 * 
 * Tests:
 * - Alert creation
 * - Priority determination
 * - Throttling
 * - Email/webhook formatting
 * - Helper functions
 */

import * as fc from 'fast-check';
import {
  AlertType,
  AlertPriority,
  AlertChannel,
  RecipientType,
  AlertConfig,
  AlertInput,
  DEFAULT_ALERT_CONFIG,
  HEALTHCARE_ALERT_CONFIG,
  getAlertPriority,
  getAlertTitle,
  getAlertMessage,
  getAlertRecipients,
  shouldThrottle,
  resetThrottleState,
  meetsPriorityThreshold,
  getRealmAlertConfig,
  createAlertData,
  formatAlertEmail,
  formatAlertWebhook,
  sendAlert,
  sendAlertSync,
  auditEventToAlertType,
  AlertHelpers
} from './alert.service';
import { AuditEventType } from './audit.service';

describe('Security Alerting Service - Unit Tests', () => {
  beforeEach(() => {
    resetThrottleState();
  });

  describe('getAlertPriority', () => {
    it('should return CRITICAL for credential stuffing', () => {
      expect(getAlertPriority(AlertType.CREDENTIAL_STUFFING)).toBe(AlertPriority.CRITICAL);
    });

    it('should return CRITICAL for impossible travel', () => {
      expect(getAlertPriority(AlertType.IMPOSSIBLE_TRAVEL)).toBe(AlertPriority.CRITICAL);
    });

    it('should return CRITICAL for brute force', () => {
      expect(getAlertPriority(AlertType.BRUTE_FORCE_DETECTED)).toBe(AlertPriority.CRITICAL);
    });

    it('should return HIGH for account locked', () => {
      expect(getAlertPriority(AlertType.ACCOUNT_LOCKED)).toBe(AlertPriority.HIGH);
    });

    it('should return HIGH for suspicious login', () => {
      expect(getAlertPriority(AlertType.SUSPICIOUS_LOGIN)).toBe(AlertPriority.HIGH);
    });

    it('should return HIGH for failed login spike', () => {
      expect(getAlertPriority(AlertType.FAILED_LOGIN_SPIKE)).toBe(AlertPriority.HIGH);
    });

    it('should return MEDIUM for new device login', () => {
      expect(getAlertPriority(AlertType.NEW_DEVICE_LOGIN)).toBe(AlertPriority.MEDIUM);
    });

    it('should return MEDIUM for password changed', () => {
      expect(getAlertPriority(AlertType.PASSWORD_CHANGED)).toBe(AlertPriority.MEDIUM);
    });

    it('should return MEDIUM for MFA disabled', () => {
      expect(getAlertPriority(AlertType.MFA_DISABLED)).toBe(AlertPriority.MEDIUM);
    });

    it('should return LOW for MFA enabled', () => {
      expect(getAlertPriority(AlertType.MFA_ENABLED)).toBe(AlertPriority.LOW);
    });

    it('should return LOW for service degradation', () => {
      expect(getAlertPriority(AlertType.SERVICE_DEGRADATION)).toBe(AlertPriority.LOW);
    });
  });

  describe('getAlertTitle', () => {
    it('should return correct title for new device login', () => {
      expect(getAlertTitle(AlertType.NEW_DEVICE_LOGIN)).toBe('New Device Login Detected');
    });

    it('should return correct title for password changed', () => {
      expect(getAlertTitle(AlertType.PASSWORD_CHANGED)).toBe('Password Changed');
    });

    it('should return correct title for MFA disabled', () => {
      expect(getAlertTitle(AlertType.MFA_DISABLED)).toBe('MFA Disabled - Security Alert');
    });

    it('should return correct title for credential stuffing', () => {
      expect(getAlertTitle(AlertType.CREDENTIAL_STUFFING)).toBe('Credential Stuffing Attack Detected');
    });

    it('should return correct title for impossible travel', () => {
      expect(getAlertTitle(AlertType.IMPOSSIBLE_TRAVEL)).toBe('Impossible Travel Detected');
    });

    it('should return default title for unknown type', () => {
      expect(getAlertTitle('unknown' as AlertType)).toBe('Security Alert');
    });
  });

  describe('getAlertMessage', () => {
    it('should include location in new device login message', () => {
      const message = getAlertMessage(AlertType.NEW_DEVICE_LOGIN, { location: 'Istanbul, Turkey' });
      expect(message).toContain('Istanbul, Turkey');
    });

    it('should include reason in account locked message', () => {
      const message = getAlertMessage(AlertType.ACCOUNT_LOCKED, { 
        reason: 'Too many failed attempts',
        lockDuration: 900
      });
      expect(message).toContain('Too many failed attempts');
      expect(message).toContain('15 minutes');
    });

    it('should include count in failed login spike message', () => {
      const message = getAlertMessage(AlertType.FAILED_LOGIN_SPIKE, { count: 50, windowMinutes: 5 });
      expect(message).toContain('50');
      expect(message).toContain('5 minutes');
    });

    it('should include distance in impossible travel message', () => {
      const message = getAlertMessage(AlertType.IMPOSSIBLE_TRAVEL, {
        fromLocation: 'Istanbul',
        toLocation: 'New York',
        distanceKm: 8000,
        timeHours: 1
      });
      expect(message).toContain('Istanbul');
      expect(message).toContain('New York');
      expect(message).toContain('8000');
    });

    it('should return default message for password changed', () => {
      const message = getAlertMessage(AlertType.PASSWORD_CHANGED);
      expect(message).toContain('password was successfully changed');
    });

    it('should return default message for MFA disabled', () => {
      const message = getAlertMessage(AlertType.MFA_DISABLED);
      expect(message).toContain('Multi-factor authentication has been disabled');
    });
  });

  describe('getAlertRecipients', () => {
    it('should include user for user alerts', () => {
      const recipients = getAlertRecipients(
        AlertType.NEW_DEVICE_LOGIN,
        'user-123',
        'user@example.com'
      );
      expect(recipients).toContainEqual({
        type: RecipientType.USER,
        email: 'user@example.com'
      });
    });

    it('should include admin for admin alerts', () => {
      const recipients = getAlertRecipients(AlertType.FAILED_LOGIN_SPIKE);
      expect(recipients).toContainEqual({ type: RecipientType.ADMIN });
    });

    it('should include security team for critical alerts', () => {
      const recipients = getAlertRecipients(AlertType.CREDENTIAL_STUFFING);
      expect(recipients).toContainEqual({ type: RecipientType.SECURITY_TEAM });
    });

    it('should include webhook if configured', () => {
      const config: AlertConfig = {
        ...DEFAULT_ALERT_CONFIG,
        webhookUrl: 'https://hooks.example.com/alert'
      };
      const recipients = getAlertRecipients(AlertType.NEW_DEVICE_LOGIN, 'user-123', 'user@example.com', config);
      expect(recipients).toContainEqual({
        type: RecipientType.WEBHOOK,
        webhookUrl: 'https://hooks.example.com/alert'
      });
    });

    it('should not include user if no email provided', () => {
      const recipients = getAlertRecipients(AlertType.NEW_DEVICE_LOGIN, 'user-123');
      expect(recipients.find(r => r.type === RecipientType.USER)).toBeUndefined();
    });
  });

  describe('shouldThrottle', () => {
    it('should not throttle first alert', () => {
      expect(shouldThrottle('realm-1', AlertType.NEW_DEVICE_LOGIN)).toBe(false);
    });

    it('should not throttle when disabled', () => {
      const config: AlertConfig = {
        ...DEFAULT_ALERT_CONFIG,
        throttle: { enabled: false, windowMs: 60000, maxAlerts: 1 }
      };
      expect(shouldThrottle('realm-1', AlertType.NEW_DEVICE_LOGIN, config)).toBe(false);
      expect(shouldThrottle('realm-1', AlertType.NEW_DEVICE_LOGIN, config)).toBe(false);
    });

    it('should throttle after max alerts reached', () => {
      const config: AlertConfig = {
        ...DEFAULT_ALERT_CONFIG,
        throttle: { enabled: true, windowMs: 60000, maxAlerts: 2 }
      };
      
      expect(shouldThrottle('realm-1', AlertType.NEW_DEVICE_LOGIN, config)).toBe(false);
      expect(shouldThrottle('realm-1', AlertType.NEW_DEVICE_LOGIN, config)).toBe(false);
      expect(shouldThrottle('realm-1', AlertType.NEW_DEVICE_LOGIN, config)).toBe(true);
    });

    it('should track different alert types separately', () => {
      const config: AlertConfig = {
        ...DEFAULT_ALERT_CONFIG,
        throttle: { enabled: true, windowMs: 60000, maxAlerts: 1 }
      };
      
      expect(shouldThrottle('realm-1', AlertType.NEW_DEVICE_LOGIN, config)).toBe(false);
      expect(shouldThrottle('realm-1', AlertType.PASSWORD_CHANGED, config)).toBe(false);
      expect(shouldThrottle('realm-1', AlertType.NEW_DEVICE_LOGIN, config)).toBe(true);
    });

    it('should track different realms separately', () => {
      const config: AlertConfig = {
        ...DEFAULT_ALERT_CONFIG,
        throttle: { enabled: true, windowMs: 60000, maxAlerts: 1 }
      };
      
      expect(shouldThrottle('realm-1', AlertType.NEW_DEVICE_LOGIN, config)).toBe(false);
      expect(shouldThrottle('realm-2', AlertType.NEW_DEVICE_LOGIN, config)).toBe(false);
    });
  });

  describe('meetsPriorityThreshold', () => {
    it('should pass CRITICAL when min is LOW', () => {
      expect(meetsPriorityThreshold(AlertPriority.CRITICAL, AlertPriority.LOW)).toBe(true);
    });

    it('should pass HIGH when min is MEDIUM', () => {
      expect(meetsPriorityThreshold(AlertPriority.HIGH, AlertPriority.MEDIUM)).toBe(true);
    });

    it('should pass MEDIUM when min is MEDIUM', () => {
      expect(meetsPriorityThreshold(AlertPriority.MEDIUM, AlertPriority.MEDIUM)).toBe(true);
    });

    it('should fail LOW when min is MEDIUM', () => {
      expect(meetsPriorityThreshold(AlertPriority.LOW, AlertPriority.MEDIUM)).toBe(false);
    });

    it('should fail MEDIUM when min is HIGH', () => {
      expect(meetsPriorityThreshold(AlertPriority.MEDIUM, AlertPriority.HIGH)).toBe(false);
    });

    it('should fail HIGH when min is CRITICAL', () => {
      expect(meetsPriorityThreshold(AlertPriority.HIGH, AlertPriority.CRITICAL)).toBe(false);
    });
  });

  describe('getRealmAlertConfig', () => {
    it('should return healthcare config for clinisyn realm', () => {
      const config = getRealmAlertConfig('clinisyn-psychologists');
      expect(config).toEqual(HEALTHCARE_ALERT_CONFIG);
    });

    it('should return healthcare config for healthcare realm', () => {
      const config = getRealmAlertConfig('healthcare-provider');
      expect(config).toEqual(HEALTHCARE_ALERT_CONFIG);
    });

    it('should return healthcare config for medical realm', () => {
      const config = getRealmAlertConfig('medical-clinic');
      expect(config).toEqual(HEALTHCARE_ALERT_CONFIG);
    });

    it('should return default config for standard realm', () => {
      const config = getRealmAlertConfig('standard-app');
      expect(config).toEqual(DEFAULT_ALERT_CONFIG);
    });
  });

  describe('createAlertData', () => {
    const baseInput: AlertInput = {
      type: AlertType.NEW_DEVICE_LOGIN,
      realmId: 'test-realm',
      userId: 'user-123',
      userEmail: 'user@example.com',
      ipAddress: '1.2.3.4'
    };

    it('should create alert with all required fields', () => {
      const alert = createAlertData(baseInput);
      
      expect(alert.id).toBeDefined();
      expect(alert.type).toBe(AlertType.NEW_DEVICE_LOGIN);
      expect(alert.priority).toBe(AlertPriority.MEDIUM);
      expect(alert.timestamp).toBeDefined();
      expect(alert.realmId).toBe('test-realm');
      expect(alert.userId).toBe('user-123');
      expect(alert.title).toBe('New Device Login Detected');
      expect(alert.message).toBeDefined();
    });

    it('should set correct priority', () => {
      const criticalInput = { ...baseInput, type: AlertType.CREDENTIAL_STUFFING };
      const alert = createAlertData(criticalInput);
      expect(alert.priority).toBe(AlertPriority.CRITICAL);
    });

    it('should include recipients', () => {
      const alert = createAlertData(baseInput);
      expect(alert.recipients.length).toBeGreaterThan(0);
    });

    it('should include channels', () => {
      const alert = createAlertData(baseInput);
      expect(alert.channels).toContain(AlertChannel.EMAIL);
    });

    it('should mark as throttled when throttle limit reached', () => {
      // First exhaust the throttle
      shouldThrottle('throttle-test-realm', AlertType.NEW_DEVICE_LOGIN, {
        ...DEFAULT_ALERT_CONFIG,
        throttle: { enabled: true, windowMs: 60000, maxAlerts: 1 }
      });
      
      const config: AlertConfig = {
        ...DEFAULT_ALERT_CONFIG,
        throttle: { enabled: true, windowMs: 60000, maxAlerts: 1 }
      };
      const alert = createAlertData({ ...baseInput, realmId: 'throttle-test-realm' }, config);
      expect(alert.throttled).toBe(true);
    });

    it('should mark as throttled when priority below threshold', () => {
      const config: AlertConfig = {
        ...DEFAULT_ALERT_CONFIG,
        minPriority: AlertPriority.HIGH
      };
      const alert = createAlertData(baseInput, config);
      expect(alert.throttled).toBe(true);
    });

    it('should mark as throttled when alerts disabled', () => {
      const config: AlertConfig = {
        ...DEFAULT_ALERT_CONFIG,
        enabled: false
      };
      const alert = createAlertData(baseInput, config);
      expect(alert.throttled).toBe(true);
    });

    it('should use custom message if provided', () => {
      const input = { ...baseInput, customMessage: 'Custom alert message' };
      const alert = createAlertData(input);
      expect(alert.message).toBe('Custom alert message');
    });
  });

  describe('formatAlertEmail', () => {
    it('should format email with subject', () => {
      const alert = createAlertData({
        type: AlertType.NEW_DEVICE_LOGIN,
        realmId: 'test-realm',
        userId: 'user-123',
        userEmail: 'user@example.com',
        ipAddress: '1.2.3.4'
      });
      
      const email = formatAlertEmail(alert);
      
      expect(email.subject).toContain('New Device Login');
      expect(email.subject).toContain('⚠️');  // Medium priority emoji
    });

    it('should include HTML body', () => {
      const alert = createAlertData({
        type: AlertType.CREDENTIAL_STUFFING,
        realmId: 'test-realm',
        ipAddress: '1.2.3.4'
      });
      
      const email = formatAlertEmail(alert);
      
      expect(email.htmlBody).toContain('<!DOCTYPE html>');
      expect(email.htmlBody).toContain('Credential Stuffing');
    });

    it('should include text body', () => {
      const alert = createAlertData({
        type: AlertType.PASSWORD_CHANGED,
        realmId: 'test-realm',
        userId: 'user-123',
        userEmail: 'user@example.com',
        ipAddress: '1.2.3.4'
      });
      
      const email = formatAlertEmail(alert);
      
      expect(email.textBody).toContain('Password Changed');
      expect(email.textBody).toContain('Zalt.io');
    });

    it('should include details in email', () => {
      const alert = createAlertData({
        type: AlertType.IMPOSSIBLE_TRAVEL,
        realmId: 'test-realm',
        userId: 'user-123',
        ipAddress: '1.2.3.4',
        details: { fromLocation: 'Istanbul', toLocation: 'New York' }
      });
      
      const email = formatAlertEmail(alert);
      
      expect(email.htmlBody).toContain('Istanbul');
      expect(email.textBody).toContain('New York');
    });

    it('should use correct emoji for priority', () => {
      const criticalAlert = createAlertData({
        type: AlertType.CREDENTIAL_STUFFING,
        realmId: 'test-realm',
        ipAddress: '1.2.3.4'
      });
      
      const email = formatAlertEmail(criticalAlert);
      expect(email.subject).toContain('🚨');
    });
  });

  describe('formatAlertWebhook', () => {
    it('should format webhook payload', () => {
      const alert = createAlertData({
        type: AlertType.NEW_DEVICE_LOGIN,
        realmId: 'test-realm',
        userId: 'user-123',
        ipAddress: '1.2.3.4'
      });
      
      const webhook = formatAlertWebhook(alert);
      
      expect(webhook.payload.id).toBe(alert.id);
      expect(webhook.payload.type).toBe(AlertType.NEW_DEVICE_LOGIN);
      expect(webhook.payload.realm_id).toBe('test-realm');
    });

    it('should include signature when secret provided', () => {
      const alert = createAlertData({
        type: AlertType.NEW_DEVICE_LOGIN,
        realmId: 'test-realm',
        userId: 'user-123',
        ipAddress: '1.2.3.4'
      });
      
      const webhook = formatAlertWebhook(alert, 'webhook-secret');
      
      expect(webhook.signature).toBeDefined();
      expect(webhook.signature?.length).toBe(64);  // SHA-256 hex
    });

    it('should not include signature when no secret', () => {
      const alert = createAlertData({
        type: AlertType.NEW_DEVICE_LOGIN,
        realmId: 'test-realm',
        userId: 'user-123',
        ipAddress: '1.2.3.4'
      });
      
      const webhook = formatAlertWebhook(alert);
      
      expect(webhook.signature).toBeUndefined();
    });
  });

  describe('sendAlert', () => {
    it('should send alert and mark as sent', async () => {
      const alert = await sendAlert({
        type: AlertType.NEW_DEVICE_LOGIN,
        realmId: 'test-realm',
        userId: 'user-123',
        userEmail: 'user@example.com',
        ipAddress: '1.2.3.4'
      });
      
      expect(alert.sent).toBe(true);
      expect(alert.sentAt).toBeDefined();
    });

    it('should not send throttled alerts', async () => {
      // First exhaust the throttle
      await sendAlert({
        type: AlertType.NEW_DEVICE_LOGIN,
        realmId: 'throttle-send-realm',
        userId: 'user-123',
        ipAddress: '1.2.3.4'
      }, {
        ...DEFAULT_ALERT_CONFIG,
        throttle: { enabled: true, windowMs: 60000, maxAlerts: 1 }
      });
      
      const config: AlertConfig = {
        ...DEFAULT_ALERT_CONFIG,
        throttle: { enabled: true, windowMs: 60000, maxAlerts: 1 }
      };
      
      const alert = await sendAlert({
        type: AlertType.NEW_DEVICE_LOGIN,
        realmId: 'throttle-send-realm',
        userId: 'user-123',
        ipAddress: '1.2.3.4'
      }, config);
      
      expect(alert.sent).toBe(false);
      expect(alert.throttled).toBe(true);
    });
  });

  describe('sendAlertSync', () => {
    it('should send alert without throttling', async () => {
      // First exhaust throttle
      const config: AlertConfig = {
        ...DEFAULT_ALERT_CONFIG,
        throttle: { enabled: true, windowMs: 60000, maxAlerts: 1 }
      };
      
      await sendAlert({
        type: AlertType.CREDENTIAL_STUFFING,
        realmId: 'test-realm',
        ipAddress: '1.2.3.4'
      }, config);
      
      // Sync should bypass throttle
      const alert = await sendAlertSync({
        type: AlertType.CREDENTIAL_STUFFING,
        realmId: 'test-realm',
        ipAddress: '1.2.3.4'
      });
      
      expect(alert.sent).toBe(true);
    });
  });

  describe('auditEventToAlertType', () => {
    it('should map NEW_DEVICE_LOGIN', () => {
      expect(auditEventToAlertType(AuditEventType.NEW_DEVICE_LOGIN)).toBe(AlertType.NEW_DEVICE_LOGIN);
    });

    it('should map PASSWORD_CHANGE', () => {
      expect(auditEventToAlertType(AuditEventType.PASSWORD_CHANGE)).toBe(AlertType.PASSWORD_CHANGED);
    });

    it('should map MFA_DISABLE', () => {
      expect(auditEventToAlertType(AuditEventType.MFA_DISABLE)).toBe(AlertType.MFA_DISABLED);
    });

    it('should map CREDENTIAL_STUFFING', () => {
      expect(auditEventToAlertType(AuditEventType.CREDENTIAL_STUFFING)).toBe(AlertType.CREDENTIAL_STUFFING);
    });

    it('should map IMPOSSIBLE_TRAVEL', () => {
      expect(auditEventToAlertType(AuditEventType.IMPOSSIBLE_TRAVEL)).toBe(AlertType.IMPOSSIBLE_TRAVEL);
    });

    it('should return null for unmapped events', () => {
      expect(auditEventToAlertType(AuditEventType.LOGIN_SUCCESS)).toBeNull();
    });
  });

  describe('DEFAULT_ALERT_CONFIG', () => {
    it('should be enabled', () => {
      expect(DEFAULT_ALERT_CONFIG.enabled).toBe(true);
    });

    it('should include email channel', () => {
      expect(DEFAULT_ALERT_CONFIG.channels).toContain(AlertChannel.EMAIL);
    });

    it('should have throttle enabled', () => {
      expect(DEFAULT_ALERT_CONFIG.throttle.enabled).toBe(true);
    });

    it('should have 5 minute throttle window', () => {
      expect(DEFAULT_ALERT_CONFIG.throttle.windowMs).toBe(5 * 60 * 1000);
    });

    it('should have min priority MEDIUM', () => {
      expect(DEFAULT_ALERT_CONFIG.minPriority).toBe(AlertPriority.MEDIUM);
    });
  });

  describe('HEALTHCARE_ALERT_CONFIG', () => {
    it('should include webhook channel', () => {
      expect(HEALTHCARE_ALERT_CONFIG.channels).toContain(AlertChannel.WEBHOOK);
    });

    it('should have higher max alerts', () => {
      expect(HEALTHCARE_ALERT_CONFIG.throttle.maxAlerts).toBeGreaterThan(DEFAULT_ALERT_CONFIG.throttle.maxAlerts);
    });

    it('should have min priority LOW', () => {
      expect(HEALTHCARE_ALERT_CONFIG.minPriority).toBe(AlertPriority.LOW);
    });
  });

  describe('AlertHelpers', () => {
    it('should have newDeviceLogin helper', async () => {
      const alert = await AlertHelpers.newDeviceLogin({
        realmId: 'test-realm',
        userId: 'user-123',
        userEmail: 'user@example.com',
        ipAddress: '1.2.3.4',
        location: 'Istanbul'
      });
      expect(alert.type).toBe(AlertType.NEW_DEVICE_LOGIN);
    });

    it('should have passwordChanged helper', async () => {
      const alert = await AlertHelpers.passwordChanged({
        realmId: 'test-realm',
        userId: 'user-123',
        userEmail: 'user@example.com',
        ipAddress: '1.2.3.4'
      });
      expect(alert.type).toBe(AlertType.PASSWORD_CHANGED);
    });

    it('should have mfaDisabled helper', async () => {
      const alert = await AlertHelpers.mfaDisabled({
        realmId: 'test-realm',
        userId: 'user-123',
        userEmail: 'user@example.com',
        ipAddress: '1.2.3.4'
      });
      expect(alert.type).toBe(AlertType.MFA_DISABLED);
    });

    it('should have accountLocked helper', async () => {
      const alert = await AlertHelpers.accountLocked({
        realmId: 'test-realm',
        userId: 'user-123',
        userEmail: 'user@example.com',
        ipAddress: '1.2.3.4',
        reason: 'Too many failed attempts',
        lockDuration: 900
      });
      expect(alert.type).toBe(AlertType.ACCOUNT_LOCKED);
      expect(alert.details?.lockDuration).toBe(900);
    });

    it('should have credentialStuffing helper', async () => {
      const alert = await AlertHelpers.credentialStuffing({
        realmId: 'test-realm',
        ipAddress: '1.2.3.4',
        blockedAttempts: 100
      });
      expect(alert.type).toBe(AlertType.CREDENTIAL_STUFFING);
      expect(alert.details?.blockedAttempts).toBe(100);
    });

    it('should have impossibleTravel helper', async () => {
      const alert = await AlertHelpers.impossibleTravel({
        realmId: 'test-realm',
        userId: 'user-123',
        userEmail: 'user@example.com',
        ipAddress: '1.2.3.4',
        fromLocation: 'Istanbul',
        toLocation: 'New York',
        distanceKm: 8000,
        timeHours: 1
      });
      expect(alert.type).toBe(AlertType.IMPOSSIBLE_TRAVEL);
      expect(alert.details?.distanceKm).toBe(8000);
    });

    it('should have failedLoginSpike helper', async () => {
      const alert = await AlertHelpers.failedLoginSpike({
        realmId: 'test-realm',
        count: 50,
        windowMinutes: 5
      });
      expect(alert.type).toBe(AlertType.FAILED_LOGIN_SPIKE);
      expect(alert.details?.count).toBe(50);
    });
  });

  describe('Property-based tests', () => {
    it('should always return valid priority', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...Object.values(AlertType)),
          (type) => {
            const priority = getAlertPriority(type);
            return Object.values(AlertPriority).includes(priority);
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should always return non-empty title', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...Object.values(AlertType)),
          (type) => {
            const title = getAlertTitle(type);
            return title.length > 0;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should always create valid alert data', () => {
      fc.assert(
        fc.property(
          fc.record({
            type: fc.constantFrom(...Object.values(AlertType)),
            realmId: fc.string({ minLength: 1 }),
            ipAddress: fc.ipV4()
          }),
          (input) => {
            const alert = createAlertData(input as AlertInput);
            return (
              alert.id !== undefined &&
              alert.timestamp !== undefined &&
              alert.type === input.type
            );
          }
        ),
        { numRuns: 50 }
      );
    });
  });
});
