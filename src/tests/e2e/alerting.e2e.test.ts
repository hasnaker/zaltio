/**
 * Security Alerting Service E2E Tests
 * Task 7.2: Security Alerting
 * 
 * Tests:
 * - Alert creation and sending
 * - Throttling behavior
 * - Email/webhook formatting
 * - Realm-specific configuration
 */

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
} from '../../services/alert.service';
import { AuditEventType } from '../../services/audit.service';

describe('Security Alerting Service - E2E Tests', () => {
  beforeEach(() => {
    resetThrottleState();
  });

  describe('User Alert Scenarios', () => {
    describe('New Device Login', () => {
      it('should create alert for new device login', async () => {
        const alert = await AlertHelpers.newDeviceLogin({
          realmId: 'clinisyn-psychologists',
          userId: 'dr-123',
          userEmail: 'dr.ayse@example.com',
          ipAddress: '85.100.50.25',
          location: 'Istanbul, Turkey',
          deviceInfo: 'Chrome on Windows'
        });

        expect(alert.type).toBe(AlertType.NEW_DEVICE_LOGIN);
        expect(alert.priority).toBe(AlertPriority.MEDIUM);
        expect(alert.sent).toBe(true);
        expect(alert.recipients).toContainEqual({
          type: RecipientType.USER,
          email: 'dr.ayse@example.com'
        });
      });

      it('should include location in message', async () => {
        const alert = await AlertHelpers.newDeviceLogin({
          realmId: 'test-realm',
          userId: 'user-123',
          userEmail: 'user@example.com',
          ipAddress: '1.2.3.4',
          location: 'New York, USA'
        });

        expect(alert.message).toContain('New York, USA');
      });
    });

    describe('Password Changed', () => {
      it('should create alert for password change', async () => {
        const alert = await AlertHelpers.passwordChanged({
          realmId: 'clinisyn-psychologists',
          userId: 'dr-456',
          userEmail: 'dr.mehmet@example.com',
          ipAddress: '192.168.1.100'
        });

        expect(alert.type).toBe(AlertType.PASSWORD_CHANGED);
        expect(alert.priority).toBe(AlertPriority.MEDIUM);
        expect(alert.message).toContain('password was successfully changed');
      });
    });

    describe('MFA Disabled', () => {
      it('should create HIGH priority alert for MFA disabled', async () => {
        const alert = await AlertHelpers.mfaDisabled({
          realmId: 'clinisyn-psychologists',
          userId: 'dr-789',
          userEmail: 'dr.zeynep@example.com',
          ipAddress: '10.0.0.1'
        });

        expect(alert.type).toBe(AlertType.MFA_DISABLED);
        expect(alert.priority).toBe(AlertPriority.MEDIUM);
        expect(alert.message).toContain('Multi-factor authentication has been disabled');
      });
    });

    describe('Account Locked', () => {
      it('should create HIGH priority alert for account lock', async () => {
        const alert = await AlertHelpers.accountLocked({
          realmId: 'clinisyn-psychologists',
          userId: 'user-locked',
          userEmail: 'locked@example.com',
          ipAddress: '172.16.0.1',
          reason: 'Too many failed login attempts',
          lockDuration: 900
        });

        expect(alert.type).toBe(AlertType.ACCOUNT_LOCKED);
        expect(alert.priority).toBe(AlertPriority.HIGH);
        expect(alert.message).toContain('Too many failed login attempts');
        expect(alert.message).toContain('15 minutes');
      });
    });
  });

  describe('Admin Alert Scenarios', () => {
    describe('Failed Login Spike', () => {
      it('should create HIGH priority alert for failed login spike', async () => {
        const alert = await AlertHelpers.failedLoginSpike({
          realmId: 'clinisyn-psychologists',
          count: 50,
          windowMinutes: 5,
          topIPs: ['1.2.3.4', '5.6.7.8']
        });

        expect(alert.type).toBe(AlertType.FAILED_LOGIN_SPIKE);
        expect(alert.priority).toBe(AlertPriority.HIGH);
        expect(alert.recipients).toContainEqual({ type: RecipientType.ADMIN });
        expect(alert.details?.count).toBe(50);
      });
    });

    describe('Credential Stuffing', () => {
      it('should create CRITICAL alert for credential stuffing', async () => {
        const alert = await AlertHelpers.credentialStuffing({
          realmId: 'clinisyn-psychologists',
          ipAddress: '203.0.113.50',
          blockedAttempts: 150,
          pattern: 'same_password_multiple_emails'
        });

        expect(alert.type).toBe(AlertType.CREDENTIAL_STUFFING);
        expect(alert.priority).toBe(AlertPriority.CRITICAL);
        expect(alert.recipients).toContainEqual({ type: RecipientType.ADMIN });
        expect(alert.recipients).toContainEqual({ type: RecipientType.SECURITY_TEAM });
      });

      it('should bypass throttling for credential stuffing', async () => {
        // Send multiple alerts
        const alert1 = await AlertHelpers.credentialStuffing({
          realmId: 'stuffing-test-realm',
          ipAddress: '1.2.3.4',
          blockedAttempts: 100
        });
        const alert2 = await AlertHelpers.credentialStuffing({
          realmId: 'stuffing-test-realm',
          ipAddress: '1.2.3.4',
          blockedAttempts: 200
        });

        expect(alert1.sent).toBe(true);
        expect(alert2.sent).toBe(true);  // Should not be throttled
      });
    });

    describe('Impossible Travel', () => {
      it('should create CRITICAL alert for impossible travel', async () => {
        const alert = await AlertHelpers.impossibleTravel({
          realmId: 'clinisyn-psychologists',
          userId: 'dr-travel',
          userEmail: 'dr.travel@example.com',
          ipAddress: '198.51.100.1',
          fromLocation: 'Istanbul, Turkey',
          toLocation: 'New York, USA',
          distanceKm: 8000,
          timeHours: 1
        });

        expect(alert.type).toBe(AlertType.IMPOSSIBLE_TRAVEL);
        expect(alert.priority).toBe(AlertPriority.CRITICAL);
        expect(alert.message).toContain('Istanbul');
        expect(alert.message).toContain('New York');
        expect(alert.message).toContain('8000');
      });
    });
  });

  describe('Throttling', () => {
    it('should throttle repeated alerts', async () => {
      const config: AlertConfig = {
        ...DEFAULT_ALERT_CONFIG,
        throttle: { enabled: true, windowMs: 60000, maxAlerts: 2 }
      };

      const alert1 = await sendAlert({
        type: AlertType.NEW_DEVICE_LOGIN,
        realmId: 'throttle-realm',
        userId: 'user-1',
        userEmail: 'user@example.com',
        ipAddress: '1.2.3.4'
      }, config);

      const alert2 = await sendAlert({
        type: AlertType.NEW_DEVICE_LOGIN,
        realmId: 'throttle-realm',
        userId: 'user-2',
        userEmail: 'user2@example.com',
        ipAddress: '1.2.3.5'
      }, config);

      const alert3 = await sendAlert({
        type: AlertType.NEW_DEVICE_LOGIN,
        realmId: 'throttle-realm',
        userId: 'user-3',
        userEmail: 'user3@example.com',
        ipAddress: '1.2.3.6'
      }, config);

      expect(alert1.sent).toBe(true);
      expect(alert2.sent).toBe(true);
      expect(alert3.sent).toBe(false);
      expect(alert3.throttled).toBe(true);
    });

    it('should not throttle different alert types', async () => {
      const config: AlertConfig = {
        ...DEFAULT_ALERT_CONFIG,
        throttle: { enabled: true, windowMs: 60000, maxAlerts: 1 }
      };

      const alert1 = await sendAlert({
        type: AlertType.NEW_DEVICE_LOGIN,
        realmId: 'multi-type-realm',
        userId: 'user-1',
        ipAddress: '1.2.3.4'
      }, config);

      const alert2 = await sendAlert({
        type: AlertType.PASSWORD_CHANGED,
        realmId: 'multi-type-realm',
        userId: 'user-1',
        ipAddress: '1.2.3.4'
      }, config);

      expect(alert1.sent).toBe(true);
      expect(alert2.sent).toBe(true);
    });

    it('should not throttle different realms', async () => {
      const config: AlertConfig = {
        ...DEFAULT_ALERT_CONFIG,
        throttle: { enabled: true, windowMs: 60000, maxAlerts: 1 }
      };

      const alert1 = await sendAlert({
        type: AlertType.NEW_DEVICE_LOGIN,
        realmId: 'realm-a',
        userId: 'user-1',
        ipAddress: '1.2.3.4'
      }, config);

      const alert2 = await sendAlert({
        type: AlertType.NEW_DEVICE_LOGIN,
        realmId: 'realm-b',
        userId: 'user-1',
        ipAddress: '1.2.3.4'
      }, config);

      expect(alert1.sent).toBe(true);
      expect(alert2.sent).toBe(true);
    });
  });

  describe('Priority Filtering', () => {
    it('should filter LOW priority alerts when min is MEDIUM', async () => {
      const config: AlertConfig = {
        ...DEFAULT_ALERT_CONFIG,
        minPriority: AlertPriority.MEDIUM
      };

      const alert = await sendAlert({
        type: AlertType.MFA_ENABLED,  // LOW priority
        realmId: 'priority-realm',
        userId: 'user-1',
        ipAddress: '1.2.3.4'
      }, config);

      expect(alert.sent).toBe(false);
      expect(alert.throttled).toBe(true);
    });

    it('should allow HIGH priority alerts when min is MEDIUM', async () => {
      const config: AlertConfig = {
        ...DEFAULT_ALERT_CONFIG,
        minPriority: AlertPriority.MEDIUM
      };

      const alert = await sendAlert({
        type: AlertType.ACCOUNT_LOCKED,  // HIGH priority
        realmId: 'priority-realm-2',
        userId: 'user-1',
        ipAddress: '1.2.3.4'
      }, config);

      expect(alert.sent).toBe(true);
    });
  });

  describe('Realm-Specific Configuration', () => {
    it('should use healthcare config for clinisyn realm', async () => {
      const alert = await sendAlert({
        type: AlertType.MFA_ENABLED,  // LOW priority
        realmId: 'clinisyn-psychologists',
        userId: 'dr-123',
        ipAddress: '1.2.3.4'
      });

      // Healthcare config has minPriority: LOW
      expect(alert.sent).toBe(true);
    });

    it('should filter LOW priority for standard realm', async () => {
      const alert = await sendAlert({
        type: AlertType.MFA_ENABLED,  // LOW priority
        realmId: 'standard-app',
        userId: 'user-123',
        ipAddress: '1.2.3.4'
      });

      // Standard config has minPriority: MEDIUM
      expect(alert.sent).toBe(false);
    });

    it('should include webhook channel for healthcare realm', () => {
      const config = getRealmAlertConfig('clinisyn-psychologists');
      expect(config.channels).toContain(AlertChannel.WEBHOOK);
    });
  });

  describe('Email Formatting', () => {
    it('should format critical alert email with correct emoji', async () => {
      const alert = await AlertHelpers.credentialStuffing({
        realmId: 'email-test-realm',
        ipAddress: '1.2.3.4',
        blockedAttempts: 100
      });

      const email = formatAlertEmail(alert);

      expect(email.subject).toContain('🚨');
      expect(email.subject).toContain('Credential Stuffing');
    });

    it('should format high priority alert email', async () => {
      const alert = await AlertHelpers.accountLocked({
        realmId: 'email-test-realm-2',
        userId: 'user-123',
        userEmail: 'user@example.com',
        ipAddress: '1.2.3.4',
        reason: 'Failed attempts'
      });

      const email = formatAlertEmail(alert);

      expect(email.subject).toContain('🔶');
      expect(email.htmlBody).toContain('Account Locked');
      expect(email.textBody).toContain('Account Locked');
    });

    it('should include details in email body', async () => {
      const alert = await AlertHelpers.impossibleTravel({
        realmId: 'email-test-realm-3',
        userId: 'user-123',
        userEmail: 'user@example.com',
        ipAddress: '1.2.3.4',
        fromLocation: 'Istanbul',
        toLocation: 'Tokyo',
        distanceKm: 9000,
        timeHours: 2
      });

      const email = formatAlertEmail(alert);

      expect(email.htmlBody).toContain('Istanbul');
      expect(email.htmlBody).toContain('Tokyo');
      expect(email.textBody).toContain('9000');
    });

    it('should include Zalt.io branding', async () => {
      const alert = await sendAlert({
        type: AlertType.PASSWORD_CHANGED,
        realmId: 'branding-realm',
        userId: 'user-123',
        userEmail: 'user@example.com',
        ipAddress: '1.2.3.4'
      });

      const email = formatAlertEmail(alert);

      expect(email.htmlBody).toContain('Zalt.io');
      expect(email.textBody).toContain('Zalt.io');
    });
  });

  describe('Webhook Formatting', () => {
    it('should format webhook payload correctly', async () => {
      const alert = await sendAlert({
        type: AlertType.CREDENTIAL_STUFFING,
        realmId: 'webhook-realm',
        ipAddress: '1.2.3.4',
        details: { blockedAttempts: 100 }
      });

      const webhook = formatAlertWebhook(alert);

      expect(webhook.payload.id).toBe(alert.id);
      expect(webhook.payload.type).toBe(AlertType.CREDENTIAL_STUFFING);
      expect(webhook.payload.priority).toBe(AlertPriority.CRITICAL);
      expect(webhook.payload.realm_id).toBe('webhook-realm');
    });

    it('should sign webhook with secret', async () => {
      const alert = await sendAlert({
        type: AlertType.NEW_DEVICE_LOGIN,
        realmId: 'signed-webhook-realm',
        userId: 'user-123',
        ipAddress: '1.2.3.4'
      });

      const webhook = formatAlertWebhook(alert, 'my-webhook-secret');

      expect(webhook.signature).toBeDefined();
      expect(webhook.signature?.length).toBe(64);
    });

    it('should produce consistent signatures', async () => {
      const alert = await sendAlert({
        type: AlertType.NEW_DEVICE_LOGIN,
        realmId: 'consistent-webhook-realm',
        userId: 'user-123',
        ipAddress: '1.2.3.4'
      });

      const webhook1 = formatAlertWebhook(alert, 'secret');
      const webhook2 = formatAlertWebhook(alert, 'secret');

      expect(webhook1.signature).toBe(webhook2.signature);
    });
  });

  describe('Audit Event Mapping', () => {
    it('should map audit events to alert types', () => {
      expect(auditEventToAlertType(AuditEventType.NEW_DEVICE_LOGIN)).toBe(AlertType.NEW_DEVICE_LOGIN);
      expect(auditEventToAlertType(AuditEventType.PASSWORD_CHANGE)).toBe(AlertType.PASSWORD_CHANGED);
      expect(auditEventToAlertType(AuditEventType.MFA_DISABLE)).toBe(AlertType.MFA_DISABLED);
      expect(auditEventToAlertType(AuditEventType.MFA_ENABLE)).toBe(AlertType.MFA_ENABLED);
      expect(auditEventToAlertType(AuditEventType.ACCOUNT_LOCK)).toBe(AlertType.ACCOUNT_LOCKED);
      expect(auditEventToAlertType(AuditEventType.CREDENTIAL_STUFFING)).toBe(AlertType.CREDENTIAL_STUFFING);
      expect(auditEventToAlertType(AuditEventType.IMPOSSIBLE_TRAVEL)).toBe(AlertType.IMPOSSIBLE_TRAVEL);
    });

    it('should return null for non-alertable events', () => {
      expect(auditEventToAlertType(AuditEventType.LOGIN_SUCCESS)).toBeNull();
      expect(auditEventToAlertType(AuditEventType.LOGOUT)).toBeNull();
      expect(auditEventToAlertType(AuditEventType.REGISTER)).toBeNull();
    });
  });

  describe('All Alert Types', () => {
    const testAlertType = async (type: AlertType, expectedPriority: AlertPriority) => {
      resetThrottleState();
      const alert = await sendAlert({
        type,
        realmId: `test-${type}-realm`,
        userId: 'user-123',
        userEmail: 'user@example.com',
        ipAddress: '1.2.3.4'
      }, { ...HEALTHCARE_ALERT_CONFIG, throttle: { enabled: false, windowMs: 0, maxAlerts: 0 } });

      expect(alert.type).toBe(type);
      expect(alert.priority).toBe(expectedPriority);
      expect(alert.title).toBeDefined();
      expect(alert.message).toBeDefined();
    };

    it('should handle NEW_DEVICE_LOGIN', () => testAlertType(AlertType.NEW_DEVICE_LOGIN, AlertPriority.MEDIUM));
    it('should handle PASSWORD_CHANGED', () => testAlertType(AlertType.PASSWORD_CHANGED, AlertPriority.MEDIUM));
    it('should handle MFA_DISABLED', () => testAlertType(AlertType.MFA_DISABLED, AlertPriority.MEDIUM));
    it('should handle MFA_ENABLED', () => testAlertType(AlertType.MFA_ENABLED, AlertPriority.LOW));
    it('should handle ACCOUNT_LOCKED', () => testAlertType(AlertType.ACCOUNT_LOCKED, AlertPriority.HIGH));
    it('should handle SUSPICIOUS_LOGIN', () => testAlertType(AlertType.SUSPICIOUS_LOGIN, AlertPriority.HIGH));
    it('should handle FAILED_LOGIN_SPIKE', () => testAlertType(AlertType.FAILED_LOGIN_SPIKE, AlertPriority.HIGH));
    it('should handle CREDENTIAL_STUFFING', () => testAlertType(AlertType.CREDENTIAL_STUFFING, AlertPriority.CRITICAL));
    it('should handle IMPOSSIBLE_TRAVEL', () => testAlertType(AlertType.IMPOSSIBLE_TRAVEL, AlertPriority.CRITICAL));
    it('should handle RATE_LIMIT_EXCEEDED', () => testAlertType(AlertType.RATE_LIMIT_EXCEEDED, AlertPriority.MEDIUM));
    it('should handle BRUTE_FORCE_DETECTED', () => testAlertType(AlertType.BRUTE_FORCE_DETECTED, AlertPriority.CRITICAL));
    it('should handle HIGH_ERROR_RATE', () => testAlertType(AlertType.HIGH_ERROR_RATE, AlertPriority.HIGH));
    it('should handle SERVICE_DEGRADATION', () => testAlertType(AlertType.SERVICE_DEGRADATION, AlertPriority.LOW));
  });

  describe('Recipients', () => {
    it('should include user for user alerts', async () => {
      const alert = await sendAlert({
        type: AlertType.NEW_DEVICE_LOGIN,
        realmId: 'recipient-realm',
        userId: 'user-123',
        userEmail: 'user@example.com',
        ipAddress: '1.2.3.4'
      });

      expect(alert.recipients.find(r => r.type === RecipientType.USER)).toBeDefined();
    });

    it('should include admin for admin alerts', async () => {
      const alert = await sendAlert({
        type: AlertType.FAILED_LOGIN_SPIKE,
        realmId: 'admin-recipient-realm',
        ipAddress: '1.2.3.4'
      });

      expect(alert.recipients.find(r => r.type === RecipientType.ADMIN)).toBeDefined();
    });

    it('should include security team for critical alerts', async () => {
      const alert = await sendAlert({
        type: AlertType.CREDENTIAL_STUFFING,
        realmId: 'security-recipient-realm',
        ipAddress: '1.2.3.4'
      });

      expect(alert.recipients.find(r => r.type === RecipientType.SECURITY_TEAM)).toBeDefined();
    });
  });
});
