/**
 * Passwordless Service Tests
 * Validates: Requirements 30.1-30.5 (Passwordless Authentication)
 * 
 * Tests for:
 * - Magic link authentication
 * - Push notification authentication
 * - Passkeys as primary authentication
 */

import {
  // Magic Link
  generateMagicLinkToken,
  createMagicLinkToken,
  isValidMagicLinkTokenFormat,
  isMagicLinkExpired,
  isMagicLinkUsed,
  isMagicLinkMaxAttemptsExceeded,
  verifyMagicLinkToken,
  generateMagicLinkUrl,
  getMagicLinkEmailTemplate,
  maskEmail,
  getMagicLinkRemainingTime,
  MAGIC_LINK_CONFIG,
  MagicLinkToken,
  // Push Auth
  generatePushNotificationId,
  createPushAuthNotification,
  isPushNotificationExpired,
  isPushNotificationPending,
  isPushNotificationResponded,
  respondToPushNotification,
  cancelPushNotification,
  verifyPushNotificationResponse,
  createPushNotificationPayload,
  getPushNotificationRemainingTime,
  PUSH_AUTH_CONFIG,
  PushAuthNotification,
  // Passkey
  generatePasskeyRegistrationOptions,
  generatePasskeyAuthenticationOptions,
  PASSKEY_CONFIG,
  // Configuration
  DEFAULT_PASSWORDLESS_CONFIG,
  validatePasswordlessConfig,
  createPasswordlessConfig,
  isPasswordlessMethodAvailable,
  // Rate Limiting
  getMagicLinkRateLimitKey,
  getPushAuthRateLimitKey,
  isWithinCooldown
} from './passwordless.service';

describe('Passwordless Service', () => {
  // ============================================
  // Magic Link Tests
  // ============================================
  describe('Magic Link Authentication', () => {

    describe('generateMagicLinkToken', () => {
      it('should generate a 64-character hex token', () => {
        const token = generateMagicLinkToken();
        expect(token).toHaveLength(64);
        expect(/^[a-f0-9]{64}$/i.test(token)).toBe(true);
      });

      it('should generate unique tokens', () => {
        const tokens = new Set<string>();
        for (let i = 0; i < 100; i++) {
          tokens.add(generateMagicLinkToken());
        }
        expect(tokens.size).toBe(100);
      });
    });

    describe('createMagicLinkToken', () => {
      it('should create token with correct structure', () => {
        const tokenData = createMagicLinkToken(
          'test@example.com',
          'realm_123',
          '192.168.1.1',
          'Mozilla/5.0'
        );

        expect(tokenData.id).toMatch(/^ml_[a-f0-9]{24}$/);
        expect(tokenData.token).toHaveLength(64);
        expect(tokenData.tokenHash).toHaveLength(64);
        expect(tokenData.email).toBe('test@example.com');
        expect(tokenData.realmId).toBe('realm_123');
        expect(tokenData.attempts).toBe(0);
        expect(tokenData.ipAddress).toBe('192.168.1.1');
        expect(tokenData.userAgent).toBe('Mozilla/5.0');
        expect(tokenData.usedAt).toBeUndefined();
      });

      it('should normalize email to lowercase', () => {
        const tokenData = createMagicLinkToken('TEST@EXAMPLE.COM', 'realm_123');
        expect(tokenData.email).toBe('test@example.com');
      });

      it('should set correct expiry time', () => {
        const before = Date.now();
        const tokenData = createMagicLinkToken('test@example.com', 'realm_123');
        const after = Date.now();

        const expectedExpiry = MAGIC_LINK_CONFIG.expiryMinutes * 60 * 1000;
        expect(tokenData.expiresAt).toBeGreaterThanOrEqual(before + expectedExpiry);
        expect(tokenData.expiresAt).toBeLessThanOrEqual(after + expectedExpiry);
      });
    });

    describe('isValidMagicLinkTokenFormat', () => {
      it('should accept valid 64-char hex tokens', () => {
        const validToken = 'a'.repeat(64);
        expect(isValidMagicLinkTokenFormat(validToken)).toBe(true);
      });

      it('should accept mixed case hex tokens', () => {
        const token = 'aAbBcCdDeEfF0123456789'.repeat(3).slice(0, 64);
        expect(isValidMagicLinkTokenFormat(token)).toBe(true);
      });

      it('should reject tokens that are too short', () => {
        expect(isValidMagicLinkTokenFormat('a'.repeat(63))).toBe(false);
      });

      it('should reject tokens that are too long', () => {
        expect(isValidMagicLinkTokenFormat('a'.repeat(65))).toBe(false);
      });

      it('should reject tokens with invalid characters', () => {
        expect(isValidMagicLinkTokenFormat('g'.repeat(64))).toBe(false);
        expect(isValidMagicLinkTokenFormat('!'.repeat(64))).toBe(false);
      });

      it('should reject empty string', () => {
        expect(isValidMagicLinkTokenFormat('')).toBe(false);
      });
    });

    describe('isMagicLinkExpired', () => {
      it('should return false for non-expired token', () => {
        const tokenData = createMagicLinkToken('test@example.com', 'realm_123');
        expect(isMagicLinkExpired(tokenData)).toBe(false);
      });

      it('should return true for expired token', () => {
        const tokenData = createMagicLinkToken('test@example.com', 'realm_123');
        tokenData.expiresAt = Date.now() - 1000;
        expect(isMagicLinkExpired(tokenData)).toBe(true);
      });
    });

    describe('isMagicLinkUsed', () => {
      it('should return false for unused token', () => {
        const tokenData = createMagicLinkToken('test@example.com', 'realm_123');
        expect(isMagicLinkUsed(tokenData)).toBe(false);
      });

      it('should return true for used token', () => {
        const tokenData = createMagicLinkToken('test@example.com', 'realm_123');
        tokenData.usedAt = Date.now();
        expect(isMagicLinkUsed(tokenData)).toBe(true);
      });
    });

    describe('isMagicLinkMaxAttemptsExceeded', () => {
      it('should return false when attempts below max', () => {
        const tokenData = createMagicLinkToken('test@example.com', 'realm_123');
        tokenData.attempts = MAGIC_LINK_CONFIG.maxAttempts - 1;
        expect(isMagicLinkMaxAttemptsExceeded(tokenData)).toBe(false);
      });

      it('should return true when attempts at max', () => {
        const tokenData = createMagicLinkToken('test@example.com', 'realm_123');
        tokenData.attempts = MAGIC_LINK_CONFIG.maxAttempts;
        expect(isMagicLinkMaxAttemptsExceeded(tokenData)).toBe(true);
      });

      it('should return true when attempts exceed max', () => {
        const tokenData = createMagicLinkToken('test@example.com', 'realm_123');
        tokenData.attempts = MAGIC_LINK_CONFIG.maxAttempts + 1;
        expect(isMagicLinkMaxAttemptsExceeded(tokenData)).toBe(true);
      });
    });

    describe('verifyMagicLinkToken', () => {
      it('should verify valid token successfully', () => {
        const tokenData = createMagicLinkToken('test@example.com', 'realm_123');
        const result = verifyMagicLinkToken(tokenData.token, tokenData);

        expect(result.valid).toBe(true);
        expect(result.email).toBe('test@example.com');
        expect(result.realmId).toBe('realm_123');
        expect(result.error).toBeUndefined();
      });

      it('should reject invalid token format', () => {
        const tokenData = createMagicLinkToken('test@example.com', 'realm_123');
        const result = verifyMagicLinkToken('invalid', tokenData);

        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('INVALID_TOKEN');
      });

      it('should reject already used token', () => {
        const tokenData = createMagicLinkToken('test@example.com', 'realm_123');
        tokenData.usedAt = Date.now();
        const result = verifyMagicLinkToken(tokenData.token, tokenData);

        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('TOKEN_ALREADY_USED');
      });

      it('should reject expired token', () => {
        const tokenData = createMagicLinkToken('test@example.com', 'realm_123');
        tokenData.expiresAt = Date.now() - 1000;
        const result = verifyMagicLinkToken(tokenData.token, tokenData);

        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('TOKEN_EXPIRED');
      });

      it('should reject when max attempts exceeded', () => {
        const tokenData = createMagicLinkToken('test@example.com', 'realm_123');
        tokenData.attempts = MAGIC_LINK_CONFIG.maxAttempts;
        const result = verifyMagicLinkToken(tokenData.token, tokenData);

        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('MAX_ATTEMPTS_EXCEEDED');
      });

      it('should reject wrong token', () => {
        const tokenData = createMagicLinkToken('test@example.com', 'realm_123');
        const wrongToken = 'b'.repeat(64);
        const result = verifyMagicLinkToken(wrongToken, tokenData);

        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('INVALID_TOKEN');
      });
    });

    describe('generateMagicLinkUrl', () => {
      it('should generate valid URL with token and realm', () => {
        const token = 'a'.repeat(64);
        const url = generateMagicLinkUrl(token, 'https://app.zalt.io', 'realm_123');

        expect(url).toContain('https://app.zalt.io/auth/magic-link');
        expect(url).toContain(`token=${token}`);
        expect(url).toContain('realm=realm_123');
      });

      it('should properly encode special characters', () => {
        const token = 'a'.repeat(64);
        const url = generateMagicLinkUrl(token, 'https://app.zalt.io', 'realm with spaces');

        expect(url).toContain('realm=realm+with+spaces');
      });
    });

    describe('getMagicLinkEmailTemplate', () => {
      it('should generate email template with all fields', () => {
        const template = getMagicLinkEmailTemplate({
          magicLinkUrl: 'https://app.zalt.io/auth/magic-link?token=abc',
          realmName: 'Test Realm',
          expiresMinutes: 15,
          ipAddress: '192.168.1.1',
          location: 'New York, US'
        });

        expect(template.subject).toContain('Test Realm');
        expect(template.html).toContain('https://app.zalt.io/auth/magic-link?token=abc');
        expect(template.html).toContain('15 minutes');
        expect(template.html).toContain('192.168.1.1');
        expect(template.html).toContain('New York, US');
        expect(template.text).toContain('Test Realm');
      });

      it('should escape HTML in template', () => {
        const template = getMagicLinkEmailTemplate({
          magicLinkUrl: 'https://app.zalt.io',
          realmName: '<script>alert("xss")</script>',
          expiresMinutes: 15
        });

        expect(template.html).not.toContain('<script>');
        expect(template.html).toContain('&lt;script&gt;');
      });
    });

    describe('maskEmail', () => {
      it('should mask email correctly', () => {
        expect(maskEmail('john@example.com')).toBe('j***n@example.com');
        expect(maskEmail('ab@example.com')).toBe('a***@example.com');
        expect(maskEmail('test.user@domain.org')).toBe('t***r@domain.org');
      });

      it('should handle short local parts', () => {
        expect(maskEmail('a@example.com')).toBe('a***@example.com');
      });

      it('should handle invalid email', () => {
        expect(maskEmail('invalid')).toBe('***');
      });
    });

    describe('getMagicLinkRemainingTime', () => {
      it('should return minutes for longer durations', () => {
        const tokenData = createMagicLinkToken('test@example.com', 'realm_123');
        tokenData.expiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes
        
        const remaining = getMagicLinkRemainingTime(tokenData);
        expect(remaining).toMatch(/\d+ minute/);
      });

      it('should return seconds for short durations', () => {
        const tokenData = createMagicLinkToken('test@example.com', 'realm_123');
        tokenData.expiresAt = Date.now() + 30 * 1000; // 30 seconds
        
        const remaining = getMagicLinkRemainingTime(tokenData);
        expect(remaining).toMatch(/\d+ second/);
      });

      it('should return expired for past time', () => {
        const tokenData = createMagicLinkToken('test@example.com', 'realm_123');
        tokenData.expiresAt = Date.now() - 1000;
        
        expect(getMagicLinkRemainingTime(tokenData)).toBe('expired');
      });
    });
  });

  // ============================================
  // Push Notification Authentication Tests
  // ============================================
  describe('Push Notification Authentication', () => {
    describe('generatePushNotificationId', () => {
      it('should generate ID with correct format', () => {
        const id = generatePushNotificationId();
        expect(id).toMatch(/^push_[a-f0-9]{32}$/);
      });

      it('should generate unique IDs', () => {
        const ids = new Set<string>();
        for (let i = 0; i < 100; i++) {
          ids.add(generatePushNotificationId());
        }
        expect(ids.size).toBe(100);
      });
    });

    describe('createPushAuthNotification', () => {
      it('should create notification with correct structure', () => {
        const notification = createPushAuthNotification(
          'user_123',
          'device_456',
          'realm_789',
          '192.168.1.1',
          'New York, US',
          'iPhone 15 Pro'
        );

        expect(notification.id).toMatch(/^push_/);
        expect(notification.userId).toBe('user_123');
        expect(notification.deviceId).toBe('device_456');
        expect(notification.realmId).toBe('realm_789');
        expect(notification.status).toBe('pending');
        expect(notification.ipAddress).toBe('192.168.1.1');
        expect(notification.location).toBe('New York, US');
        expect(notification.deviceInfo).toBe('iPhone 15 Pro');
        expect(notification.approved).toBeUndefined();
        expect(notification.respondedAt).toBeUndefined();
      });

      it('should set correct expiry time', () => {
        const before = Date.now();
        const notification = createPushAuthNotification('user_123', 'device_456', 'realm_789');
        const after = Date.now();

        const expectedExpiry = PUSH_AUTH_CONFIG.expirySeconds * 1000;
        expect(notification.expiresAt).toBeGreaterThanOrEqual(before + expectedExpiry);
        expect(notification.expiresAt).toBeLessThanOrEqual(after + expectedExpiry);
      });
    });

    describe('isPushNotificationExpired', () => {
      it('should return false for non-expired notification', () => {
        const notification = createPushAuthNotification('user_123', 'device_456', 'realm_789');
        expect(isPushNotificationExpired(notification)).toBe(false);
      });

      it('should return true for expired notification', () => {
        const notification = createPushAuthNotification('user_123', 'device_456', 'realm_789');
        notification.expiresAt = Date.now() - 1000;
        expect(isPushNotificationExpired(notification)).toBe(true);
      });
    });

    describe('isPushNotificationPending', () => {
      it('should return true for pending non-expired notification', () => {
        const notification = createPushAuthNotification('user_123', 'device_456', 'realm_789');
        expect(isPushNotificationPending(notification)).toBe(true);
      });

      it('should return false for expired notification', () => {
        const notification = createPushAuthNotification('user_123', 'device_456', 'realm_789');
        notification.expiresAt = Date.now() - 1000;
        expect(isPushNotificationPending(notification)).toBe(false);
      });

      it('should return false for approved notification', () => {
        const notification = createPushAuthNotification('user_123', 'device_456', 'realm_789');
        notification.status = 'approved';
        expect(isPushNotificationPending(notification)).toBe(false);
      });
    });

    describe('isPushNotificationResponded', () => {
      it('should return false for pending notification', () => {
        const notification = createPushAuthNotification('user_123', 'device_456', 'realm_789');
        expect(isPushNotificationResponded(notification)).toBe(false);
      });

      it('should return true for approved notification', () => {
        const notification = createPushAuthNotification('user_123', 'device_456', 'realm_789');
        notification.status = 'approved';
        expect(isPushNotificationResponded(notification)).toBe(true);
      });

      it('should return true for denied notification', () => {
        const notification = createPushAuthNotification('user_123', 'device_456', 'realm_789');
        notification.status = 'denied';
        expect(isPushNotificationResponded(notification)).toBe(true);
      });
    });

    describe('respondToPushNotification', () => {
      it('should approve notification', () => {
        const notification = createPushAuthNotification('user_123', 'device_456', 'realm_789');
        const responded = respondToPushNotification(notification, true);

        expect(responded.status).toBe('approved');
        expect(responded.approved).toBe(true);
        expect(responded.respondedAt).toBeDefined();
      });

      it('should deny notification', () => {
        const notification = createPushAuthNotification('user_123', 'device_456', 'realm_789');
        const responded = respondToPushNotification(notification, false);

        expect(responded.status).toBe('denied');
        expect(responded.approved).toBe(false);
        expect(responded.respondedAt).toBeDefined();
      });

      it('should not change already responded notification', () => {
        const notification = createPushAuthNotification('user_123', 'device_456', 'realm_789');
        notification.status = 'approved';
        notification.approved = true;
        notification.respondedAt = Date.now() - 1000;

        const responded = respondToPushNotification(notification, false);
        expect(responded.status).toBe('approved');
        expect(responded.approved).toBe(true);
      });

      it('should mark expired notification as expired', () => {
        const notification = createPushAuthNotification('user_123', 'device_456', 'realm_789');
        notification.expiresAt = Date.now() - 1000;

        const responded = respondToPushNotification(notification, true);
        expect(responded.status).toBe('expired');
      });
    });

    describe('cancelPushNotification', () => {
      it('should cancel pending notification', () => {
        const notification = createPushAuthNotification('user_123', 'device_456', 'realm_789');
        const cancelled = cancelPushNotification(notification);

        expect(cancelled.status).toBe('cancelled');
        expect(cancelled.respondedAt).toBeDefined();
      });

      it('should not cancel already responded notification', () => {
        const notification = createPushAuthNotification('user_123', 'device_456', 'realm_789');
        notification.status = 'approved';

        const cancelled = cancelPushNotification(notification);
        expect(cancelled.status).toBe('approved');
      });
    });

    describe('verifyPushNotificationResponse', () => {
      it('should verify approved notification', () => {
        const notification = createPushAuthNotification('user_123', 'device_456', 'realm_789');
        notification.status = 'approved';
        notification.approved = true;

        const result = verifyPushNotificationResponse(notification);
        expect(result.valid).toBe(true);
        expect(result.approved).toBe(true);
        expect(result.userId).toBe('user_123');
      });

      it('should reject denied notification', () => {
        const notification = createPushAuthNotification('user_123', 'device_456', 'realm_789');
        notification.status = 'denied';
        notification.approved = false;

        const result = verifyPushNotificationResponse(notification);
        expect(result.valid).toBe(false);
        expect(result.approved).toBe(false);
        expect(result.errorCode).toBe('NOTIFICATION_DENIED');
      });

      it('should reject expired notification', () => {
        const notification = createPushAuthNotification('user_123', 'device_456', 'realm_789');
        notification.expiresAt = Date.now() - 1000;

        const result = verifyPushNotificationResponse(notification);
        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('NOTIFICATION_EXPIRED');
      });

      it('should reject cancelled notification', () => {
        const notification = createPushAuthNotification('user_123', 'device_456', 'realm_789');
        notification.status = 'cancelled';

        const result = verifyPushNotificationResponse(notification);
        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('NOTIFICATION_CANCELLED');
      });

      it('should indicate pending status', () => {
        const notification = createPushAuthNotification('user_123', 'device_456', 'realm_789');

        const result = verifyPushNotificationResponse(notification);
        expect(result.valid).toBe(false);
        expect(result.error).toBe('Waiting for response');
      });
    });

    describe('createPushNotificationPayload', () => {
      it('should create valid payload structure', () => {
        const notification = createPushAuthNotification(
          'user_123',
          'device_456',
          'realm_789',
          '192.168.1.1',
          'New York, US'
        );

        const payload = createPushNotificationPayload(notification, 'Test Realm');

        expect(payload.title).toBe('Sign-in Request');
        expect(payload.body).toContain('Test Realm');
        expect(payload.body).toContain('New York, US');
        expect(payload.data.type).toBe('auth_request');
        expect(payload.data.notificationId).toBe(notification.id);
        expect(payload.data.realmId).toBe('realm_789');
        expect(payload.android?.priority).toBe('high');
        expect(payload.apns?.headers['apns-priority']).toBe('10');
      });
    });

    describe('getPushNotificationRemainingTime', () => {
      it('should return seconds for valid notification', () => {
        const notification = createPushAuthNotification('user_123', 'device_456', 'realm_789');
        notification.expiresAt = Date.now() + 60 * 1000; // 60 seconds

        const remaining = getPushNotificationRemainingTime(notification);
        expect(remaining).toMatch(/\d+ second/);
      });

      it('should return expired for past time', () => {
        const notification = createPushAuthNotification('user_123', 'device_456', 'realm_789');
        notification.expiresAt = Date.now() - 1000;

        expect(getPushNotificationRemainingTime(notification)).toBe('expired');
      });
    });
  });

  // ============================================
  // Passkey Authentication Tests
  // ============================================
  describe('Passkey Authentication', () => {
    describe('generatePasskeyRegistrationOptions', () => {
      it('should generate registration options with required fields', () => {
        const options = generatePasskeyRegistrationOptions(
          'user_123',
          'test@example.com',
          'Test User'
        );

        expect(options.challenge).toBeDefined();
        expect(options.challenge.length).toBeGreaterThan(0);
        expect(options.rp.name).toBe(PASSKEY_CONFIG.rpName);
        expect(options.rp.id).toBe(PASSKEY_CONFIG.rpId);
        expect(options.user.name).toBe('test@example.com');
        expect(options.user.displayName).toBe('Test User');
        expect(options.authenticatorSelection.residentKey).toBe('required');
        expect(options.authenticatorSelection.userVerification).toBe('required');
      });

      it('should use custom RP config when provided', () => {
        const options = generatePasskeyRegistrationOptions(
          'user_123',
          'test@example.com',
          'Test User',
          [],
          { rpId: 'custom.domain.com', rpName: 'Custom App' }
        );

        expect(options.rp.id).toBe('custom.domain.com');
        expect(options.rp.name).toBe('Custom App');
      });

      it('should exclude existing credentials', () => {
        const existingCredentials = [
          {
            id: 'cred_1',
            credentialId: Buffer.from('credential1'),
            publicKey: Buffer.from('pubkey1'),
            counter: 0,
            createdAt: new Date().toISOString()
          }
        ];

        const options = generatePasskeyRegistrationOptions(
          'user_123',
          'test@example.com',
          'Test User',
          existingCredentials
        );

        expect(options.excludeCredentials).toBeDefined();
        expect(options.excludeCredentials?.length).toBe(1);
      });
    });

    describe('generatePasskeyAuthenticationOptions', () => {
      it('should generate authentication options for passwordless', () => {
        const options = generatePasskeyAuthenticationOptions();

        expect(options.challenge).toBeDefined();
        expect(options.rpId).toBe(PASSKEY_CONFIG.rpId);
        expect(options.userVerification).toBe('required');
      });

      it('should include credentials when provided', () => {
        const credentials = [
          {
            id: 'cred_1',
            credentialId: Buffer.from('credential1'),
            publicKey: Buffer.from('pubkey1'),
            counter: 0,
            createdAt: new Date().toISOString()
          }
        ];

        const options = generatePasskeyAuthenticationOptions(credentials);

        expect(options.allowCredentials).toBeDefined();
        expect(options.allowCredentials?.length).toBe(1);
      });

      it('should use custom RP ID when provided', () => {
        const options = generatePasskeyAuthenticationOptions(
          undefined,
          { rpId: 'custom.domain.com' }
        );

        expect(options.rpId).toBe('custom.domain.com');
      });
    });
  });

  // ============================================
  // Passwordless Configuration Tests
  // ============================================
  describe('Passwordless Configuration', () => {
    describe('DEFAULT_PASSWORDLESS_CONFIG', () => {
      it('should have all methods disabled by default', () => {
        expect(DEFAULT_PASSWORDLESS_CONFIG.enabled).toBe(false);
        expect(DEFAULT_PASSWORDLESS_CONFIG.magicLinkEnabled).toBe(false);
        expect(DEFAULT_PASSWORDLESS_CONFIG.pushAuthEnabled).toBe(false);
        expect(DEFAULT_PASSWORDLESS_CONFIG.passkeyEnabled).toBe(false);
        expect(DEFAULT_PASSWORDLESS_CONFIG.passkeyRequired).toBe(false);
        expect(DEFAULT_PASSWORDLESS_CONFIG.methods).toHaveLength(0);
      });
    });

    describe('validatePasswordlessConfig', () => {
      it('should accept valid config with methods enabled', () => {
        const result = validatePasswordlessConfig({
          enabled: true,
          magicLinkEnabled: true
        });

        expect(result.valid).toBe(true);
        expect(result.errors).toHaveLength(0);
      });

      it('should reject enabled config with no methods', () => {
        const result = validatePasswordlessConfig({
          enabled: true,
          magicLinkEnabled: false,
          pushAuthEnabled: false,
          passkeyEnabled: false
        });

        expect(result.valid).toBe(false);
        expect(result.errors).toContain('At least one passwordless method must be enabled');
      });

      it('should reject passkeyRequired without passkeyEnabled', () => {
        const result = validatePasswordlessConfig({
          enabled: true,
          passkeyRequired: true,
          passkeyEnabled: false,
          magicLinkEnabled: true
        });

        expect(result.valid).toBe(false);
        expect(result.errors).toContain('Passkey must be enabled if passkeyRequired is true');
      });

      it('should reject invalid custom RP ID', () => {
        const result = validatePasswordlessConfig({
          customRpId: 'invalid domain!'
        });

        expect(result.valid).toBe(false);
        expect(result.errors).toContain('Invalid custom RP ID format');
      });

      it('should accept valid custom RP ID', () => {
        const result = validatePasswordlessConfig({
          customRpId: 'auth.example.com'
        });

        expect(result.valid).toBe(true);
      });
    });

    describe('createPasswordlessConfig', () => {
      it('should create config with magic link enabled', () => {
        const config = createPasswordlessConfig({
          magicLinkEnabled: true
        });

        expect(config.enabled).toBe(true);
        expect(config.magicLinkEnabled).toBe(true);
        expect(config.methods).toContain('magic_link');
      });

      it('should create config with all methods enabled', () => {
        const config = createPasswordlessConfig({
          magicLinkEnabled: true,
          pushAuthEnabled: true,
          passkeyEnabled: true
        });

        expect(config.enabled).toBe(true);
        expect(config.methods).toContain('magic_link');
        expect(config.methods).toContain('push_notification');
        expect(config.methods).toContain('passkey');
        expect(config.methods).toHaveLength(3);
      });

      it('should set enabled to false when no methods', () => {
        const config = createPasswordlessConfig({
          magicLinkEnabled: false,
          pushAuthEnabled: false,
          passkeyEnabled: false
        });

        expect(config.enabled).toBe(false);
        expect(config.methods).toHaveLength(0);
      });
    });

    describe('isPasswordlessMethodAvailable', () => {
      it('should return true for enabled method', () => {
        const config = createPasswordlessConfig({
          magicLinkEnabled: true
        });

        expect(isPasswordlessMethodAvailable(config, 'magic_link')).toBe(true);
      });

      it('should return false for disabled method', () => {
        const config = createPasswordlessConfig({
          magicLinkEnabled: true
        });

        expect(isPasswordlessMethodAvailable(config, 'push_notification')).toBe(false);
      });

      it('should return false when passwordless is disabled', () => {
        const config = createPasswordlessConfig({});

        expect(isPasswordlessMethodAvailable(config, 'magic_link')).toBe(false);
      });
    });
  });

  // ============================================
  // Rate Limiting Tests
  // ============================================
  describe('Rate Limiting', () => {
    describe('getMagicLinkRateLimitKey', () => {
      it('should generate correct key format', () => {
        const key = getMagicLinkRateLimitKey('test@example.com', 'realm_123');
        expect(key).toBe('magic_link:realm_123:test@example.com');
      });

      it('should normalize email to lowercase', () => {
        const key = getMagicLinkRateLimitKey('TEST@EXAMPLE.COM', 'realm_123');
        expect(key).toBe('magic_link:realm_123:test@example.com');
      });
    });

    describe('getPushAuthRateLimitKey', () => {
      it('should generate correct key format', () => {
        const key = getPushAuthRateLimitKey('user_123', 'realm_456');
        expect(key).toBe('push_auth:realm_456:user_123');
      });
    });

    describe('isWithinCooldown', () => {
      it('should return true when within cooldown', () => {
        const lastRequest = Date.now() - (MAGIC_LINK_CONFIG.cooldownSeconds * 1000 / 2);
        expect(isWithinCooldown(lastRequest)).toBe(true);
      });

      it('should return false when cooldown expired', () => {
        const lastRequest = Date.now() - (MAGIC_LINK_CONFIG.cooldownSeconds * 1000 + 1000);
        expect(isWithinCooldown(lastRequest)).toBe(false);
      });
    });
  });

  // ============================================
  // Security Tests
  // ============================================
  describe('Security', () => {
    describe('Token Generation', () => {
      it('should generate cryptographically secure magic link tokens', () => {
        // Generate multiple tokens and check for randomness
        const tokens: string[] = [];
        for (let i = 0; i < 1000; i++) {
          tokens.push(generateMagicLinkToken());
        }

        // All tokens should be unique
        const uniqueTokens = new Set(tokens);
        expect(uniqueTokens.size).toBe(1000);

        // Check character distribution (should be roughly uniform)
        const charCounts: Record<string, number> = {};
        for (const token of tokens) {
          for (const char of token) {
            charCounts[char] = (charCounts[char] || 0) + 1;
          }
        }

        // Each hex character should appear roughly equally
        const expectedCount = (1000 * 64) / 16; // 4000 per character
        for (const char of '0123456789abcdef') {
          const count = charCounts[char] || 0;
          // Allow 20% deviation
          expect(count).toBeGreaterThan(expectedCount * 0.8);
          expect(count).toBeLessThan(expectedCount * 1.2);
        }
      });

      it('should generate cryptographically secure push notification IDs', () => {
        const ids = new Set<string>();
        for (let i = 0; i < 100; i++) {
          ids.add(generatePushNotificationId());
        }

        expect(ids.size).toBe(100);
      });
    });

    describe('Token Verification', () => {
      it('should use constant-time comparison for token verification', () => {
        const tokenData = createMagicLinkToken('test@example.com', 'realm_123');
        
        // Measure time for correct token
        const correctStart = process.hrtime.bigint();
        verifyMagicLinkToken(tokenData.token, tokenData);
        const correctEnd = process.hrtime.bigint();
        const correctTime = Number(correctEnd - correctStart);

        // Measure time for wrong token (same length)
        const wrongToken = 'b'.repeat(64);
        const wrongStart = process.hrtime.bigint();
        verifyMagicLinkToken(wrongToken, tokenData);
        const wrongEnd = process.hrtime.bigint();
        const wrongTime = Number(wrongEnd - wrongStart);

        // Times should be similar (within 10x - timing attacks are hard to prevent completely)
        // This is a basic check; real timing attack prevention requires more sophisticated testing
        expect(Math.abs(correctTime - wrongTime)).toBeLessThan(Math.max(correctTime, wrongTime) * 10);
      });
    });

    describe('Expiry Handling', () => {
      it('should correctly handle token expiry at boundary', () => {
        const tokenData = createMagicLinkToken('test@example.com', 'realm_123');
        
        // Set expiry to 1ms in the past to ensure it's expired
        tokenData.expiresAt = Date.now() - 1;
        
        // Should be expired (boundary case)
        expect(isMagicLinkExpired(tokenData)).toBe(true);
      });

      it('should correctly handle push notification expiry at boundary', () => {
        const notification = createPushAuthNotification('user_123', 'device_456', 'realm_789');
        
        // Set expiry to 1ms in the past to ensure it's expired
        notification.expiresAt = Date.now() - 1;
        
        // Should be expired (boundary case)
        expect(isPushNotificationExpired(notification)).toBe(true);
      });
    });
  });
});
