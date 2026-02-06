/**
 * Webhook Signature Verification Tests
 * Validates: Requirement 12.10
 */

import {
  verifyWebhookSignature,
  parseSignatureHeader,
  computeSignature,
  safeCompare,
  constructWebhookEvent,
  createTestSignature,
  WebhookVerificationError,
  WebhookVerificationErrorCode,
  DEFAULT_TIMESTAMP_TOLERANCE
} from '../webhooks';

describe('Webhook Signature Verification', () => {
  const testSecret = 'whsec_test_secret_12345';
  const testPayload = JSON.stringify({
    id: 'evt_123',
    type: 'user.created',
    timestamp: '2026-02-02T10:00:00Z',
    data: { user_id: 'user_123', email: 'test@example.com' }
  });

  describe('verifyWebhookSignature', () => {
    it('should verify valid signature', () => {
      const timestamp = Math.floor(Date.now() / 1000);
      const signature = createTestSignature(testPayload, testSecret, timestamp);

      const result = verifyWebhookSignature(testPayload, signature, testSecret);
      expect(result).toBe(true);
    });

    it('should verify signature with object payload', () => {
      const payload = { id: 'evt_123', type: 'user.created', timestamp: '2026-02-02T10:00:00Z', data: {} };
      const timestamp = Math.floor(Date.now() / 1000);
      const signature = createTestSignature(payload, testSecret, timestamp);

      const result = verifyWebhookSignature(payload, signature, testSecret);
      expect(result).toBe(true);
    });

    it('should throw on missing signature', () => {
      expect(() => verifyWebhookSignature(testPayload, null, testSecret))
        .toThrow(WebhookVerificationError);
      expect(() => verifyWebhookSignature(testPayload, undefined, testSecret))
        .toThrow(WebhookVerificationError);
      expect(() => verifyWebhookSignature(testPayload, '', testSecret))
        .toThrow(WebhookVerificationError);
    });

    it('should throw on missing secret', () => {
      const signature = createTestSignature(testPayload, testSecret);
      
      expect(() => verifyWebhookSignature(testPayload, signature, null))
        .toThrow(WebhookVerificationError);
      expect(() => verifyWebhookSignature(testPayload, signature, undefined))
        .toThrow(WebhookVerificationError);
      expect(() => verifyWebhookSignature(testPayload, signature, ''))
        .toThrow(WebhookVerificationError);
    });

    it('should throw on invalid signature', () => {
      const timestamp = Math.floor(Date.now() / 1000);
      const invalidSignature = `t=${timestamp},v1=invalid_signature_hex`;

      expect(() => verifyWebhookSignature(testPayload, invalidSignature, testSecret))
        .toThrow(WebhookVerificationError);
    });

    it('should throw on tampered payload', () => {
      const timestamp = Math.floor(Date.now() / 1000);
      const signature = createTestSignature(testPayload, testSecret, timestamp);
      const tamperedPayload = testPayload.replace('user_123', 'user_456');

      expect(() => verifyWebhookSignature(tamperedPayload, signature, testSecret))
        .toThrow(WebhookVerificationError);
    });

    it('should throw on expired timestamp', () => {
      const oldTimestamp = Math.floor(Date.now() / 1000) - 600; // 10 minutes ago
      const signature = createTestSignature(testPayload, testSecret, oldTimestamp);

      expect(() => verifyWebhookSignature(testPayload, signature, testSecret))
        .toThrow(WebhookVerificationError);
      
      try {
        verifyWebhookSignature(testPayload, signature, testSecret);
      } catch (error) {
        expect(error).toBeInstanceOf(WebhookVerificationError);
        expect((error as WebhookVerificationError).code).toBe(WebhookVerificationErrorCode.TIMESTAMP_EXPIRED);
      }
    });

    it('should throw on future timestamp', () => {
      const futureTimestamp = Math.floor(Date.now() / 1000) + 600; // 10 minutes in future
      const signature = createTestSignature(testPayload, testSecret, futureTimestamp);

      expect(() => verifyWebhookSignature(testPayload, signature, testSecret))
        .toThrow(WebhookVerificationError);
    });

    it('should allow custom timestamp tolerance', () => {
      const oldTimestamp = Math.floor(Date.now() / 1000) - 600; // 10 minutes ago
      const signature = createTestSignature(testPayload, testSecret, oldTimestamp);

      // Should pass with 15 minute tolerance
      const result = verifyWebhookSignature(testPayload, signature, testSecret, {
        timestampTolerance: 900
      });
      expect(result).toBe(true);
    });

    it('should skip timestamp validation when tolerance is 0', () => {
      const veryOldTimestamp = Math.floor(Date.now() / 1000) - 86400; // 1 day ago
      const signature = createTestSignature(testPayload, testSecret, veryOldTimestamp);

      const result = verifyWebhookSignature(testPayload, signature, testSecret, {
        timestampTolerance: 0
      });
      expect(result).toBe(true);
    });

    it('should use custom current timestamp for testing', () => {
      const timestamp = 1700000000;
      const signature = createTestSignature(testPayload, testSecret, timestamp);

      const result = verifyWebhookSignature(testPayload, signature, testSecret, {
        currentTimestamp: timestamp + 60 // 1 minute later
      });
      expect(result).toBe(true);
    });
  });

  describe('parseSignatureHeader', () => {
    it('should parse valid signature header', () => {
      const header = 't=1700000000,v1=abc123def456';
      const parsed = parseSignatureHeader(header);

      expect(parsed.timestamp).toBe(1700000000);
      expect(parsed.signature).toBe('abc123def456');
    });

    it('should handle different order', () => {
      const header = 'v1=abc123def456,t=1700000000';
      const parsed = parseSignatureHeader(header);

      expect(parsed.timestamp).toBe(1700000000);
      expect(parsed.signature).toBe('abc123def456');
    });

    it('should throw on missing timestamp', () => {
      expect(() => parseSignatureHeader('v1=abc123'))
        .toThrow(WebhookVerificationError);
    });

    it('should throw on missing signature', () => {
      expect(() => parseSignatureHeader('t=1700000000'))
        .toThrow(WebhookVerificationError);
    });

    it('should throw on invalid format', () => {
      expect(() => parseSignatureHeader('invalid'))
        .toThrow(WebhookVerificationError);
    });

    it('should throw on simple hex signature (wrong format)', () => {
      const hexSignature = 'a'.repeat(64);
      expect(() => parseSignatureHeader(hexSignature))
        .toThrow(WebhookVerificationError);
    });
  });

  describe('computeSignature', () => {
    it('should compute consistent signatures', () => {
      const payload = 'test payload';
      const sig1 = computeSignature(payload, testSecret);
      const sig2 = computeSignature(payload, testSecret);

      expect(sig1).toBe(sig2);
    });

    it('should produce different signatures for different payloads', () => {
      const sig1 = computeSignature('payload1', testSecret);
      const sig2 = computeSignature('payload2', testSecret);

      expect(sig1).not.toBe(sig2);
    });

    it('should produce different signatures for different secrets', () => {
      const payload = 'test payload';
      const sig1 = computeSignature(payload, 'secret1');
      const sig2 = computeSignature(payload, 'secret2');

      expect(sig1).not.toBe(sig2);
    });

    it('should produce 64-character hex string', () => {
      const sig = computeSignature('test', testSecret);
      expect(sig).toHaveLength(64);
      expect(/^[a-f0-9]+$/.test(sig)).toBe(true);
    });
  });

  describe('safeCompare', () => {
    it('should return true for equal strings', () => {
      const hex = 'abc123def456abc123def456abc123def456abc123def456abc123def456abc123';
      expect(safeCompare(hex, hex)).toBe(true);
    });

    it('should return false for different strings', () => {
      const hex1 = 'abc123def456abc123def456abc123def456abc123def456abc123def456abc123';
      const hex2 = 'abc123def456abc123def456abc123def456abc123def456abc123def456abc124';
      expect(safeCompare(hex1, hex2)).toBe(false);
    });

    it('should return false for different lengths', () => {
      expect(safeCompare('abc123', 'abc123def456')).toBe(false);
    });

    it('should return false for invalid hex', () => {
      // Different length strings should return false
      expect(safeCompare('abc', 'abcdef')).toBe(false);
    });
  });

  describe('constructWebhookEvent', () => {
    it('should parse valid webhook payload', () => {
      const payload = {
        id: 'evt_123',
        type: 'user.created',
        timestamp: '2026-02-02T10:00:00Z',
        data: { user_id: 'user_123' }
      };

      const event = constructWebhookEvent(payload);
      expect(event.id).toBe('evt_123');
      expect(event.type).toBe('user.created');
      expect(event.data.user_id).toBe('user_123');
    });

    it('should parse string payload', () => {
      const payload = JSON.stringify({
        id: 'evt_123',
        type: 'user.created',
        timestamp: '2026-02-02T10:00:00Z',
        data: {}
      });

      const event = constructWebhookEvent(payload);
      expect(event.id).toBe('evt_123');
    });

    it('should throw on missing required fields', () => {
      expect(() => constructWebhookEvent({ id: 'evt_123' }))
        .toThrow(WebhookVerificationError);
      expect(() => constructWebhookEvent({ id: 'evt_123', type: 'test' }))
        .toThrow(WebhookVerificationError);
    });
  });

  describe('createTestSignature', () => {
    it('should create valid signature', () => {
      const signature = createTestSignature(testPayload, testSecret);
      
      expect(signature).toMatch(/^t=\d+,v1=[a-f0-9]+$/);
    });

    it('should use provided timestamp', () => {
      const timestamp = 1700000000;
      const signature = createTestSignature(testPayload, testSecret, timestamp);
      
      expect(signature).toContain(`t=${timestamp}`);
    });

    it('should create verifiable signature', () => {
      const signature = createTestSignature(testPayload, testSecret);
      
      const result = verifyWebhookSignature(testPayload, signature, testSecret);
      expect(result).toBe(true);
    });
  });

  describe('DEFAULT_TIMESTAMP_TOLERANCE', () => {
    it('should be 5 minutes (300 seconds)', () => {
      expect(DEFAULT_TIMESTAMP_TOLERANCE).toBe(300);
    });
  });

  describe('WebhookVerificationError', () => {
    it('should have correct name', () => {
      const error = new WebhookVerificationError(
        WebhookVerificationErrorCode.INVALID_SIGNATURE_FORMAT,
        'Test error'
      );
      expect(error.name).toBe('WebhookVerificationError');
    });

    it('should have code property', () => {
      const error = new WebhookVerificationError(
        WebhookVerificationErrorCode.SIGNATURE_MISMATCH,
        'Test error'
      );
      expect(error.code).toBe(WebhookVerificationErrorCode.SIGNATURE_MISMATCH);
    });
  });
});
