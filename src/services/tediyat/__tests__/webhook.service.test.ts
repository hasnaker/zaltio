/**
 * Tediyat Webhook Service Tests
 * Property 25: Webhook Signature Verification
 * 
 * Validates: Requirements 22.1-22.4
 */

import {
  generateSignature,
  verifySignature,
  createWebhookEvent,
  prepareWebhookDelivery,
  formatWebhookHeaders,
  parseIncomingWebhook,
  WebhookEventType,
} from '../webhook.service';

describe('Tediyat Webhook Service', () => {
  const testSecret = 'whsec_test_secret_key_12345';

  describe('Signature Generation', () => {
    it('should generate consistent signatures for same input', () => {
      const payload = '{"test":"data"}';
      const timestamp = 1706400000;

      const sig1 = generateSignature(payload, testSecret, timestamp);
      const sig2 = generateSignature(payload, testSecret, timestamp);

      expect(sig1).toBe(sig2);
      expect(sig1).toMatch(/^v1=[a-f0-9]{64}$/);
    });

    it('should generate different signatures for different payloads', () => {
      const timestamp = 1706400000;

      const sig1 = generateSignature('{"a":1}', testSecret, timestamp);
      const sig2 = generateSignature('{"a":2}', testSecret, timestamp);

      expect(sig1).not.toBe(sig2);
    });

    it('should generate different signatures for different timestamps', () => {
      const payload = '{"test":"data"}';

      const sig1 = generateSignature(payload, testSecret, 1706400000);
      const sig2 = generateSignature(payload, testSecret, 1706400001);

      expect(sig1).not.toBe(sig2);
    });

    it('should generate different signatures for different secrets', () => {
      const payload = '{"test":"data"}';
      const timestamp = 1706400000;

      const sig1 = generateSignature(payload, 'secret1', timestamp);
      const sig2 = generateSignature(payload, 'secret2', timestamp);

      expect(sig1).not.toBe(sig2);
    });
  });

  describe('Signature Verification', () => {
    it('should verify valid signature', () => {
      const payload = '{"test":"data"}';
      const timestamp = Math.floor(Date.now() / 1000);
      const signature = generateSignature(payload, testSecret, timestamp);

      const isValid = verifySignature(payload, signature, testSecret, timestamp);
      expect(isValid).toBe(true);
    });

    it('should reject invalid signature', () => {
      const payload = '{"test":"data"}';
      const timestamp = Math.floor(Date.now() / 1000);
      const invalidSignature = 'v1=invalid_signature_here';

      const isValid = verifySignature(payload, invalidSignature, testSecret, timestamp);
      expect(isValid).toBe(false);
    });

    it('should reject expired timestamp (replay protection)', () => {
      const payload = '{"test":"data"}';
      const oldTimestamp = Math.floor(Date.now() / 1000) - 600; // 10 minutes ago
      const signature = generateSignature(payload, testSecret, oldTimestamp);

      const isValid = verifySignature(payload, signature, testSecret, oldTimestamp);
      expect(isValid).toBe(false);
    });

    it('should accept timestamp within tolerance', () => {
      const payload = '{"test":"data"}';
      const recentTimestamp = Math.floor(Date.now() / 1000) - 60; // 1 minute ago
      const signature = generateSignature(payload, testSecret, recentTimestamp);

      const isValid = verifySignature(payload, signature, testSecret, recentTimestamp);
      expect(isValid).toBe(true);
    });
  });

  describe('Event Creation', () => {
    it('should create event with unique ID', () => {
      const event1 = createWebhookEvent('user.created', { user_id: 'u1' });
      const event2 = createWebhookEvent('user.created', { user_id: 'u1' });

      expect(event1.id).toMatch(/^evt_[a-f0-9]{32}$/);
      expect(event1.id).not.toBe(event2.id);
    });

    it('should include all event types', () => {
      const eventTypes: WebhookEventType[] = [
        'user.created',
        'user.updated',
        'user.deleted',
        'tenant.created',
        'tenant.updated',
        'tenant.deleted',
        'member.added',
        'member.removed',
        'member.role_changed',
        'session.created',
        'session.terminated',
      ];

      for (const type of eventTypes) {
        const event = createWebhookEvent(type, { test: true });
        expect(event.type).toBe(type);
        expect(event.timestamp).toBeDefined();
      }
    });

    it('should include tenant_id when provided', () => {
      const event = createWebhookEvent('member.added', { user_id: 'u1' }, 'tenant_xxx');
      expect(event.tenant_id).toBe('tenant_xxx');
    });

    it('should not include tenant_id when not provided', () => {
      const event = createWebhookEvent('user.created', { user_id: 'u1' });
      expect(event.tenant_id).toBeUndefined();
    });
  });

  describe('Webhook Delivery Preparation', () => {
    it('should prepare delivery with signature', () => {
      const event = createWebhookEvent('user.created', { user_id: 'u1' });
      const delivery = prepareWebhookDelivery(event, testSecret);

      expect(delivery.event).toBe(event);
      expect(delivery.signature).toMatch(/^v1=[a-f0-9]{64}$/);
      expect(delivery.timestamp).toBeGreaterThan(0);
    });

    it('should format headers correctly', () => {
      const event = createWebhookEvent('user.created', { user_id: 'u1' });
      const delivery = prepareWebhookDelivery(event, testSecret);
      const headers = formatWebhookHeaders(delivery);

      expect(headers['Content-Type']).toBe('application/json');
      expect(headers['X-Webhook-Signature']).toBe(delivery.signature);
      expect(headers['X-Webhook-Timestamp']).toBe(delivery.timestamp.toString());
      expect(headers['X-Webhook-Id']).toBe(event.id);
    });
  });

  describe('Incoming Webhook Parsing', () => {
    it('should parse valid incoming webhook', () => {
      const event = createWebhookEvent('user.created', { user_id: 'u1' });
      const body = JSON.stringify(event);
      const timestamp = Math.floor(Date.now() / 1000);
      const signature = generateSignature(body, testSecret, timestamp);

      const result = parseIncomingWebhook(body, signature, timestamp.toString(), testSecret);

      expect(result.valid).toBe(true);
      expect(result.event).toEqual(event);
    });

    it('should reject invalid signature', () => {
      const event = createWebhookEvent('user.created', { user_id: 'u1' });
      const body = JSON.stringify(event);
      const timestamp = Math.floor(Date.now() / 1000);

      const result = parseIncomingWebhook(body, 'v1=invalid', timestamp.toString(), testSecret);

      expect(result.valid).toBe(false);
      expect(result.error).toContain('Invalid signature');
    });

    it('should reject invalid timestamp format', () => {
      const body = '{"test":"data"}';

      const result = parseIncomingWebhook(body, 'v1=sig', 'invalid', testSecret);

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Invalid timestamp');
    });

    it('should reject invalid JSON', () => {
      const body = 'not json';
      const timestamp = Math.floor(Date.now() / 1000);
      const signature = generateSignature(body, testSecret, timestamp);

      const result = parseIncomingWebhook(body, signature, timestamp.toString(), testSecret);

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Invalid JSON payload');
    });
  });
});
