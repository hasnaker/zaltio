/**
 * Webhook Model Tests
 * Tests for webhook model utilities and helper functions
 * 
 * Validates: Requirements 12.1 (Webhook System)
 * ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
 */

import {
  generateWebhookId,
  generateWebhookSecret,
  generateDeliveryId,
  generateIdempotencyKey,
  createWebhookSignature,
  verifyWebhookSignature,
  isValidWebhookUrl,
  isValidWebhookEvent,
  isValidWebhookStatus,
  eventMatchesSubscription,
  toWebhookResponse,
  createWebhookPayload,
  createSignatureHeaders,
  maskWebhookUrl,
  WEBHOOK_ID_PREFIX,
  WEBHOOK_SECRET_BYTES,
  WEBHOOK_EVENTS,
  SIGNATURE_TIMESTAMP_TOLERANCE,
  WebhookEventType,
  Webhook
} from './webhook.model';

describe('Webhook Model Utilities', () => {
  describe('generateWebhookId', () => {
    it('should generate ID with webhook_ prefix', () => {
      const id = generateWebhookId();
      expect(id).toMatch(/^webhook_[a-f0-9]{24}$/);
      expect(id.startsWith(WEBHOOK_ID_PREFIX)).toBe(true);
    });
    
    it('should generate unique IDs', () => {
      const ids = new Set<string>();
      for (let i = 0; i < 100; i++) {
        ids.add(generateWebhookId());
      }
      expect(ids.size).toBe(100);
    });
  });
  
  describe('generateWebhookSecret', () => {
    it('should generate 64 character hex secret', () => {
      const secret = generateWebhookSecret();
      expect(secret).toMatch(/^[a-f0-9]{64}$/);
      expect(secret.length).toBe(WEBHOOK_SECRET_BYTES * 2);
    });
    
    it('should generate unique secrets', () => {
      const secrets = new Set<string>();
      for (let i = 0; i < 100; i++) {
        secrets.add(generateWebhookSecret());
      }
      expect(secrets.size).toBe(100);
    });
  });
  
  describe('generateDeliveryId', () => {
    it('should generate ID with del_ prefix', () => {
      const id = generateDeliveryId();
      expect(id).toMatch(/^del_[a-f0-9]{32}$/);
    });
    
    it('should generate unique delivery IDs', () => {
      const ids = new Set<string>();
      for (let i = 0; i < 100; i++) {
        ids.add(generateDeliveryId());
      }
      expect(ids.size).toBe(100);
    });
  });
  
  describe('generateIdempotencyKey', () => {
    it('should generate key with idem_ prefix', () => {
      const key = generateIdempotencyKey();
      expect(key).toMatch(/^idem_[a-f0-9]{32}$/);
    });
    
    it('should generate unique idempotency keys', () => {
      const keys = new Set<string>();
      for (let i = 0; i < 100; i++) {
        keys.add(generateIdempotencyKey());
      }
      expect(keys.size).toBe(100);
    });
  });
  
  describe('createWebhookSignature', () => {
    it('should create HMAC-SHA256 signature', () => {
      const payload = '{"test": "data"}';
      const timestamp = 1706180400; // Fixed timestamp
      const secret = 'a'.repeat(64);
      
      const signature = createWebhookSignature(payload, timestamp, secret);
      
      // Should be 64 character hex string (SHA-256)
      expect(signature).toMatch(/^[a-f0-9]{64}$/);
    });
    
    it('should produce consistent signature for same input', () => {
      const payload = '{"test": "data"}';
      const timestamp = 1706180400;
      const secret = 'b'.repeat(64);
      
      const sig1 = createWebhookSignature(payload, timestamp, secret);
      const sig2 = createWebhookSignature(payload, timestamp, secret);
      
      expect(sig1).toBe(sig2);
    });
    
    it('should produce different signature for different payload', () => {
      const timestamp = 1706180400;
      const secret = 'c'.repeat(64);
      
      const sig1 = createWebhookSignature('{"a": 1}', timestamp, secret);
      const sig2 = createWebhookSignature('{"a": 2}', timestamp, secret);
      
      expect(sig1).not.toBe(sig2);
    });
    
    it('should produce different signature for different timestamp', () => {
      const payload = '{"test": "data"}';
      const secret = 'd'.repeat(64);
      
      const sig1 = createWebhookSignature(payload, 1706180400, secret);
      const sig2 = createWebhookSignature(payload, 1706180401, secret);
      
      expect(sig1).not.toBe(sig2);
    });
    
    it('should produce different signature for different secret', () => {
      const payload = '{"test": "data"}';
      const timestamp = 1706180400;
      
      const sig1 = createWebhookSignature(payload, timestamp, 'e'.repeat(64));
      const sig2 = createWebhookSignature(payload, timestamp, 'f'.repeat(64));
      
      expect(sig1).not.toBe(sig2);
    });
  });
  
  describe('verifyWebhookSignature', () => {
    it('should verify valid signature', () => {
      const payload = '{"test": "data"}';
      const secret = generateWebhookSecret();
      const timestamp = Math.floor(Date.now() / 1000);
      const signature = createWebhookSignature(payload, timestamp, secret);
      
      const isValid = verifyWebhookSignature(payload, signature, timestamp, secret);
      
      expect(isValid).toBe(true);
    });
    
    it('should reject invalid signature', () => {
      const payload = '{"test": "data"}';
      const secret = generateWebhookSecret();
      const timestamp = Math.floor(Date.now() / 1000);
      const invalidSignature = 'invalid'.repeat(8);
      
      const isValid = verifyWebhookSignature(payload, invalidSignature, timestamp, secret);
      
      expect(isValid).toBe(false);
    });
    
    it('should reject tampered payload', () => {
      const originalPayload = '{"test": "data"}';
      const tamperedPayload = '{"test": "tampered"}';
      const secret = generateWebhookSecret();
      const timestamp = Math.floor(Date.now() / 1000);
      const signature = createWebhookSignature(originalPayload, timestamp, secret);
      
      const isValid = verifyWebhookSignature(tamperedPayload, signature, timestamp, secret);
      
      expect(isValid).toBe(false);
    });
    
    it('should reject expired timestamp', () => {
      const payload = '{"test": "data"}';
      const secret = generateWebhookSecret();
      const oldTimestamp = Math.floor(Date.now() / 1000) - SIGNATURE_TIMESTAMP_TOLERANCE - 60;
      const signature = createWebhookSignature(payload, oldTimestamp, secret);
      
      const isValid = verifyWebhookSignature(payload, signature, oldTimestamp, secret);
      
      expect(isValid).toBe(false);
    });
    
    it('should reject future timestamp beyond tolerance', () => {
      const payload = '{"test": "data"}';
      const secret = generateWebhookSecret();
      const futureTimestamp = Math.floor(Date.now() / 1000) + SIGNATURE_TIMESTAMP_TOLERANCE + 60;
      const signature = createWebhookSignature(payload, futureTimestamp, secret);
      
      const isValid = verifyWebhookSignature(payload, signature, futureTimestamp, secret);
      
      expect(isValid).toBe(false);
    });
    
    it('should accept timestamp within tolerance', () => {
      const payload = '{"test": "data"}';
      const secret = generateWebhookSecret();
      const timestamp = Math.floor(Date.now() / 1000) - SIGNATURE_TIMESTAMP_TOLERANCE + 10;
      const signature = createWebhookSignature(payload, timestamp, secret);
      
      const isValid = verifyWebhookSignature(payload, signature, timestamp, secret);
      
      expect(isValid).toBe(true);
    });
    
    it('should reject wrong secret', () => {
      const payload = '{"test": "data"}';
      const secret1 = generateWebhookSecret();
      const secret2 = generateWebhookSecret();
      const timestamp = Math.floor(Date.now() / 1000);
      const signature = createWebhookSignature(payload, timestamp, secret1);
      
      const isValid = verifyWebhookSignature(payload, signature, timestamp, secret2);
      
      expect(isValid).toBe(false);
    });
    
    it('should handle malformed signature gracefully', () => {
      const payload = '{"test": "data"}';
      const secret = generateWebhookSecret();
      const timestamp = Math.floor(Date.now() / 1000);
      
      // Non-hex signature
      expect(verifyWebhookSignature(payload, 'not-hex', timestamp, secret)).toBe(false);
      
      // Empty signature
      expect(verifyWebhookSignature(payload, '', timestamp, secret)).toBe(false);
      
      // Wrong length
      expect(verifyWebhookSignature(payload, 'abc123', timestamp, secret)).toBe(false);
    });
  });
  
  describe('isValidWebhookUrl', () => {
    it('should accept valid HTTPS URLs', () => {
      expect(isValidWebhookUrl('https://example.com/webhook')).toBe(true);
      expect(isValidWebhookUrl('https://api.example.com/v1/webhooks')).toBe(true);
      expect(isValidWebhookUrl('https://example.com:8443/webhook')).toBe(true);
    });
    
    it('should reject HTTP URLs', () => {
      expect(isValidWebhookUrl('http://example.com/webhook')).toBe(false);
    });
    
    it('should reject invalid URLs', () => {
      expect(isValidWebhookUrl('not-a-url')).toBe(false);
      expect(isValidWebhookUrl('')).toBe(false);
      expect(isValidWebhookUrl('ftp://example.com/webhook')).toBe(false);
    });
  });
  
  describe('isValidWebhookEvent', () => {
    it('should accept valid event types', () => {
      expect(isValidWebhookEvent('user.created')).toBe(true);
      expect(isValidWebhookEvent('session.revoked')).toBe(true);
      expect(isValidWebhookEvent('member.invited')).toBe(true);
      expect(isValidWebhookEvent('mfa.enabled')).toBe(true);
    });
    
    it('should reject invalid event types', () => {
      expect(isValidWebhookEvent('invalid.event')).toBe(false);
      expect(isValidWebhookEvent('user')).toBe(false);
      expect(isValidWebhookEvent('')).toBe(false);
    });
    
    it('should validate all defined events', () => {
      for (const event of WEBHOOK_EVENTS) {
        expect(isValidWebhookEvent(event)).toBe(true);
      }
    });
  });
  
  describe('isValidWebhookStatus', () => {
    it('should accept valid statuses', () => {
      expect(isValidWebhookStatus('active')).toBe(true);
      expect(isValidWebhookStatus('inactive')).toBe(true);
      expect(isValidWebhookStatus('deleted')).toBe(true);
    });
    
    it('should reject invalid statuses', () => {
      expect(isValidWebhookStatus('invalid')).toBe(false);
      expect(isValidWebhookStatus('ACTIVE')).toBe(false);
      expect(isValidWebhookStatus('')).toBe(false);
    });
  });
  
  describe('eventMatchesSubscription', () => {
    it('should match exact event', () => {
      const subscriptions: WebhookEventType[] = ['user.created', 'user.deleted'];
      
      expect(eventMatchesSubscription('user.created', subscriptions)).toBe(true);
      expect(eventMatchesSubscription('user.deleted', subscriptions)).toBe(true);
      expect(eventMatchesSubscription('user.updated', subscriptions)).toBe(false);
    });
    
    it('should not match unsubscribed events', () => {
      const subscriptions: WebhookEventType[] = ['user.created'];
      
      expect(eventMatchesSubscription('session.created', subscriptions)).toBe(false);
      expect(eventMatchesSubscription('member.invited', subscriptions)).toBe(false);
    });
  });
  
  describe('toWebhookResponse', () => {
    it('should convert webhook to response format', () => {
      const webhook: Webhook = {
        id: 'webhook_test123',
        realm_id: 'realm_abc',
        url: 'https://example.com/webhook',
        secret: 'secret123',
        events: ['user.created'],
        status: 'active',
        description: 'Test webhook',
        created_at: '2026-01-25T10:00:00Z',
        metadata: {
          created_by: 'user_123',
          failure_count: 0
        }
      };
      
      const response = toWebhookResponse(webhook);
      
      expect(response.id).toBe(webhook.id);
      expect(response.realm_id).toBe(webhook.realm_id);
      expect(response.url).toBe(webhook.url);
      expect(response.events).toEqual(webhook.events);
      expect(response.status).toBe(webhook.status);
      expect(response.description).toBe(webhook.description);
      expect(response.created_at).toBe(webhook.created_at);
      // Should not include secret
      expect((response as unknown as { secret?: string }).secret).toBeUndefined();
      // Should not include created_by in metadata (it's filtered out by Omit type)
      expect((response.metadata as unknown as { created_by?: string })?.created_by).toBeUndefined();
    });
    
    it('should handle webhook without metadata', () => {
      const webhook: Webhook = {
        id: 'webhook_test123',
        realm_id: 'realm_abc',
        url: 'https://example.com/webhook',
        secret: 'secret123',
        events: ['user.created'],
        status: 'active',
        created_at: '2026-01-25T10:00:00Z'
      };
      
      const response = toWebhookResponse(webhook);
      
      expect(response.metadata).toBeUndefined();
    });
  });
  
  describe('createWebhookPayload', () => {
    it('should create valid payload structure', () => {
      const eventType: WebhookEventType = 'user.created';
      const data = { user_id: 'user_123', email: 'test@example.com' };
      
      const payload = createWebhookPayload(eventType, data);
      
      expect(payload.id).toMatch(/^del_[a-f0-9]{32}$/);
      expect(payload.type).toBe(eventType);
      expect(payload.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
      expect(payload.idempotency_key).toMatch(/^idem_[a-f0-9]{32}$/);
      expect(payload.data).toEqual(data);
    });
    
    it('should generate unique IDs for each payload', () => {
      const payload1 = createWebhookPayload('user.created', {});
      const payload2 = createWebhookPayload('user.created', {});
      
      expect(payload1.id).not.toBe(payload2.id);
      expect(payload1.idempotency_key).not.toBe(payload2.idempotency_key);
    });
  });
  
  describe('createSignatureHeaders', () => {
    it('should create valid signature headers', () => {
      const payload = '{"test": "data"}';
      const secret = generateWebhookSecret();
      const deliveryId = 'del_test123';
      
      const headers = createSignatureHeaders(payload, secret, deliveryId);
      
      expect(headers['x-zalt-signature']).toMatch(/^[a-f0-9]{64}$/);
      expect(headers['x-zalt-timestamp']).toMatch(/^\d+$/);
      expect(headers['x-zalt-delivery-id']).toBe(deliveryId);
    });
    
    it('should create verifiable signature', () => {
      const payload = '{"test": "data"}';
      const secret = generateWebhookSecret();
      const deliveryId = 'del_test123';
      
      const headers = createSignatureHeaders(payload, secret, deliveryId);
      const timestamp = parseInt(headers['x-zalt-timestamp'], 10);
      
      const isValid = verifyWebhookSignature(
        payload,
        headers['x-zalt-signature'],
        timestamp,
        secret
      );
      
      expect(isValid).toBe(true);
    });
  });
  
  describe('maskWebhookUrl', () => {
    it('should mask URL path', () => {
      expect(maskWebhookUrl('https://example.com/webhook/secret')).toBe('https://example.com/***');
      expect(maskWebhookUrl('https://api.example.com:8443/v1/hooks')).toBe('https://api.example.com:8443/***');
    });
    
    it('should handle invalid URLs', () => {
      expect(maskWebhookUrl('not-a-url')).toBe('***');
      expect(maskWebhookUrl('')).toBe('***');
    });
  });
});
