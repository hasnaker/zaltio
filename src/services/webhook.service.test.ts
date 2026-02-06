/**
 * Webhook Service Tests
 * Validates: Requirements 12.1, 12.3, 12.6, 12.9
 */

import { createHmac } from 'crypto';

const mockSend = jest.fn().mockResolvedValue({ MessageId: 'msg_123' });
jest.mock('@aws-sdk/client-sqs', () => ({
  SQSClient: jest.fn().mockImplementation(() => ({ send: mockSend })),
  SendMessageCommand: jest.fn((params) => params)
}));

jest.mock('../repositories/webhook.repository');
jest.mock('../repositories/webhook-delivery.repository');
jest.mock('./audit.service', () => ({
  logAuditEvent: jest.fn().mockResolvedValue({}),
  AuditEventType: { ADMIN_ACTION: 'admin_action' },
  AuditResult: { SUCCESS: 'success', FAILURE: 'failure' }
}));

import * as webhookRepository from '../repositories/webhook.repository';
import * as webhookDeliveryRepository from '../repositories/webhook-delivery.repository';
import { WebhookService, WebhookErrorCode } from './webhook.service';
import { Webhook, WebhookEventType, createWebhookSignature, verifyWebhookSignature, SIGNATURE_TIMESTAMP_TOLERANCE } from '../models/webhook.model';

const mockedWebhookRepo = webhookRepository as jest.Mocked<typeof webhookRepository>;
const mockedDeliveryRepo = webhookDeliveryRepository as jest.Mocked<typeof webhookDeliveryRepository>;

describe('WebhookService', () => {
  let service: WebhookService;
  const testRealmId = 'realm_test123';
  const testWebhookId = 'webhook_test456';
  const testSecret = 'whsec_test_secret_key_32bytes_long';

  const createMockWebhook = (overrides: Partial<Webhook> = {}): Webhook => ({
    id: testWebhookId, realm_id: testRealmId, url: 'https://example.com/webhook',
    secret: testSecret, events: ['user.created', 'user.updated'] as WebhookEventType[],
    status: 'active', description: 'Test webhook',
    created_at: new Date().toISOString(), updated_at: new Date().toISOString(), ...overrides
  });

  const createMockDelivery = (overrides = {}) => ({
    id: 'del_test123', webhook_id: testWebhookId, event_type: 'user.created',
    payload: { id: 'p1', type: 'user.created', timestamp: new Date().toISOString(), idempotency_key: 'ik1', data: {} },
    status: 'pending' as const, attempts: 0, max_attempts: 5, created_at: new Date().toISOString(), ...overrides
  });

  beforeEach(() => { jest.clearAllMocks(); service = new WebhookService(); });

  describe('create', () => {
    it('should create webhook with valid input', async () => {
      mockedWebhookRepo.createWebhook.mockResolvedValue({ webhook: createMockWebhook(), secret: testSecret });
      const result = await service.create({ realm_id: testRealmId, url: 'https://example.com/webhook', events: ['user.created'] as WebhookEventType[] });
      expect(result.webhook.id).toBe(testWebhookId);
    });
    it('should reject non-HTTPS URLs', async () => {
      await expect(service.create({ realm_id: testRealmId, url: 'http://example.com/webhook', events: ['user.created'] as WebhookEventType[] }))
        .rejects.toMatchObject({ code: WebhookErrorCode.INVALID_URL });
    });
    it('should reject invalid events', async () => {
      await expect(service.create({ realm_id: testRealmId, url: 'https://example.com/webhook', events: ['invalid' as unknown as WebhookEventType] }))
        .rejects.toMatchObject({ code: WebhookErrorCode.INVALID_EVENT });
    });
  });

  describe('dispatch', () => {
    it('should dispatch to subscribed webhooks', async () => {
      mockedWebhookRepo.getWebhooksForEvent.mockResolvedValue([createMockWebhook()]);
      mockedDeliveryRepo.createWebhookDelivery.mockResolvedValue(createMockDelivery() as any);
      const result = await service.dispatch({ realm_id: testRealmId, event_type: 'user.created', data: { user_id: 'u1' } });
      expect(result.webhooks_triggered).toBe(1);
    });
    it('should return empty when no webhooks', async () => {
      mockedWebhookRepo.getWebhooksForEvent.mockResolvedValue([]);
      const result = await service.dispatch({ realm_id: testRealmId, event_type: 'user.created', data: {} });
      expect(result.webhooks_triggered).toBe(0);
    });
  });

  describe('test', () => {
    it('should send test event', async () => {
      mockedWebhookRepo.getWebhookById.mockResolvedValue(createMockWebhook());
      mockedDeliveryRepo.createWebhookDelivery.mockResolvedValue(createMockDelivery({ event_type: 'test' }) as any);
      const result = await service.test({ webhook_id: testWebhookId, realm_id: testRealmId });
      expect(result.event_type).toBe('test');
    });
    it('should throw if not found', async () => {
      mockedWebhookRepo.getWebhookById.mockResolvedValue(null);
      await expect(service.test({ webhook_id: testWebhookId, realm_id: testRealmId })).rejects.toMatchObject({ code: WebhookErrorCode.WEBHOOK_NOT_FOUND });
    });
    it('should throw if inactive', async () => {
      mockedWebhookRepo.getWebhookById.mockResolvedValue(createMockWebhook({ status: 'inactive' }));
      await expect(service.test({ webhook_id: testWebhookId, realm_id: testRealmId })).rejects.toMatchObject({ code: WebhookErrorCode.WEBHOOK_DISABLED });
    });
  });

  describe('getDeliveryLogs', () => {
    it('should return logs', async () => {
      mockedWebhookRepo.getWebhookById.mockResolvedValue(createMockWebhook());
      mockedDeliveryRepo.listWebhookDeliveries.mockResolvedValue({ deliveries: [{ id: 'd1', webhook_id: testWebhookId, event_type: 'user.created', status: 'success', attempts: 1, max_attempts: 5, created_at: '' }], nextCursor: undefined });
      const result = await service.getDeliveryLogs({ webhook_id: testWebhookId, realm_id: testRealmId });
      expect(result.deliveries).toHaveLength(1);
    });
  });

  describe('rotateSecret', () => {
    it('should rotate secret', async () => {
      mockedWebhookRepo.getWebhookById.mockResolvedValue(createMockWebhook());
      mockedWebhookRepo.rotateWebhookSecret.mockResolvedValue({ webhook: createMockWebhook(), secret: 'new_secret' });
      const result = await service.rotateSecret({ webhook_id: testWebhookId, realm_id: testRealmId });
      expect(result.secret).toBe('new_secret');
    });
  });

  describe('verifySignature', () => {
    it('should verify valid timestamp signature', () => {
      const payload = '{"test":true}';
      const ts = Math.floor(Date.now() / 1000);
      const sig = createWebhookSignature(payload, ts, testSecret);
      expect(service.verifySignature(payload, 't=' + ts + ',v1=' + sig, testSecret)).toBe(true);
    });
    it('should verify simple signature', () => {
      const payload = '{"test":true}';
      const sig = createHmac('sha256', testSecret).update(payload).digest('hex');
      expect(service.verifySignature(payload, sig, testSecret)).toBe(true);
    });
    it('should reject invalid signature', () => {
      expect(service.verifySignature('{}', 't=1,v1=invalid', testSecret)).toBe(false);
    });
  });

  describe('getById', () => {
    it('should return webhook', async () => {
      mockedWebhookRepo.getWebhookById.mockResolvedValue(createMockWebhook());
      const result = await service.getById(testRealmId, testWebhookId);
      expect(result?.id).toBe(testWebhookId);
    });
  });

  describe('list', () => {
    it('should list webhooks', async () => {
      mockedWebhookRepo.listWebhooksByRealm.mockResolvedValue({ webhooks: [{ id: 'w1', realm_id: testRealmId, url: 'https://a.com', events: [], status: 'active', created_at: '', updated_at: '' }], nextCursor: undefined });
      const result = await service.list(testRealmId);
      expect(result.webhooks).toHaveLength(1);
    });
  });

  describe('update', () => {
    it('should update webhook', async () => {
      mockedWebhookRepo.updateWebhook.mockResolvedValue(createMockWebhook());
      const result = await service.update(testRealmId, testWebhookId, { description: 'Updated' });
      expect(result).not.toBeNull();
    });
    it('should reject invalid URL', async () => {
      await expect(service.update(testRealmId, testWebhookId, { url: 'http://bad.com' })).rejects.toMatchObject({ code: WebhookErrorCode.INVALID_URL });
    });
  });

  describe('delete', () => {
    it('should delete webhook', async () => {
      mockedWebhookRepo.deleteWebhook.mockResolvedValue(true);
      expect(await service.delete(testRealmId, testWebhookId)).toBe(true);
    });
  });

  describe('getStatistics', () => {
    it('should return stats', async () => {
      mockedWebhookRepo.countWebhooksByStatus.mockResolvedValue({ active: 5, inactive: 2, deleted: 1 });
      const result = await service.getStatistics(testRealmId);
      expect(result.active).toBe(5);
    });
  });
});

describe('Webhook Signature Security', () => {
  const secret = 'whsec_security_test';
  it('should generate consistent signatures', () => {
    const s1 = createWebhookSignature('{"a":1}', 1706400000, secret);
    const s2 = createWebhookSignature('{"a":1}', 1706400000, secret);
    expect(s1).toBe(s2);
  });
  it('should differ for different payloads', () => {
    expect(createWebhookSignature('{"a":1}', 1706400000, secret)).not.toBe(createWebhookSignature('{"a":2}', 1706400000, secret));
  });
  it('should differ for different timestamps', () => {
    expect(createWebhookSignature('{"a":1}', 1706400000, secret)).not.toBe(createWebhookSignature('{"a":1}', 1706400001, secret));
  });
  it('should verify within tolerance', () => {
    const ts = Math.floor(Date.now() / 1000) - 60;
    const sig = createWebhookSignature('{"t":1}', ts, secret);
    expect(verifyWebhookSignature('{"t":1}', sig, ts, secret)).toBe(true);
  });
  it('should reject expired timestamp', () => {
    const ts = Math.floor(Date.now() / 1000) - SIGNATURE_TIMESTAMP_TOLERANCE - 60;
    const sig = createWebhookSignature('{"t":1}', ts, secret);
    expect(verifyWebhookSignature('{"t":1}', sig, ts, secret)).toBe(false);
  });
});
