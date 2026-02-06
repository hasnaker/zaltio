/**
 * Webhook Delivery Handler Tests
 * Validates: Requirements 12.3, 12.4, 12.5
 */

jest.mock('../repositories/webhook-delivery.repository');
jest.mock('../services/audit.service', () => ({
  logAuditEvent: jest.fn().mockResolvedValue({}),
  AuditEventType: { ADMIN_ACTION: 'admin_action' },
  AuditResult: { SUCCESS: 'success', FAILURE: 'failure' }
}));

const mockFetch = jest.fn();
global.fetch = mockFetch;

import { handler } from './webhook-delivery.handler';
import * as webhookDeliveryRepository from '../repositories/webhook-delivery.repository';
import { SQSEvent, Context } from 'aws-lambda';

const mockedDeliveryRepo = webhookDeliveryRepository as jest.Mocked<typeof webhookDeliveryRepository>;

describe('Webhook Delivery Handler', () => {
  const mockContext = { functionName: 'test' } as Context;
  const mockDelivery = { id: 'del_123', webhook_id: 'wh_123', status: 'success', attempts: 1 };

  const createSQSEvent = (messages: object[]): SQSEvent => ({
    Records: messages.map((msg, i) => ({
      messageId: `msg_${i}`,
      receiptHandle: `receipt_${i}`,
      body: JSON.stringify(msg),
      attributes: {} as any,
      messageAttributes: {},
      md5OfBody: '',
      eventSource: 'aws:sqs',
      eventSourceARN: 'arn:aws:sqs:eu-central-1:123456789:test-queue',
      awsRegion: 'eu-central-1'
    }))
  });

  const createWebhookMessage = (overrides = {}) => ({
    webhook_id: 'webhook_123',
    delivery_id: 'delivery_456',
    url: 'https://example.com/webhook',
    payload: '{"event":"user.created","data":{}}',
    signature: 't=123456,v1=abc123',
    timestamp: 123456,
    attempt: 1,
    max_attempts: 5,
    ...overrides
  });

  beforeEach(() => {
    jest.clearAllMocks();
    mockFetch.mockReset();
  });

  describe('successful delivery', () => {
    it('should deliver webhook and mark as success', async () => {
      mockFetch.mockResolvedValue({ status: 200, text: () => Promise.resolve('OK') });
      mockedDeliveryRepo.markDeliverySuccess.mockResolvedValue(mockDelivery as any);

      const event = createSQSEvent([createWebhookMessage()]);
      await handler(event, mockContext);

      expect(mockFetch).toHaveBeenCalledWith(
        'https://example.com/webhook',
        expect.objectContaining({ method: 'POST', headers: expect.objectContaining({ 'Content-Type': 'application/json' }) })
      );
      expect(mockedDeliveryRepo.markDeliverySuccess).toHaveBeenCalledWith('webhook_123', 'delivery_456', 200, expect.any(Number));
    });

    it('should handle 201 status as success', async () => {
      mockFetch.mockResolvedValue({ status: 201, text: () => Promise.resolve('Created') });
      mockedDeliveryRepo.markDeliverySuccess.mockResolvedValue(mockDelivery as any);

      await handler(createSQSEvent([createWebhookMessage()]), mockContext);
      expect(mockedDeliveryRepo.markDeliverySuccess).toHaveBeenCalled();
    });
  });

  describe('failed delivery with retry', () => {
    it('should retry on 500 error', async () => {
      mockFetch.mockResolvedValue({ status: 500, text: () => Promise.resolve('Error') });
      mockedDeliveryRepo.incrementDeliveryAttempt.mockResolvedValue(mockDelivery as any);

      await expect(handler(createSQSEvent([createWebhookMessage({ attempt: 1 })]), mockContext)).rejects.toThrow();
      expect(mockedDeliveryRepo.incrementDeliveryAttempt).toHaveBeenCalled();
    });

    it('should retry on network error', async () => {
      mockFetch.mockRejectedValue(new Error('Network error'));
      mockedDeliveryRepo.incrementDeliveryAttempt.mockResolvedValue(mockDelivery as any);

      await expect(handler(createSQSEvent([createWebhookMessage({ attempt: 2 })]), mockContext)).rejects.toThrow();
      expect(mockedDeliveryRepo.incrementDeliveryAttempt).toHaveBeenCalled();
    });
  });

  describe('max attempts exceeded', () => {
    it('should mark as failed after max attempts', async () => {
      mockFetch.mockResolvedValue({ status: 500, text: () => Promise.resolve('Error') });
      mockedDeliveryRepo.markDeliveryFailed.mockResolvedValue(mockDelivery as any);

      await handler(createSQSEvent([createWebhookMessage({ attempt: 5, max_attempts: 5 })]), mockContext);
      expect(mockedDeliveryRepo.markDeliveryFailed).toHaveBeenCalledWith('webhook_123', 'delivery_456', expect.any(String));
    });
  });

  describe('malformed messages', () => {
    it('should skip malformed JSON', async () => {
      const event: SQSEvent = {
        Records: [{ messageId: 'msg_1', receiptHandle: 'r1', body: 'not json', attributes: {} as any, messageAttributes: {}, md5OfBody: '', eventSource: 'aws:sqs', eventSourceARN: 'arn', awsRegion: 'eu-central-1' }]
      };
      await handler(event, mockContext);
      expect(mockFetch).not.toHaveBeenCalled();
    });
  });

  describe('batch processing', () => {
    it('should process multiple messages', async () => {
      mockFetch.mockResolvedValue({ status: 200, text: () => Promise.resolve('OK') });
      mockedDeliveryRepo.markDeliverySuccess.mockResolvedValue(mockDelivery as any);

      await handler(createSQSEvent([createWebhookMessage({ delivery_id: 'del_1' }), createWebhookMessage({ delivery_id: 'del_2' })]), mockContext);
      expect(mockFetch).toHaveBeenCalledTimes(2);
      expect(mockedDeliveryRepo.markDeliverySuccess).toHaveBeenCalledTimes(2);
    });
  });
});
