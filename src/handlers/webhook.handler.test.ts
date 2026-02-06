/**
 * Webhook Handler Tests
 * Validates: Requirements 12.6, 12.7, 12.9
 */

// Mock the service module before importing handler
const mockCreate = jest.fn();
const mockList = jest.fn();
const mockGetById = jest.fn();
const mockDelete = jest.fn();
const mockTest = jest.fn();
const mockGetDeliveryLogs = jest.fn();
const mockRotateSecret = jest.fn();

jest.mock('../services/webhook.service', () => ({
  WebhookService: jest.fn().mockImplementation(() => ({
    create: mockCreate,
    list: mockList,
    getById: mockGetById,
    delete: mockDelete,
    test: mockTest,
    getDeliveryLogs: mockGetDeliveryLogs,
    rotateSecret: mockRotateSecret
  })),
  WebhookServiceError: class WebhookServiceError extends Error {
    constructor(public code: string, message: string) {
      super(message);
      this.name = 'WebhookServiceError';
    }
  },
  WebhookErrorCode: {
    INVALID_URL: 'INVALID_URL',
    INVALID_EVENT: 'INVALID_EVENT',
    WEBHOOK_NOT_FOUND: 'WEBHOOK_NOT_FOUND',
    WEBHOOK_DISABLED: 'WEBHOOK_DISABLED',
    MAX_WEBHOOKS_EXCEEDED: 'MAX_WEBHOOKS_EXCEEDED',
    DISPATCH_FAILED: 'DISPATCH_FAILED',
    INVALID_SIGNATURE: 'INVALID_SIGNATURE',
    SIGNATURE_EXPIRED: 'SIGNATURE_EXPIRED'
  }
}));

jest.mock('../services/ratelimit.service', () => ({
  checkRateLimit: jest.fn().mockResolvedValue({ allowed: true, remaining: 99 }),
  RateLimitEndpoint: { API_GENERAL: 'api_general' }
}));

import { handler } from './webhook.handler';
import { WebhookServiceError, WebhookErrorCode } from '../services/webhook.service';
import { APIGatewayProxyEvent } from 'aws-lambda';

describe('Webhook Handler', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  const createEvent = (overrides: Partial<APIGatewayProxyEvent> = {}): APIGatewayProxyEvent => ({
    httpMethod: 'GET',
    resource: '/webhooks',
    path: '/webhooks',
    pathParameters: null,
    queryStringParameters: null,
    headers: { 'x-realm-id': 'realm_123' },
    body: null,
    isBase64Encoded: false,
    requestContext: {
      authorizer: { claims: { sub: 'user_123', realm_id: 'realm_123' } },
      identity: { sourceIp: '127.0.0.1' },
      requestId: 'req_123'
    } as any,
    multiValueHeaders: {},
    multiValueQueryStringParameters: null,
    stageVariables: null,
    ...overrides
  });

  describe('POST /webhooks', () => {
    it('should create webhook', async () => {
      mockCreate.mockResolvedValue({
        webhook: { id: 'wh_123', url: 'https://example.com', events: ['user.created'], status: 'active' },
        secret: 'whsec_secret123'
      });

      const event = createEvent({
        httpMethod: 'POST',
        resource: '/webhooks',
        body: JSON.stringify({ url: 'https://example.com', events: ['user.created'] })
      });

      const result = await handler(event);
      expect(result.statusCode).toBe(201);
      const body = JSON.parse(result.body);
      expect(body.data.secret).toBe('whsec_secret123');
    });

    it('should return 400 for missing body', async () => {
      const event = createEvent({ httpMethod: 'POST', resource: '/webhooks', body: null });
      const result = await handler(event);
      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('MISSING_BODY');
    });

    it('should return 400 for invalid input', async () => {
      const event = createEvent({
        httpMethod: 'POST',
        resource: '/webhooks',
        body: JSON.stringify({ url: 'https://example.com' }) // missing events
      });
      const result = await handler(event);
      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('INVALID_INPUT');
    });
  });

  describe('GET /webhooks', () => {
    it('should list webhooks', async () => {
      mockList.mockResolvedValue({
        webhooks: [{ id: 'wh_1' }, { id: 'wh_2' }],
        next_cursor: undefined
      });

      const event = createEvent({ httpMethod: 'GET', resource: '/webhooks' });
      const result = await handler(event);
      
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.data.webhooks).toHaveLength(2);
    });
  });

  describe('GET /webhooks/{id}', () => {
    it('should get webhook by ID', async () => {
      mockGetById.mockResolvedValue({ id: 'wh_123', url: 'https://example.com' });

      const event = createEvent({
        httpMethod: 'GET',
        resource: '/webhooks/{id}',
        pathParameters: { id: 'wh_123' }
      });
      const result = await handler(event);
      
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.data.webhook.id).toBe('wh_123');
    });

    it('should return 404 for not found', async () => {
      mockGetById.mockResolvedValue(null);

      const event = createEvent({
        httpMethod: 'GET',
        resource: '/webhooks/{id}',
        pathParameters: { id: 'nonexistent' }
      });
      const result = await handler(event);
      
      expect(result.statusCode).toBe(404);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('NOT_FOUND');
    });
  });

  describe('DELETE /webhooks/{id}', () => {
    it('should delete webhook', async () => {
      mockDelete.mockResolvedValue(true);

      const event = createEvent({
        httpMethod: 'DELETE',
        resource: '/webhooks/{id}',
        pathParameters: { id: 'wh_123' }
      });
      const result = await handler(event);
      
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.data.deleted).toBe(true);
    });

    it('should return 404 when webhook not found', async () => {
      mockDelete.mockResolvedValue(false);

      const event = createEvent({
        httpMethod: 'DELETE',
        resource: '/webhooks/{id}',
        pathParameters: { id: 'nonexistent' }
      });
      const result = await handler(event);
      
      expect(result.statusCode).toBe(404);
    });
  });

  describe('POST /webhooks/{id}/test', () => {
    it('should test webhook', async () => {
      mockTest.mockResolvedValue({ id: 'del_123', event_type: 'test', status: 'pending' });

      const event = createEvent({
        httpMethod: 'POST',
        resource: '/webhooks/{id}/test',
        pathParameters: { id: 'wh_123' }
      });
      const result = await handler(event);
      
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.data.delivery.event_type).toBe('test');
    });
  });

  describe('GET /webhooks/{id}/deliveries', () => {
    it('should get delivery logs', async () => {
      mockGetDeliveryLogs.mockResolvedValue({
        deliveries: [{ id: 'del_1' }, { id: 'del_2' }],
        next_cursor: undefined
      });

      const event = createEvent({
        httpMethod: 'GET',
        resource: '/webhooks/{id}/deliveries',
        pathParameters: { id: 'wh_123' }
      });
      const result = await handler(event);
      
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.data.deliveries).toHaveLength(2);
    });
  });

  describe('POST /webhooks/{id}/rotate-secret', () => {
    it('should rotate secret', async () => {
      mockRotateSecret.mockResolvedValue({
        webhook: { id: 'wh_123' },
        secret: 'whsec_new_secret'
      });

      const event = createEvent({
        httpMethod: 'POST',
        resource: '/webhooks/{id}/rotate-secret',
        pathParameters: { id: 'wh_123' }
      });
      const result = await handler(event);
      
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.data.secret).toBe('whsec_new_secret');
    });
  });

  describe('error handling', () => {
    it('should handle WebhookServiceError', async () => {
      const { WebhookServiceError } = require('../services/webhook.service');
      mockCreate.mockRejectedValue(new WebhookServiceError('INVALID_URL', 'Invalid URL'));

      const event = createEvent({
        httpMethod: 'POST',
        resource: '/webhooks',
        body: JSON.stringify({ url: 'http://bad.com', events: ['user.created'] })
      });
      const result = await handler(event);
      
      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('INVALID_URL');
    });

    it('should handle missing realm ID', async () => {
      const event = createEvent({
        httpMethod: 'GET',
        resource: '/webhooks',
        headers: {},
        requestContext: { authorizer: null, identity: { sourceIp: '127.0.0.1' }, requestId: 'req_123' } as any
      });
      const result = await handler(event);
      
      expect(result.statusCode).toBe(401);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });

    it('should handle rate limiting', async () => {
      const { checkRateLimit } = require('../services/ratelimit.service');
      checkRateLimit.mockResolvedValueOnce({ allowed: false, retryAfter: 60 });

      const event = createEvent({ httpMethod: 'GET', resource: '/webhooks' });
      const result = await handler(event);
      
      expect(result.statusCode).toBe(429);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('RATE_LIMITED');
    });

    it('should return 404 for unknown endpoint', async () => {
      const event = createEvent({
        httpMethod: 'PATCH',
        resource: '/webhooks/unknown'
      });
      const result = await handler(event);
      
      expect(result.statusCode).toBe(404);
    });
  });
});
