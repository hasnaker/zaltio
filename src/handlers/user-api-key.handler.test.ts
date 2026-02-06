/**
 * User API Key Handler Tests
 * Task 2.3: Implement API Key Handler (Lambda)
 * 
 * Tests:
 * - POST /api-keys - Create API key
 * - GET /api-keys - List API keys
 * - GET /api-keys/{id} - Get API key
 * - DELETE /api-keys/{id} - Revoke API key
 * - PATCH /api-keys/{id} - Update API key
 * 
 * Validates: Requirements 2.7, 2.9
 */

import { APIGatewayProxyEvent } from 'aws-lambda';
import { handler } from './user-api-key.handler';
import { userAPIKeyService, UserAPIKeyError } from '../services/user-api-key.service';
import * as rateLimitService from '../services/ratelimit.service';

// Mock services
jest.mock('../services/user-api-key.service', () => ({
  userAPIKeyService: {
    createKey: jest.fn(),
    validateKey: jest.fn(),
    listKeys: jest.fn(),
    getKey: jest.fn(),
    revokeKey: jest.fn(),
    updateKey: jest.fn(),
    revokeAllKeys: jest.fn(),
    hasActiveKeys: jest.fn(),
    checkKeyScope: jest.fn()
  },
  UserAPIKeyError: class UserAPIKeyError extends Error {
    code: string;
    statusCode: number;
    constructor(code: string, message: string, statusCode: number = 400) {
      super(message);
      this.name = 'UserAPIKeyError';
      this.code = code;
      this.statusCode = statusCode;
    }
  }
}));
jest.mock('../services/ratelimit.service');

const mockService = userAPIKeyService as jest.Mocked<typeof userAPIKeyService>;
const mockRateLimitService = rateLimitService as jest.Mocked<typeof rateLimitService>;

// Helper to create mock event
function createMockEvent(overrides: Partial<APIGatewayProxyEvent> = {}): APIGatewayProxyEvent {
  return {
    httpMethod: 'GET',
    path: '/api-keys',
    headers: {
      Authorization: 'Bearer test_token'
    },
    body: null,
    queryStringParameters: null,
    pathParameters: null,
    requestContext: {
      authorizer: {
        userId: 'user_123',
        realmId: 'realm_456',
        tenantId: 'tenant_789'
      }
    } as any,
    ...overrides
  } as APIGatewayProxyEvent;
}

describe('User API Key Handler', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    
    // Default rate limit to allow
    mockRateLimitService.checkRateLimit.mockResolvedValue({
      allowed: true,
      remaining: 9,
      resetAt: Date.now() + 3600000
    });
  });

  describe('OPTIONS (CORS preflight)', () => {
    it('should return 200 for OPTIONS request', async () => {
      const event = createMockEvent({ httpMethod: 'OPTIONS' });
      
      const result = await handler(event);
      
      expect(result.statusCode).toBe(200);
      expect(result.headers).toHaveProperty('Access-Control-Allow-Origin', '*');
    });
  });

  describe('POST /api-keys', () => {
    it('should create API key successfully', async () => {
      const mockResult = {
        key: {
          id: 'key_abc',
          user_id: 'user_123',
          realm_id: 'realm_456',
          name: 'My API Key',
          key_prefix: 'zalt_key_ABC...',
          scopes: ['full:access'],
          status: 'active' as const,
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-01T00:00:00Z',
          usage_count: 0
        },
        full_key: 'zalt_key_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef'
      };

      mockService.createKey.mockResolvedValueOnce(mockResult);

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/api-keys',
        body: JSON.stringify({ name: 'My API Key' })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(201);
      expect(body.message).toBe('API key created successfully');
      expect(body.full_key).toBe('zalt_key_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef');
    });

    it('should reject without authentication', async () => {
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/api-keys',
        headers: {},
        requestContext: {} as any,
        body: JSON.stringify({ name: 'My API Key' })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(401);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });

    it('should reject when rate limited', async () => {
      mockRateLimitService.checkRateLimit.mockResolvedValueOnce({
        allowed: false,
        remaining: 0,
        resetAt: Date.now() + 3600000,
        retryAfter: 3600
      });

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/api-keys',
        body: JSON.stringify({ name: 'My API Key' })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(429);
      expect(body.error.code).toBe('RATE_LIMIT_EXCEEDED');
    });

    it('should reject missing name', async () => {
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/api-keys',
        body: JSON.stringify({})
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(400);
      expect(body.error.code).toBe('MISSING_NAME');
    });

    it('should reject invalid JSON', async () => {
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/api-keys',
        body: 'not json'
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_JSON');
    });
  });

  describe('GET /api-keys', () => {
    it('should list API keys', async () => {
      const mockKeys = [
        {
          id: 'key_1',
          user_id: 'user_123',
          realm_id: 'realm_456',
          name: 'Key 1',
          key_prefix: 'zalt_key_ABC...',
          scopes: ['full:access'],
          status: 'active' as const,
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-01T00:00:00Z',
          usage_count: 10
        }
      ];

      mockService.listKeys.mockResolvedValueOnce(mockKeys);

      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/api-keys'
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(200);
      expect(body.keys).toHaveLength(1);
      expect(body.count).toBe(1);
    });

    it('should reject without authentication', async () => {
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/api-keys',
        headers: {},
        requestContext: {} as any
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(401);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });
  });

  describe('GET /api-keys/{id}', () => {
    it('should get API key details', async () => {
      const mockKey = {
        id: 'key_abc',
        user_id: 'user_123',
        realm_id: 'realm_456',
        name: 'Test Key',
        key_prefix: 'zalt_key_ABC...',
        key_hash: 'hash123',
        scopes: ['full:access'],
        status: 'active' as const,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z',
        usage_count: 5
      };

      mockService.getKey.mockResolvedValueOnce(mockKey);

      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/api-keys/key_abc'
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(200);
      expect(body.key.id).toBe('key_abc');
    });

    it('should return 404 for non-existent key', async () => {
      mockService.getKey.mockResolvedValueOnce(null);

      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/api-keys/nonexistent'
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(404);
      expect(body.error.code).toBe('KEY_NOT_FOUND');
    });
  });

  describe('DELETE /api-keys/{id}', () => {
    it('should revoke API key', async () => {
      mockService.revokeKey.mockResolvedValueOnce({
        id: 'key_abc',
        status: 'revoked'
      } as any);

      const event = createMockEvent({
        httpMethod: 'DELETE',
        path: '/api-keys/key_abc'
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(200);
      expect(body.message).toBe('API key revoked successfully');
    });

    it('should handle revoke error', async () => {
      mockService.revokeKey.mockRejectedValueOnce(
        new UserAPIKeyError('KEY_NOT_FOUND', 'API key not found', 404)
      );

      const event = createMockEvent({
        httpMethod: 'DELETE',
        path: '/api-keys/nonexistent'
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(404);
      expect(body.error.code).toBe('KEY_NOT_FOUND');
    });
  });

  describe('PATCH /api-keys/{id}', () => {
    it('should update API key', async () => {
      const mockUpdatedKey = {
        id: 'key_abc',
        user_id: 'user_123',
        realm_id: 'realm_456',
        name: 'Updated Name',
        key_prefix: 'zalt_key_ABC...',
        key_hash: 'hash123',
        scopes: ['full:access'],
        status: 'active' as const,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-02-01T00:00:00Z',
        usage_count: 5
      };

      mockService.updateKey.mockResolvedValueOnce(mockUpdatedKey);

      const event = createMockEvent({
        httpMethod: 'PATCH',
        path: '/api-keys/key_abc',
        body: JSON.stringify({ name: 'Updated Name' })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(200);
      expect(body.message).toBe('API key updated successfully');
      expect(body.key.name).toBe('Updated Name');
    });

    it('should reject empty update', async () => {
      const event = createMockEvent({
        httpMethod: 'PATCH',
        path: '/api-keys/key_abc',
        body: JSON.stringify({})
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(400);
      expect(body.error.code).toBe('NO_UPDATES');
    });
  });

  describe('Unknown endpoint', () => {
    it('should return 404 for unknown path', async () => {
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/unknown'
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(404);
      expect(body.error.code).toBe('NOT_FOUND');
    });
  });
});
