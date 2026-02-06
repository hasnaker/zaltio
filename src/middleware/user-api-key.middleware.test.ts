/**
 * User API Key Middleware Tests
 * Task 2.4: Implement API Key authentication middleware
 * 
 * Tests:
 * - Key extraction from headers
 * - Key validation
 * - Scope enforcement
 * - IP restrictions
 * - Error handling
 * 
 * Validates: Requirements 2.7, 2.8
 */

import { APIGatewayProxyEvent } from 'aws-lambda';
import {
  isUserAPIKeyAuth,
  extractUserAPIKey,
  validateUserAPIKey,
  createUserAPIKeyErrorResponse,
  withUserAPIKeyAuth,
  injectUserAPIKeyContext,
  keyHasScope
} from './user-api-key.middleware';
import { userAPIKeyService, UserAPIKeyError } from '../services/user-api-key.service';

// Mock the service
jest.mock('../services/user-api-key.service', () => ({
  userAPIKeyService: {
    validateKey: jest.fn()
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

const mockService = userAPIKeyService as jest.Mocked<typeof userAPIKeyService>;

// Helper to create mock event
function createMockEvent(overrides: Partial<APIGatewayProxyEvent> = {}): APIGatewayProxyEvent {
  return {
    httpMethod: 'GET',
    path: '/test',
    headers: {},
    body: null,
    queryStringParameters: null,
    pathParameters: null,
    requestContext: {
      identity: {
        sourceIp: '192.168.1.100'
      }
    } as any,
    ...overrides
  } as APIGatewayProxyEvent;
}

describe('User API Key Middleware', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('isUserAPIKeyAuth', () => {
    it('should return true for valid user API key', () => {
      const event = createMockEvent({
        headers: {
          Authorization: 'Bearer zalt_key_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef'
        }
      });

      expect(isUserAPIKeyAuth(event)).toBe(true);
    });

    it('should return false for regular Bearer token', () => {
      const event = createMockEvent({
        headers: {
          Authorization: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
        }
      });

      expect(isUserAPIKeyAuth(event)).toBe(false);
    });

    it('should return false for missing Authorization header', () => {
      const event = createMockEvent({
        headers: {}
      });

      expect(isUserAPIKeyAuth(event)).toBe(false);
    });

    it('should return false for SDK API key', () => {
      const event = createMockEvent({
        headers: {
          Authorization: 'Bearer pk_live_mock_key_for_testing_only'
        }
      });

      expect(isUserAPIKeyAuth(event)).toBe(false);
    });
  });

  describe('extractUserAPIKey', () => {
    it('should extract user API key from Bearer token', () => {
      const event = createMockEvent({
        headers: {
          Authorization: 'Bearer zalt_key_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef'
        }
      });

      expect(extractUserAPIKey(event)).toBe('zalt_key_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef');
    });

    it('should return null for missing header', () => {
      const event = createMockEvent({
        headers: {}
      });

      expect(extractUserAPIKey(event)).toBeNull();
    });

    it('should return null for non-Bearer token', () => {
      const event = createMockEvent({
        headers: {
          Authorization: 'Basic dXNlcjpwYXNz'
        }
      });

      expect(extractUserAPIKey(event)).toBeNull();
    });

    it('should return null for non-user API key', () => {
      const event = createMockEvent({
        headers: {
          Authorization: 'Bearer some_other_token'
        }
      });

      expect(extractUserAPIKey(event)).toBeNull();
    });

    it('should handle lowercase authorization header', () => {
      const event = createMockEvent({
        headers: {
          authorization: 'Bearer zalt_key_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef'
        }
      });

      expect(extractUserAPIKey(event)).toBe('zalt_key_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef');
    });
  });

  describe('validateUserAPIKey', () => {
    it('should validate active key and return context', async () => {
      const mockContext = {
        key: {
          id: 'key_abc',
          user_id: 'user_123',
          realm_id: 'realm_456',
          tenant_id: 'tenant_789',
          name: 'Test Key',
          key_prefix: 'zalt_key_ABC...',
          key_hash: 'hash123',
          scopes: ['profile:read', 'sessions:read'],
          status: 'active' as const,
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-01T00:00:00Z',
          usage_count: 5
        },
        user_id: 'user_123',
        realm_id: 'realm_456',
        tenant_id: 'tenant_789',
        scopes: ['profile:read', 'sessions:read']
      };

      mockService.validateKey.mockResolvedValueOnce(mockContext);

      const event = createMockEvent({
        headers: {
          Authorization: 'Bearer zalt_key_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef'
        }
      });

      const result = await validateUserAPIKey(event);

      expect(result.valid).toBe(true);
      expect(result.context?.user_id).toBe('user_123');
      expect(result.context?.scopes).toEqual(['profile:read', 'sessions:read']);
    });

    it('should skip validation when configured', async () => {
      const event = createMockEvent({
        headers: {}
      });

      const result = await validateUserAPIKey(event, { skipValidation: true });

      expect(result.valid).toBe(true);
      expect(mockService.validateKey).not.toHaveBeenCalled();
    });

    it('should return error for missing key', async () => {
      const event = createMockEvent({
        headers: {}
      });

      const result = await validateUserAPIKey(event);

      expect(result.valid).toBe(false);
      expect(result.error?.code).toBe('MISSING_API_KEY');
      expect(result.error?.statusCode).toBe(401);
    });

    it('should return error for invalid key format', async () => {
      const event = createMockEvent({
        headers: {
          Authorization: 'Bearer zalt_key_short'
        }
      });

      const result = await validateUserAPIKey(event);

      expect(result.valid).toBe(false);
      expect(result.error?.code).toBe('INVALID_KEY_FORMAT');
    });

    it('should return error for revoked key', async () => {
      mockService.validateKey.mockRejectedValueOnce(
        new UserAPIKeyError('API_KEY_INVALID', 'API key not found or revoked', 401)
      );

      const event = createMockEvent({
        headers: {
          Authorization: 'Bearer zalt_key_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef'
        }
      });

      const result = await validateUserAPIKey(event);

      expect(result.valid).toBe(false);
      expect(result.error?.code).toBe('API_KEY_INVALID');
      expect(result.error?.statusCode).toBe(401);
    });

    it('should return error for expired key', async () => {
      mockService.validateKey.mockRejectedValueOnce(
        new UserAPIKeyError('API_KEY_EXPIRED', 'API key has expired', 401)
      );

      const event = createMockEvent({
        headers: {
          Authorization: 'Bearer zalt_key_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef'
        }
      });

      const result = await validateUserAPIKey(event);

      expect(result.valid).toBe(false);
      expect(result.error?.code).toBe('API_KEY_EXPIRED');
      expect(result.error?.statusCode).toBe(401);
    });

    it('should enforce required scope', async () => {
      const mockContext = {
        key: {
          id: 'key_abc',
          user_id: 'user_123',
          realm_id: 'realm_456',
          name: 'Test Key',
          key_prefix: 'zalt_key_ABC...',
          key_hash: 'hash123',
          scopes: ['profile:read'],
          status: 'active' as const,
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-01T00:00:00Z',
          usage_count: 5
        },
        user_id: 'user_123',
        realm_id: 'realm_456',
        scopes: ['profile:read']
      };

      mockService.validateKey.mockResolvedValueOnce(mockContext);

      const event = createMockEvent({
        headers: {
          Authorization: 'Bearer zalt_key_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef'
        }
      });

      const result = await validateUserAPIKey(event, { requiredScope: 'sessions:revoke' });

      expect(result.valid).toBe(false);
      expect(result.error?.code).toBe('INSUFFICIENT_SCOPE');
      expect(result.error?.statusCode).toBe(403);
    });

    it('should allow full:access scope for any required scope', async () => {
      const mockContext = {
        key: {
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
        },
        user_id: 'user_123',
        realm_id: 'realm_456',
        scopes: ['full:access']
      };

      mockService.validateKey.mockResolvedValueOnce(mockContext);

      const event = createMockEvent({
        headers: {
          Authorization: 'Bearer zalt_key_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef'
        }
      });

      const result = await validateUserAPIKey(event, { requiredScope: 'sessions:revoke' });

      expect(result.valid).toBe(true);
    });

    it('should enforce IP restrictions', async () => {
      const mockContext = {
        key: {
          id: 'key_abc',
          user_id: 'user_123',
          realm_id: 'realm_456',
          name: 'Test Key',
          key_prefix: 'zalt_key_ABC...',
          key_hash: 'hash123',
          scopes: ['full:access'],
          status: 'active' as const,
          ip_restrictions: ['10.0.0.0/8'],
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-01T00:00:00Z',
          usage_count: 5
        },
        user_id: 'user_123',
        realm_id: 'realm_456',
        scopes: ['full:access']
      };

      mockService.validateKey.mockResolvedValueOnce(mockContext);

      const event = createMockEvent({
        headers: {
          Authorization: 'Bearer zalt_key_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef'
        },
        requestContext: {
          identity: {
            sourceIp: '192.168.1.100' // Not in allowed range
          }
        } as any
      });

      const result = await validateUserAPIKey(event);

      expect(result.valid).toBe(false);
      expect(result.error?.code).toBe('IP_NOT_ALLOWED');
      expect(result.error?.statusCode).toBe(403);
    });

    it('should allow Bearer tokens when configured', async () => {
      const event = createMockEvent({
        headers: {
          Authorization: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
        }
      });

      const result = await validateUserAPIKey(event, { allowBearerTokens: true });

      expect(result.valid).toBe(true);
      expect(mockService.validateKey).not.toHaveBeenCalled();
    });
  });

  describe('createUserAPIKeyErrorResponse', () => {
    it('should create 401 response for auth errors', () => {
      const response = createUserAPIKeyErrorResponse({
        code: 'API_KEY_INVALID',
        message: 'Invalid API key',
        statusCode: 401
      });

      expect(response.statusCode).toBe(401);
      expect(response.headers?.['WWW-Authenticate']).toBe('Bearer');
      
      const body = JSON.parse(response.body);
      expect(body.error.code).toBe('API_KEY_INVALID');
    });

    it('should create 403 response for scope errors', () => {
      const response = createUserAPIKeyErrorResponse({
        code: 'INSUFFICIENT_SCOPE',
        message: 'Required scope: sessions:revoke',
        statusCode: 403
      });

      expect(response.statusCode).toBe(403);
      expect(response.headers?.['WWW-Authenticate']).toBeUndefined();
    });
  });

  describe('withUserAPIKeyAuth', () => {
    it('should call handler with context on valid key', async () => {
      const mockContext = {
        key: {
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
        },
        user_id: 'user_123',
        realm_id: 'realm_456',
        scopes: ['full:access']
      };

      mockService.validateKey.mockResolvedValueOnce(mockContext);

      const mockHandler = jest.fn().mockResolvedValue({
        statusCode: 200,
        body: JSON.stringify({ success: true })
      });

      const wrappedHandler = withUserAPIKeyAuth(mockHandler);

      const event = createMockEvent({
        headers: {
          Authorization: 'Bearer zalt_key_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef'
        }
      });

      const result = await wrappedHandler(event);

      expect(result.statusCode).toBe(200);
      expect(mockHandler).toHaveBeenCalledWith(event, mockContext);
    });

    it('should return error response on invalid key', async () => {
      const mockHandler = jest.fn();

      const wrappedHandler = withUserAPIKeyAuth(mockHandler);

      const event = createMockEvent({
        headers: {}
      });

      const result = await wrappedHandler(event);

      expect(result.statusCode).toBe(401);
      expect(mockHandler).not.toHaveBeenCalled();
    });
  });

  describe('injectUserAPIKeyContext', () => {
    it('should inject context into event', () => {
      const event = createMockEvent();
      const context = {
        key: {
          id: 'key_abc',
          user_id: 'user_123',
          realm_id: 'realm_456',
          tenant_id: 'tenant_789',
          name: 'Test Key',
          key_prefix: 'zalt_key_ABC...',
          key_hash: 'hash123',
          scopes: ['profile:read'],
          status: 'active' as const,
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-01T00:00:00Z',
          usage_count: 5
        },
        user_id: 'user_123',
        realm_id: 'realm_456',
        tenant_id: 'tenant_789',
        scopes: ['profile:read']
      };

      const injectedEvent = injectUserAPIKeyContext(event, context);

      expect(injectedEvent.requestContext?.authorizer?.apiKey).toBe(true);
      expect(injectedEvent.requestContext?.authorizer?.userId).toBe('user_123');
      expect(injectedEvent.requestContext?.authorizer?.realmId).toBe('realm_456');
      expect(injectedEvent.requestContext?.authorizer?.tenantId).toBe('tenant_789');
    });
  });

  describe('keyHasScope', () => {
    it('should return true when key has scope', () => {
      const context = {
        key: {} as any,
        user_id: 'user_123',
        realm_id: 'realm_456',
        scopes: ['profile:read', 'sessions:read']
      };

      expect(keyHasScope(context, 'profile:read')).toBe(true);
    });

    it('should return false when key lacks scope', () => {
      const context = {
        key: {} as any,
        user_id: 'user_123',
        realm_id: 'realm_456',
        scopes: ['profile:read']
      };

      expect(keyHasScope(context, 'sessions:revoke')).toBe(false);
    });

    it('should return true for any scope with full:access', () => {
      const context = {
        key: {} as any,
        user_id: 'user_123',
        realm_id: 'realm_456',
        scopes: ['full:access']
      };

      expect(keyHasScope(context, 'sessions:revoke')).toBe(true);
      expect(keyHasScope(context, 'tenants:write')).toBe(true);
    });
  });
});
