/**
 * API Keys Handler Tests
 * GET/POST/DELETE /platform/api-keys
 * 
 * Validates: Requirements 4.1, 4.2, 4.3, 4.4 (API Key management)
 */

import { APIGatewayProxyEvent } from 'aws-lambda';

// Mock dependencies
jest.mock('uuid', () => ({
  v4: jest.fn().mockReturnValue('12345678-1234-1234-1234-123456789012')
}));

const mockCreateAPIKey = jest.fn();
const mockListAPIKeysByCustomer = jest.fn();
const mockRevokeAPIKey = jest.fn();
const mockGetAPIKeyById = jest.fn();
jest.mock('../../repositories/api-key.repository', () => ({
  createAPIKey: (...args: unknown[]) => mockCreateAPIKey(...args),
  listAPIKeysByCustomer: (...args: unknown[]) => mockListAPIKeysByCustomer(...args),
  revokeAPIKey: (...args: unknown[]) => mockRevokeAPIKey(...args),
  getAPIKeyById: (...args: unknown[]) => mockGetAPIKeyById(...args)
}));

const mockGetCustomerById = jest.fn();
jest.mock('../../repositories/customer.repository', () => ({
  getCustomerById: (...args: unknown[]) => mockGetCustomerById(...args)
}));

const mockVerifyAccessToken = jest.fn();
jest.mock('../../utils/jwt', () => ({
  verifyAccessToken: (...args: unknown[]) => mockVerifyAccessToken(...args)
}));

const mockLogSecurityEvent = jest.fn();
jest.mock('../../services/security-logger.service', () => ({
  logSecurityEvent: (...args: unknown[]) => mockLogSecurityEvent(...args)
}));

import { handler } from './api-keys.handler';

describe('API Keys Handler', () => {
  const mockEvent = (
    method: string,
    body?: unknown,
    pathParameters?: Record<string, string> | null,
    headers?: Record<string, string>
  ): APIGatewayProxyEvent => ({
    body: body ? JSON.stringify(body) : null,
    headers: {
      Authorization: 'Bearer valid-token',
      ...headers
    },
    multiValueHeaders: {},
    httpMethod: method,
    isBase64Encoded: false,
    path: '/platform/api-keys',
    pathParameters: pathParameters || null,
    queryStringParameters: null,
    multiValueQueryStringParameters: null,
    stageVariables: null,
    requestContext: {
      accountId: '123456789012',
      apiId: 'api123',
      authorizer: null,
      protocol: 'HTTP/1.1',
      httpMethod: method,
      identity: {
        sourceIp: '127.0.0.1',
        accessKey: null,
        accountId: null,
        apiKey: null,
        apiKeyId: null,
        caller: null,
        clientCert: null,
        cognitoAuthenticationProvider: null,
        cognitoAuthenticationType: null,
        cognitoIdentityId: null,
        cognitoIdentityPoolId: null,
        principalOrgId: null,
        user: null,
        userAgent: null,
        userArn: null
      },
      path: '/platform/api-keys',
      stage: 'prod',
      requestId: 'test-request-id',
      requestTimeEpoch: Date.now(),
      resourceId: 'resource123',
      resourcePath: '/platform/api-keys'
    },
    resource: '/platform/api-keys'
  });

  const mockCustomer = {
    id: 'customer_abc123',
    email: 'test@company.com',
    profile: { company_name: 'Test Company' },
    billing: { plan: 'pro' },
    status: 'active'
  };

  const mockAPIKey = {
    id: 'key_abc123',
    customer_id: 'customer_abc123',
    realm_id: 'realm_xyz789',
    type: 'publishable',
    environment: 'live',
    key_prefix: 'pk_live_',
    key_hint: '...XYZ1',
    name: 'Test Key',
    description: 'Test description',
    status: 'active',
    usage_count: 10,
    created_at: '2026-01-25T10:00:00Z'
  };

  beforeEach(() => {
    jest.clearAllMocks();
    
    // Default mocks
    mockVerifyAccessToken.mockResolvedValue({ sub: 'customer_abc123' });
    mockGetCustomerById.mockResolvedValue(mockCustomer);
    mockLogSecurityEvent.mockResolvedValue(undefined);
    mockListAPIKeysByCustomer.mockResolvedValue([mockAPIKey]);
  });


  describe('Authentication', () => {
    it('should return 401 when no Authorization header', async () => {
      const event = mockEvent('GET');
      event.headers = {};

      const result = await handler(event);

      expect(result.statusCode).toBe(401);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });

    it('should return 401 for invalid token format', async () => {
      const event = mockEvent('GET');
      event.headers = { Authorization: 'InvalidFormat' };

      const result = await handler(event);

      expect(result.statusCode).toBe(401);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });

    it('should return 401 for expired token', async () => {
      mockVerifyAccessToken.mockRejectedValue(new Error('Token expired'));

      const result = await handler(mockEvent('GET'));

      expect(result.statusCode).toBe(401);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('INVALID_TOKEN');
    });
  });

  describe('GET /platform/api-keys - List Keys', () => {
    it('should return list of API keys', async () => {
      const result = await handler(mockEvent('GET'));

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.api_keys).toHaveLength(1);
      expect(body.api_keys[0].id).toBe('key_abc123');
      expect(body.api_keys[0].key_prefix).toBe('pk_live_');
      expect(body.total).toBe(1);
    });

    it('should return masked keys without full key or hash', async () => {
      const result = await handler(mockEvent('GET'));

      const body = JSON.parse(result.body);
      expect(body.api_keys[0].full_key).toBeUndefined();
      expect(body.api_keys[0].key_hash).toBeUndefined();
      expect(body.api_keys[0].key_hint).toBe('...XYZ1');
    });

    it('should return empty array when no keys exist', async () => {
      mockListAPIKeysByCustomer.mockResolvedValue([]);

      const result = await handler(mockEvent('GET'));

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.api_keys).toHaveLength(0);
      expect(body.total).toBe(0);
    });
  });

  describe('POST /platform/api-keys - Create Key', () => {
    const validCreateRequest = {
      realm_id: 'realm_xyz789',
      type: 'publishable',
      environment: 'live',
      name: 'New API Key'
    };

    beforeEach(() => {
      mockCreateAPIKey.mockResolvedValue({
        id: 'key_new123',
        type: 'publishable',
        environment: 'live',
        key_prefix: 'pk_live_',
        key_hint: '...ABCD',
        name: 'New API Key',
        status: 'active',
        created_at: '2026-01-25T10:00:00Z',
        full_key: 'pk_live_mock_key_for_testing_only'
      });
    });

    it('should create API key successfully', async () => {
      const result = await handler(mockEvent('POST', validCreateRequest));

      expect(result.statusCode).toBe(201);
      const body = JSON.parse(result.body);
      expect(body.message).toBe('API key created successfully');
      expect(body.api_key.id).toBe('key_new123');
      expect(body.api_key.full_key).toMatch(/^pk_live_/);
      expect(body.warning).toContain('will not be shown again');
    });

    it('should log security event on key creation', async () => {
      await handler(mockEvent('POST', validCreateRequest));

      expect(mockLogSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'api_key_created'
        })
      );
    });

    it('should return 400 for missing body', async () => {
      const event = mockEvent('POST');
      event.body = null;

      const result = await handler(event);

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('INVALID_REQUEST');
    });

    it('should return 400 for invalid JSON', async () => {
      const event = mockEvent('POST');
      event.body = 'invalid json';

      const result = await handler(event);

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('INVALID_JSON');
    });

    it('should return 400 for missing required fields', async () => {
      const result = await handler(mockEvent('POST', { name: 'Test' }));

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('MISSING_FIELDS');
    });

    it('should return 400 for invalid type', async () => {
      const result = await handler(mockEvent('POST', {
        ...validCreateRequest,
        type: 'invalid'
      }));

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('INVALID_TYPE');
    });

    it('should return 400 for invalid environment', async () => {
      const result = await handler(mockEvent('POST', {
        ...validCreateRequest,
        environment: 'staging'
      }));

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('INVALID_ENVIRONMENT');
    });

    it('should return 400 for name too long', async () => {
      const result = await handler(mockEvent('POST', {
        ...validCreateRequest,
        name: 'A'.repeat(101)
      }));

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('INVALID_NAME');
    });

    it('should return 404 when customer not found', async () => {
      mockGetCustomerById.mockResolvedValue(null);

      const result = await handler(mockEvent('POST', validCreateRequest));

      expect(result.statusCode).toBe(404);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('CUSTOMER_NOT_FOUND');
    });

    it('should return 403 when key limit exceeded for free plan', async () => {
      mockGetCustomerById.mockResolvedValue({
        ...mockCustomer,
        billing: { plan: 'free' }
      });
      mockListAPIKeysByCustomer.mockResolvedValue(
        Array(5).fill(mockAPIKey)
      );

      const result = await handler(mockEvent('POST', validCreateRequest));

      expect(result.statusCode).toBe(403);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('KEY_LIMIT_EXCEEDED');
    });

    it('should allow unlimited keys for enterprise plan', async () => {
      mockGetCustomerById.mockResolvedValue({
        ...mockCustomer,
        billing: { plan: 'enterprise' }
      });
      mockListAPIKeysByCustomer.mockResolvedValue(
        Array(100).fill(mockAPIKey)
      );

      const result = await handler(mockEvent('POST', validCreateRequest));

      expect(result.statusCode).toBe(201);
    });
  });


  describe('DELETE /platform/api-keys/{id} - Revoke Key', () => {
    beforeEach(() => {
      mockGetAPIKeyById.mockResolvedValue(mockAPIKey);
      mockRevokeAPIKey.mockResolvedValue({
        ...mockAPIKey,
        status: 'revoked',
        revoked_at: '2026-01-25T12:00:00Z'
      });
    });

    it('should revoke API key successfully', async () => {
      const result = await handler(mockEvent('DELETE', null, { id: 'key_abc123' }));

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.message).toBe('API key revoked successfully');
      expect(body.api_key.status).toBe('revoked');
    });

    it('should log security event on key revocation', async () => {
      await handler(mockEvent('DELETE', null, { id: 'key_abc123' }));

      expect(mockLogSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'api_key_revoked'
        })
      );
    });

    it('should return 400 when key ID is missing', async () => {
      const result = await handler(mockEvent('DELETE', null, null));

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('MISSING_KEY_ID');
    });

    it('should return 404 when key not found', async () => {
      mockGetAPIKeyById.mockResolvedValue(null);

      const result = await handler(mockEvent('DELETE', null, { id: 'key_nonexistent' }));

      expect(result.statusCode).toBe(404);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('KEY_NOT_FOUND');
    });

    it('should return 400 when key already revoked', async () => {
      mockGetAPIKeyById.mockResolvedValue({
        ...mockAPIKey,
        status: 'revoked'
      });

      const result = await handler(mockEvent('DELETE', null, { id: 'key_abc123' }));

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('KEY_ALREADY_REVOKED');
    });
  });

  describe('Method Not Allowed', () => {
    it('should return 405 for PUT method', async () => {
      const event = mockEvent('PUT');

      const result = await handler(event);

      expect(result.statusCode).toBe(405);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('METHOD_NOT_ALLOWED');
    });

    it('should return 405 for PATCH method', async () => {
      const event = mockEvent('PATCH');

      const result = await handler(event);

      expect(result.statusCode).toBe(405);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('METHOD_NOT_ALLOWED');
    });
  });

  describe('Error Handling', () => {
    it('should return 500 for unexpected errors', async () => {
      mockListAPIKeysByCustomer.mockRejectedValueOnce('Unexpected failure');

      const result = await handler(mockEvent('GET'));

      expect(result.statusCode).toBe(500);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('INTERNAL_ERROR');
    });

    it('should log error on unexpected failure', async () => {
      mockListAPIKeysByCustomer.mockRejectedValueOnce('Unexpected failure');

      await handler(mockEvent('GET'));

      expect(mockLogSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'api_keys_error'
        })
      );
    });
  });

  describe('Security Headers', () => {
    it('should include security headers in response', async () => {
      const result = await handler(mockEvent('GET'));

      expect(result.headers?.['X-Content-Type-Options']).toBe('nosniff');
      expect(result.headers?.['X-Frame-Options']).toBe('DENY');
      expect(result.headers?.['Content-Type']).toBe('application/json');
      expect(result.headers?.['Access-Control-Allow-Origin']).toBe('*');
    });
  });
});
