/**
 * Customer Me Handler Tests
 * GET /platform/me
 * 
 * Validates: Requirements 2.2 (Customer profile)
 */

import { APIGatewayProxyEvent } from 'aws-lambda';

// Mock dependencies
const mockGetCustomerById = jest.fn();
jest.mock('../../repositories/customer.repository', () => ({
  getCustomerById: (...args: unknown[]) => mockGetCustomerById(...args)
}));

const mockListAPIKeysByCustomer = jest.fn();
jest.mock('../../repositories/api-key.repository', () => ({
  listAPIKeysByCustomer: (...args: unknown[]) => mockListAPIKeysByCustomer(...args)
}));

const mockVerifyAccessToken = jest.fn();
jest.mock('../../utils/jwt', () => ({
  verifyAccessToken: (...args: unknown[]) => mockVerifyAccessToken(...args)
}));

const mockLogSecurityEvent = jest.fn();
jest.mock('../../services/security-logger.service', () => ({
  logSecurityEvent: (...args: unknown[]) => mockLogSecurityEvent(...args)
}));

import { handler } from './customer-me.handler';

describe('Customer Me Handler', () => {
  const mockEvent = (token?: string): APIGatewayProxyEvent => ({
    body: null,
    headers: token ? { Authorization: `Bearer ${token}` } : {},
    multiValueHeaders: {},
    httpMethod: 'GET',
    isBase64Encoded: false,
    path: '/platform/me',
    pathParameters: null,
    queryStringParameters: null,
    multiValueQueryStringParameters: null,
    stageVariables: null,
    requestContext: {
      accountId: '123456789012',
      apiId: 'api123',
      authorizer: null,
      protocol: 'HTTP/1.1',
      httpMethod: 'GET',
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
      path: '/platform/me',
      stage: 'prod',
      requestId: 'test-request-id',
      requestTimeEpoch: Date.now(),
      resourceId: 'resource123',
      resourcePath: '/platform/me'
    },
    resource: '/platform/me'
  });

  const mockCustomer = {
    id: 'customer_abc123',
    email: 'test@company.com',
    email_verified: true,
    password_hash: '$argon2id$mock_hash',
    profile: { 
      company_name: 'Test Company',
      company_website: 'https://test.com'
    },
    billing: { 
      plan: 'pro',
      plan_started_at: '2026-01-01T00:00:00Z'
    },
    usage_limits: {
      max_mau: 10000,
      max_realms: 5,
      max_api_calls: 100000,
      mfa_enabled: true,
      sso_enabled: true,
      webhooks_enabled: true,
      audit_logs_days: 30
    },
    status: 'active',
    default_realm_id: 'realm_xyz789',
    created_at: '2026-01-01T00:00:00Z'
  };

  const mockApiKeys = [
    {
      id: 'key_pub123',
      type: 'publishable',
      environment: 'live',
      key_prefix: 'pk_live_',
      key_hint: '...abc1',
      name: 'Default Publishable Key',
      status: 'active',
      usage_count: 100,
      created_at: '2026-01-01T00:00:00Z'
    },
    {
      id: 'key_sec456',
      type: 'secret',
      environment: 'live',
      key_prefix: 'sk_live_',
      key_hint: '...xyz9',
      name: 'Default Secret Key',
      status: 'active',
      usage_count: 50,
      created_at: '2026-01-01T00:00:00Z'
    }
  ];

  beforeEach(() => {
    jest.clearAllMocks();
    
    mockVerifyAccessToken.mockResolvedValue({
      sub: 'customer_abc123',
      email: 'test@company.com',
      type: 'access'
    });
    
    mockGetCustomerById.mockResolvedValue(mockCustomer);
    mockListAPIKeysByCustomer.mockResolvedValue(mockApiKeys);
    mockLogSecurityEvent.mockResolvedValue(undefined);
  });

  describe('Successful Request', () => {
    it('should return customer profile and API keys', async () => {
      const result = await handler(mockEvent('valid_token'));

      expect(result.statusCode).toBe(200);
      
      const body = JSON.parse(result.body);
      expect(body.customer.id).toBe('customer_abc123');
      expect(body.customer.email).toBe('test@company.com');
      expect(body.customer.profile.company_name).toBe('Test Company');
      expect(body.customer.billing.plan).toBe('pro');
      expect(body.api_keys).toHaveLength(2);
    });

    it('should not include password_hash in response', async () => {
      const result = await handler(mockEvent('valid_token'));

      const body = JSON.parse(result.body);
      expect(body.customer.password_hash).toBeUndefined();
    });

    it('should not include stripe_customer_id in response', async () => {
      mockGetCustomerById.mockResolvedValue({
        ...mockCustomer,
        billing: {
          ...mockCustomer.billing,
          stripe_customer_id: 'cus_secret123'
        }
      });

      const result = await handler(mockEvent('valid_token'));

      const body = JSON.parse(result.body);
      expect(body.customer.billing.stripe_customer_id).toBeUndefined();
    });

    it('should include masked API keys', async () => {
      const result = await handler(mockEvent('valid_token'));

      const body = JSON.parse(result.body);
      expect(body.api_keys[0].key_hint).toBe('...abc1');
      expect(body.api_keys[0].full_key).toBeUndefined();
      expect(body.api_keys[0].key_hash).toBeUndefined();
    });

    it('should include realms list', async () => {
      const result = await handler(mockEvent('valid_token'));

      const body = JSON.parse(result.body);
      expect(body.realms).toHaveLength(1);
      expect(body.realms[0].id).toBe('realm_xyz789');
      expect(body.realms[0].is_default).toBe(true);
    });

    it('should include Cache-Control header', async () => {
      const result = await handler(mockEvent('valid_token'));

      expect(result.headers?.['Cache-Control']).toBe('no-store, no-cache, must-revalidate');
    });
  });

  describe('Authentication Errors', () => {
    it('should return 401 for missing Authorization header', async () => {
      const result = await handler(mockEvent());

      expect(result.statusCode).toBe(401);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });

    it('should return 401 for invalid token format', async () => {
      const event = mockEvent();
      event.headers = { Authorization: 'InvalidFormat token123' };

      const result = await handler(event);

      expect(result.statusCode).toBe(401);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });

    it('should return 401 for invalid token', async () => {
      mockVerifyAccessToken.mockRejectedValue(new Error('Invalid token'));

      const result = await handler(mockEvent('invalid_token'));

      expect(result.statusCode).toBe(401);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('INVALID_TOKEN');
    });

    it('should return 401 for expired token', async () => {
      mockVerifyAccessToken.mockRejectedValue(new Error('Token expired'));

      const result = await handler(mockEvent('expired_token'));

      expect(result.statusCode).toBe(401);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('INVALID_TOKEN');
    });
  });

  describe('Customer Status', () => {
    it('should return 404 for deleted customer', async () => {
      mockGetCustomerById.mockResolvedValue(null);

      const result = await handler(mockEvent('valid_token'));

      expect(result.statusCode).toBe(404);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('CUSTOMER_NOT_FOUND');
    });

    it('should return 403 for suspended customer', async () => {
      mockGetCustomerById.mockResolvedValue({
        ...mockCustomer,
        status: 'suspended'
      });

      const result = await handler(mockEvent('valid_token'));

      expect(result.statusCode).toBe(403);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('ACCOUNT_SUSPENDED');
    });
  });

  describe('Error Handling', () => {
    it('should return 500 for unexpected errors', async () => {
      mockGetCustomerById.mockRejectedValue(new Error('Database error'));

      const result = await handler(mockEvent('valid_token'));

      expect(result.statusCode).toBe(500);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('INTERNAL_ERROR');
    });

    it('should log error event', async () => {
      mockGetCustomerById.mockRejectedValue(new Error('Database error'));

      await handler(mockEvent('valid_token'));

      expect(mockLogSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'customer_me_error'
        })
      );
    });
  });

  describe('Security Headers', () => {
    it('should include security headers in response', async () => {
      const result = await handler(mockEvent('valid_token'));

      expect(result.headers?.['X-Content-Type-Options']).toBe('nosniff');
      expect(result.headers?.['X-Frame-Options']).toBe('DENY');
      expect(result.headers?.['Content-Type']).toBe('application/json');
    });
  });
});
