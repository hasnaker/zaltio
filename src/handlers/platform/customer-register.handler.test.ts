/**
 * Customer Register Handler Tests
 * POST /platform/register
 * 
 * Validates: Requirements 1.2, 1.3, 1.4 (Customer account system)
 */

import { APIGatewayProxyEvent } from 'aws-lambda';

// Mock dependencies
jest.mock('uuid', () => ({
  v4: jest.fn().mockReturnValue('12345678-1234-1234-1234-123456789012')
}));

const mockCreateCustomer = jest.fn();
const mockGetCustomerByEmail = jest.fn();
const mockSetDefaultRealm = jest.fn();
jest.mock('../../repositories/customer.repository', () => ({
  createCustomer: (...args: unknown[]) => mockCreateCustomer(...args),
  getCustomerByEmail: (...args: unknown[]) => mockGetCustomerByEmail(...args),
  setDefaultRealm: (...args: unknown[]) => mockSetDefaultRealm(...args)
}));

const mockCreateDefaultAPIKeys = jest.fn();
jest.mock('../../repositories/api-key.repository', () => ({
  createDefaultAPIKeys: (...args: unknown[]) => mockCreateDefaultAPIKeys(...args)
}));

const mockCreateRealm = jest.fn();
jest.mock('../../repositories/realm.repository', () => ({
  createRealm: (...args: unknown[]) => mockCreateRealm(...args)
}));

const mockCheckRateLimit = jest.fn();
jest.mock('../../services/ratelimit.service', () => ({
  checkRateLimit: (...args: unknown[]) => mockCheckRateLimit(...args)
}));

const mockCheckPasswordPwned = jest.fn();
const mockValidatePasswordPolicy = jest.fn();
jest.mock('../../utils/password', () => ({
  checkPasswordPwned: (...args: unknown[]) => mockCheckPasswordPwned(...args),
  validatePasswordPolicy: (...args: unknown[]) => mockValidatePasswordPolicy(...args),
  hashPassword: jest.fn().mockResolvedValue('$argon2id$mock_hash')
}));

const mockLogSecurityEvent = jest.fn();
jest.mock('../../services/security-logger.service', () => ({
  logSecurityEvent: (...args: unknown[]) => mockLogSecurityEvent(...args)
}));

jest.mock('../../utils/validation', () => ({
  validateEmail: jest.fn().mockReturnValue({ valid: true, errors: [] })
}));

import { handler } from './customer-register.handler';

describe('Customer Register Handler', () => {
  const mockEvent = (body: unknown): APIGatewayProxyEvent => ({
    body: JSON.stringify(body),
    headers: {},
    multiValueHeaders: {},
    httpMethod: 'POST',
    isBase64Encoded: false,
    path: '/platform/register',
    pathParameters: null,
    queryStringParameters: null,
    multiValueQueryStringParameters: null,
    stageVariables: null,
    requestContext: {
      accountId: '123456789012',
      apiId: 'api123',
      authorizer: null,
      protocol: 'HTTP/1.1',
      httpMethod: 'POST',
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
      path: '/platform/register',
      stage: 'prod',
      requestId: 'test-request-id',
      requestTimeEpoch: Date.now(),
      resourceId: 'resource123',
      resourcePath: '/platform/register'
    },
    resource: '/platform/register'
  });

  beforeEach(() => {
    jest.clearAllMocks();
    
    // Default mocks
    mockCheckRateLimit.mockResolvedValue({
      allowed: true,
      remaining: 2,
      resetAt: Date.now() + 3600000
    });
    
    mockValidatePasswordPolicy.mockReturnValue({ valid: true, errors: [] });
    mockCheckPasswordPwned.mockResolvedValue(0);
    mockGetCustomerByEmail.mockResolvedValue(null);
    mockLogSecurityEvent.mockResolvedValue(undefined);
    
    mockCreateCustomer.mockResolvedValue({
      id: 'customer_abc123',
      email: 'test@company.com',
      profile: { company_name: 'Test Company' },
      billing: { plan: 'free' },
      status: 'pending_verification',
      created_at: new Date().toISOString()
    });
    
    mockCreateRealm.mockResolvedValue({
      id: 'realm_xyz789',
      name: 'Test Company',
      domain: 'test-company.zalt.io'
    });
    
    mockSetDefaultRealm.mockResolvedValue({});
    
    // Using FAKE_ prefix to avoid GitHub secret scanning false positives
    mockCreateDefaultAPIKeys.mockResolvedValue({
      publishableKey: {
        full_key: 'pk_live_mock_key_for_testing_only'
      },
      secretKey: {
        full_key: 'sk_live_mock_key_for_testing_only'
      }
    });
  });

  describe('Successful Registration', () => {
    it('should create customer, realm, and API keys', async () => {
      const result = await handler(mockEvent({
        email: 'test@company.com',
        password: 'SecurePass123!',
        company_name: 'Test Company'
      }));

      expect(result.statusCode).toBe(201);
      
      const body = JSON.parse(result.body);
      expect(body.customer.id).toBe('customer_abc123');
      expect(body.customer.email).toBe('test@company.com');
      expect(body.realm.id).toBe('realm_xyz789');
      expect(body.api_keys.publishable_key).toMatch(/^pk_live_/);
      expect(body.api_keys.secret_key).toMatch(/^sk_live_/);
      expect(body.api_keys.warning).toContain('will not be shown again');
    });

    it('should create customer with specified plan', async () => {
      mockCreateCustomer.mockResolvedValue({
        id: 'customer_abc123',
        email: 'enterprise@company.com',
        profile: { company_name: 'Enterprise Corp' },
        billing: { plan: 'enterprise' },
        status: 'pending_verification',
        created_at: new Date().toISOString()
      });

      const result = await handler(mockEvent({
        email: 'enterprise@company.com',
        password: 'SecurePass123!',
        company_name: 'Enterprise Corp',
        plan: 'enterprise'
      }));

      expect(result.statusCode).toBe(201);
      const body = JSON.parse(result.body);
      expect(body.customer.plan).toBe('enterprise');
    });

    it('should log security event on successful registration', async () => {
      await handler(mockEvent({
        email: 'test@company.com',
        password: 'SecurePass123!',
        company_name: 'Test Company'
      }));

      expect(mockLogSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'customer_registered'
        })
      );
    });
  });

  describe('Validation Errors', () => {
    it('should return 400 for missing email', async () => {
      const result = await handler(mockEvent({
        password: 'SecurePass123!',
        company_name: 'Test Company'
      }));

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('MISSING_FIELDS');
    });

    it('should return 400 for missing password', async () => {
      const result = await handler(mockEvent({
        email: 'test@company.com',
        company_name: 'Test Company'
      }));

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('MISSING_FIELDS');
    });

    it('should return 400 for missing company_name', async () => {
      const result = await handler(mockEvent({
        email: 'test@company.com',
        password: 'SecurePass123!'
      }));

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('MISSING_FIELDS');
    });

    it('should return 400 for invalid password policy', async () => {
      mockValidatePasswordPolicy.mockReturnValue({
        valid: false,
        errors: ['Password must be at least 12 characters']
      });

      const result = await handler(mockEvent({
        email: 'test@company.com',
        password: 'weak',
        company_name: 'Test Company'
      }));

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('INVALID_PASSWORD');
    });

    it('should return 400 for compromised password', async () => {
      mockCheckPasswordPwned.mockResolvedValue(1000);

      const result = await handler(mockEvent({
        email: 'test@company.com',
        password: 'password123',
        company_name: 'Test Company'
      }));

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('PASSWORD_COMPROMISED');
    });

    it('should return 400 for short company name', async () => {
      const result = await handler(mockEvent({
        email: 'test@company.com',
        password: 'SecurePass123!',
        company_name: 'A'
      }));

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('INVALID_COMPANY_NAME');
    });
  });

  describe('Rate Limiting', () => {
    it('should return 429 when rate limit exceeded', async () => {
      mockCheckRateLimit.mockResolvedValue({
        allowed: false,
        remaining: 0,
        retryAfter: 3600,
        resetAt: Date.now() + 3600000
      });

      const result = await handler(mockEvent({
        email: 'test@company.com',
        password: 'SecurePass123!',
        company_name: 'Test Company'
      }));

      expect(result.statusCode).toBe(429);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('RATE_LIMIT_EXCEEDED');
    });

    it('should include rate limit headers in response', async () => {
      const result = await handler(mockEvent({
        email: 'test@company.com',
        password: 'SecurePass123!',
        company_name: 'Test Company'
      }));

      expect(result.headers?.['X-RateLimit-Remaining']).toBeDefined();
      expect(result.headers?.['X-RateLimit-Reset']).toBeDefined();
    });
  });

  describe('Duplicate Customer', () => {
    it('should return 409 when customer already exists', async () => {
      mockGetCustomerByEmail.mockResolvedValue({
        id: 'existing_customer',
        email: 'test@company.com'
      });

      const result = await handler(mockEvent({
        email: 'test@company.com',
        password: 'SecurePass123!',
        company_name: 'Test Company'
      }));

      expect(result.statusCode).toBe(409);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('CUSTOMER_EXISTS');
    });

    it('should log duplicate registration attempt', async () => {
      mockGetCustomerByEmail.mockResolvedValue({
        id: 'existing_customer',
        email: 'test@company.com'
      });

      await handler(mockEvent({
        email: 'test@company.com',
        password: 'SecurePass123!',
        company_name: 'Test Company'
      }));

      expect(mockLogSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'duplicate_customer_registration'
        })
      );
    });
  });

  describe('Error Handling', () => {
    it('should return 400 for invalid JSON', async () => {
      const event = mockEvent({});
      event.body = 'invalid json';

      const result = await handler(event);

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('INVALID_JSON');
    });

    it('should return 400 for missing body', async () => {
      const event = mockEvent({});
      event.body = null;

      const result = await handler(event);

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('INVALID_REQUEST');
    });

    it('should return 500 for unexpected errors', async () => {
      mockCreateCustomer.mockRejectedValue(new Error('Database error'));

      const result = await handler(mockEvent({
        email: 'test@company.com',
        password: 'SecurePass123!',
        company_name: 'Test Company'
      }));

      expect(result.statusCode).toBe(500);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('INTERNAL_ERROR');
    });
  });

  describe('Security Headers', () => {
    it('should include security headers in response', async () => {
      const result = await handler(mockEvent({
        email: 'test@company.com',
        password: 'SecurePass123!',
        company_name: 'Test Company'
      }));

      expect(result.headers?.['X-Content-Type-Options']).toBe('nosniff');
      expect(result.headers?.['X-Frame-Options']).toBe('DENY');
      expect(result.headers?.['Content-Type']).toBe('application/json');
    });
  });
});
