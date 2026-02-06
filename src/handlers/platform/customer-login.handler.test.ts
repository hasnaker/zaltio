/**
 * Customer Login Handler Tests
 * POST /platform/login
 * 
 * Validates: Requirements 2.1 (Customer login)
 */

import { APIGatewayProxyEvent } from 'aws-lambda';

// Mock dependencies
const mockGetCustomerByEmail = jest.fn();
const mockRecordLoginAttempt = jest.fn();
const mockLockCustomerAccount = jest.fn();
jest.mock('../../repositories/customer.repository', () => ({
  getCustomerByEmail: (...args: unknown[]) => mockGetCustomerByEmail(...args),
  recordLoginAttempt: (...args: unknown[]) => mockRecordLoginAttempt(...args),
  lockCustomerAccount: (...args: unknown[]) => mockLockCustomerAccount(...args)
}));

const mockCheckRateLimit = jest.fn();
jest.mock('../../services/ratelimit.service', () => ({
  checkRateLimit: (...args: unknown[]) => mockCheckRateLimit(...args)
}));

const mockVerifyPassword = jest.fn();
jest.mock('../../utils/password', () => ({
  verifyPassword: (...args: unknown[]) => mockVerifyPassword(...args)
}));

const mockGenerateTokenPair = jest.fn();
jest.mock('../../utils/jwt', () => ({
  generateTokenPair: (...args: unknown[]) => mockGenerateTokenPair(...args)
}));

const mockLogSecurityEvent = jest.fn();
jest.mock('../../services/security-logger.service', () => ({
  logSecurityEvent: (...args: unknown[]) => mockLogSecurityEvent(...args)
}));

jest.mock('../../utils/validation', () => ({
  validateEmail: jest.fn().mockReturnValue({ valid: true, errors: [] })
}));

import { handler } from './customer-login.handler';

describe('Customer Login Handler', () => {
  const mockEvent = (body: unknown): APIGatewayProxyEvent => ({
    body: JSON.stringify(body),
    headers: {},
    multiValueHeaders: {},
    httpMethod: 'POST',
    isBase64Encoded: false,
    path: '/platform/login',
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
      path: '/platform/login',
      stage: 'prod',
      requestId: 'test-request-id',
      requestTimeEpoch: Date.now(),
      resourceId: 'resource123',
      resourcePath: '/platform/login'
    },
    resource: '/platform/login'
  });

  const mockCustomer = {
    id: 'customer_abc123',
    email: 'test@company.com',
    password_hash: '$argon2id$mock_hash',
    profile: { company_name: 'Test Company' },
    billing: { plan: 'pro' },
    status: 'active',
    default_realm_id: 'realm_xyz789',
    failed_login_attempts: 0
  };

  beforeEach(() => {
    jest.clearAllMocks();
    
    // Default mocks
    mockCheckRateLimit.mockResolvedValue({
      allowed: true,
      remaining: 4,
      resetAt: Date.now() + 900000
    });
    
    mockGetCustomerByEmail.mockResolvedValue(mockCustomer);
    mockVerifyPassword.mockResolvedValue(true);
    mockRecordLoginAttempt.mockResolvedValue(undefined);
    mockLogSecurityEvent.mockResolvedValue(undefined);
    mockGenerateTokenPair.mockResolvedValue({
      access_token: 'mock_access_token',
      refresh_token: 'mock_refresh_token',
      expires_in: 900
    });
  });

  describe('Successful Login', () => {
    it('should return tokens on successful login', async () => {
      const result = await handler(mockEvent({
        email: 'test@company.com',
        password: 'SecurePass123!'
      }));

      expect(result.statusCode).toBe(200);
      
      const body = JSON.parse(result.body);
      expect(body.customer.id).toBe('customer_abc123');
      expect(body.customer.email).toBe('test@company.com');
      expect(body.customer.plan).toBe('pro');
      expect(body.tokens.access_token).toBeDefined();
      expect(body.tokens.refresh_token).toBeDefined();
      expect(body.tokens.token_type).toBe('Bearer');
      expect(body.tokens.expires_in).toBe(900);
    });

    it('should record successful login attempt', async () => {
      await handler(mockEvent({
        email: 'test@company.com',
        password: 'SecurePass123!'
      }));

      expect(mockRecordLoginAttempt).toHaveBeenCalledWith('customer_abc123', true);
    });

    it('should log successful login event', async () => {
      await handler(mockEvent({
        email: 'test@company.com',
        password: 'SecurePass123!'
      }));

      expect(mockLogSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'customer_login_success'
        })
      );
    });
  });

  describe('Invalid Credentials', () => {
    it('should return 401 for non-existent customer', async () => {
      mockGetCustomerByEmail.mockResolvedValue(null);

      const result = await handler(mockEvent({
        email: 'nonexistent@company.com',
        password: 'SecurePass123!'
      }));

      expect(result.statusCode).toBe(401);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('INVALID_CREDENTIALS');
    });

    it('should return 401 for wrong password', async () => {
      mockVerifyPassword.mockResolvedValue(false);

      const result = await handler(mockEvent({
        email: 'test@company.com',
        password: 'WrongPassword!'
      }));

      expect(result.statusCode).toBe(401);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('INVALID_CREDENTIALS');
    });

    it('should record failed login attempt', async () => {
      mockVerifyPassword.mockResolvedValue(false);

      await handler(mockEvent({
        email: 'test@company.com',
        password: 'WrongPassword!'
      }));

      expect(mockRecordLoginAttempt).toHaveBeenCalledWith('customer_abc123', false);
    });
  });

  describe('Account Lockout', () => {
    it('should return 423 for locked account', async () => {
      mockGetCustomerByEmail.mockResolvedValue({
        ...mockCustomer,
        locked_until: new Date(Date.now() + 3600000).toISOString() // 1 hour from now
      });

      const result = await handler(mockEvent({
        email: 'test@company.com',
        password: 'SecurePass123!'
      }));

      expect(result.statusCode).toBe(423);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('ACCOUNT_LOCKED');
    });

    it('should lock account after 10 failed attempts', async () => {
      mockGetCustomerByEmail.mockResolvedValue({
        ...mockCustomer,
        failed_login_attempts: 9
      });
      mockVerifyPassword.mockResolvedValue(false);

      await handler(mockEvent({
        email: 'test@company.com',
        password: 'WrongPassword!'
      }));

      expect(mockLockCustomerAccount).toHaveBeenCalledWith('customer_abc123', 30);
    });

    it('should not lock account before 10 failed attempts', async () => {
      mockGetCustomerByEmail.mockResolvedValue({
        ...mockCustomer,
        failed_login_attempts: 5
      });
      mockVerifyPassword.mockResolvedValue(false);

      await handler(mockEvent({
        email: 'test@company.com',
        password: 'WrongPassword!'
      }));

      expect(mockLockCustomerAccount).not.toHaveBeenCalled();
    });
  });

  describe('Account Status', () => {
    it('should return 403 for suspended account', async () => {
      mockGetCustomerByEmail.mockResolvedValue({
        ...mockCustomer,
        status: 'suspended'
      });

      const result = await handler(mockEvent({
        email: 'test@company.com',
        password: 'SecurePass123!'
      }));

      expect(result.statusCode).toBe(403);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('ACCOUNT_SUSPENDED');
    });
  });

  describe('Rate Limiting', () => {
    it('should return 429 when rate limit exceeded', async () => {
      mockCheckRateLimit.mockResolvedValue({
        allowed: false,
        remaining: 0,
        retryAfter: 900,
        resetAt: Date.now() + 900000
      });

      const result = await handler(mockEvent({
        email: 'test@company.com',
        password: 'SecurePass123!'
      }));

      expect(result.statusCode).toBe(429);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('RATE_LIMIT_EXCEEDED');
    });

    it('should include rate limit headers in response', async () => {
      const result = await handler(mockEvent({
        email: 'test@company.com',
        password: 'SecurePass123!'
      }));

      expect(result.headers?.['X-RateLimit-Remaining']).toBeDefined();
      expect(result.headers?.['X-RateLimit-Reset']).toBeDefined();
    });
  });

  describe('Validation Errors', () => {
    it('should return 400 for missing email', async () => {
      const result = await handler(mockEvent({
        password: 'SecurePass123!'
      }));

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('MISSING_FIELDS');
    });

    it('should return 400 for missing password', async () => {
      const result = await handler(mockEvent({
        email: 'test@company.com'
      }));

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('MISSING_FIELDS');
    });

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
  });

  describe('Error Handling', () => {
    it('should return 500 for unexpected errors', async () => {
      mockGetCustomerByEmail.mockRejectedValue(new Error('Database error'));

      const result = await handler(mockEvent({
        email: 'test@company.com',
        password: 'SecurePass123!'
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
        password: 'SecurePass123!'
      }));

      expect(result.headers?.['X-Content-Type-Options']).toBe('nosniff');
      expect(result.headers?.['X-Frame-Options']).toBe('DENY');
      expect(result.headers?.['Content-Type']).toBe('application/json');
    });
  });
});
