/**
 * Customer Signup E2E Tests
 * Tests the complete B2B customer signup flow for Zalt.io platform
 * 
 * Flow:
 * 1. Customer signs up at zalt.io/signup
 * 2. System creates customer account
 * 3. System creates default realm
 * 4. System generates API keys (pk_live_xxx, sk_live_xxx)
 * 5. Customer receives onboarding info
 * 
 * Validates: Requirements 1.2, 1.3, 1.4 (Customer account system)
 */

import { handler as customerRegisterHandler } from '../../handlers/platform/customer-register.handler';
import { APIGatewayProxyEvent } from 'aws-lambda';

// Mock dependencies
jest.mock('uuid', () => ({
  v4: jest.fn().mockReturnValue('test-uuid-12345678')
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

describe('Customer Signup E2E Flow', () => {
  const createMockEvent = (body: unknown): APIGatewayProxyEvent => ({
    body: JSON.stringify(body),
    headers: { 'Content-Type': 'application/json' },
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
        sourceIp: '203.0.113.42',
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
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        userArn: null
      },
      path: '/platform/register',
      stage: 'prod',
      requestId: 'e2e-test-request-id',
      requestTimeEpoch: Date.now(),
      resourceId: 'resource123',
      resourcePath: '/platform/register'
    },
    resource: '/platform/register'
  });

  beforeEach(() => {
    jest.clearAllMocks();
    
    // Default successful mocks
    mockCheckRateLimit.mockResolvedValue({
      allowed: true,
      remaining: 2,
      resetAt: Date.now() + 3600000
    });
    
    mockValidatePasswordPolicy.mockReturnValue({ valid: true, errors: [] });
    mockCheckPasswordPwned.mockResolvedValue(0);
    mockGetCustomerByEmail.mockResolvedValue(null);
    mockLogSecurityEvent.mockResolvedValue(undefined);
    mockSetDefaultRealm.mockResolvedValue({});
  });

  describe('Complete Signup Flow', () => {
    it('should complete full signup flow: customer → realm → API keys', async () => {
      // Setup mocks for complete flow
      const mockCustomer = {
        id: 'customer_abc123',
        email: 'cto@techstartup.com',
        profile: { company_name: 'Tech Startup Inc' },
        billing: { plan: 'free' },
        status: 'pending_verification',
        created_at: new Date().toISOString()
      };

      const mockRealm = {
        id: 'realm_xyz789',
        name: 'Tech Startup Inc',
        domain: 'tech-startup-inc.zalt.io'
      };

      // Using FAKE_ prefix to avoid GitHub secret scanning false positives
      const mockApiKeys = {
        publishableKey: {
          full_key: 'pk_live_mock_key_for_testing_only'
        },
        secretKey: {
          full_key: 'sk_live_mock_key_for_testing_only'
        }
      };

      mockCreateCustomer.mockResolvedValue(mockCustomer);
      mockCreateRealm.mockResolvedValue(mockRealm);
      mockCreateDefaultAPIKeys.mockResolvedValue(mockApiKeys);

      // Execute signup
      const result = await customerRegisterHandler(createMockEvent({
        email: 'cto@techstartup.com',
        password: 'SecurePassword123!',
        company_name: 'Tech Startup Inc'
      }));

      // Verify response
      expect(result.statusCode).toBe(201);
      
      const body = JSON.parse(result.body);
      
      // Verify customer created
      expect(body.customer).toBeDefined();
      expect(body.customer.id).toBe('customer_abc123');
      expect(body.customer.email).toBe('cto@techstartup.com');
      expect(body.customer.company_name).toBe('Tech Startup Inc');
      expect(body.customer.plan).toBe('free');
      
      // Verify realm created
      expect(body.realm).toBeDefined();
      expect(body.realm.id).toBe('realm_xyz789');
      expect(body.realm.name).toBe('Tech Startup Inc');
      expect(body.realm.domain).toBe('tech-startup-inc.zalt.io');
      
      // Verify API keys generated
      expect(body.api_keys).toBeDefined();
      expect(body.api_keys.publishable_key).toMatch(/^pk_live_/);
      expect(body.api_keys.secret_key).toMatch(/^sk_live_/);
      expect(body.api_keys.warning).toContain('will not be shown again');
      
      // Verify flow order
      expect(mockCreateCustomer).toHaveBeenCalledTimes(1);
      expect(mockCreateRealm).toHaveBeenCalledTimes(1);
      expect(mockSetDefaultRealm).toHaveBeenCalledWith('customer_abc123', 'realm_xyz789');
      expect(mockCreateDefaultAPIKeys).toHaveBeenCalledWith('customer_abc123', 'realm_xyz789');
    });

    it('should create realm with URL-safe slug from company name', async () => {
      mockCreateCustomer.mockResolvedValue({
        id: 'customer_123',
        email: 'test@company.com',
        profile: { company_name: 'My Awesome Company & Partners!' },
        billing: { plan: 'free' },
        status: 'pending_verification',
        created_at: new Date().toISOString()
      });

      mockCreateRealm.mockResolvedValue({
        id: 'realm_456',
        name: 'My Awesome Company & Partners!',
        domain: 'my-awesome-company-partners.zalt.io'
      });

      mockCreateDefaultAPIKeys.mockResolvedValue({
        publishableKey: { full_key: 'pk_live_mock_key_for_testing_only' },
        secretKey: { full_key: 'sk_live_mock_key_for_testing_only' }
      });

      await customerRegisterHandler(createMockEvent({
        email: 'test@company.com',
        password: 'SecurePassword123!',
        company_name: 'My Awesome Company & Partners!'
      }));

      // Verify realm was created with proper slug
      expect(mockCreateRealm).toHaveBeenCalledWith(
        expect.objectContaining({
          name: 'My Awesome Company & Partners!',
          domain: expect.stringMatching(/^my-awesome-company-partners\.zalt\.io$/)
        })
      );
    });

    it('should support enterprise plan signup', async () => {
      mockCreateCustomer.mockResolvedValue({
        id: 'customer_enterprise',
        email: 'enterprise@bigcorp.com',
        profile: { company_name: 'Big Corporation' },
        billing: { plan: 'enterprise' },
        status: 'pending_verification',
        created_at: new Date().toISOString()
      });

      mockCreateRealm.mockResolvedValue({
        id: 'realm_enterprise',
        name: 'Big Corporation',
        domain: 'big-corporation.zalt.io'
      });

      mockCreateDefaultAPIKeys.mockResolvedValue({
        publishableKey: { full_key: 'pk_live_mock_key_for_testing_only' },
        secretKey: { full_key: 'sk_live_mock_key_for_testing_only' }
      });

      const result = await customerRegisterHandler(createMockEvent({
        email: 'enterprise@bigcorp.com',
        password: 'SecurePassword123!',
        company_name: 'Big Corporation',
        plan: 'enterprise'
      }));

      expect(result.statusCode).toBe(201);
      const body = JSON.parse(result.body);
      expect(body.customer.plan).toBe('enterprise');
    });
  });

  describe('Security Validations', () => {
    it('should reject compromised passwords (HaveIBeenPwned)', async () => {
      mockCheckPasswordPwned.mockResolvedValue(50000); // Found in 50k breaches

      const result = await customerRegisterHandler(createMockEvent({
        email: 'test@company.com',
        password: 'password123',
        company_name: 'Test Company'
      }));

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('PASSWORD_COMPROMISED');
      expect(body.error.details.breach_count).toBe(50000);
      
      // Verify security event logged
      expect(mockLogSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'pwned_password_rejected'
        })
      );
    });

    it('should enforce password policy', async () => {
      mockValidatePasswordPolicy.mockReturnValue({
        valid: false,
        errors: [
          'Password must be at least 8 characters',
          'Password must contain at least one uppercase letter'
        ]
      });

      const result = await customerRegisterHandler(createMockEvent({
        email: 'test@company.com',
        password: 'weak',
        company_name: 'Test Company'
      }));

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('INVALID_PASSWORD');
    });

    it('should rate limit signup attempts (3/hour/IP)', async () => {
      mockCheckRateLimit.mockResolvedValue({
        allowed: false,
        remaining: 0,
        retryAfter: 2400,
        resetAt: Date.now() + 2400000
      });

      const result = await customerRegisterHandler(createMockEvent({
        email: 'test@company.com',
        password: 'SecurePassword123!',
        company_name: 'Test Company'
      }));

      expect(result.statusCode).toBe(429);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('RATE_LIMIT_EXCEEDED');
      expect(body.error.details.retry_after).toBe(2400);
    });

    it('should prevent duplicate customer registration', async () => {
      mockGetCustomerByEmail.mockResolvedValue({
        id: 'existing_customer',
        email: 'existing@company.com'
      });

      const result = await customerRegisterHandler(createMockEvent({
        email: 'existing@company.com',
        password: 'SecurePassword123!',
        company_name: 'Test Company'
      }));

      expect(result.statusCode).toBe(409);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('CUSTOMER_EXISTS');
    });

    it('should include security headers in response', async () => {
      mockCreateCustomer.mockResolvedValue({
        id: 'customer_123',
        email: 'test@company.com',
        profile: { company_name: 'Test Company' },
        billing: { plan: 'free' },
        status: 'pending_verification',
        created_at: new Date().toISOString()
      });

      mockCreateRealm.mockResolvedValue({
        id: 'realm_456',
        name: 'Test Company',
        domain: 'test-company.zalt.io'
      });

      mockCreateDefaultAPIKeys.mockResolvedValue({
        publishableKey: { full_key: 'pk_live_mock_key_for_testing_only' },
        secretKey: { full_key: 'sk_live_mock_key_for_testing_only' }
      });

      const result = await customerRegisterHandler(createMockEvent({
        email: 'test@company.com',
        password: 'SecurePassword123!',
        company_name: 'Test Company'
      }));

      expect(result.headers?.['X-Content-Type-Options']).toBe('nosniff');
      expect(result.headers?.['X-Frame-Options']).toBe('DENY');
      expect(result.headers?.['Content-Type']).toBe('application/json');
    });
  });

  describe('Audit Logging', () => {
    it('should log successful customer registration', async () => {
      mockCreateCustomer.mockResolvedValue({
        id: 'customer_audit_test',
        email: 'audit@company.com',
        profile: { company_name: 'Audit Test Company' },
        billing: { plan: 'pro' },
        status: 'pending_verification',
        created_at: new Date().toISOString()
      });

      mockCreateRealm.mockResolvedValue({
        id: 'realm_audit',
        name: 'Audit Test Company',
        domain: 'audit-test-company.zalt.io'
      });

      mockCreateDefaultAPIKeys.mockResolvedValue({
        publishableKey: { full_key: 'pk_live_mock_key_for_testing_0003' },
        secretKey: { full_key: 'sk_live_mock_key_for_testing_0003' }
      });

      await customerRegisterHandler(createMockEvent({
        email: 'audit@company.com',
        password: 'SecurePassword123!',
        company_name: 'Audit Test Company',
        plan: 'pro'
      }));

      expect(mockLogSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'customer_registered',
          user_id: 'customer_audit_test',
          realm_id: 'realm_audit',
          details: expect.objectContaining({
            company_name: 'Audit Test Company',
            plan: 'pro'
          })
        })
      );
    });

    it('should log rate limit exceeded events', async () => {
      mockCheckRateLimit.mockResolvedValue({
        allowed: false,
        remaining: 0,
        retryAfter: 3600,
        resetAt: Date.now() + 3600000
      });

      await customerRegisterHandler(createMockEvent({
        email: 'test@company.com',
        password: 'SecurePassword123!',
        company_name: 'Test Company'
      }));

      expect(mockLogSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'rate_limit_exceeded',
          details: expect.objectContaining({
            endpoint: 'platform/register'
          })
        })
      );
    });
  });

  describe('API Key Format Validation', () => {
    it('should generate publishable key with pk_live_ prefix', async () => {
      mockCreateCustomer.mockResolvedValue({
        id: 'customer_key_test',
        email: 'keys@company.com',
        profile: { company_name: 'Key Test Company' },
        billing: { plan: 'free' },
        status: 'pending_verification',
        created_at: new Date().toISOString()
      });

      mockCreateRealm.mockResolvedValue({
        id: 'realm_key_test',
        name: 'Key Test Company',
        domain: 'key-test-company.zalt.io'
      });

      mockCreateDefaultAPIKeys.mockResolvedValue({
        publishableKey: { full_key: 'pk_live_mock_key_for_testing_only' },
        secretKey: { full_key: 'sk_live_mock_key_for_testing_only' }
      });

      const result = await customerRegisterHandler(createMockEvent({
        email: 'keys@company.com',
        password: 'SecurePassword123!',
        company_name: 'Key Test Company'
      }));

      const body = JSON.parse(result.body);
      
      // Publishable key format: pk_live_ + 32 chars
      expect(body.api_keys.publishable_key).toMatch(/^pk_live_[A-Za-z0-9]{32}$/);
      
      // Secret key format: sk_live_ + 32 chars
      expect(body.api_keys.secret_key).toMatch(/^sk_live_[A-Za-z0-9]{32}$/);
    });
  });
});
